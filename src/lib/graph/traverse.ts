import { and, desc, eq, inArray, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { entities, entityRelationships } from "@/db/schema";
import { ENTITY_TYPES, RELATIONSHIP_TYPES, type EntityType, type RelationshipType } from "./model";

export const MAX_DEPTH = 3;
export const DEFAULT_LIMIT = 200;
export const MAX_LIMIT = 1000;

export type TraverseOptions = {
  /** Hops from the start entity, 1–3. */
  maxDepth?: number;
  /** Only traverse through, and return, entities of these types. The start entity is always returned. */
  entityTypes?: EntityType[];
  /** Only follow these relationship types, in either direction. */
  relationshipTypes?: RelationshipType[];
  /** Maximum entities returned, start included. Edges are capped at four times this. */
  limit?: number;
};

export type GraphNode = typeof entities.$inferSelect & { depth: number };
export type GraphEdge = typeof entityRelationships.$inferSelect;
export type GraphView = { start: GraphNode; nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean };

/**
 * Breadth-first walk from one entity, one query per hop, returning the subgraph induced on the
 * entities reached. Per-hop queries rather than one recursive CTE: a CTE cannot share a visited
 * set across branches, so a hub (one user on hundreds of alerts) is re-expanded on every path.
 * Here each entity is expanded once and the walk stops when the row limit is reached; entities
 * on the most recent edges are kept first. Runs inside the caller's RLS scope and also filters
 * by tenant, so another tenant's start id finds nothing.
 */
export async function traverse(tx: Tx, tenantId: string, startId: string, opts: TraverseOptions = {}): Promise<GraphView | null> {
  const maxDepth = Math.min(Math.max(Math.trunc(opts.maxDepth ?? 2), 1), MAX_DEPTH);
  const limit = Math.min(Math.max(Math.trunc(opts.limit ?? DEFAULT_LIMIT), 1), MAX_LIMIT);
  const entityTypes = opts.entityTypes?.filter((t) => (ENTITY_TYPES as readonly string[]).includes(t));
  const relTypes = opts.relationshipTypes?.filter((t) => (RELATIONSHIP_TYPES as readonly string[]).includes(t));

  const [start] = await tx.select().from(entities).where(and(eq(entities.id, startId), eq(entities.tenantId, tenantId)));
  if (!start) return null;

  const depthOf = new Map<string, number>([[start.id, 0]]);
  let frontier = [start.id];
  let truncated = false;
  const relFilter = relTypes?.length ? sql`and r.type in ${relTypes}` : sql``;
  const typeFilter = entityTypes?.length ? sql`and e.type in ${entityTypes}` : sql``;

  for (let depth = 1; depth <= maxDepth && frontier.length; depth++) {
    const room = limit - depthOf.size;
    if (room <= 0) {
      truncated = true;
      break;
    }
    const f = sql`array[${sql.join(frontier.map((id) => sql`${id}::uuid`), sql`, `)}]`;
    const visited = sql`array[${sql.join([...depthOf.keys()].map((id) => sql`${id}::uuid`), sql`, `)}]`;
    const rows = await tx.execute<{ id: string }>(sql`
      select n.other as id from (
        select r.to_entity_id as other, r.last_seen from entity_relationships r
        where r.tenant_id = ${tenantId} and r.from_entity_id = any(${f}) ${relFilter}
        union all
        select r.from_entity_id, r.last_seen from entity_relationships r
        where r.tenant_id = ${tenantId} and r.to_entity_id = any(${f}) ${relFilter}
      ) n
      join entities e on e.id = n.other
      where n.other <> all(${visited}) ${typeFilter}
      group by n.other
      order by max(n.last_seen) desc
      limit ${room + 1}`);
    if (rows.length > room) truncated = true;
    frontier = rows.slice(0, room).map((r) => r.id);
    for (const id of frontier) depthOf.set(id, depth);
  }

  const ids = [...depthOf.keys()];
  const nodeRows = await tx.select().from(entities).where(and(eq(entities.tenantId, tenantId), inArray(entities.id, ids)));
  const edgeLimit = limit * 4;
  const edges = ids.length > 1
    ? await tx
        .select()
        .from(entityRelationships)
        .where(and(
          eq(entityRelationships.tenantId, tenantId),
          inArray(entityRelationships.fromEntityId, ids),
          inArray(entityRelationships.toEntityId, ids),
          relTypes?.length ? inArray(entityRelationships.type, relTypes) : undefined,
        ))
        .orderBy(desc(entityRelationships.lastSeen))
        .limit(edgeLimit + 1)
    : [];
  if (edges.length > edgeLimit) truncated = true;

  const nodes = nodeRows.map((n) => ({ ...n, depth: depthOf.get(n.id)! })).sort((a, b) => a.depth - b.depth || +b.lastSeen - +a.lastSeen);
  return { start: { ...start, depth: 0 }, nodes, edges: edges.slice(0, edgeLimit), truncated };
}
