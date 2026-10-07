import { and, asc, eq, inArray, or } from "drizzle-orm";
import { entities, entityAliases, intelMatches, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { canonicalKey } from "@/lib/graph/model";
import { traverse, type GraphEdge, type TraverseOptions } from "@/lib/graph/traverse";
import { scoped } from "./common";

// The graph joins alerts, assets and intel, so reading it needs alert:read.

/** Traversal from one entity in the caller's scope. Null when the entity is not visible. */
export async function traverseEntity(ctx: AccessContext, id: string, opts: TraverseOptions = {}) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const [e] = await tx.select({ tenantId: entities.tenantId }).from(entities).where(and(eq(entities.id, id), inArray(entities.tenantId, tenantIds)));
    return e ? traverse(tx, e.tenantId, id, opts) : null;
  });
}

export type EntityEdgeView = GraphEdge & { evidenceAlertId: string | null };

/** Entity page: identifiers, aliases, direct neighbours, and what is reachable within three hops. */
export async function getEntity(ctx: AccessContext, id: string) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const [row] = await tx
      .select({ entity: entities, tenantName: tenants.name })
      .from(entities)
      .innerJoin(tenants, eq(tenants.id, entities.tenantId))
      .where(and(eq(entities.id, id), inArray(entities.tenantId, tenantIds)));
    if (!row) return null;
    const tenantId = row.entity.tenantId;
    const [aliases, neighbours, reach] = await Promise.all([
      tx.select().from(entityAliases).where(eq(entityAliases.entityId, id)).orderBy(asc(entityAliases.kind), asc(entityAliases.value)),
      traverse(tx, tenantId, id, { maxDepth: 1, limit: 300 }),
      traverse(tx, tenantId, id, { maxDepth: 3, limit: 300 }),
    ]);
    // Intel edges cite the intel match; link the analyst to the alert it was found on.
    const matchIds = neighbours!.edges.filter((e) => e.evidenceType === "intel_match").map((e) => e.evidenceId);
    const matchAlerts = matchIds.length
      ? new Map((await tx.select({ id: intelMatches.id, alertId: intelMatches.alertId }).from(intelMatches).where(inArray(intelMatches.id, matchIds))).map((m) => [m.id, m.alertId]))
      : new Map<string, string | null>();
    const edges: EntityEdgeView[] = neighbours!.edges
      .filter((e) => e.fromEntityId === id || e.toEntityId === id)
      .map((e) => ({ ...e, evidenceAlertId: e.evidenceType === "alert" ? e.evidenceId : e.evidenceType === "intel_match" ? matchAlerts.get(e.evidenceId) ?? null : null }));
    return { ...row, aliases, neighbours: neighbours!.nodes.filter((n) => n.id !== id), edges, reach: reach!.nodes.filter((n) => n.id !== id), reachTruncated: reach!.truncated };
  });
}

/** Entity ids for records shown elsewhere (alert, its user, an asset), for linking to entity pages. */
export async function entityLinks(ctx: AccessContext, tenantId: string, refs: { alertId?: string; userName?: string | null; assetId?: string }) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const out: { alert?: string; user?: string; asset?: string } = {};
    if (!tenantIds.includes(tenantId)) return out;
    const keys = [
      refs.alertId ? and(eq(entities.type, "alert"), eq(entities.key, refs.alertId)) : undefined,
      refs.userName?.trim() ? and(eq(entities.type, "user"), eq(entities.key, canonicalKey("user", refs.userName))) : undefined,
    ].filter(Boolean);
    if (keys.length) {
      for (const r of await tx.select({ id: entities.id, type: entities.type }).from(entities).where(and(eq(entities.tenantId, tenantId), or(...keys)))) {
        if (r.type === "alert") out.alert = r.id;
        else out.user = r.id;
      }
    }
    if (refs.assetId) {
      const [a] = await tx.select({ id: entityAliases.entityId }).from(entityAliases).where(and(eq(entityAliases.tenantId, tenantId), eq(entityAliases.kind, "asset_id"), eq(entityAliases.value, refs.assetId)));
      out.asset = a?.id;
    }
    return out;
  }, [tenantId]);
}
