import { and, eq, inArray, or, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { entities, entityAliases, entityRelationships } from "@/db/schema";
import { accountCandidates, alertFacts, assetFacts, refKey, type AlertGraphInput, type AssetInput, type EdgeFact, type EntityFact, type EntityRef, type GraphFacts } from "./model";

/**
 * Upserts facts for one tenant. Returns refKey → entity id.
 * Edge counts move only when a new evidence row lands, so replaying a record (re-ingest,
 * backfill) leaves counts, first_seen and last_seen where they were.
 */
export async function writeGraph(tx: Tx, tenantId: string, facts: GraphFacts): Promise<Map<string, string>> {
  const merged = new Map<string, EntityFact & { sources: Set<string> }>();
  for (const e of facts.entities) {
    const k = refKey(e);
    const cur = merged.get(k);
    if (!cur) {
      merged.set(k, { ...e, sources: new Set([e.source]) });
      continue;
    }
    // Inventory names beat names taken from event text.
    if (e.identifiers?.assetId && !cur.identifiers?.assetId) cur.displayName = e.displayName;
    cur.identifiers = { ...cur.identifiers, ...e.identifiers };
    cur.sources.add(e.source);
    if (e.seenAt > cur.seenAt) cur.seenAt = e.seenAt;
    const first = e.firstSeen ?? e.seenAt;
    if (first < (cur.firstSeen ?? cur.seenAt)) cur.firstSeen = first;
  }
  const ids = new Map<string, string>();
  // Sorted so concurrent writers take row locks in the same order.
  const rows = !merged.size ? [] : await tx
    .insert(entities)
    .values([...merged.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, e]) => ({
      tenantId,
      type: e.type,
      key: e.key,
      displayName: e.displayName,
      identifiers: e.identifiers ?? {},
      sourceSystems: [...e.sources].sort(),
      firstSeen: e.firstSeen && e.firstSeen < e.seenAt ? e.firstSeen : e.seenAt,
      lastSeen: e.seenAt,
    })))
    .onConflictDoUpdate({
      target: [entities.tenantId, entities.type, entities.key],
      set: {
        displayName: sql`case when excluded.identifiers ? 'assetId' then excluded.display_name else ${entities.displayName} end`,
        identifiers: sql`${entities.identifiers} || excluded.identifiers`,
        sourceSystems: sql`array(select distinct s from unnest(${entities.sourceSystems} || excluded.source_systems) s order by s)`,
        firstSeen: sql`least(${entities.firstSeen}, excluded.first_seen)`,
        lastSeen: sql`greatest(${entities.lastSeen}, excluded.last_seen)`,
      },
    })
    .returning({ id: entities.id, type: entities.type, key: entities.key });
  for (const r of rows) ids.set(refKey(r), r.id);
  const existing = (facts.existing ?? []).filter((r) => !ids.has(refKey(r)));
  if (existing.length) {
    const found = await tx
      .select({ id: entities.id, type: entities.type, key: entities.key })
      .from(entities)
      .where(and(eq(entities.tenantId, tenantId), or(...existing.map((r) => and(eq(entities.type, r.type), eq(entities.key, r.key))))));
    for (const r of found) ids.set(refKey(r), r.id);
  }
  const existingKeys = new Set(existing.map(refKey));
  // Undefined only for an `existing` entity deleted since it was looked up; its edges are dropped.
  const idOf = (ref: EntityRef) => {
    const id = ids.get(refKey(ref));
    if (!id && !existingKeys.has(refKey(ref))) throw new Error(`graph fact references ${ref.type} ${ref.key} without an entity`);
    return id;
  };

  const aliases = new Map<string, typeof entityAliases.$inferInsert>();
  for (const a of facts.aliases) {
    const entityId = idOf(a.entity);
    if (entityId) aliases.set(`${a.kind}|${a.value}`, { tenantId, entityId, kind: a.kind, value: a.value, source: a.source });
  }
  if (aliases.size) {
    // First claim wins: an alias that already names another entity is left alone.
    await tx.insert(entityAliases).values([...aliases.values()]).onConflictDoUpdate({ target: [entityAliases.tenantId, entityAliases.kind, entityAliases.value], set: { lastSeen: sql`now()` } });
  }

  const edges = new Map<string, { fromId: string; toId: string; edge: EdgeFact; firstSeen: Date; lastSeen: Date; evidence: Map<string, EdgeFact> }>();
  for (const e of facts.edges) {
    const fromId = idOf(e.from);
    const toId = idOf(e.to);
    if (!fromId || !toId || fromId === toId) continue;
    const k = `${fromId}|${toId}|${e.type}`;
    const cur = edges.get(k);
    if (!cur) {
      edges.set(k, { fromId, toId, edge: e, firstSeen: e.seenAt, lastSeen: e.seenAt, evidence: new Map([[`${e.evidence.type}|${e.evidence.id}`, e]]) });
      continue;
    }
    if (e.provenance === "observed") cur.edge = { ...cur.edge, provenance: "observed" };
    if (e.seenAt < cur.firstSeen) cur.firstSeen = e.seenAt;
    if (e.seenAt > cur.lastSeen) cur.lastSeen = e.seenAt;
    cur.evidence.set(`${e.evidence.type}|${e.evidence.id}`, e);
  }
  if (!edges.size) return ids;

  const rels = await tx
    .insert(entityRelationships)
    .values([...edges.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, e]) => ({
      tenantId,
      fromEntityId: e.fromId,
      toEntityId: e.toId,
      type: e.edge.type,
      provenance: e.edge.provenance,
      firstSeen: e.firstSeen,
      lastSeen: e.lastSeen,
      evidenceType: e.edge.evidence.type,
      evidenceId: e.edge.evidence.id,
    })))
    .onConflictDoUpdate({
      target: [entityRelationships.tenantId, entityRelationships.fromEntityId, entityRelationships.toEntityId, entityRelationships.type],
      set: {
        // Once any record states the edge, it stays observed.
        provenance: sql`case when excluded.provenance = 'observed' then excluded.provenance else ${entityRelationships.provenance} end`,
        firstSeen: sql`least(${entityRelationships.firstSeen}, excluded.first_seen)`,
        lastSeen: sql`greatest(${entityRelationships.lastSeen}, excluded.last_seen)`,
      },
    })
    .returning({ id: entityRelationships.id, fromEntityId: entityRelationships.fromEntityId, toEntityId: entityRelationships.toEntityId, type: entityRelationships.type });

  const evidenceRows = rels.flatMap((r) =>
    [...edges.get(`${r.fromEntityId}|${r.toEntityId}|${r.type}`)!.evidence.values()].map(
      (e) => sql`(${r.id}::uuid, ${tenantId}::uuid, ${e.evidence.type}, ${e.evidence.id}, ${e.seenAt.toISOString()}::timestamptz)`,
    ),
  );
  await tx.execute(sql`
    with ins as (
      insert into entity_relationship_evidence (relationship_id, tenant_id, evidence_type, evidence_id, observed_at)
      values ${sql.join(evidenceRows, sql`, `)}
      on conflict do nothing
      returning relationship_id
    )
    update entity_relationships r set count = r.count + c.n
    from (select relationship_id, count(*)::int as n from ins group by relationship_id) c
    where r.id = c.relationship_id`);
  return ids;
}

/** The identity entity an alert's user name names, matched on account aliases written by asset sync. */
export async function identityFor(tx: Tx, tenantId: string, userName: string | null) {
  if (!userName?.trim()) return null;
  const [hit] = await tx
    .select({ key: entities.key })
    .from(entityAliases)
    .innerJoin(entities, eq(entities.id, entityAliases.entityId))
    .where(and(eq(entityAliases.tenantId, tenantId), eq(entityAliases.kind, "account"), inArray(entityAliases.value, accountCandidates(userName)), eq(entities.type, "identity")))
    .limit(1);
  return hit ?? null;
}

// The graph is derived data: a failed graph write rolls back to its savepoint and is logged, never
// costing the alert or the asset. Backfill rebuilds anything missed.
async function guarded(tx: Tx, what: string, fn: (tx: Tx) => Promise<unknown>) {
  try {
    await tx.transaction(fn);
  } catch (err) {
    console.warn(`[graph] ${what}: ${err instanceof Error ? err.message : err}`);
  }
}

export async function recordAlertGraph(tx: Tx, tenantId: string, input: Omit<AlertGraphInput, "identity">) {
  await guarded(tx, `alert ${input.alert.id}`, async (sp) => {
    const identity = await identityFor(sp, tenantId, input.alert.userName);
    await writeGraph(sp, tenantId, alertFacts({ ...input, identity }));
  });
}

export async function recordAssetGraph(tx: Tx, tenantId: string, asset: AssetInput, sources: string[]) {
  await guarded(tx, `asset ${asset.id}`, async (sp) => {
    const facts = assetFacts(asset, sources[0] ?? "inventory", { matchingUsers: await matchingUsers(sp, tenantId, asset) });
    for (const s of sources.slice(1)) facts.entities.push({ ...facts.entities[0]!, source: s });
    await writeGraph(sp, tenantId, facts);
  });
}

/** User entities (from earlier alerts) whose name matches an identity asset. */
async function matchingUsers(tx: Tx, tenantId: string, asset: AssetInput): Promise<string[]> {
  if (asset.kind !== "identity") return [];
  const rows = await tx
    .select({ key: entities.key })
    .from(entities)
    .where(and(eq(entities.tenantId, tenantId), eq(entities.type, "user"), inArray(entities.key, accountCandidates(asset.name))));
  return rows.map((r) => r.key);
}
