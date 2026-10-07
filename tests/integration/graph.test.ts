/**
 * Entity graph: ingest and asset sync populate it, traversal walks it, RLS isolates it.
 * Fresh tenants only. The load test at the end prints traversal latency (docs/ARCHITECTURE.md).
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { entities, entityRelationships, integrations, roleAssignments, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { withScope } from "@/db/scope";
import { resolveAccess, systemScope } from "@/lib/auth/access";
import { backfillGraph } from "@/lib/graph/backfill";
import type { GraphFacts } from "@/lib/graph/model";
import { writeGraph } from "@/lib/graph/store";
import { traverse } from "@/lib/graph/traverse";
import { FixtureIntelProvider } from "@/lib/intel/fixture";
import { syncAssets } from "@/lib/pipeline/assets";
import { ingestAlert } from "@/lib/pipeline/ingest";
import type { NormalisedAlert, NormalisedAsset } from "@/lib/providers/types";
import { getEntity, traverseEntity } from "@/lib/services/entities";

const stamp = `gr${randomUUID().slice(0, 8)}`;
const tenantIds: string[] = [];
const userIds: string[] = [];
let A = "";
let B = "";
let integrationA = "";
let integrationB = "";

async function addTenant(name: string) {
  const [t] = await adminDb().insert(tenants).values({ name, slug: `${stamp}-${name.toLowerCase().replace(/\W+/g, "-")}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantIds.push(t!.id);
  return t!.id;
}

async function addIntegration(tenantId: string) {
  const [row] = await adminDb().insert(integrations).values({ tenantId, category: "siem", provider: "wazuh", name: `${stamp} wazuh`, config: {} }).returning();
  return row!.id;
}

async function analystFor(tenantId: string) {
  const id = `${stamp}-${randomUUID().slice(0, 6)}`;
  await adminDb().insert(user).values({ id, name: id, email: `${id}@example.invalid`, emailVerified: true });
  userIds.push(id);
  await adminDb().insert(roleAssignments).values({ userId: id, roleKey: "customer_security", tenantId });
  return resolveAccess({ userId: id, name: id, email: `${id}@example.invalid`, isBreakGlass: false });
}

const device = (hostname: string, ip: string): NormalisedAsset => ({
  externalId: `agent-${hostname}`, kind: "endpoint", name: hostname.toUpperCase(), hostname: `${hostname}.corp.example`, ips: [ip], os: "Windows 11", macs: [], agentStatus: "active", lastSeen: new Date(), routingKeys: [], raw: {},
});
const identity = (name: string): NormalisedAsset => ({
  externalId: `idp-${name}`, kind: "identity", name, hostname: null, ips: [], os: null, macs: [], agentStatus: null, lastSeen: new Date(), routingKeys: [], raw: {},
});

function alert(over: Partial<NormalisedAlert> & { title: string; hostname: string }): NormalisedAlert {
  return {
    externalId: randomUUID(), ruleId: "60106", description: null, category: "windows", siemSeverity: 8, severity: "high", occurredAt: new Date(),
    assetExternalId: `agent-${over.hostname}`, userName: "alice", attackTechniques: [], routingKeys: [], raw: {}, ...over,
  };
}

async function entityId(tenantId: string, type: (typeof entities.$inferSelect)["type"], key: string) {
  const [row] = await adminDb().select({ id: entities.id }).from(entities).where(and(eq(entities.tenantId, tenantId), eq(entities.type, type), eq(entities.key, key)));
  return row?.id;
}

async function edgesOf(tenantId: string) {
  const rows = await adminDb().execute<{ type: string; provenance: string; count: number; from_type: string; from_key: string; to_type: string; to_key: string }>(sql`
    select r.type, r.provenance, r.count, f.type as from_type, f.key as from_key, t.type as to_type, t.key as to_key
    from entity_relationships r join entities f on f.id = r.from_entity_id join entities t on t.id = r.to_entity_id
    where r.tenant_id = ${tenantId}`);
  return [...rows];
}

beforeAll(async () => {
  A = await addTenant("Graph A");
  B = await addTenant("Graph B");
  integrationA = await addIntegration(A);
  integrationB = await addIntegration(B);
  await withScope(systemScope(A), (tx) => syncAssets(tx, A, integrationA, [device("ws-graph-01", "10.9.0.5"), identity("alice@graph.example")], "wazuh"));
  await withScope(systemScope(B), (tx) => syncAssets(tx, B, integrationB, [device("ws-graph-01", "10.9.0.5")], "wazuh"));
  const intel = new FixtureIntelProvider();
  for (const [tenantId, integrationId] of [[A, integrationA], [B, integrationB]] as const) {
    await ingestAlert({
      tenantId, integrationId, source: "wazuh", intel,
      alert: alert({ title: "Successful logon from external IP after failures", hostname: "ws-graph-01", raw: { rule: { groups: ["windows", "authentication_success"] }, data: { srcip: "185.220.101.47", dstuser: "alice" } } }),
    });
  }
  await ingestAlert({
    tenantId: A, integrationId: integrationA, source: "wazuh", intel,
    alert: alert({ title: "Encoded PowerShell command executed", ruleId: "92057", hostname: "ws-graph-01", raw: { data: { url: "http://update-check.xyz/p.ps1" } } }),
  });
});

afterAll(async () => {
  if (tenantIds.length) await adminDb().delete(tenants).where(inArray(tenants.id, tenantIds));
  if (userIds.length) await adminDb().delete(user).where(inArray(user.id, userIds));
});

describe("graph population", () => {
  it("asset sync and ingest write entities and edges with provenance", async () => {
    const edges = await edgesOf(A);
    const has = (type: string, from: string, to: string) => edges.find((e) => e.type === type && `${e.from_type}:${e.from_key}` === from && `${e.to_type}:${e.to_key}` === to);
    expect(has("has_ip", "device:ws-graph-01", "ip:10.9.0.5")).toMatchObject({ provenance: "observed" });
    // Successful logon states the login; the PowerShell alert alone would only infer it. Observed wins.
    expect(has("logged_into", "user:alice", "device:ws-graph-01")).toMatchObject({ provenance: "observed", count: 2 });
    expect(has("same_as", "user:alice", "identity:alice@graph.example")).toMatchObject({ provenance: "inferred" });
    expect(has("indicates", "indicator:demo--185.220.101.47", "ip:185.220.101.47")).toMatchObject({ provenance: "observed" });
    expect(has("attributed_to", "indicator:demo--185.220.101.47", "campaign:password spraying against au m365 tenants")).toBeTruthy();
    expect(edges.filter((e) => e.type === "alerted_on" && e.to_key === "ws-graph-01")).toHaveLength(2);
    // Both alerts matched intel: the source IP and the PowerShell download domain.
    expect(edges.filter((e) => e.type === "matched").map((e) => e.to_key).sort()).toEqual(["demo--185.220.101.47", "demo--update-check.xyz"]);

    const [dev] = await adminDb().select().from(entities).where(and(eq(entities.tenantId, A), eq(entities.type, "device"), eq(entities.key, "ws-graph-01")));
    expect(dev).toMatchObject({ displayName: "WS-GRAPH-01", sourceSystems: ["wazuh"] });
  });

  it("backfill and replay leave counts unchanged", async () => {
    const before = await edgesOf(A);
    await backfillGraph(A);
    await backfillGraph(A);
    const after = await edgesOf(A);
    const key = (e: (typeof before)[number]) => `${e.type}|${e.from_key}|${e.to_key}|${e.count}|${e.provenance}`;
    // The asset pass may add the identity's own evidence to same_as; everything else is unchanged.
    expect(after.filter((e) => e.type !== "same_as").map(key).sort()).toEqual(before.filter((e) => e.type !== "same_as").map(key).sort());
  });
});

describe("traversal", () => {
  it("reaches a user's devices, alerts and indicators", async () => {
    const alice = (await entityId(A, "user", "alice"))!;
    const g = await withScope(systemScope(A), (tx) => traverse(tx, A, alice, { maxDepth: 3 }));
    const types = new Set(g!.nodes.map((n) => n.type));
    for (const t of ["device", "alert", "indicator", "identity", "ip", "campaign"]) expect(types).toContain(t);
    expect(g!.nodes.find((n) => n.type === "device")!.depth).toBe(1);
    expect(g!.nodes.find((n) => n.type === "indicator")!.depth).toBe(2);
    expect(g!.edges.every((e) => e.tenantId === A)).toBe(true);
    expect(new Set(g!.edges.map((e) => e.provenance))).toEqual(new Set(["observed", "inferred"]));
  });

  it("honours depth, type filters and the row limit", async () => {
    const alice = (await entityId(A, "user", "alice"))!;
    await withScope(systemScope(A), async (tx) => {
      const one = await traverse(tx, A, alice, { maxDepth: 1 });
      expect(one!.nodes.every((n) => n.depth <= 1)).toBe(true);
      expect(one!.nodes.some((n) => n.type === "indicator")).toBe(false);
      const capped = await traverse(tx, A, alice, { maxDepth: 9 });
      expect(Math.max(...capped!.nodes.map((n) => n.depth))).toBeLessThanOrEqual(3);
      const devicesOnly = await traverse(tx, A, alice, { maxDepth: 3, entityTypes: ["device", "ip"] });
      expect(new Set(devicesOnly!.nodes.slice(1).map((n) => n.type))).toEqual(new Set(["device", "ip"]));
      const viaLogins = await traverse(tx, A, alice, { maxDepth: 3, relationshipTypes: ["logged_into", "has_ip"] });
      expect(viaLogins!.nodes.map((n) => n.key).sort()).toEqual(["10.9.0.5", "alice", "ws-graph-01"]);
      const small = await traverse(tx, A, alice, { maxDepth: 3, limit: 3 });
      expect(small!.nodes).toHaveLength(3);
      expect(small!.truncated).toBe(true);
    });
  });
});

describe("tenant isolation", () => {
  it("keeps entities and edges inside their tenant under RLS", async () => {
    const aliceA = (await entityId(A, "user", "alice"))!;
    const aliceB = (await entityId(B, "user", "alice"))!;
    expect(aliceA).not.toBe(aliceB);

    await withScope(systemScope(B), async (tx) => {
      // Asking for tenant A's entity from B's scope, with either tenant id, finds nothing.
      expect(await traverse(tx, B, aliceA, { maxDepth: 3 })).toBeNull();
      expect(await traverse(tx, A, aliceA, { maxDepth: 3 })).toBeNull();
      expect(await tx.select().from(entities).where(eq(entities.tenantId, A))).toEqual([]);
      expect(await tx.select().from(entityRelationships).where(eq(entityRelationships.tenantId, A))).toEqual([]);
      const g = await traverse(tx, B, aliceB, { maxDepth: 3 });
      expect(g!.nodes.every((n) => n.tenantId === B)).toBe(true);
      expect(g!.nodes.map((n) => n.id)).not.toContain(aliceA);
    });

    // An edge from B's entity to A's is rejected even when written under B's scope.
    const facts: GraphFacts = { entities: [], aliases: [], edges: [] };
    await expect(withScope(systemScope(B), (tx) => tx.insert(entityRelationships).values({ tenantId: B, fromEntityId: aliceB, toEntityId: aliceA, type: "same_as", provenance: "inferred", evidenceType: "alert", evidenceId: "x" }))).rejects.toThrow();
    expect(await withScope(systemScope(B), (tx) => writeGraph(tx, B, facts))).toEqual(new Map());
  });

  it("services return nothing for another tenant's entity", async () => {
    const aliceA = (await entityId(A, "user", "alice"))!;
    const analystB = await analystFor(B);
    expect(await traverseEntity(analystB, aliceA, { maxDepth: 3 })).toBeNull();
    expect(await getEntity(analystB, aliceA)).toBeNull();
    const analystA = await analystFor(A);
    const page = await getEntity(analystA, aliceA);
    expect(page!.edges.some((e) => e.type === "logged_into" && e.evidenceAlertId)).toBe(true);
    expect(page!.reach.some((n) => n.type === "indicator")).toBe(true);
  });
});

describe("traversal latency", () => {
  it("walks a 3-hop neighbourhood of a busy user within budget", async () => {
    const T = await addTenant("Graph Load");
    const now = Date.now();
    // One user across 50 devices and 2,000 alerts, each with two IPs and a domain; 1 in 10 matches intel.
    for (let batch = 0; batch < 20; batch++) {
      const facts: GraphFacts = { entities: [], aliases: [], edges: [] };
      for (let i = batch * 100; i < (batch + 1) * 100; i++) {
        const seenAt = new Date(now - i * 60_000);
        const alertRef = { type: "alert" as const, key: `load-${i}` };
        const dev = { type: "device" as const, key: `ws-${i % 50}` };
        const usr = { type: "user" as const, key: "busy.user" };
        const ips = [{ type: "ip" as const, key: `198.51.${i % 200}.${i % 250}` }, { type: "ip" as const, key: `203.0.${i % 97}.${i % 31}` }];
        const dom = { type: "domain" as const, key: `d${i % 300}.example` };
        facts.entities.push(...[alertRef, dev, usr, ...ips, dom].map((r) => ({ ...r, displayName: r.key, source: "load", seenAt })));
        const evidence = { type: "alert" as const, id: `load-${i}` };
        for (const to of [dev, usr, ...ips, dom]) facts.edges.push({ from: alertRef, to, type: "alerted_on", provenance: "observed", evidence, seenAt });
        facts.edges.push({ from: usr, to: dev, type: "logged_into", provenance: "inferred", evidence, seenAt });
        if (i % 10 === 0) {
          const ind = { type: "indicator" as const, key: `ind-${i % 40}` };
          facts.entities.push({ ...ind, displayName: ind.key, source: "load", seenAt });
          facts.edges.push({ from: alertRef, to: ind, type: "matched", provenance: "observed", evidence, seenAt }, { from: ind, to: ips[0]!, type: "indicates", provenance: "observed", evidence, seenAt });
        }
      }
      await withScope(systemScope(T), (tx) => writeGraph(tx, T, facts));
    }
    const start = (await entityId(T, "user", "busy.user"))!;
    const [{ n: edgeCount }] = [...await adminDb().execute<{ n: number }>(sql`select count(*)::int as n from entity_relationships where tenant_id = ${T}`)] as [{ n: number }];

    const timings: Record<string, number[]> = {};
    for (const limit of [200, 1000]) {
      const runs: number[] = [];
      for (let i = 0; i < 15; i++) {
        const t0 = performance.now();
        const g = await withScope(systemScope(T), (tx) => traverse(tx, T, start, { maxDepth: 3, limit }));
        runs.push(performance.now() - t0);
        expect(g!.nodes).toHaveLength(limit);
        expect(g!.nodes.some((n) => n.type === "device")).toBe(true);
      }
      timings[limit] = runs.sort((a, b) => a - b);
    }
    const p = (xs: number[], q: number) => xs[Math.min(xs.length - 1, Math.floor(q * xs.length))]!.toFixed(1);
    console.log(`[graph latency] ${edgeCount} edges; depth 3 limit 200: p50 ${p(timings[200]!, 0.5)}ms p95 ${p(timings[200]!, 0.95)}ms; limit 1000: p50 ${p(timings[1000]!, 0.5)}ms p95 ${p(timings[1000]!, 0.95)}ms`);
    expect(Number(p(timings[200]!, 0.5))).toBeLessThan(500);
  }, 120_000);
});
