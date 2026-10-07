import { randomUUID } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assetSources, assets, auditLog, integrations, integrationTenantLinks, syslogEvents, tenantPlans, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { eventProvider, secretAad } from "@/lib/connectors/instances";
import { encryptSecret } from "@/lib/crypto";
import { defaultArchiveStore } from "@/lib/hosting/store";
import type { EventPage } from "@/lib/providers/data";
import { SyslogDataProvider } from "@/lib/providers/syslog";
import { listAlerts } from "@/lib/services/alerts";
import { AccessDenied } from "@/lib/services/common";
import { getTenantEvent, listTenantDataSources, searchTenantEvents, tenantEntityActivity } from "@/lib/services/search";
import { acceptSyslog, archiveColdForTenant, createSyslogSource } from "@/lib/services/syslog";
import { agentTerms, fakeSearch, startIndexer, type IndexerDoc } from "../fixtures/opensearch";
import { SYSLOG_LINES } from "../fixtures/syslog";

const createdTenants: string[] = [];
const createdIntegrations: string[] = [];
let indexer: Awaited<ReturnType<typeof startIndexer>>;
let indexerDown = false;
const now = Date.now();
const iso = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

const DOCS: IndexerDoc[] = [
  { _id: "evt-a1", _index: "wazuh-alerts-4.x-a", _source: { timestamp: iso(5), rule: { id: "5712", level: 10, description: "SSHD brute force" }, agent: { id: "501", name: "ACME-WEB01" }, data: { srcip: "45.155.205.233" } } },
  { _id: "evt-a2", _index: "wazuh-alerts-4.x-a", _source: { timestamp: iso(15), rule: { id: "60122", level: 5, description: "Logon failure" }, agent: { id: "501", name: "ACME-WEB01" }, data: { dstuser: "svc-backup" } } },
  { _id: "evt-b1", _index: "wazuh-alerts-4.x-b", _source: { timestamp: iso(10), rule: { id: "92057", level: 12, description: "Encoded PowerShell" }, agent: { id: "502", name: "BANKSIA-DC01" } } },
];

function analyst(tenantIds: string[], permissions: Permission[] = ["alert:read", "alert:triage", "integration:manage"]): AccessContext {
  return {
    principal: { userId: `hunter-${randomUUID().slice(0, 6)}`, name: "Hunter", email: "hunter@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: tenantIds.map((tenantId) => ({ roleKey: "soc_analyst_l2", tenantId, permissions: new Set(permissions) })),
    tenantIds,
    tenants: tenantIds.map((id) => ({ id, slug: id.slice(0, 8), name: `Tenant ${id.slice(0, 4)}`, kind: "customer" as const })),
  };
}

async function tenant(tier: "essentials" | "standard" = "standard") {
  const [row] = await adminDb().insert(tenants).values({ slug: `hunt-${randomUUID().slice(0, 8)}`, name: "Hunt customer", kind: "customer" }).returning();
  createdTenants.push(row!.id);
  await adminDb().insert(tenantPlans).values({ tenantId: row!.id, tier }).onConflictDoUpdate({ target: tenantPlans.tenantId, set: { tier } });
  return row!.id;
}

async function mapAgent(tenantId: string, integrationId: string, agentId: string, name: string) {
  const [asset] = await adminDb().insert(assets).values({ tenantId, kind: "server", name, hostname: name }).returning();
  await adminDb().insert(assetSources).values({ tenantId, assetId: asset!.id, integrationId, externalId: agentId });
}

let A: string;
let B: string;
let C: string;
let D: string;
let wazuhId: string;

beforeAll(async () => {
  process.env.BLAKSOC_ARCHIVE_DIR = await mkdtemp(path.join(tmpdir(), "blaksoc-hunt-"));
  indexer = await startIndexer((req) => (indexerDown ? { status: 503, body: { error: "unavailable" } } : { body: fakeSearch(DOCS, req.body) }));

  [A, B, C, D] = [await tenant(), await tenant(), await tenant(), await tenant("essentials")];
  const [wz] = await adminDb()
    .insert(integrations)
    .values({ tenantId: null, category: "siem", provider: "wazuh", name: `Shared Wazuh ${randomUUID().slice(0, 6)}`, config: { apiUrl: indexer.url, indexerUrl: indexer.url, region: "ap-southeast-2", tlsVerify: true } })
    .returning();
  wazuhId = wz!.id;
  createdIntegrations.push(wazuhId);
  await adminDb().update(integrations).set({ secretCiphertext: encryptSecret(JSON.stringify({ apiUser: "api", apiPassword: "pw", indexerUser: "reader", indexerPassword: "secret" }), secretAad(wazuhId)) }).where(eq(integrations.id, wazuhId));
  for (const t of [A, B, C, D]) await adminDb().insert(integrationTenantLinks).values({ integrationId: wazuhId, tenantId: t, selector: {} });
  await mapAgent(A, wazuhId, "501", "ACME-WEB01");
  await mapAgent(B, wazuhId, "502", "BANKSIA-DC01");
  await mapAgent(D, wazuhId, "504", "PLAN-WS01");

  const manage = (t: string) => analyst([t], ["integration:manage"]);
  const srcA = await createSyslogSource(manage(A), A, { name: "A firewall" });
  const srcB = await createSyslogSource(manage(B), B, { name: "B firewall" });
  await acceptSyslog({ token: srcA.token, sourceIp: "", body: SYSLOG_LINES.fortinet });
  await acceptSyslog({ token: srcB.token, sourceIp: "", body: SYSLOG_LINES.sophos });
  // One old line per tenant, moved to the cold archive.
  const old = new Date(now - 35 * 86_400_000);
  await acceptSyslog({ token: srcA.token, sourceIp: "", body: SYSLOG_LINES.draytek, now: old });
  await acceptSyslog({ token: srcB.token, sourceIp: "", body: SYSLOG_LINES.mikrotik, now: old });
  expect(await archiveColdForTenant(A, new Date(), "ap-southeast-2", defaultArchiveStore())).toBe(1);
  expect(await archiveColdForTenant(B, new Date(), "ap-southeast-2", defaultArchiveStore())).toBe(1);
});

beforeEach(() => {
  indexer.requests.length = 0;
  indexerDown = false;
});

afterAll(async () => {
  await indexer.close();
  if (createdIntegrations.length) await adminDb().delete(integrations).where(inArray(integrations.id, createdIntegrations));
  if (createdTenants.length) await adminDb().delete(tenants).where(inArray(tenants.id, createdTenants));
});

const day = () => ({ from: new Date(now - 86_400_000), to: new Date(now + 60_000) });

describe("federated event search", () => {
  it("searches a tenant's Wazuh events in place and its own syslog only", async () => {
    const before = await adminDb().select({ n: alerts.id }).from(alerts).where(inArray(alerts.tenantId, [A, B]));
    const res = await searchTenantEvents(analyst([A]), { tenantId: A, ...day() });

    expect(indexer.requests).toHaveLength(1);
    expect(agentTerms(indexer.requests[0]!.body)).toEqual(["501"]);
    const wz = res.sources.find((s) => s.integrationId === wazuhId)!;
    expect(wz).toMatchObject({ status: "ok", count: 2 });
    expect(res.sources.find((s) => s.provider === "syslog")).toMatchObject({ status: "ok", count: 1 });

    expect(res.events.every((e) => e.provenance.tenantId === A && e.ocsf.metadata.tenant_uid === A)).toBe(true);
    expect(res.events.filter((e) => e.provenance.provider === "wazuh").map((e) => e.id).sort()).toEqual(["evt-a1", "evt-a2"]);
    const lines = res.events.filter((e) => e.provenance.provider === "syslog").map((e) => (e.raw as { line: string }).line);
    expect(lines).toEqual([SYSLOG_LINES.fortinet]);
    expect(JSON.stringify(res.events)).not.toContain("BANKSIA");
    expect(JSON.stringify(res.events)).not.toContain(SYSLOG_LINES.sophos);

    // Query-in-place: nothing was copied into alerts.
    const after = await adminDb().select({ n: alerts.id }).from(alerts).where(inArray(alerts.tenantId, [A, B]));
    expect(after.length).toBe(before.length);
    const [entry] = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, A), eq(auditLog.action, "event.search")));
    expect(entry).toBeTruthy();
  });

  it("refuses a tenant the analyst has no grant for, and a customer role without triage", async () => {
    await expect(searchTenantEvents(analyst([A]), { tenantId: B, ...day() })).rejects.toBeInstanceOf(AccessDenied);
    await expect(searchTenantEvents(analyst([A], ["alert:read"]), { tenantId: A, ...day() })).rejects.toBeInstanceOf(AccessDenied);
    await expect(listTenantDataSources(analyst([A]), B)).rejects.toBeInstanceOf(AccessDenied);
    expect(indexer.requests).toHaveLength(0);
  });

  it("does not return another tenant's event by id", async () => {
    const ctx = analyst([A]);
    const [lineB] = await adminDb().select().from(syslogEvents).where(and(eq(syslogEvents.tenantId, B), eq(syslogEvents.tier, "hot")));
    const [syslogA] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, A), eq(integrations.provider, "syslog")));
    const [syslogB] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, B), eq(integrations.provider, "syslog")));

    expect(await getTenantEvent(ctx, A, syslogA!.id, lineB!.id)).toBeNull();
    expect(await getTenantEvent(ctx, A, syslogB!.id, lineB!.id)).toBeNull();
    expect(await getTenantEvent(ctx, A, wazuhId, "evt-b1")).toBeNull();
    expect(agentTerms(indexer.requests.at(-1)!.body)).toEqual(["501"]);
    expect((await getTenantEvent(ctx, A, wazuhId, "evt-a1"))?.id).toBe("evt-a1");
  });

  it("searches the cold syslog archive for the tenant only", async () => {
    const range = { from: new Date(now - 40 * 86_400_000), to: new Date(now + 60_000) };
    const hot = await searchTenantEvents(analyst([A]), { tenantId: A, ...range, text: "BLOCK" });
    expect(hot.events.filter((e) => e.provenance.provider === "syslog")).toEqual([]);

    const res = await searchTenantEvents(analyst([A]), { tenantId: A, ...range, includeArchive: true });
    // Results are ordered by event time; the fixture lines carry their own dates, so compare by tier.
    const syslog = res.events.filter((e) => e.provenance.provider === "syslog").sort((a, b) => (a.provenance.tier === "hot" ? -1 : 1) - (b.provenance.tier === "hot" ? -1 : 1));
    expect(syslog.map((e) => [e.provenance.tier, (e.raw as { line: string }).line])).toEqual([
      ["hot", SYSLOG_LINES.fortinet],
      ["cold", SYSLOG_LINES.draytek],
    ]);
    expect(syslog[1]!.provenance.location).toBe("archive:ap-southeast-2");
    expect(JSON.stringify(res.events)).not.toContain(SYSLOG_LINES.mikrotik);

    // The Wazuh range is clamped to its 90-day limit only when asked for more; 40 days is fine.
    expect(res.sources.find((s) => s.integrationId === wazuhId)?.status).toBe("ok");
    const cold = await getTenantEvent(analyst([A]), A, syslog[1]!.provenance.integrationId, syslog[1]!.id);
    expect(cold?.provenance.tier).toBe("cold");
  });

  it("reports a failing source and still returns the others", async () => {
    indexerDown = true;
    const res = await searchTenantEvents(analyst([A]), { tenantId: A, ...day() });
    expect(res.sources.find((s) => s.integrationId === wazuhId)).toMatchObject({ status: "error", message: expect.stringMatching(/503/) });
    expect(res.sources.find((s) => s.provider === "syslog")?.status).toBe("ok");
    expect(res.events.map((e) => e.provenance.provider)).toEqual(["syslog"]);
  });

  it("never queries the shared cluster for a linked tenant with no mapped agents, and respects the plan", async () => {
    const res = await searchTenantEvents(analyst([C]), { tenantId: C, ...day() });
    expect(res.sources.find((s) => s.integrationId === wazuhId)).toMatchObject({ status: "ok", count: 0, message: expect.stringMatching(/no agents/i) });
    const plan = await searchTenantEvents(analyst([D]), { tenantId: D, ...day() });
    expect(plan.sources.find((s) => s.integrationId === wazuhId)).toMatchObject({ status: "unsupported", message: expect.stringMatching(/plan/) });
    expect(indexer.requests).toHaveLength(0);
  });

  it("pivots on an entity across sources", async () => {
    const res = await tenantEntityActivity(analyst([A]), A, { type: "ip", value: "203.0.113.10" }, day());
    expect(res.events.filter((e) => e.provenance.provider === "syslog").map((e) => (e.raw as { line: string }).line)).toEqual([SYSLOG_LINES.fortinet]);
    // The indexer receives the pivot as a typed IP filter next to the tenant's agent filter.
    expect(JSON.stringify(indexer.requests[0]!.body)).toContain('"data.srcip":"203.0.113.10"');
    expect(agentTerms(indexer.requests[0]!.body)).toEqual(["501"]);
  });

  it("discovers each source's capabilities for the tenant", async () => {
    const list = await listTenantDataSources(analyst([A]), A);
    const wz = list.find((s) => s.integrationId === wazuhId)!;
    expect(wz).toMatchObject({ provider: "wazuh", shared: true, available: true, capabilities: { search: true, paging: "cursor" } });
    expect(list.find((s) => s.provider === "syslog")).toMatchObject({ shared: false, available: true, capabilities: { tiers: ["hot", "cold"] } });
  });
});

describe("syslog data provider paging", () => {
  it("pages through hot and cold lines newest first without gaps or repeats", async () => {
    const E = await tenant();
    const src = await createSyslogSource(analyst([E], ["integration:manage"]), E, { name: "E firewall" });
    const lines = Object.values(SYSLOG_LINES);
    const ages = [1, 2, 3, 40, 41]; // days; the last two go cold
    for (const [i, days] of ages.entries()) await acceptSyslog({ token: src.token, sourceIp: "", body: lines[i]!, now: new Date(now - days * 86_400_000) });
    expect(await archiveColdForTenant(E, new Date(), "ap-southeast-2", defaultArchiveStore())).toBe(2);

    const [row] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, E), eq(integrations.provider, "syslog")));
    const data = new SyslogDataProvider({ tenantId: E, integrationId: row!.id, agentIds: "all" }, defaultArchiveStore());
    const window = { from: new Date(now - 60 * 86_400_000), to: new Date(now) };
    const seen: [string, string][] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page: EventPage = await data.search({ ...window, pageSize: 2, cursor, includeArchive: true });
      seen.push(...page.events.map((e): [string, string] => [e.provenance.tier, (e.raw as { line: string }).line]));
      cursor = page.cursor;
      pages += 1;
    } while (cursor && pages < 10);
    expect(seen).toEqual(ages.map((_, i) => [i < 3 ? "hot" : "cold", lines[i]!]));

    // A substring filter applies to both tiers.
    const blocked = await data.search({ ...window, text: "203.0.113.12", includeArchive: true });
    expect(blocked.events.map((e) => (e.raw as { line: string }).line)).toEqual([SYSLOG_LINES.draytek]);
    // Without includeArchive only the hot tier is read.
    expect((await data.search({ ...window, includeArchive: false })).events).toHaveLength(3);
    // The provider refuses to be bound to a tenant that does not own the integration.
    expect(() => eventProvider(row!).dataProvider!({ tenantId: A, integrationId: row!.id, agentIds: "all" })).toThrow(/another tenant/);
  });
});

describe("alert full-text search", () => {
  it("matches words anywhere in the alert, in any order, inside the caller's tenants", async () => {
    const mk = (tenantId: string, title: string, description: string) =>
      adminDb().insert(alerts).values({ tenantId, source: "fixture", externalId: randomUUID(), title, description, severity: "high", occurredAt: new Date() }).returning({ id: alerts.id });
    const [hitA] = await mk(A, "Suspicious process", "Credential dumping from lsass memory by rundll32");
    await mk(B, "Suspicious process", "Credential dumping from lsass memory by rundll32");

    const ctx = analyst([A]);
    const { rows } = await listAlerts(ctx, { tenantIds: [A], q: "lsass dumping" });
    expect(rows.map((r) => r.id)).toEqual([hitA!.id]);
    expect((await listAlerts(ctx, { tenantIds: [A], q: "lsass -rundll32" })).rows).toEqual([]);
    // Substring matching on the title is kept.
    expect((await listAlerts(ctx, { tenantIds: [A], q: "uspicious proc" })).rows.map((r) => r.id)).toEqual([hitA!.id]);
  });
});
