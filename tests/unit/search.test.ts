import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { connectorDef } from "@/lib/connectors/registry";
import { validateOcsf } from "@/lib/ocsf/validate";
import {
  decodeCursor, eventSummary, NO_DATA_CAPABILITIES,
  type DataCapabilities, type EventPage, type SearchEvent, type SecurityDataProvider, type TenantDataScope,
} from "@/lib/providers/data";
import { DemoProvider } from "@/lib/providers/demo";
import type { SecurityEventProvider } from "@/lib/providers/types";
import { WAZUH_DATA_CAPABILITIES } from "@/lib/providers/wazuh";
import { connectorDataCapabilities, federate, type DataSource } from "@/lib/services/search";
import { agentTerms, fakeSearch, startIndexer, type IndexerDoc, type IndexerRequest } from "../fixtures/opensearch";

const TENANT = "11111111-1111-4111-8111-111111111111";
const INTEGRATION = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-10-01T12:00:00Z");
const iso = (minsAgo: number) => new Date(NOW - minsAgo * 60_000).toISOString();

const DOCS: IndexerDoc[] = [
  { _id: "a1", _index: "wazuh-alerts-4.x-2026.10.01", _source: { timestamp: iso(1), rule: { id: "5712", level: 10, description: "SSHD brute force", groups: ["sshd"], mitre: { id: ["T1110.001"] } }, agent: { id: "001", name: "WEB01", ip: "10.0.0.5" }, data: { srcip: "45.155.205.233", srcuser: "root" }, full_log: "Failed password for root" } },
  { _id: "a2", _index: "wazuh-alerts-4.x-2026.10.01", _source: { timestamp: iso(2), rule: { id: "60122", level: 5, description: "Logon failure", groups: ["windows"] }, agent: { id: "002", name: "DC01" }, data: { dstuser: "svc-backup" } } },
  { _id: "a3", _index: "wazuh-alerts-4.x-2026.10.01", _source: { timestamp: iso(3), rule: { id: "92057", level: 12, description: "Encoded PowerShell", groups: ["windows"] }, agent: { id: "001", name: "WEB01" } } },
  { _id: "x1", _index: "wazuh-archives-4.x-2026.10.01", _source: { timestamp: iso(4), decoder: { name: "sshd" }, agent: { id: "001", name: "WEB01" }, full_log: "Accepted publickey for deploy", data: { srcip: "10.0.0.9" } } },
  { _id: "c1", _index: "wazuh-alerts-4.x-2026.10.01", _source: { timestamp: iso(5), rule: { id: "1", level: 3, description: "Other customer" }, agent: { id: "900", name: "OTHER" } } },
];

let indexer: Awaited<ReturnType<typeof startIndexer>>;
let fail = false;

beforeAll(async () => {
  indexer = await startIndexer((req) => (fail ? { status: 500, body: { error: "boom" } } : { body: fakeSearch(DOCS, req.body) }));
});
afterAll(async () => {
  await indexer.close();
});
beforeEach(() => {
  indexer.requests.length = 0;
  fail = false;
});

function wazuh(config: Record<string, unknown> = {}): SecurityEventProvider {
  const def = connectorDef("wazuh")!;
  const inst = def.create!(
    def.config.parse({ apiUrl: indexer.url, indexerUrl: indexer.url, region: "ap-southeast-2", ...config }),
    def.secrets.parse({ apiUser: "api", apiPassword: "pw", indexerUser: "reader", indexerPassword: "secret" }),
  );
  if (inst.kind !== "events") throw new Error("not events");
  return inst.provider;
}

const scope = (agentIds: TenantDataScope["agentIds"]): TenantDataScope => ({ tenantId: TENANT, integrationId: INTEGRATION, agentIds });
const range = { from: new Date(NOW - 3_600_000), to: new Date(NOW) };
const lastSearch = (): IndexerRequest => indexer.requests.at(-1)!;

describe("Wazuh query-in-place", () => {
  it("searches the alerts index with the tenant's agent filter and returns OCSF events with provenance", async () => {
    const data = wazuh().dataProvider!(scope(["001"]));
    const page = await data.search({ ...range, pageSize: 10 });

    const req = lastSearch();
    expect(req.method).toBe("POST");
    expect(req.path).toBe("/wazuh-alerts-4.x-*/_search");
    expect(req.auth).toBe(`Basic ${Buffer.from("reader:secret").toString("base64")}`);
    expect(agentTerms(req.body)).toEqual(["001"]);
    expect(req.body?.query?.bool?.filter).toContainEqual({ range: { timestamp: { gte: range.from.toISOString(), lte: range.to.toISOString() } } });

    expect(page.events.map((e) => e.id)).toEqual(["a1", "a3", "x1"]);
    expect(page.cursor).toBeNull();
    const first = page.events[0]!;
    expect(first.ocsf.class_uid).toBe(2004);
    expect(first.ocsf.metadata).toMatchObject({ tenant_uid: TENANT, log_name: "wazuh", original_event_uid: "a1" });
    expect(first.provenance).toEqual({ integrationId: INTEGRATION, provider: "wazuh", tenantId: TENANT, tier: "hot", location: "wazuh-alerts-4.x-2026.10.01" });
    for (const e of page.events) expect(validateOcsf(e.ocsf)).toEqual({ ok: true });
    // A record without a rule is still returned, as an OCSF Base Event.
    expect(page.events[2]!.ocsf.class_uid).toBe(0);
    expect(eventSummary(page.events[2]!.ocsf)).toMatchObject({ host: "WEB01", src: "10.0.0.9" });
  });

  it("pages with search_after and stops when a page comes back short", async () => {
    const data = wazuh().dataProvider!(scope(["001", "002"]));
    const p1 = await data.search({ ...range, pageSize: 2 });
    expect(p1.events.map((e) => e.id)).toEqual(["a1", "a2"]);
    expect(p1.cursor).not.toBeNull();
    expect(lastSearch().body?.search_after).toBeUndefined();
    expect(lastSearch().body?.sort).toEqual([{ timestamp: { order: "desc" } }, { _id: { order: "desc" } }]);

    const p2 = await data.search({ ...range, pageSize: 2, cursor: p1.cursor });
    expect(lastSearch().body?.search_after).toEqual([Date.parse(iso(2)), "a2"]);
    expect(p2.events.map((e) => e.id)).toEqual(["a3", "x1"]);
    const p3 = await data.search({ ...range, pageSize: 2, cursor: p2.cursor });
    expect(p3.events).toEqual([]);
    expect(p3.cursor).toBeNull();

    // A cursor that is not one of ours is ignored rather than sent to the indexer.
    await data.search({ ...range, pageSize: 2, cursor: Buffer.from(JSON.stringify({ script: "x" })).toString("base64url") });
    expect(lastSearch().body?.search_after).toBeUndefined();
  });

  it("never queries a shared cluster for a tenant with no mapped agents", async () => {
    const data = wazuh().dataProvider!(scope([]));
    const page = await data.search({ ...range });
    expect(page).toMatchObject({ events: [], cursor: null, notice: expect.stringMatching(/no agents/i) });
    expect(await data.getEvent("a1")).toBeNull();
    expect(indexer.requests).toHaveLength(0);
  });

  it("searches the whole cluster only when the tenant owns it", async () => {
    await wazuh().dataProvider!(scope("all")).search({ ...range });
    expect(agentTerms(lastSearch().body)).toBeUndefined();
  });

  it("applies typed filters and free text at the source and adds the archive index when configured", async () => {
    const data = wazuh({ archivesIndex: "wazuh-archives-4.x-*" }).dataProvider!(scope(["001"]));
    await data.search({ ...range, text: "rule.groups:sshd", filters: { severity: ["high"], host: "web*", user: "root", ip: "45.155.205.233", ruleId: "5712" } });
    const req = lastSearch();
    expect(req.path).toBe("/wazuh-alerts-4.x-*,wazuh-archives-4.x-*/_search");
    const filter = req.body!.query!.bool!.filter!;
    expect(filter).toContainEqual({ terms: { "agent.id": ["001"] } });
    expect(filter).toContainEqual({ bool: { should: [{ range: { "rule.level": { gte: 10, lte: 12 } } }], minimum_should_match: 1 } });
    expect(JSON.stringify(filter)).toContain('"value":"*web\\\\**"');
    expect(JSON.stringify(filter)).toContain('"data.srcip":"45.155.205.233"');
    expect(JSON.stringify(filter)).toContain('"data.srcuser":{"value":"root","case_insensitive":true}');
    expect(filter).toContainEqual({ term: { "rule.id": "5712" } });
    expect(filter).toContainEqual({ query_string: { query: "rule.groups:sshd", default_operator: "AND", lenient: true, analyze_wildcard: true } });
  });

  it("clamps a range longer than the provider allows and reports the page as partial", async () => {
    const to = new Date(NOW);
    const page = await wazuh().dataProvider!(scope(["001"])).search({ from: new Date(NOW - 200 * 86_400_000), to });
    expect(page.partial).toMatch(/90 days/);
    expect(JSON.stringify(lastSearch().body)).toContain(new Date(NOW - 90 * 86_400_000).toISOString());
  });

  it("looks up one event only inside the tenant's agents", async () => {
    const data = wazuh().dataProvider!(scope(["001"]));
    expect((await data.getEvent("a1"))?.id).toBe("a1");
    expect(lastSearch().body?.query?.bool?.filter).toEqual([{ ids: { values: ["a1"] } }, { terms: { "agent.id": ["001"] } }]);
    expect(await data.getEvent("c1")).toBeNull();
  });

  it("pivots on an entity with a typed filter", async () => {
    await wazuh().dataProvider!(scope(["001"])).getEntityActivity({ type: "user", value: "root" }, range);
    expect(JSON.stringify(lastSearch().body)).toContain('"data.srcuser":{"value":"root","case_insensitive":true}');
  });

  it("surfaces indexer errors to the caller", async () => {
    fail = true;
    await expect(wazuh().dataProvider!(scope(["001"])).search({ ...range })).rejects.toThrow(/500/);
  });
});

describe("demo cluster search", () => {
  const agents = [
    { id: "100", name: "ACME-DC01", group: "acme", os: "Windows Server", ip: "10.20.0.10" },
    { id: "200", name: "WATTLE-DC01", group: "wattle", os: "Windows Server", ip: "10.21.0.10" },
  ];
  const window = { from: new Date(NOW - 3 * 86_400_000), to: new Date(NOW) };

  it("is deterministic, generates only the tenant's agents and pages without repeats", async () => {
    const data = new DemoProvider(agents).dataProvider(scope(["100"]));
    const all = await data.search({ ...window, pageSize: 200 });
    expect(all.events.length).toBeGreaterThan(5);
    expect(all.events.every((e) => (e.raw as { agent: { id: string } }).agent.id === "100")).toBe(true);
    expect((await data.search({ ...window, pageSize: 200 })).events.map((e) => e.id)).toEqual(all.events.map((e) => e.id));

    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: EventPage = await data.search({ ...window, pageSize: 7, cursor });
      seen.push(...page.events.map((e) => e.id));
      cursor = page.cursor;
    } while (cursor);
    expect(seen.sort()).toEqual(all.events.map((e) => e.id).sort());

    const one = all.events[0]!;
    expect((await data.getEvent(one.id))?.id).toBe(one.id);
    expect(await new DemoProvider(agents).dataProvider(scope(["200"])).getEvent(one.id)).toBeNull();
  });
});

function source(id: string, impl: Partial<SecurityDataProvider> | (() => never), caps: Partial<DataCapabilities> = {}): DataSource {
  const capabilities = { ...WAZUH_DATA_CAPABILITIES, ...caps };
  return {
    integrationId: id,
    name: `Source ${id}`,
    provider: "test",
    shared: false,
    capabilities,
    open: typeof impl === "function" ? impl : () => ({ kind: "test", capabilities: () => capabilities, getEvent: async () => null, getEntityActivity: async () => ({ events: [], cursor: null }), health: async () => ({ ok: true, latencyMs: 0, detail: {} }), search: async () => ({ events: [], cursor: null }), ...impl }),
  };
}

function event(id: string, time: number): SearchEvent {
  return {
    id,
    time,
    ocsf: { class_uid: 0, category_uid: 0, activity_id: 99, type_uid: 99, severity_id: 1, time, metadata: { version: "1.9.0", product: { name: "t" } } },
    provenance: { integrationId: id, provider: "test", tenantId: TENANT, tier: "hot", location: "t" },
    raw: {},
  };
}

describe("federated search", () => {
  it("returns every source's own status and never fails the whole search", async () => {
    const res = await federate(
      [
        source("ok", { search: async () => ({ events: [event("e1", 10), event("e3", 30)], cursor: "next-ok", total: 5 }) }),
        source("partial", { search: async () => ({ events: [event("e2", 20)], cursor: null, partial: "archive scan capped" }) }),
        source("boom", { search: async () => { throw new Error("401 Unauthorized from indexer"); } }),
        source("slow", { search: () => new Promise<EventPage>(() => {}) }),
        source("nosearch", {}, NO_DATA_CAPABILITIES),
        source("nofilter", {}, { filters: [] }),
        source("bad-secret", () => { throw new Error("cannot decrypt"); }),
      ],
      { ...range, filters: { host: "WEB01" } },
      { timeoutMs: 50 },
    );
    const status = Object.fromEntries(res.sources.map((s) => [s.integrationId, [s.status, s.message]]));
    expect(status).toEqual({
      ok: ["ok", undefined],
      partial: ["partial", "archive scan capped"],
      boom: ["error", "401 Unauthorized from indexer"],
      slow: ["error", "timed out after 0.1s"],
      nosearch: ["unsupported", "search is not supported"],
      nofilter: ["unsupported", "cannot filter by host"],
      "bad-secret": ["error", "cannot decrypt"],
    });
    expect(res.events.map((e) => e.id)).toEqual(["e3", "e2", "e1"]);
    expect(res.sources.find((s) => s.integrationId === "ok")).toMatchObject({ count: 2, total: 5, hasMore: true });
    expect(decodeCursor(res.cursor, (v): v is Record<string, string> => typeof v === "object")).toEqual({ ok: "next-ok" });
  });

  it("continues only the sources that had more results", async () => {
    const calls: (string | null | undefined)[] = [];
    const sources = [
      source("a", { search: async (q) => { calls.push(q.cursor); return { events: [event("a2", 1)], cursor: null }; } }),
      source("b", { search: async () => { throw new Error("must not be called"); } }),
    ];
    const res = await federate(sources, { ...range, cursor: Buffer.from(JSON.stringify({ a: "p2" })).toString("base64url") });
    expect(calls).toEqual(["p2"]);
    expect(res.sources.map((s) => [s.integrationId, s.status, s.message])).toEqual([["a", "ok", undefined], ["b", "ok", "no further results"]]);
    expect(res.cursor).toBeNull();
  });

  it("runs entity pivots through getEntityActivity", async () => {
    const seen: unknown[] = [];
    await federate([source("a", { getEntityActivity: async (entity) => { seen.push(entity); return { events: [], cursor: null }; } })], { ...range, entity: { type: "ip", value: "10.0.0.1" } });
    expect(seen).toEqual([{ type: "ip", value: "10.0.0.1" }]);
  });
});

describe("capability discovery", () => {
  it("declares query-in-place for Wazuh, syslog and demo, and no search for the rest", () => {
    const caps = Object.fromEntries(connectorDataCapabilities().map((c) => [c.provider, c.data]));
    expect(caps.wazuh).toMatchObject({ search: true, paging: "cursor", freeText: "lucene", ocsfClasses: [2004, 0] });
    expect(caps.syslog).toMatchObject({ search: true, tiers: ["hot", "cold"], ocsfClasses: [4001, 0] });
    expect(caps.demo?.search).toBe(true);
    expect(caps.sentinel).toEqual(NO_DATA_CAPABILITIES);
    expect(caps.tawny).toEqual(NO_DATA_CAPABILITIES);
  });
});
