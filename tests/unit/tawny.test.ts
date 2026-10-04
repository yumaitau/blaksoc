import { afterEach, describe, expect, it } from "vitest";
import { collectionAllowed } from "@/lib/billing/catalogue";
import { connectorDef } from "@/lib/connectors/registry";
import { exampleConfig, secretFields } from "@/lib/integrations/form-spec";
import { normaliseTawnyAgent, normaliseTawnyAlert, parseTawnyPid, tawnyActionState, type TawnyAgent, type TawnyAlert } from "@/lib/providers/tawny";
import type { SecurityEventProvider } from "@/lib/providers/types";

const TOKEN = "twny_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const AGENT = "7c0e2f4a-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const LIVE = { apiUrl: "https://tawny.example.com/", region: "ap-southeast-2", mode: "live" };

function provider(config: Record<string, unknown>, secrets: Record<string, string> = { apiToken: TOKEN }): SecurityEventProvider {
  const def = connectorDef("tawny")!;
  const inst = def.create!(def.config.parse(config), def.secrets.parse(secrets));
  if (inst.kind !== "events") throw new Error("not an event provider");
  return inst.provider;
}

const alert: TawnyAlert = {
  id: 42,
  alert_rule_id: "rule-1",
  rule_name: "Encoded PowerShell",
  agent_id: AGENT,
  hostname: "ws-01",
  agent_os: "windows",
  agent_os_version: "10.0.26100",
  telemetry_event_id: 7,
  event_type: "process_launch",
  occurred_at: "2026-09-01T01:02:03Z",
  received_at: "2026-09-01T01:02:04Z",
  payload: { pid: 4242, name: "powershell.exe", command_line: "powershell -enc AAA http://bad.example/p.ps1", user: "j.nguyen" },
  severity: "critical",
  status: "open",
  title: "Encoded PowerShell on ws-01",
  description: "PowerShell started with an encoded command.",
  created_at: "2026-09-01T01:02:05Z",
  mitre_techniques: ["T1059.001"],
};

const agent: TawnyAgent = {
  id: AGENT,
  hostname: "ws-01",
  operating_system: "macos",
  os_version: "15.1",
  agent_version: "0.1.0",
  architecture: "arm64",
  status: "online",
  last_heartbeat_at: "2026-09-01T01:00:00Z",
  enrolled_at: "2026-08-01T00:00:00Z",
};

type Call = { url: string; method: string; headers: Record<string, string>; body: unknown };
const original = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = original;
});

function stubFetch(handler: (call: Call) => { status?: number; body: unknown }): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])),
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const res = handler(call);
    const status = res.status ?? 200;
    return new Response(JSON.stringify(res.body), { status, statusText: status === 200 ? "OK" : status === 201 ? "Created" : "Error" });
  }) as typeof fetch;
  return calls;
}

describe("tawny connector definition", () => {
  it("is an available endpoint connector with events, assets and response", () => {
    const def = connectorDef("tawny")!;
    expect(def.status).toBe("available");
    expect(def.category).toBe("endpoint");
    expect(def.capabilities).toEqual(["events", "assets", "response"]);
    expect(def.description).toMatch(/isolation support/);
    expect(def.remotePermissions.join(" ")).toMatch(/Admin/);
  });

  it("validates config, defaults to live, and pins the region to Australia", () => {
    const def = connectorDef("tawny")!;
    expect(def.config.parse({ apiUrl: "https://tawny.example.com", region: "ap-southeast-4" })).toMatchObject({ mode: "live", tlsVerify: true });
    expect(() => def.config.parse({ apiUrl: "https://tawny.example.com", region: "us-east-1" })).toThrow();
    expect(() => def.config.parse({ apiUrl: "tawny.example.com", region: "ap-southeast-2" })).toThrow();
    expect(() => def.config.parse({ apiUrl: "https://tawny.example.com" })).toThrow();
    expect(def.config.parse(exampleConfig("tawny"))).toMatchObject({ region: "ap-southeast-2" });
  });

  it("only accepts twny_ API tokens and keeps the token write-only", () => {
    const def = connectorDef("tawny")!;
    expect(def.secrets.parse({ apiToken: TOKEN })).toEqual({ apiToken: TOKEN });
    expect(() => def.secrets.parse({ apiToken: "abcdefghijklmnopqrstuvwxyz" })).toThrow(/twny_/);
    expect(() => def.secrets.parse({ apiToken: "twny_" })).toThrow();
    expect(() => def.secrets.parse({ apiToken: "twny_has spaces in it 0123456789" })).toThrow();
    expect(() => def.secrets.parse({})).toThrow();
    expect(secretFields("tawny")).toEqual([{ key: "apiToken", optional: false }]);
  });

  it("is plan-gated like the Wazuh endpoint service", () => {
    expect(collectionAllowed("essentials", "tawny")).toBe(false);
    expect(collectionAllowed("standard", "tawny")).toBe(true);
  });
});

describe("tawny normalisation", () => {
  it("maps an alert to a blakSOC alert with the telemetry under raw", () => {
    const n = normaliseTawnyAlert(alert);
    expect(n).toMatchObject({
      externalId: "42",
      ruleId: "rule-1",
      title: "Encoded PowerShell on ws-01",
      description: "PowerShell started with an encoded command.",
      category: "process_launch",
      siemSeverity: 3,
      severity: "critical",
      assetExternalId: AGENT,
      hostname: "ws-01",
      userName: "j.nguyen",
      attackTechniques: ["T1059.001"],
      routingKeys: [`agent:${AGENT}`],
    });
    expect(n.occurredAt.toISOString()).toBe("2026-09-01T01:02:03.000Z");
    expect(n.raw).toMatchObject({
      alert: { payload: { command_line: expect.stringContaining("http://bad.example/p.ps1") } },
      agent: { id: AGENT, name: "ws-01", os: { platform: "windows", version: "10.0.26100" } },
      process: { pid: 4242, name: "powershell.exe" },
    });
  });

  it("maps every severity and falls back to the rule name", () => {
    expect((["low", "medium", "high", "critical"] as const).map((severity) => {
      const n = normaliseTawnyAlert({ ...alert, severity });
      return [n.severity, n.siemSeverity];
    })).toEqual([["low", 0], ["medium", 1], ["high", 2], ["critical", 3]]);
    const bare = normaliseTawnyAlert({ ...alert, title: "", payload: { processes: [] }, mitre_techniques: undefined });
    expect(bare.title).toBe("Encoded PowerShell");
    expect(bare.userName).toBeNull();
    expect(bare.attackTechniques).toEqual([]);
    expect(bare.raw.process).toBeUndefined();
  });

  it("maps an agent to an endpoint asset with raw.os.platform for the executor", () => {
    const a = normaliseTawnyAgent(agent);
    expect(a).toMatchObject({ externalId: AGENT, kind: "endpoint", name: "ws-01", hostname: "ws-01", os: "macOS 15.1", agentStatus: "online", ips: [], routingKeys: [`agent:${AGENT}`] });
    expect(a.lastSeen?.toISOString()).toBe("2026-09-01T01:00:00.000Z");
    expect((a.raw as { os: { platform: string } }).os.platform).toBe("macos");
    expect(normaliseTawnyAgent({ ...agent, last_heartbeat_at: null }).lastSeen).toBeNull();
  });

  it("parses a kill_process PID and refuses names", () => {
    expect(parseTawnyPid({ arguments: ["4242"] })).toEqual({ pid: 4242 });
    expect(parseTawnyPid({ arguments: [" 17 "] })).toEqual({ pid: 17 });
    expect(parseTawnyPid({ pid: 99, arguments: ["5"] })).toEqual({ pid: 99 });
    expect(parseTawnyPid({ arguments: ["chrome.exe"] })).toEqual({ error: expect.stringMatching(/numeric process id.*chrome\.exe/) });
    expect(parseTawnyPid({ arguments: ["-1"] })).toEqual({ error: expect.stringMatching(/numeric/) });
    expect(parseTawnyPid({ arguments: ["0"] })).toEqual({ error: expect.stringMatching(/out of range/) });
    expect(parseTawnyPid({ arguments: ["99999999999"] })).toEqual({ error: expect.stringMatching(/out of range/) });
    expect(parseTawnyPid({ arguments: [] })).toEqual({ error: expect.stringMatching(/needs a process id/) });
    expect(parseTawnyPid(undefined)).toEqual({ error: expect.stringMatching(/needs a process id/) });
  });

  it("maps Tawny action states, keeping the agent's failure message", () => {
    expect(tawnyActionState({ status: "pending", action_type: "kill_process" }).state).toBe("pending");
    expect(tawnyActionState({ status: "dispatched", action_type: "kill_process" }).state).toBe("running");
    expect(tawnyActionState({ status: "running", action_type: "kill_process" }).state).toBe("running");
    expect(tawnyActionState({ status: "succeeded", action_type: "kill_process", result: { message: "terminated 4242" } })).toEqual({ state: "succeeded", message: "terminated 4242" });
    expect(tawnyActionState({ status: "failed", action_type: "isolate_host", result: { message: "isolation not supported" } })).toEqual({ state: "failed", message: "Tawny isolate_host failed: isolation not supported" });
    expect(tawnyActionState({ status: "cancelled", action_type: "kill_process" })).toEqual({ state: "failed", message: "Tawny kill_process cancelled" });
    expect(tawnyActionState({ status: "expired", action_type: "kill_process" }).state).toBe("failed");
  });
});

describe("tawny fixture mode", () => {
  it("never calls the network", async () => {
    globalThis.fetch = (() => {
      throw new Error("network");
    }) as typeof fetch;
    const p = provider({ ...LIVE, mode: "fixture" });
    expect((await p.health()).ok).toBe(true);

    const first = await p.getAlerts({ since: new Date(Date.now() - 86_400_000), limit: 500 });
    expect(first.alerts.map((a) => a.externalId)).toEqual(["101", "102"]);
    expect(first.cursor).toBe("102");
    expect(await p.getAlerts({ afterCursor: "102" })).toEqual({ alerts: [], cursor: null });
    expect((await p.getAlerts({ afterCursor: "101" })).alerts.map((a) => a.externalId)).toEqual(["102"]);
    expect((await p.getAlert("102"))?.severity).toBe("critical");
    expect(await p.getAlert("999")).toBeNull();

    const assets = await p.getAssets();
    expect(assets).toHaveLength(1);
    expect((await p.getAsset(assets[0]!.externalId))?.hostname).toBe("fixture-ws-01");

    const kill = await p.executeResponseAction({ action: "kill_process", assetExternalId: assets[0]!.externalId, params: { arguments: ["4242"], actionId: "a-1" } });
    expect(kill).toMatchObject({ ok: true, pending: true });
    expect(await p.getResponseActionStatus!({ assetExternalId: assets[0]!.externalId, providerRef: kill.providerRef! })).toMatchObject({ state: "succeeded" });

    const isolate = await p.executeResponseAction({ action: "isolate_endpoint", assetExternalId: assets[0]!.externalId });
    expect(isolate).toMatchObject({ ok: true, pending: true });
    expect(await p.getResponseActionStatus!({ assetExternalId: assets[0]!.externalId, providerRef: isolate.providerRef! })).toMatchObject({ state: "failed", message: expect.stringMatching(/isolation/) });

    expect(await p.executeResponseAction({ action: "kill_process", assetExternalId: assets[0]!.externalId, params: { arguments: ["explorer.exe"] } })).toMatchObject({ ok: false, message: expect.stringMatching(/numeric/) });
    expect(await p.executeResponseAction({ action: "block_ip", assetExternalId: assets[0]!.externalId })).toMatchObject({ ok: false });
    await expect(p.searchEvents({ query: "process.name:x" })).rejects.toThrow(/provider-native/);
  });
});

describe("tawny live mode", () => {
  it("pages alerts forward with the bearer token and an id cursor", async () => {
    const calls = stubFetch(() => ({ body: [alert, { ...alert, id: 43, agent_id: "other-agent" }] }));
    const p = provider(LIVE);
    const since = new Date("2026-09-01T00:00:00.000Z");
    const first = await p.getAlerts({ since, limit: 900 });
    expect(calls[0]!.url).toBe(`https://tawny.example.com/api/alerts?limit=500&since=${encodeURIComponent(since.toISOString())}`);
    expect(calls[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(first.cursor).toBe("43");
    expect(first.alerts.map((a) => a.externalId)).toEqual(["42", "43"]);

    const routed = await p.getAlerts({ since, afterCursor: "43", routingKeys: [`agent:${AGENT}`] });
    expect(calls[1]!.url).toBe("https://tawny.example.com/api/alerts?limit=500&after_id=43");
    expect(routed.alerts.map((a) => a.externalId)).toEqual(["42"]);
    // The cursor still moves past the row that was filtered out.
    expect(routed.cursor).toBe("43");

    await expect(p.getAlerts({ afterCursor: "eyJ3YXp1aCI6MX0" })).rejects.toThrow(/invalid Tawny cursor/);
  });

  it("returns a null cursor on an empty page and finds one alert by id", async () => {
    const calls = stubFetch((call) => ({ body: call.url.includes("after_id=41") ? [alert] : [] }));
    const p = provider(LIVE);
    expect(await p.getAlerts({ afterCursor: "50" })).toEqual({ alerts: [], cursor: null });
    expect((await p.getAlert("42"))?.externalId).toBe("42");
    expect(calls[1]!.url).toBe("https://tawny.example.com/api/alerts?after_id=41&limit=1");
    expect(await p.getAlert("not-a-number")).toBeNull();
  });

  it("syncs agents and skips revoked ones", async () => {
    const calls = stubFetch(() => ({ body: [agent, { ...agent, id: "11111111-2222-3333-4444-555555555555", status: "revoked" }] }));
    const assets = await provider(LIVE).getAssets();
    expect(calls[0]!.url).toBe("https://tawny.example.com/api/agents");
    expect(assets.map((a) => a.externalId)).toEqual([AGENT]);
  });

  it("posts kill_process with the PID and the blakSOC action id as idempotency key, then polls the result", async () => {
    let state = "pending";
    const calls = stubFetch((call) => {
      if (call.method === "POST") return { status: 201, body: { id: "act-1", agent_id: AGENT, action_type: "kill_process", status: "pending", payload: { pid: 4242 }, result: null } };
      return { body: [{ id: "act-0", agent_id: AGENT, action_type: "kill_process", status: "failed" }, { id: "act-1", agent_id: AGENT, action_type: "kill_process", status: state, result: state === "succeeded" ? { message: "terminated pid 4242" } : null }] };
    });
    const p = provider(LIVE);
    const r = await p.executeResponseAction({ action: "kill_process", assetExternalId: AGENT, params: { arguments: ["4242"], actionId: "9b3d6f1e-0000-4000-8000-000000000001", platform: "windows" } });
    expect(r).toMatchObject({ ok: true, pending: true, providerRef: "act-1" });
    expect(calls[0]).toMatchObject({
      url: `https://tawny.example.com/api/agents/${AGENT}/actions`,
      method: "POST",
      body: { action_type: "kill_process", payload: { pid: 4242 }, idempotency_key: "9b3d6f1e-0000-4000-8000-000000000001" },
    });
    expect(calls[0]!.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]!.headers["content-type"]).toBe("application/json");

    expect(await p.getResponseActionStatus!({ assetExternalId: AGENT, providerRef: "act-1" })).toMatchObject({ state: "pending" });
    state = "running";
    expect(await p.getResponseActionStatus!({ assetExternalId: AGENT, providerRef: "act-1" })).toMatchObject({ state: "running" });
    state = "succeeded";
    expect(await p.getResponseActionStatus!({ assetExternalId: AGENT, providerRef: "act-1" })).toEqual({ state: "succeeded", message: "terminated pid 4242" });
    expect(calls[1]!.url).toBe(`https://tawny.example.com/api/agents/${AGENT}/actions`);
    expect(await p.getResponseActionStatus!({ assetExternalId: AGENT, providerRef: "act-missing" })).toMatchObject({ state: "pending" });
  });

  it("maps isolate and release to Tawny host actions with an empty payload", async () => {
    const calls = stubFetch((call) => ({ status: 201, body: { id: "act-2", agent_id: AGENT, action_type: (call.body as { action_type: string }).action_type, status: "pending" } }));
    const p = provider(LIVE);
    await p.executeResponseAction({ action: "isolate_endpoint", assetExternalId: AGENT, params: { actionId: "x" } });
    await p.executeResponseAction({ action: "release_endpoint", assetExternalId: AGENT });
    expect(calls.map((c) => c.body)).toEqual([
      { action_type: "isolate_host", payload: {}, idempotency_key: "x" },
      { action_type: "release_host", payload: {} },
    ]);
  });

  it("treats an idempotent replay that already finished as final", async () => {
    stubFetch(() => ({ body: { id: "act-3", agent_id: AGENT, action_type: "isolate_host", status: "failed", result: { message: "isolation not supported by this agent" } } }));
    const r = await provider(LIVE).executeResponseAction({ action: "isolate_endpoint", assetExternalId: AGENT, params: { actionId: "x" } });
    expect(r).toEqual({ ok: false, providerRef: "act-3", message: "Tawny isolate_host failed: isolation not supported by this agent" });
  });

  it("explains a Viewer token on a response action and refuses bad targets before calling Tawny", async () => {
    const calls = stubFetch(() => ({ status: 403, body: {} }));
    const p = provider(LIVE);
    const r = await p.executeResponseAction({ action: "kill_process", assetExternalId: AGENT, params: { arguments: ["1"] } });
    expect(r).toMatchObject({ ok: false, message: expect.stringMatching(/Admin API token/) });
    expect(await p.executeResponseAction({ action: "kill_process", assetExternalId: "../../admin", params: { arguments: ["1"] } })).toMatchObject({ ok: false });
    expect(await p.executeResponseAction({ action: "kill_process", assetExternalId: AGENT, params: { arguments: ["notepad"] } })).toMatchObject({ ok: false });
    expect(calls).toHaveLength(1);
  });

  it("checks the API and the token in health", async () => {
    const calls = stubFetch((call) => ({ body: call.url.endsWith("/api/health") ? { status: "ok" } : [agent] }));
    const h = await provider(LIVE).health();
    expect(h).toMatchObject({ ok: true, detail: { mode: "live", status: "ok", agents: 1 } });
    expect(calls.map((c) => c.url)).toEqual(["https://tawny.example.com/api/health", "https://tawny.example.com/api/agents"]);

    stubFetch((call) => ({ status: call.url.endsWith("/api/health") ? 200 : 401, body: { status: "ok" } }));
    const bad = await provider(LIVE).health();
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/rejected the API token/);
  });
});
