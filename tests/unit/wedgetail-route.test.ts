import { createHmac } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WEDGETAIL_CREATED } from "../fixtures/wedgetail";

const mocks = vi.hoisted(() => ({ lookup: vi.fn(), ingest: vi.fn(), intel: vi.fn(), audit: vi.fn(), publish: vi.fn(), triggers: vi.fn(), rate: vi.fn(), tx: { execute: vi.fn(), select: vi.fn(), update: vi.fn() }, count: vi.fn(), lag: vi.fn() }));
const id = "11111111-1111-4111-8111-111111111111";
const tenantId = "22222222-2222-4222-8222-222222222222";
// Built at runtime: a literal signing secret, even a fake one, trips the secret scan.
const secret = "s".repeat(32);
const row = { id, tenantId, enabled: true, provider: "wedgetail", secretCiphertext: "encrypted" };
vi.mock("@/db/client", () => ({ systemDb: () => ({ select: () => ({ from: () => ({ where: mocks.lookup }) }) }) }));
vi.mock("@/db/scope", () => ({ withScope: (scope: unknown, fn: (tx: unknown) => unknown) => { expect(scope).toEqual({ tenantIds: [tenantId], grantIds: [tenantId], platform: false }); return fn(mocks.tx); } }));
vi.mock("@/lib/crypto", () => ({ decryptSecret: () => JSON.stringify({ signingSecret: "s".repeat(32) }) }));
vi.mock("@/lib/connectors/instances", () => ({ secretAad: (value: string) => `integration:${value}`, intelProviderFor: mocks.intel }));
vi.mock("@/lib/pipeline/ingest", () => ({ ingestAlert: mocks.ingest, IngestIntegrationUnavailable: class extends Error {}, IngestIntegrationConflict: class extends Error {} }));
vi.mock("@/lib/audit", () => ({ audit: mocks.audit }));
vi.mock("@/lib/events", () => ({ publish: mocks.publish }));
vi.mock("@/lib/soar/engine", () => ({ evaluateTriggers: mocks.triggers }));
vi.mock("@/lib/obs/metrics", () => ({ ingestAlerts: () => ({ inc: mocks.count }), ingestLag: () => ({ observe: mocks.lag }) }));
vi.mock("@/lib/auth/rate-limit", () => ({ sharedRateLimitStore: () => ({ consume: mocks.rate }) }));
vi.mock("@/lib/redis", () => ({ redis: vi.fn() }));

import { POST } from "@/app/api/ingest/wedgetail/[integrationId]/route";

function request(body: string, options: { timestamp?: string; signature?: string; headers?: Record<string, string>; stream?: boolean; integrationId?: string } = {}) {
  const timestamp = options.timestamp ?? String(Math.floor(Date.now() / 1000));
  const headers = { "content-type": "application/json", "x-wedgetail-timestamp": timestamp, "x-wedgetail-signature": options.signature ?? `v1=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`, ...options.headers };
  const init = options.stream ? { method: "POST", headers, duplex: "half", body: new ReadableStream({ start(controller) { for (const chunk of [body.slice(0, 100), body.slice(100)]) controller.enqueue(Buffer.from(chunk)); controller.close(); } }) } : { method: "POST", headers, body };
  return POST(new Request(`https://soc.example.com/api/ingest/wedgetail/${id}`, init as RequestInit), { params: Promise.resolve({ integrationId: options.integrationId ?? id }) });
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.lookup.mockResolvedValue([row]);
  mocks.rate.mockResolvedValue({ allowed: true });
  mocks.intel.mockResolvedValue(null);
  mocks.ingest.mockResolvedValue({ created: true, alertId: "fictional-alert" });
  mocks.tx.update.mockReturnValue({ set: () => ({ where: () => Promise.resolve() }) });
});

describe("Wedgetail inbound route", () => {
  it("ingests valid signed bytes with tenant authority from the integration, then updates a replay", async () => {
    const body = JSON.stringify({ ...WEDGETAIL_CREATED, tenant: { id: "33333333-3333-4333-8333-333333333333" } });
    const response = await request(body, { headers: { "x-request-id": "fictional-request" } });
    expect(response.status).toBe(202);
    expect(response.headers.get("x-request-id")).toBe("fictional-request");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mocks.ingest).toHaveBeenCalledWith(expect.objectContaining({ tenantId, integrationId: id, source: "wedgetail", updateExisting: true }));
    expect(mocks.triggers).toHaveBeenCalledTimes(1);
    mocks.ingest.mockResolvedValue({ created: false, alertId: "fictional-alert" });
    const replay = await request(body);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ outcome: "duplicate", alertId: "fictional-alert" });
    expect(mocks.triggers).toHaveBeenCalledTimes(1);
    expect(mocks.count).toHaveBeenCalledWith({ provider: "wedgetail", integration: id, outcome: "duplicate" });
  });

  it.each(["wedgetail.incident.created", "wedgetail.incident.escalated", "wedgetail.future.notice"])("acknowledges signed %s notices without storing them", async (type) => {
    const setHealth = vi.fn().mockReturnValue({ where: () => Promise.resolve() });
    mocks.tx.update.mockReturnValue({ set: setHealth });
    const body = JSON.stringify({ type, incident: { id: "wt-fictional-incident", title: "Fictional AWS incident", accountId: "111122223333" }, url: "https://wedgetail.example.com/incidents/wt-fictional-incident" });
    const response = await request(body);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ outcome: "ignored" });
    expect(mocks.count).toHaveBeenCalledExactlyOnceWith({ provider: "wedgetail", integration: id, outcome: "ignored" });
    expect(mocks.tx.update).toHaveBeenCalledTimes(1);
    expect(setHealth).toHaveBeenCalledWith(expect.objectContaining({ health: expect.any(Object), status: "healthy", lastSuccessAt: expect.any(Date) }));
    expect(mocks.tx.select).not.toHaveBeenCalled();
    expect(mocks.ingest).not.toHaveBeenCalled();
    expect(mocks.intel).not.toHaveBeenCalled();
    expect(mocks.audit).not.toHaveBeenCalled();
    expect(mocks.publish).not.toHaveBeenCalled();
    expect(mocks.triggers).not.toHaveBeenCalled();
    expect(mocks.lag).not.toHaveBeenCalled();
  });

  it("refuses unsigned/stale unhandled notices and malformed envelopes or handled events", async () => {
    const body = JSON.stringify({ type: "wedgetail.incident.created", incident: { id: "wt-fictional-incident" } });
    for (const options of [{ signature: "" }, { signature: "v1=bad" }, { timestamp: String(Math.floor(Date.now() / 1000) - 301) }]) {
      expect((await request(body, options)).status).toBe(401);
    }
    for (const malformed of ["not-json", "null", "[]", "{}", JSON.stringify("wedgetail.incident.created"), JSON.stringify({ type: 123 }), JSON.stringify({ type: "other.incident.created" }), JSON.stringify({ type: "wedgetail.alert.created" }), JSON.stringify({ type: "wedgetail.alert.updated" })]) {
      expect((await request(malformed)).status).toBe(400);
    }
    expect(mocks.count.mock.calls.every(([labels]) => labels.outcome === "rejected")).toBe(true);
    expect(mocks.ingest).not.toHaveBeenCalled();
    expect(mocks.audit).not.toHaveBeenCalled();
  });

  it("rejects bad, stale, future and missing signatures without ingesting", async () => {
    const body = JSON.stringify(WEDGETAIL_CREATED);
    for (const options of [{ signature: "v1=bad" }, { signature: "" }, { timestamp: String(Math.floor(Date.now() / 1000) - 301) }, { timestamp: String(Math.floor(Date.now() / 1000) + 301) }]) {
      const response = await request(body, options);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "unauthorised" });
    }
    expect(mocks.ingest).not.toHaveBeenCalled();
    expect(mocks.count).toHaveBeenCalledWith({ provider: "wedgetail", integration: id, outcome: "rejected" });
  });

  it("returns the same 404 for unknown and disabled integrations and bounds metric labels", async () => {
    mocks.lookup.mockResolvedValue([]);
    for (const integrationId of [id, "invalid"]) expect((await request("{}", { integrationId })).status).toBe(404);
    expect(mocks.count).toHaveBeenCalledWith({ provider: "wedgetail", integration: "unknown", outcome: "rejected" });
    expect(mocks.ingest).not.toHaveBeenCalled();
  });

  it("caps bytes for declared and chunked bodies, including multi-byte text", async () => {
    expect((await request("{}", { headers: { "content-length": "262145" } })).status).toBe(413);
    expect((await request("x".repeat(262145), { stream: true })).status).toBe(413);
    expect((await request("澳".repeat(90000), { stream: true })).status).toBe(413);
    // Exactly the cap is read and then rejected as malformed JSON, not oversized.
    expect((await request("x".repeat(262144), { stream: true })).status).toBe(400);
    expect(mocks.ingest).not.toHaveBeenCalled();
  });

  it("rejects malformed signed data, returns safe failures and honours rate limits", async () => {
    expect((await request("not-json")).status).toBe(400);
    expect((await request(JSON.stringify({ type: "wedgetail.alert.created" }))).status).toBe(400);
    mocks.ingest.mockRejectedValue(new Error("PRIVATE RAW PAYLOAD"));
    const unavailable = await request(JSON.stringify(WEDGETAIL_CREATED));
    expect(unavailable.status).toBe(503);
    expect(await unavailable.text()).not.toContain("PRIVATE");
    mocks.lookup.mockRejectedValue(new Error("PRIVATE DATABASE FAILURE"));
    const failedLookup = await request("{}");
    expect(failedLookup.status).toBe(503);
    expect(await failedLookup.text()).not.toContain("PRIVATE");
    expect(failedLookup.headers.get("x-request-id")).toBeTruthy();
    mocks.rate.mockResolvedValue({ allowed: false, retryAfter: 60 });
    const limited = await request("{}");
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    expect((await request("{}", { headers: { "x-forwarded-proto": "http" } })).status).toBe(400);
  });

  it("applies status updates under tenant RLS, audits actor and does not publish a loop", async () => {
    let alert = { id: "fictional-alert", tenantId, integrationId: id, status: "NEW", raw: {} as Record<string, unknown> };
    mocks.tx.select.mockImplementation(() => ({ from: (table: { enabled?: unknown }) => ({ where: () => ({ for: () => Promise.resolve(table.enabled ? [{ enabled: true }] : [alert]) }) }) }));
    mocks.tx.update.mockImplementation(() => ({ set: (patch: Record<string, unknown>) => ({ where: () => { if (patch.status && patch.status !== "healthy") alert = { ...alert, ...patch }; return Promise.resolve(); } }) }));
    const update = (status: string, updatedAt: string) => request(JSON.stringify({ type: "wedgetail.alert.updated", alert: { id: WEDGETAIL_CREATED.alert.id, status, updatedAt } }));
    for (const [status, expected, time] of [["acknowledged", "TRIAGING", "01"], ["closed_true_positive", "RESOLVED", "02"], ["new", "NEW", "03"]]) {
      expect((await update(status!, `2026-10-13T00:00:${time}Z`)).status).toBe(200);
      expect(alert.status).toBe(expected);
      expect(mocks.audit).toHaveBeenLastCalledWith(mocks.tx, expect.objectContaining({ actorId: `wedgetail:${id}`, actorKind: "system", tenantId, action: "alert.update", detail: expect.objectContaining({ status: expected, origin: "wedgetail" }) }));
    }
    expect(mocks.audit).toHaveBeenCalledTimes(3);
    await update("closed_true_positive", "2026-10-13T00:00:02Z");
    await update("new", "2026-10-13T00:00:03Z");
    expect(alert.status).toBe("NEW");
    expect(mocks.audit).toHaveBeenCalledTimes(3);
    expect(mocks.publish).not.toHaveBeenCalled();
    expect(mocks.ingest).not.toHaveBeenCalled();
    expect(mocks.triggers).not.toHaveBeenCalled();
  });

  it("returns an unrouted retry response when the status target is outside this install", async () => {
    mocks.tx.select.mockImplementation(() => ({ from: (table: { enabled?: unknown }) => ({ where: () => ({ for: () => Promise.resolve(table.enabled ? [{ enabled: true }] : []) }) }) }));
    const response = await request(JSON.stringify({ type: "wedgetail.alert.updated", alert: { id: "not-this-install", status: "closed", updatedAt: "2026-10-13T00:00:01Z" } }));
    expect(response.status).toBe(409);
    expect(mocks.audit).not.toHaveBeenCalled();
    expect(mocks.count).toHaveBeenCalledWith({ provider: "wedgetail", integration: id, outcome: "unrouted" });
  });
});
