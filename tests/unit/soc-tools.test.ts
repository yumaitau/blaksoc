import { beforeEach, describe, expect, it } from "vitest";
import { clearThreatSieveProbeCache, integrationStatus, probeThreatSieve, type HealthFetch } from "@/lib/services/soc-tools";
import { supportsAlertFloor } from "@/lib/integrations/alert-floor";

const at = new Date("2026-10-08T03:00:00Z");
const row = (o: Partial<Parameters<typeof integrationStatus>[0][number]> = {}) => ({ enabled: true, status: "healthy", lastError: null, lastSuccessAt: at, lastErrorAt: null, ...o });

describe("tool status from integrations", () => {
  it("reports operational, down, degraded and unknown", () => {
    expect(integrationStatus([row()])).toEqual({ state: "ok", summary: "Connected", checkedAt: at });
    expect(integrationStatus([row({ status: "error", lastError: "connect ETIMEDOUT", lastErrorAt: new Date(at.getTime() + 1000) })])).toMatchObject({ state: "down", summary: "connect ETIMEDOUT" });
    expect(integrationStatus([row(), row({ status: "error" })])).toMatchObject({ state: "degraded", summary: "1 of 2 connections healthy" });
    expect(integrationStatus([])).toMatchObject({ state: "unknown", summary: "No integration connected" });
    expect(integrationStatus([row({ enabled: false })])).toMatchObject({ state: "unknown", summary: "Integration disabled" });
    expect(integrationStatus([row({ status: "unknown", lastSuccessAt: null })])).toMatchObject({ state: "unknown", summary: "Not checked yet" });
  });
});

describe("ThreatSieve probe", () => {
  beforeEach(() => clearThreatSieveProbeCache());
  const reply = (status: number, body: unknown): HealthFetch => async () => ({ ok: status < 400, status, json: async () => body });

  it("is operational only when /health answers status ok, and caches for a minute", async () => {
    let calls = 0;
    const ok: HealthFetch = async (url) => { calls++; expect(url.pathname).toBe("/health"); return { ok: true, status: 200, json: async () => ({ status: "ok" }) }; };
    expect(await probeThreatSieve("https://api.example.test", ok, 1_000)).toMatchObject({ state: "ok" });
    await probeThreatSieve("https://api.example.test", ok, 30_000);
    expect(calls).toBe(1);
    await probeThreatSieve("https://api.example.test", ok, 62_000);
    expect(calls).toBe(2);
  });

  it("explains a failed check", async () => {
    expect(await probeThreatSieve("https://a.example.test", reply(404, null))).toMatchObject({ state: "down", summary: "API health check returned HTTP 404" });
    expect(await probeThreatSieve("https://b.example.test", reply(200, { status: "degraded" }))).toMatchObject({ state: "down" });
    const refused: HealthFetch = async () => { throw new TypeError("fetch failed"); };
    expect(await probeThreatSieve("https://c.example.test", refused)).toMatchObject({ state: "down", summary: "API unreachable" });
  });
});

describe("alert floor support", () => {
  it("is offered only where the connector keeps minSeverity", () => {
    expect(supportsAlertFloor("wazuh")).toBe(true);
    expect(supportsAlertFloor("kelpie")).toBe(false);
    expect(supportsAlertFloor("no-such-connector")).toBe(false);
  });
});
