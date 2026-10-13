import { beforeEach, describe, expect, it, vi } from "vitest";
import { alerts, integrations, observables } from "@/db/schema";
import type { NormalisedAlert } from "@/lib/providers/types";

const mocks = vi.hoisted(() => ({ scope: vi.fn(), publish: vi.fn(), graph: vi.fn(), noise: vi.fn(), hits: vi.fn() }));
vi.mock("@/db/scope", () => ({ withScope: mocks.scope }));
vi.mock("@/lib/events", () => ({ publish: mocks.publish }));
vi.mock("@/lib/graph/store", () => ({ recordAlertGraph: mocks.graph }));
vi.mock("@/lib/services/tuning", () => ({ dispositionStats: async () => null, liveNoiseRules: async () => [], recordNoiseHits: mocks.hits }));
vi.mock("@/lib/tuning/noise", () => ({ firstMatch: mocks.noise, passiveReasonFor: () => "Known noise" }));
vi.mock("@/lib/intel/enrich", () => ({ filterByEntitlement: async (_tx: unknown, _tenant: unknown, matches: unknown) => matches }));
import { ingestAlert, IngestIntegrationConflict, IngestIntegrationUnavailable } from "@/lib/pipeline/ingest";

const tenantId = "11111111-1111-4111-8111-111111111111";
const integrationId = "22222222-2222-4222-8222-222222222222";
const alert: NormalisedAlert = { externalId: "wt-fictional", title: "Fictional detection", description: null, severity: "high", siemSeverity: null, ruleId: "WT-AWS-001", category: "aws", occurredAt: new Date("2026-10-13T00:00:00Z"), assetExternalId: null, hostname: null, userName: null, routingKeys: [], attackTechniques: ["T1078.004"], raw: { sourceIp: "203.0.113.10" } };
const initialIngest = new Date("2026-10-13T00:01:00Z");
const duplicate = { id: "fictional-alert", integrationId, riskScore: 1, intelVerdict: "unchecked", lane: "active", ingestedAt: initialIngest, raw: { wedgetailSync: { updatedAt: "2026-10-13T00:02:00Z" } } };
let patch: Record<string, unknown> | null;
function database(dupe: typeof duplicate | null, enabled = true) {
  return {
    execute: vi.fn().mockResolvedValue([]),
    select: () => ({ from: (table: unknown) => ({ where: () => {
      const rows = table === integrations ? [{ enabled }] : table === alerts ? dupe ? [dupe] : [] : [];
      return { then: (resolve: (value: unknown) => unknown) => resolve(rows), for: () => Promise.resolve(rows) };
    } }) }),
    update: (table: unknown) => ({ set: (values: Record<string, unknown>) => {
      if (table === alerts) patch = values;
      return { where: () => ({ returning: () => Promise.resolve([{ id: dupe?.id ?? "fictional-alert" }]) }) };
    } }),
    insert: (table: unknown) => ({ values: (values: Record<string, unknown>) => {
      if (table === alerts) patch = values;
      return { returning: () => Promise.resolve([{ id: "fictional-alert" }]), onConflictDoUpdate: () => ({ returning: () => Promise.resolve([{ id: table === observables ? "fictional-ip" : "fictional" }]) }), onConflictDoNothing: () => Promise.resolve() };
    } }),
  };
}
beforeEach(() => { vi.resetAllMocks(); patch = null; mocks.noise.mockReturnValue(null); });
function configure(dupe: typeof duplicate | null, enabled = true) {
  const tx = database(dupe, enabled);
  mocks.scope.mockImplementation(async (scope, fn) => {
    expect(scope).toEqual({ tenantIds: [tenantId], grantIds: [tenantId], platform: false });
    return fn(tx);
  });
  return tx;
}
const ingest = (updateExisting = true) => ingestAlert({ tenantId, integrationId, source: "wedgetail", alert, intel: null, updateExisting });

describe("Wedgetail opt-in pipeline refresh", () => {
  it("creates a scored OCSF finding and sends one creation event", async () => {
    configure(null);
    expect(await ingest()).toMatchObject({ created: true, alertId: "fictional-alert", riskScore: expect.any(Number) });
    expect(patch).toMatchObject({ tenantId, integrationId, externalId: "wt-fictional", ocsf: { class_uid: 2004, metadata: { tenant_uid: tenantId } } });
    expect(mocks.publish).toHaveBeenCalledTimes(1);
    expect(mocks.graph).toHaveBeenCalledTimes(1);
  });

  it("refreshes scoring, raw and OCSF while retaining analyst status and sync watermark", async () => {
    const tx = configure(duplicate);
    const result = await ingest();
    expect(result.created).toBe(false);
    expect(result.riskScore).toBeGreaterThan(1);
    expect(patch).toMatchObject({ title: "Fictional detection", raw: { sourceIp: "203.0.113.10", wedgetailSync: duplicate.raw.wedgetailSync }, ocsf: { metadata: { logged_time: initialIngest.getTime() } } });
    expect(patch).not.toHaveProperty("status");
    expect(patch?.ingestedAt).toBeUndefined();
    expect(tx.execute).toHaveBeenCalledTimes(1);
    expect(mocks.publish).not.toHaveBeenCalled();
    expect(mocks.hits).not.toHaveBeenCalled();
  });

  it("preserves the existing duplicate behaviour for other providers", async () => {
    const tx = configure(duplicate);
    expect(await ingest(false)).toMatchObject({ created: false, riskScore: 1 });
    expect(patch).toBeNull();
    expect(tx.execute).not.toHaveBeenCalled();
    expect(mocks.graph).not.toHaveBeenCalled();
    expect(mocks.publish).not.toHaveBeenCalled();
  });

  it("refuses disabled and foreign integration bindings before any write", async () => {
    configure(duplicate, false);
    await expect(ingest()).rejects.toBeInstanceOf(IngestIntegrationUnavailable);
    configure({ ...duplicate, integrationId: "33333333-3333-4333-8333-333333333333" });
    await expect(ingest()).rejects.toBeInstanceOf(IngestIntegrationConflict);
    expect(patch).toBeNull();
    expect(mocks.graph).not.toHaveBeenCalled();
  });
});
