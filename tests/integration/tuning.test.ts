/**
 * Alert fatigue, phase 1, against the database: noise rules put matching alerts in the passive lane at
 * ingest (only live rules, only in their own tenant), passive alerts never open incidents, "Mark as noise"
 * backfills open alerts, disposition memory feeds the score, and the dashboard measures it.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, auditLog, noiseRules, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { ingestAlert } from "@/lib/pipeline/ingest";
import type { NormalisedAlert } from "@/lib/providers/types";
import { redis } from "@/lib/redis";
import { runGrouping } from "@/lib/services/correlation";
import { fatigueMetrics } from "@/lib/services/dashboard";
import { listNoiseRules, markAsNoise, moveAlertsToActive } from "@/lib/services/tuning";

const run = randomUUID().slice(0, 8);
const now = new Date();
const DAY = 86_400_000;
let tenantA = "";
let tenantB = "";
const analystId = `tune-analyst-${run}`;

const all = new Set(BUILTIN_ROLES.find((r) => r.key === "platform_admin")!.permissions as Permission[]);
const analyst = (tenantIds = [tenantA, tenantB]): AccessContext => ({
  principal: { userId: analystId, name: "Analyst", email: "a@example.invalid", isBreakGlass: false },
  isPlatform: true,
  grants: [{ roleKey: "platform_admin", tenantId: null, permissions: all }],
  tenantIds,
  tenants: [
    { id: tenantA, slug: `tune-a-${run}`, name: "Tuning A", kind: "customer" as const },
    { id: tenantB, slug: `tune-b-${run}`, name: "Tuning B", kind: "customer" as const },
  ].filter((t) => tenantIds.includes(t.id)),
});

let n = 0;
function event(ruleId: string, over: Partial<NormalisedAlert> = {}): NormalisedAlert {
  n++;
  return {
    externalId: `tune-${run}-${n}`, ruleId, title: `Noisy event ${ruleId}`, description: null, category: "test", siemSeverity: 12, severity: "high",
    occurredAt: new Date(now.getTime() - 60_000), assetExternalId: null, hostname: "ws-77", userName: null, attackTechniques: [], routingKeys: [], raw: { agent: { name: "ws-77" } }, ...over,
  };
}

const ingest = (tenantId: string, ruleId: string, over: Partial<NormalisedAlert> = {}) => ingestAlert({ tenantId, integrationId: null, source: "wazuh", alert: event(ruleId, over), intel: null });
const alertRow = async (id: string) => (await adminDb().select().from(alerts).where(eq(alerts.id, id)))[0]!;

async function rule(tenantId: string, ruleId: string, over: Partial<typeof noiseRules.$inferInsert> = {}) {
  const [r] = await adminDb()
    .insert(noiseRules)
    .values({ tenantId, source: "wazuh", ruleId, reason: `known noise ${ruleId}`, status: "active", createdByKind: "user", createdBy: analystId, expiresAt: new Date(now.getTime() + 30 * DAY), ...over })
    .returning();
  return r!;
}

beforeAll(async () => {
  await adminDb().insert(user).values({ id: analystId, name: "Analyst", email: `tune-${run}@example.invalid`, emailVerified: true });
  const [a] = await adminDb().insert(tenants).values({ name: "Tuning A", slug: `tune-a-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  const [b] = await adminDb().insert(tenants).values({ name: "Tuning B", slug: `tune-b-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantA = a!.id;
  tenantB = b!.id;
});

afterAll(async () => {
  for (const id of [tenantA, tenantB].filter(Boolean)) await adminDb().delete(tenants).where(eq(tenants.id, id));
  await adminDb().delete(user).where(eq(user.id, analystId));
  await redis().quit();
});

describe("noise rules at ingest", () => {
  it("puts a matching alert in the passive lane, counts the hit, and keeps it out of automatic incidents", async () => {
    const r = await rule(tenantA, "noise-1");
    const res = await ingest(tenantA, "noise-1");
    expect(res.created).toBe(true);
    expect(res.lane).toBe("passive");
    const row = await alertRow(res.alertId);
    expect(row).toMatchObject({ lane: "passive", noiseRuleId: r.id, status: "NEW", passiveReason: "Known noise: known noise noise-1" });
    const [after] = await adminDb().select().from(noiseRules).where(eq(noiseRules.id, r.id));
    expect(after!.hitCount).toBe(1);
    expect(after!.lastHitAt).not.toBeNull();

    // A high-severity active alert opens an incident; the passive one beside it must not.
    const active = await ingest(tenantA, "real-1");
    expect(active.lane).toBe("active");
    const g = await runGrouping(tenantA, now);
    expect(g.opened).toBeGreaterThanOrEqual(1);
    expect((await alertRow(res.alertId)).incidentId).toBeNull();
    expect((await alertRow(active.alertId)).incidentId).not.toBeNull();
  });

  it("ignores proposed, rejected and expired rules", async () => {
    await rule(tenantA, "noise-2", { status: "proposed", createdByKind: "service" });
    await rule(tenantA, "noise-3", { status: "rejected" });
    await rule(tenantA, "noise-4", { status: "active", expiresAt: new Date(now.getTime() - 1000) });
    for (const id of ["noise-2", "noise-3", "noise-4"]) expect((await ingest(tenantA, id)).lane, id).toBe("active");
  });

  it("keeps a host-scoped rule to its host", async () => {
    await rule(tenantA, "noise-5", { hostname: "ws-01" });
    expect((await ingest(tenantA, "noise-5", { hostname: "WS-01.corp.example" })).lane).toBe("passive");
    expect((await ingest(tenantA, "noise-5", { hostname: "ws-02" })).lane).toBe("active");
  });

  it("is tenant-scoped: another tenant's rule never matches, and RLS hides it", async () => {
    await rule(tenantB, "noise-6");
    expect((await ingest(tenantA, "noise-6")).lane).toBe("active");
    expect((await ingest(tenantB, "noise-6")).lane).toBe("passive");
    const seenByA = await withScope(systemScope(tenantA), (tx) => tx.select().from(noiseRules).where(eq(noiseRules.ruleId, "noise-6")));
    expect(seenByA).toEqual([]);
    const listed = await listNoiseRules(analyst([tenantA]));
    expect(listed.every((r) => r.rule.tenantId === tenantA)).toBe(true);
    expect(listed.some((r) => r.rule.ruleId === "noise-1")).toBe(true);
  });
});

describe("analyst tuning", () => {
  it("“Mark as noise” creates an audited active rule and moves open matching alerts, never closing them", async () => {
    const first = await ingest(tenantA, "mark-1", { severity: "low" });
    const second = await ingest(tenantA, "mark-1", { severity: "low", hostname: "ws-88" });
    await adminDb().update(alerts).set({ status: "TRIAGING" }).where(eq(alerts.id, second.alertId));
    const investigating = await ingest(tenantA, "mark-1", { severity: "low" });
    await adminDb().update(alerts).set({ status: "INVESTIGATING" }).where(eq(alerts.id, investigating.alertId));

    const res = await markAsNoise(analyst(), first.alertId, { scope: "tenant", reason: "Scanner appliance, agreed with customer", expiresInDays: 14 });
    expect(res.moved).toBe(2);
    expect(await alertRow(first.alertId)).toMatchObject({ lane: "passive", status: "NEW" });
    expect(await alertRow(second.alertId)).toMatchObject({ lane: "passive", status: "TRIAGING" });
    expect((await alertRow(investigating.alertId)).lane).toBe("active");

    const [r] = await adminDb().select().from(noiseRules).where(eq(noiseRules.id, res.id));
    expect(r).toMatchObject({ status: "active", createdByKind: "user", approvedBy: analystId, hitCount: 2 });
    expect(r!.expiresAt.getTime() - Date.now()).toBeGreaterThan(13 * DAY);
    const [entry] = await adminDb().select().from(auditLog).where(and(eq(auditLog.action, "noise_rule.create"), eq(auditLog.targetId, res.id)));
    expect((entry!.detail as { alertIds: string[] }).alertIds.sort()).toEqual([first.alertId, second.alertId].sort());

    // A later alert of the rule is passive at ingest; a second identical rule is refused.
    expect((await ingest(tenantA, "mark-1", { severity: "low" })).lane).toBe("passive");
    await expect(markAsNoise(analyst(), investigating.alertId, { scope: "tenant", reason: "again please", expiresInDays: 14 })).rejects.toThrow(/already covers/);
    await expect(markAsNoise(analyst(), investigating.alertId, { scope: "host", reason: "too long a rule", expiresInDays: 181 })).rejects.toThrow(/180 days/);

    expect(await moveAlertsToActive(analyst(), [first.alertId])).toBe(1);
    expect(await alertRow(first.alertId)).toMatchObject({ lane: "active", passiveReason: null, status: "NEW" });
    const [moved] = await adminDb().select().from(auditLog).where(and(eq(auditLog.action, "alert.lane"), eq(auditLog.targetId, first.alertId)));
    expect(moved?.actorId).toBe(analystId);
  });

  it("needs alert:tune", async () => {
    const l1 = new Set(BUILTIN_ROLES.find((r) => r.key === "soc_analyst_l1")!.permissions as Permission[]);
    const ctx: AccessContext = { ...analyst(), grants: [{ roleKey: "soc_analyst_l1", tenantId: null, permissions: l1 }] };
    const a = await ingest(tenantA, "mark-2", { severity: "low" });
    await expect(markAsNoise(ctx, a.alertId, { scope: "tenant", reason: "not allowed here", expiresInDays: 7 })).rejects.toThrow(/alert:tune/);
  });
});

describe("disposition memory and fatigue", () => {
  it("scores a rule analysts keep closing as false positive lower, with the reason in plain language", async () => {
    for (let i = 0; i < 6; i++) {
      await adminDb().insert(alerts).values({ tenantId: tenantB, source: "wazuh", externalId: `disp-${run}-${i}`, ruleId: "disp-1", title: "old", severity: "medium", status: "FALSE_POSITIVE", occurredAt: new Date(now.getTime() - (i + 2) * DAY) });
    }
    const res = await ingest(tenantB, "disp-1", { severity: "medium" });
    const row = await alertRow(res.alertId);
    expect(row.riskFactors.find((f) => f.key === "disposition_fp")).toMatchObject({ points: -15, evidence: "Closed as false positive 6 of 6 times in 90 days across this customer" });
  });

  it("measures stored, passive, waiting and false-positive share for the dashboard", async () => {
    const f = await fatigueMetrics(analyst(), [tenantA, tenantB]);
    expect(f.stored).toBeGreaterThan(0);
    expect(f.passive).toBeGreaterThan(0);
    expect(f.passiveShare).toBeGreaterThan(0);
    expect(f.topRules.length).toBeGreaterThan(0);
    expect(f.topRules.length).toBeLessThanOrEqual(3);
    const passiveIds = (await adminDb().select({ id: alerts.id }).from(alerts).where(and(inArray(alerts.tenantId, [tenantA, tenantB]), eq(alerts.lane, "passive")))).length;
    expect(f.passive).toBe(passiveIds);
  });
});
