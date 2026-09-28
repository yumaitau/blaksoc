/**
 * Runs against a migrated + DEMO_MODE-seeded database (pnpm db:migrate && pnpm db:seed).
 * Exercises tenant isolation and the approval gates through the real service layer.
 */
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, approvals, playbookRuns, responseActions, tenants, user } from "@/db/schema";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { redis } from "@/lib/redis";
import { getAlert, listAlerts, updateAlerts } from "@/lib/services/alerts";
import { AccessDenied } from "@/lib/services/common";
import { decideApproval, requestFromUser } from "@/lib/soar/response";
import { advanceRun, evaluateTriggers } from "@/lib/soar/engine";

async function ctxFor(email: string): Promise<AccessContext> {
  const [u] = await adminDb().select().from(user).where(eq(user.email, email));
  if (!u) throw new Error(`seed user ${email} missing — run pnpm db:seed with DEMO_MODE=true`);
  return resolveAccess({ userId: u.id, name: u.name, email: u.email, isBreakGlass: u.isBreakGlass });
}

let wattle: string, murray: string;
let customer: AccessContext, l1: AccessContext, manager: AccessContext;

beforeAll(async () => {
  const ts = await adminDb().select().from(tenants);
  wattle = ts.find((t) => t.slug === "wattle-health")!.id;
  murray = ts.find((t) => t.slug === "murray-water")!.id;
  customer = await ctxFor("wattle.admin@demo.blaksoc.local");
  l1 = await ctxFor("l1@demo.blaksoc.local");
  manager = await ctxFor("manager@demo.blaksoc.local");
});

afterAll(async () => {
  await redis().quit();
});

describe("tenant isolation", () => {
  it("customer sees only their tenant", async () => {
    expect(customer.tenantIds).toEqual([wattle]);
    const { rows } = await listAlerts(customer, {});
    expect(rows.length).toBeGreaterThan(0);
    expect(new Set(rows.map((r) => r.tenantId))).toEqual(new Set([wattle]));
  });

  it("requesting another tenant's data by id returns nothing", async () => {
    const [other] = await adminDb().select({ id: alerts.id }).from(alerts).where(eq(alerts.tenantId, murray)).limit(1);
    expect(await getAlert(customer, other!.id)).toBeNull();
  });

  it("requesting another tenant via filters fails closed", async () => {
    await expect(listAlerts(customer, { tenantIds: [murray] })).rejects.toBeInstanceOf(AccessDenied);
  });

  it("customers get normalised alerts without raw SIEM payloads", async () => {
    const { rows } = await listAlerts(customer, { limit: 1 });
    const detail = await getAlert(customer, rows[0]!.id);
    expect(detail?.alert.raw).toBeNull();
  });

  it("customers cannot triage", async () => {
    const { rows } = await listAlerts(customer, { limit: 1 });
    await expect(updateAlerts(customer, [rows[0]!.id], { status: "RESOLVED" })).rejects.toBeInstanceOf(AccessDenied);
  });

  it("platform analysts reach every customer", async () => {
    expect(l1.isPlatform).toBe(true);
    expect(l1.tenantIds).toEqual(expect.arrayContaining([wattle, murray]));
  });
});

describe("approval gates", () => {
  it("destructive analyst request waits for an approver; L1 cannot approve", async () => {
    const [a] = await adminDb().select().from(alerts).where(eq(alerts.tenantId, murray)).limit(1);
    const res = await requestFromUser(l1, { tenantId: murray, action: "isolate_endpoint", target: { assetId: a!.assetId! }, reason: "test", alertId: a!.id });
    expect(res.needsApproval).toBe(true);
    await expect(decideApproval(l1, res.approvalId!, "APPROVED", "")).rejects.toBeInstanceOf(AccessDenied);
    await decideApproval(manager, res.approvalId!, "REJECTED", "test cleanup");
    const [act] = await adminDb().select().from(responseActions).where(eq(responseActions.id, res.action.id));
    expect(act!.status).toBe("REJECTED");
  });

  it("AI-originated destructive actions need approval even with auto-containment on", async () => {
    const [t] = await adminDb().select().from(tenants).where(eq(tenants.id, murray));
    await adminDb().update(tenants).set({ settings: { ...t!.settings, autoContainment: true } }).where(eq(tenants.id, murray));
    try {
      const [a] = await adminDb().select().from(alerts).where(eq(alerts.tenantId, murray)).limit(1);
      const res = await requestFromUser(l1, { tenantId: murray, action: "isolate_endpoint", target: { assetId: a!.assetId! }, reason: "ai test" }, "ai");
      expect(res.needsApproval).toBe(true);
      await decideApproval(manager, res.approvalId!, "REJECTED", "cleanup");
    } finally {
      await adminDb().update(tenants).set({ settings: t!.settings }).where(eq(tenants.id, murray));
    }
  });

  it("the containment playbook stops at a human gate", async () => {
    const [mal] = await adminDb().select().from(alerts).where(eq(alerts.intelVerdict, "malicious")).orderBy(alerts.riskScore).limit(1);
    await adminDb().update(alerts).set({ riskScore: 90 }).where(eq(alerts.id, mal!.id));
    const [runId] = await evaluateTriggers(mal!.tenantId, "alert.created", { alertId: mal!.id });
    expect(runId).toBeDefined();
    const status = await advanceRun(mal!.tenantId, runId!);
    expect(status).toBe("WAITING_APPROVAL");
    const [run] = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.id, runId!));
    expect(run!.incidentId).toBeTruthy();
    const pending = await adminDb().select().from(approvals).where(eq(approvals.status, "PENDING"));
    expect(pending.some((p) => p.destructive)).toBe(true);
  });
});
