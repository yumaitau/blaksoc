/**
 * Alert provenance and history, and the audit trail's filters and export, against the demo seed: the SQL runs
 * under each persona's RLS scope, and a customer user sees only their own alerts' records.
 */
import { desc, eq, notInArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, auditLog, user } from "@/db/schema";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { redis } from "@/lib/redis";
import { alertHistory, alertProvenance } from "@/lib/services/alert-provenance";
import { auditTrail, exportAuditTrail } from "@/lib/services/admin";
import { updateAlerts } from "@/lib/services/alerts";

async function ctxFor(email: string): Promise<AccessContext> {
  const [u] = await adminDb().select().from(user).where(eq(user.email, email));
  if (!u) throw new Error(`seed user ${email} missing — run pnpm db:seed with DEMO_MODE=true`);
  return resolveAccess({ userId: u.id, name: u.name, email: u.email, isBreakGlass: u.isBreakGlass });
}

let l2: AccessContext;
let manager: AccessContext;
let alertId = "";

beforeAll(async () => {
  l2 = await ctxFor("l2@demo.blaksoc.local");
  manager = await ctxFor("manager@demo.blaksoc.local");
  const [a] = await adminDb().select({ id: alerts.id }).from(alerts).orderBy(desc(alerts.ingestedAt)).limit(1);
  alertId = a!.id;
  await updateAlerts(l2, [alertId], { status: "TRIAGING", assigneeId: l2.principal.userId });
});

afterAll(async () => {
  await redis().quit();
});

describe("alert provenance and history", () => {
  it("explains where the alert came from and when it was stored", async () => {
    const p = await alertProvenance(l2, alertId);
    expect(p).toBeTruthy();
    expect(p!.where.source).toBeTruthy();
    expect(p!.when.ingestedAt).toBeInstanceOf(Date);
  });

  it("starts with the ingest entry and includes the analyst's change, without needing audit:read", async () => {
    const h = await alertHistory(l2, alertId);
    expect(h!.entries.length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(h!.entries)).toMatch(/triaging/i);
  });

  it("hides another customer's alert from a customer user", async () => {
    const customer = await ctxFor("wattle.admin@demo.blaksoc.local");
    const [other] = await adminDb().select({ id: alerts.id }).from(alerts).where(notInArray(alerts.tenantId, customer.tenantIds)).limit(1);
    expect(other).toBeTruthy();
    const seen = await alertProvenance(customer, other!.id).catch(() => null);
    expect(seen ?? null).toBeNull();
    const history = await alertHistory(customer, other!.id).catch(() => null);
    expect(history ?? null).toBeNull();
  });
});

describe("audit trail", () => {
  it("filters by target and actor in SQL", async () => {
    const byTarget = await auditTrail(manager, { sinceDays: 30, targetType: "alert", targetId: alertId });
    expect(byTarget.rows.length).toBeGreaterThan(0);
    expect(byTarget.rows.every((r) => r.entry.targetId === alertId)).toBe(true);
    const byActor = await auditTrail(manager, { sinceDays: 30, actor: "Sam Nguyen" });
    expect(byActor.rows.every((r) => r.entry.actorId === l2.principal.userId)).toBe(true);
    const none = await auditTrail(manager, { sinceDays: 30, action: "100%_literal" });
    expect(none.rows).toHaveLength(0);
  });

  it("pages older entries by cursor", async () => {
    const first = await auditTrail(manager, { sinceDays: 365 }, 2);
    if (!first.nextBefore) return;
    const next = await auditTrail(manager, { sinceDays: 365, before: first.nextBefore }, 2);
    expect(next.rows.every((r) => r.entry.id < first.nextBefore!)).toBe(true);
  });

  it("refuses readers without audit:read and audits each export", async () => {
    await expect(auditTrail(l2, { sinceDays: 30 })).rejects.toThrow();
    const before = await adminDb().select({ id: auditLog.id }).from(auditLog).where(eq(auditLog.action, "audit.export"));
    const out = await exportAuditTrail(manager, { sinceDays: 30, targetType: "alert" }, "127.0.0.1");
    expect(out.rows.length).toBeGreaterThan(0);
    const after = await adminDb().select({ id: auditLog.id }).from(auditLog).where(eq(auditLog.action, "audit.export"));
    expect(after.length).toBeGreaterThan(before.length);
  });
});
