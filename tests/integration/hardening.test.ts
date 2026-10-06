/**
 * Database-level checks for the fixes in docs/ENTERPRISE-GAP-ANALYSIS.md (D1, D4, D6, D7, D8, D17).
 * Runs against a migrated, seeded database. Fresh tenants only.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb, systemDb } from "@/db/client";
import { approvals, auditLog, integrations, partnerConsents, playbookRuns, playbookRunSteps, playbooks, responseActions, roleAssignments, roles, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { withScope } from "@/db/scope";
import { audit, verifyAuditChain } from "@/lib/audit";
import { resolveAccess, systemScope, type AccessContext } from "@/lib/auth/access";
import { queue, QUEUES } from "@/lib/queue";
import { deliveryJobId, fanOutEvent, subscribedEventTypes, subscriptionsChanged } from "@/lib/connectors/subscriptions";
import { assignRole, revokeRole, updateTenantSettings } from "@/lib/services/admin";
import { advanceRun, evaluateTriggers, resumeRun } from "@/lib/soar/engine";
import { decideApproval, executeResponseAction, expireDueApprovals, recoverStalledRuns, requestResponseAction } from "@/lib/soar/response";

const stamp = `hd${randomUUID().slice(0, 8)}`;
const tenantIds: string[] = [];
const userIds: string[] = [];

async function addTenant(name: string, kind: "customer" | "partner", parentId: string | null = null) {
  const [row] = await adminDb().insert(tenants).values({ name, slug: `${stamp}-${name.toLowerCase().replace(/\W+/g, "-")}`, kind, parentId, sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantIds.unshift(row!.id);
  return row!;
}

async function addUser(roleKey: string, tenantId: string): Promise<AccessContext> {
  const id = `${stamp}-${randomUUID().slice(0, 6)}`;
  await adminDb().insert(user).values({ id, name: id, email: `${id}@example.invalid`, emailVerified: true });
  userIds.push(id);
  await adminDb().insert(roleAssignments).values({ userId: id, roleKey, tenantId });
  return resolveAccess({ userId: id, name: id, email: `${id}@example.invalid`, isBreakGlass: false });
}

let customer: typeof tenants.$inferSelect;
let other: typeof tenants.$inferSelect;
let partner: typeof tenants.$inferSelect;
let child: typeof tenants.$inferSelect;

beforeAll(async () => {
  customer = await addTenant("Hardening Customer", "customer");
  other = await addTenant("Hardening Other", "customer");
  partner = await addTenant("Hardening Partner", "partner");
  child = await addTenant("Hardening Child", "customer", partner.id);
  await adminDb().insert(partnerConsents).values({ partnerTenantId: partner.id, customerTenantId: child.id, statement: "test consent", consentedBy: "test" });
});

afterAll(async () => {
  if (tenantIds.length) await adminDb().delete(tenants).where(inArray(tenants.id, tenantIds));
  if (userIds.length) await adminDb().delete(user).where(inArray(user.id, userIds));
});

describe("D1 role grant ceiling", () => {
  it("refuses a customer admin raising a colleague to partner admin", async () => {
    const admin = await addUser("customer_admin", customer.id);
    const colleague = await addUser("customer_readonly", customer.id);
    await expect(assignRole(admin, { userId: colleague.principal.userId, roleKey: "partner_admin", tenantId: customer.id })).rejects.toThrow(/partner tenant/);
    await assignRole(admin, { userId: colleague.principal.userId, roleKey: "customer_security", tenantId: customer.id });
    const rows = await adminDb().select({ roleKey: roleAssignments.roleKey }).from(roleAssignments).where(eq(roleAssignments.userId, colleague.principal.userId));
    expect(rows.map((r) => r.roleKey).sort()).toEqual(["customer_readonly", "customer_security"]);
  });
});

describe("D1 revocation", () => {
  it("lets a partner admin remove a partner analyst it could add", async () => {
    const admin = await addUser("partner_admin", partner.id);
    const analyst = await addUser("customer_readonly", child.id);
    await assignRole(admin, { userId: analyst.principal.userId, roleKey: "partner_analyst", tenantId: partner.id });
    const [row] = await adminDb().select({ id: roleAssignments.id }).from(roleAssignments).where(and(eq(roleAssignments.userId, analyst.principal.userId), eq(roleAssignments.roleKey, "partner_analyst")));
    await revokeRole(admin, row!.id);
    const left = await adminDb().select({ id: roleAssignments.id }).from(roleAssignments).where(eq(roleAssignments.id, row!.id));
    expect(left).toHaveLength(0);
  });
});

describe("D4 system database role", () => {
  it("is neither superuser nor BYPASSRLS", async () => {
    const [role] = await adminDb().execute<{ rolsuper: boolean; rolbypassrls: boolean }>(sql`select rolsuper, rolbypassrls from pg_roles where rolname = 'blaksoc_system'`);
    expect(role).toEqual({ rolsuper: false, rolbypassrls: false });
  });

  it("reads every tenant's rows through the system_access policy", async () => {
    const rows = await systemDb().select({ id: tenants.id }).from(tenants).where(inArray(tenants.id, [customer.id, other.id]));
    expect(rows).toHaveLength(2);
  });

  it("cannot change schema, policies, triggers or audit rows", async () => {
    await expect(systemDb().execute(sql`alter table alerts disable row level security`)).rejects.toThrow();
    await expect(systemDb().execute(sql`alter table audit_log disable trigger audit_log_immutable`)).rejects.toThrow();
    await expect(systemDb().execute(sql`update audit_log set ip = '6.6.6.6' where id = (select max(id) from audit_log)`)).rejects.toThrow();
    await expect(systemDb().execute(sql`delete from audit_log where id = (select max(id) from audit_log)`)).rejects.toThrow();
    await expect(systemDb().execute(sql`select * from dashboard_readers`)).rejects.toThrow();
  });
});

describe("D6 tenant settings scope", () => {
  it("lets a partner admin update a consented customer and nothing else", async () => {
    const admin = await addUser("partner_admin", partner.id);
    await updateTenantSettings(admin, child.id, { slaMinutes: { critical: 45 } as never });
    const [row] = await adminDb().select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, child.id));
    expect(row!.settings.slaMinutes.critical).toBe(45);
    // The partner's own RLS scope cannot touch an unrelated tenant even if a filter is missed.
    const touched = await withScope({ tenantIds: [other.id], grantIds: [partner.id], platform: false }, (tx) =>
      tx.update(tenants).set({ brandName: "hijacked" }).where(eq(tenants.id, other.id)).returning({ id: tenants.id }),
    );
    expect(touched).toHaveLength(0);
  });
});

describe("D7 and D8 playbook runs", () => {
  async function gatedPlaybook(tenantId: string) {
    const steps = [
      { id: "gate", action: "approval.request", name: "First gate" },
      { id: "second", action: "approval.request", name: "Second gate" },
    ];
    const [pb] = await adminDb().insert(playbooks).values({ tenantId, name: `${stamp} gated`, trigger: { event: "manual", conditions: [] }, steps, enabled: true }).returning();
    return pb!;
  }

  it("keeps the steps a run started with after the playbook is edited (D8)", async () => {
    const pb = await gatedPlaybook(customer.id);
    const started = await evaluateTriggers(customer.id, "manual", {});
    const runId = (await adminDb().select({ id: playbookRuns.id }).from(playbookRuns).where(and(inArray(playbookRuns.id, started), eq(playbookRuns.playbookId, pb.id))))[0]!.id;
    expect(await advanceRun(customer.id, runId)).toBe("WAITING_APPROVAL");
    await adminDb().update(playbooks).set({ steps: [], version: 2 }).where(eq(playbooks.id, pb.id));
    const [gate] = await adminDb().select().from(approvals).where(and(eq(approvals.tenantId, customer.id), eq(approvals.refId, runId)));
    await resumeRun(customer.id, runId, gate!.id, "APPROVED");
    // The edit emptied the playbook; the run still reaches its second gate.
    expect(await advanceRun(customer.id, runId)).toBe("WAITING_APPROVAL");
    const [run] = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.id, runId));
    expect(run!.steps?.map((s) => s.id)).toEqual(["gate", "second"]);
    expect(run!.stepIndex).toBe(1);
  });

  it("expires lapsed approvals and stops what waited on them (D7)", async () => {
    const pb = await gatedPlaybook(other.id);
    const started = await evaluateTriggers(other.id, "manual", {});
    const runId = (await adminDb().select({ id: playbookRuns.id }).from(playbookRuns).where(and(inArray(playbookRuns.id, started), eq(playbookRuns.playbookId, pb.id))))[0]!.id;
    await advanceRun(other.id, runId);
    const { action } = await withScope(systemScope(other.id), (tx) =>
      requestResponseAction(tx, { tenantId: other.id, action: "isolate_endpoint", target: { assetId: randomUUID() }, reason: "expiry test", requestedBy: null, requestedByKind: "user" }),
    );
    await adminDb().update(approvals).set({ expiresAt: new Date(Date.now() - 60_000) }).where(eq(approvals.tenantId, other.id));

    const res = await expireDueApprovals(new Date());
    expect(res.expired).toBeGreaterThanOrEqual(2);
    const gates = await adminDb().select({ status: approvals.status }).from(approvals).where(eq(approvals.tenantId, other.id));
    expect(gates.every((g) => g.status === "EXPIRED")).toBe(true);
    const [act] = await adminDb().select({ status: responseActions.status }).from(responseActions).where(eq(responseActions.id, action.id));
    expect(act!.status).toBe("REJECTED");

    // The worker receives a resume job carrying the rejection; run it as the worker would.
    const jobs = await queue(QUEUES.playbook).getJobs(["waiting", "delayed"]);
    const job = jobs.find((j) => j.name === "resume" && j.data.runId === runId);
    expect(job?.data).toMatchObject({ decision: "REJECTED", reason: "approval expired" });
    await resumeRun(other.id, runId, job!.data.approvalId, job!.data.decision, job!.data.reason);
    await job!.remove();
    const [run] = await adminDb().select({ status: playbookRuns.status, error: playbookRuns.error }).from(playbookRuns).where(eq(playbookRuns.id, runId));
    expect(run).toEqual({ status: "CANCELLED", error: "approval expired" });
    const audited = await adminDb().select({ id: auditLog.id }).from(auditLog).where(and(eq(auditLog.tenantId, other.id), eq(auditLog.action, "approval.expired")));
    expect(audited.length).toBeGreaterThanOrEqual(2);
  });
});

describe("approval follow-ups (review of PR #111)", () => {
  it("refuses a human decision on an approval the worker already expired", async () => {
    const approver = await addUser("customer_admin", customer.id);
    const { action, approvalId } = await withScope(systemScope(customer.id), (tx) =>
      requestResponseAction(tx, { tenantId: customer.id, action: "isolate_endpoint", target: { assetId: randomUUID() }, reason: "race test", requestedBy: null, requestedByKind: "user" }),
    );
    await adminDb().update(approvals).set({ expiresAt: new Date(Date.now() - 60_000) }).where(eq(approvals.id, approvalId!));
    await expireDueApprovals(new Date());
    await expect(decideApproval(approver, approvalId!, "APPROVED", "too late")).rejects.toThrow(/already EXPIRED/);
    const [act] = await adminDb().select({ status: responseActions.status }).from(responseActions).where(eq(responseActions.id, action.id));
    expect(act!.status).toBe("REJECTED");
  });

  it("re-queues the resume for a run left waiting on a settled gate", async () => {
    const steps = [{ id: "gate", action: "approval.request", name: "Gate" }];
    const [pb] = await adminDb().insert(playbooks).values({ tenantId: customer.id, name: `${stamp} stalled`, trigger: { event: "manual", conditions: [] }, steps, enabled: true }).returning();
    const started = await evaluateTriggers(customer.id, "manual", {});
    const runId = (await adminDb().select({ id: playbookRuns.id }).from(playbookRuns).where(and(inArray(playbookRuns.id, started), eq(playbookRuns.playbookId, pb!.id))))[0]!.id;
    await advanceRun(customer.id, runId);
    const [step] = await adminDb().select({ approvalId: playbookRunSteps.approvalId }).from(playbookRunSteps).where(eq(playbookRunSteps.runId, runId));
    // A decision committed but its resume job never reached Redis.
    await adminDb().update(approvals).set({ status: "APPROVED", decidedAt: new Date() }).where(eq(approvals.id, step!.approvalId!));
    expect(await recoverStalledRuns()).toBeGreaterThanOrEqual(1);
    expect(await recoverStalledRuns()).toBeGreaterThanOrEqual(1);
    const jobs = (await queue(QUEUES.playbook).getJobs(["waiting", "delayed"])).filter((j) => j.name === "resume" && j.data.runId === runId);
    expect(jobs).toHaveLength(1);
    expect(jobs[0]!.data).toMatchObject({ decision: "APPROVED", approvalId: step!.approvalId });
    await resumeRun(customer.id, runId, step!.approvalId!, "APPROVED");
    await jobs[0]!.remove();
    const [run] = await adminDb().select({ status: playbookRuns.status }).from(playbookRuns).where(eq(playbookRuns.id, runId));
    expect(run!.status).toBe("RUNNING");
  });
});

describe("event delivery (review of PR #111)", () => {
  it("queues one delivery per event and integration across fan-out retries", async () => {
    const [hook] = await adminDb().insert(integrations).values({ tenantId: customer.id, category: "ticketing", provider: "webhook", name: `${stamp} hook`, config: { url: "https://hooks.example.com/x", events: ["incident.created"] }, permissions: [], enabled: true }).returning();
    const event = { type: "incident.created" as const, tenantId: customer.id, id: randomUUID(), title: "Fan-out", severity: "high" };
    const eventId = randomUUID();
    expect(await fanOutEvent(event, eventId)).toEqual({ queued: 1 });
    await fanOutEvent(event, eventId);
    const job = await queue(QUEUES.notify).getJob(deliveryJobId(eventId, hook!.id));
    const all = (await queue(QUEUES.notify).getJobs(["waiting", "delayed"])).filter((j) => j.name === "deliver" && j.data.integrationId === hook!.id);
    expect(job).toBeDefined();
    expect(all).toHaveLength(1);
    for (const j of all) await j.remove();
  });

  it("refreshes cached subscriptions soon after an integration changes", async () => {
    // A marker only this test subscribes to, and explicit clock values, so other tests cannot change the outcome.
    const marker = `test.${stamp}`;
    const t0 = Date.now();
    await subscribedEventTypes(t0);
    await adminDb().insert(integrations).values({ tenantId: customer.id, category: "collaboration", provider: "slack", name: `${stamp} slack`, config: { events: [marker] }, permissions: [], enabled: true });
    expect((await subscribedEventTypes(t0 + 1_000)).has(marker)).toBe(false);
    await subscriptionsChanged();
    expect((await subscribedEventTypes(t0 + 6_000)).has(marker)).toBe(true);
  });
});

describe("review of PR #112", () => {
  it("ignores a late resume for an earlier gate once the run waits on a later one", async () => {
    const steps = [
      { id: "a", action: "approval.request", name: "Gate A" },
      { id: "b", action: "approval.request", name: "Gate B" },
    ];
    const [pb] = await adminDb().insert(playbooks).values({ tenantId: other.id, name: `${stamp} two gates`, trigger: { event: "manual", conditions: [] }, steps, enabled: true }).returning();
    const started = await evaluateTriggers(other.id, "manual", {});
    const runId = (await adminDb().select({ id: playbookRuns.id }).from(playbookRuns).where(and(inArray(playbookRuns.id, started), eq(playbookRuns.playbookId, pb!.id))))[0]!.id;
    await advanceRun(other.id, runId);
    const [gateA] = await adminDb().select({ approvalId: playbookRunSteps.approvalId }).from(playbookRunSteps).where(eq(playbookRunSteps.runId, runId));
    await resumeRun(other.id, runId, gateA!.approvalId!, "APPROVED");
    expect(await advanceRun(other.id, runId)).toBe("WAITING_APPROVAL");
    // The same resume delivered again must not carry the run past gate B.
    await resumeRun(other.id, runId, gateA!.approvalId!, "APPROVED");
    const [run] = await adminDb().select({ status: playbookRuns.status, stepIndex: playbookRuns.stepIndex }).from(playbookRuns).where(eq(playbookRuns.id, runId));
    expect(run).toEqual({ status: "WAITING_APPROVAL", stepIndex: 1 });
  });

  it("queues execution for an approved action whose job was lost, and runs it only once", async () => {
    const { action } = await withScope(systemScope(other.id), (tx) =>
      requestResponseAction(tx, { tenantId: other.id, action: "scan_endpoint", target: { assetId: randomUUID() }, reason: "lost job", requestedBy: null, requestedByKind: "user" }),
    );
    expect(action.status).toBe("APPROVED");
    await recoverStalledRuns();
    await recoverStalledRuns();
    const jobs = (await queue(QUEUES.response).getJobs(["waiting", "delayed"])).filter((j) => j.name === "execute" && j.data.actionId === action.id);
    expect(jobs).toHaveLength(1);
    for (const j of jobs) await j.remove();
    // Two executions racing: only the one that claims APPROVED → EXECUTING proceeds.
    const [first, second] = await Promise.all([executeResponseAction(other.id, action.id), executeResponseAction(other.id, action.id)]);
    expect([first, second].filter((r) => (r as { skipped?: boolean }).skipped)).toHaveLength(1);
  });
});

describe("review of PR #113", () => {
  const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000);

  it("fails an approved action that was never executed within the recovery window", async () => {
    const { action } = await withScope(systemScope(other.id), (tx) =>
      requestResponseAction(tx, { tenantId: other.id, action: "scan_endpoint", target: { assetId: randomUUID() }, reason: "stale", requestedBy: null, requestedByKind: "user" }),
    );
    await adminDb().update(responseActions).set({ createdAt: hoursAgo(25) }).where(eq(responseActions.id, action.id));
    await recoverStalledRuns();
    const [act] = await adminDb().select({ status: responseActions.status }).from(responseActions).where(eq(responseActions.id, action.id));
    expect(act!.status).toBe("FAILED");
    const jobs = (await queue(QUEUES.response).getJobs(["waiting", "delayed"])).filter((j) => j.data.actionId === action.id);
    expect(jobs).toHaveLength(0);
    const audited = await adminDb().select({ id: auditLog.id }).from(auditLog).where(and(eq(auditLog.targetId, action.id), eq(auditLog.action, "response.stale_fail")));
    expect(audited).toHaveLength(1);
  });

  it("cancels a run whose gate was settled long ago instead of resuming it", async () => {
    const steps = [{ id: "gate", action: "approval.request", name: "Old gate" }];
    const [pb] = await adminDb().insert(playbooks).values({ tenantId: other.id, name: `${stamp} old gate`, trigger: { event: "manual", conditions: [] }, steps, enabled: true }).returning();
    const started = await evaluateTriggers(other.id, "manual", {});
    const runId = (await adminDb().select({ id: playbookRuns.id }).from(playbookRuns).where(and(inArray(playbookRuns.id, started), eq(playbookRuns.playbookId, pb!.id))))[0]!.id;
    await advanceRun(other.id, runId);
    const [step] = await adminDb().select({ approvalId: playbookRunSteps.approvalId }).from(playbookRunSteps).where(eq(playbookRunSteps.runId, runId));
    await adminDb().update(approvals).set({ status: "APPROVED", decidedAt: hoursAgo(30) }).where(eq(approvals.id, step!.approvalId!));
    await recoverStalledRuns();
    const [run] = await adminDb().select({ status: playbookRuns.status }).from(playbookRuns).where(eq(playbookRuns.id, runId));
    expect(run!.status).toBe("CANCELLED");
    const jobs = (await queue(QUEUES.playbook).getJobs(["waiting", "delayed"])).filter((j) => j.name === "resume" && j.data.runId === runId);
    expect(jobs).toHaveLength(0);
  });

  it("fails an execution interrupted after it was claimed", async () => {
    const { action } = await withScope(systemScope(other.id), (tx) =>
      requestResponseAction(tx, { tenantId: other.id, action: "scan_endpoint", target: { assetId: randomUUID() }, reason: "interrupted", requestedBy: null, requestedByKind: "user" }),
    );
    await adminDb().update(responseActions).set({ status: "EXECUTING", claimedAt: hoursAgo(1) }).where(eq(responseActions.id, action.id));
    await recoverStalledRuns();
    const [act] = await adminDb().select({ status: responseActions.status, result: responseActions.result }).from(responseActions).where(eq(responseActions.id, action.id));
    expect(act!.status).toBe("FAILED");
    expect(JSON.stringify(act!.result)).toMatch(/interrupted/);
  });

  it("refuses, without auditing, a settings change RLS does not let the caller make", async () => {
    await adminDb().insert(roles).values({ key: `custom_${stamp}`, name: "Settings only", scope: "tenant", permissions: ["settings:manage", "portal:read"], builtin: false }).onConflictDoNothing();
    const caller = await addUser(`custom_${stamp}`, customer.id);
    await expect(updateTenantSettings(caller, customer.id, { slaMinutes: { critical: 5 } as never })).rejects.toThrow(/cannot be changed from this role/);
    const audited = await adminDb().select({ id: auditLog.id }).from(auditLog).where(and(eq(auditLog.actorId, caller.principal.userId), eq(auditLog.action, "tenant.settings")));
    expect(audited).toHaveLength(0);
    await adminDb().delete(roleAssignments).where(eq(roleAssignments.roleKey, `custom_${stamp}`));
    await adminDb().delete(roles).where(eq(roles.key, `custom_${stamp}`));
  });
});

describe("D17 audit hash covers ip", () => {
  it("detects an ip changed behind the triggers", async () => {
    await withScope(systemScope(customer.id), (tx) => audit(tx, { actorId: null, actorKind: "system", tenantId: customer.id, action: "hardening.ip", ip: "203.0.113.7" }));
    const [row] = await adminDb().select({ id: auditLog.id, hashVersion: auditLog.hashVersion }).from(auditLog).where(and(eq(auditLog.tenantId, customer.id), eq(auditLog.action, "hardening.ip")));
    expect(row!.hashVersion).toBe(2);
    expect((await withScope({ tenantIds: [], platform: true }, (tx) => verifyAuditChain(tx))).ok).toBe(true);

    // Tamper as the owner, check, then roll everything back.
    const tampered = await adminDb()
      .transaction(async (tx) => {
        await tx.execute(sql`alter table audit_log disable trigger audit_log_immutable`);
        await tx.execute(sql`update audit_log set ip = '198.51.100.9' where id = ${row!.id}`);
        const result = await verifyAuditChain(tx);
        throw Object.assign(new Error("rollback"), { result });
      })
      .catch((err: Error & { result?: Awaited<ReturnType<typeof verifyAuditChain>> }) => err.result);
    expect(tampered).toMatchObject({ ok: false, firstBadId: row!.id });
    expect((await withScope({ tenantIds: [], platform: true }, (tx) => verifyAuditChain(tx))).ok).toBe(true);
  });
});
