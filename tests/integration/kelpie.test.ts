/**
 * Kelpie owns case work for a connected tenant: incidents become cases once, observables and playbook tasks follow,
 * Kelpie's status comes back, and blakSOC refuses its own case edits. Kelpie is an in-memory fake here.
 */
import { randomUUID } from "node:crypto";
import { and, eq, gte } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, auditLog, incidentAlerts, incidentLinks, incidents, incidentTasks, incidentTimeline, integrations, kelpieCases, tenants, user } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { secretAad } from "@/lib/connectors/instances";
import { encryptSecret } from "@/lib/crypto";
import { KelpieError, type KelpieCase, type KelpieClient, type KelpieCreateCase } from "@/lib/kelpie/client";
import { addNote, addTask, updateIncident } from "@/lib/services/incidents";
import { KelpieManaged, syncKelpie } from "@/lib/services/kelpie";

class FakeKelpie {
  cases = new Map<string, KelpieCase & { ref: string }>();
  comments: { caseId: string; body: string }[] = [];
  observables: { caseId: string; type: string; value: string }[] = [];
  creates: KelpieCreateCase[] = [];
  down = false;
  caseUrl(id: string) { return `https://kelpie.example.au/cases/${id}`; }
  async createCase(input: KelpieCreateCase) {
    if (this.down) throw new KelpieError("Kelpie POST /api/v1/cases returned 503", 503);
    this.creates.push(input);
    const existing = [...this.cases.values()].find((c) => c.ref === input.sourceReference);
    if (existing) return { id: existing.id, caseNumber: existing.caseNumber, created: false };
    const id = `case_${this.cases.size + 1}`;
    const c = { id, ref: input.sourceReference, caseNumber: `KP-2026-${String(this.cases.size + 1).padStart(4, "0")}`, title: input.title, summary: input.summary, status: "open" as const, severity: input.severity ?? "medium", version: 1, closedAt: null, updatedAt: new Date().toISOString() };
    this.cases.set(id, c);
    return { id, caseNumber: c.caseNumber, created: true };
  }
  async getCase(id: string) { return this.cases.get(id)!; }
  async updateSummary(id: string, summary: string, version: number) {
    if (this.cases.get(id)!.version !== version) throw new KelpieError("Version conflict", 409);
    this.move(id, { summary });
  }
  async addComment(caseId: string, body: string) { this.comments.push({ caseId, body }); return { id: `cm_${this.comments.length}` }; }
  async addObservable(caseId: string, o: { type: string; value: string }) { this.observables.push({ caseId, ...o }); return { id: `ob_${this.observables.length}` }; }
  move(id: string, patch: Partial<KelpieCase>) { const c = this.cases.get(id)!; this.cases.set(id, { ...c, ...patch, version: c.version + 1 }); }
}

const fake = new FakeKelpie();
const connect = () => fake as unknown as KelpieClient;
const run = randomUUID().slice(0, 8);
let tenantId = "";
let incidentId = "";
const started = new Date();

const all = new Set(BUILTIN_ROLES.find((r) => r.key === "platform_admin")!.permissions as Permission[]);
const analyst = (): AccessContext => ({
  principal: { userId: `kelpie-analyst-${run}`, name: "Analyst", email: "a@example.invalid", isBreakGlass: false },
  isPlatform: true,
  grants: [{ roleKey: "platform_admin", tenantId: null, permissions: all }],
  tenantIds: [tenantId],
  tenants: [{ id: tenantId, slug: `kelpie-${run}`, name: "Kelpie Test", kind: "customer" }],
});

beforeAll(async () => {
  await adminDb().insert(user).values({ id: `kelpie-analyst-${run}`, name: "Analyst", email: `kelpie-${run}@example.invalid`, emailVerified: true });
  const [t] = await adminDb().insert(tenants).values({ slug: `kelpie-${run}`, name: "Kelpie Test Org", sectors: ["SMB"] }).returning();
  tenantId = t!.id;
  const [inc] = await adminDb().insert(incidents).values({ tenantId, title: "Inbox rule hides invoices", severity: "high", attackTechniques: ["T1564.008"] }).returning();
  incidentId = inc!.id;
  const [wazuh] = await adminDb().insert(integrations).values({ tenantId, category: "siem", provider: "wazuh", name: "Test Wazuh", enabled: false, config: { dashboardUrl: "https://wazuh.example.au" } }).returning();
  const [source] = await adminDb().insert(alerts).values({ tenantId, integrationId: wazuh!.id, source: "wazuh", externalId: "wazuh-doc-1", title: "File changed", ruleId: "550", severity: "medium", siemSeverity: 7, occurredAt: started, raw: { agent: { name: "WEB-03" }, syscheck: { path: "/etc/config", event: "modified" } } }).returning();
  await adminDb().insert(incidentAlerts).values({ tenantId, incidentId, alertId: source!.id });
  await adminDb().insert(incidentLinks).values([
    { tenantId, incidentId, kind: "observable", refId: "ipv4:203.0.113.9", label: "203.0.113.9" },
    { tenantId, incidentId, kind: "asset", refId: randomUUID(), label: "WEB-03" },
  ]);
  // A playbook step wrote this before Kelpie was connected.
  await adminDb().insert(incidentTasks).values({ tenantId, incidentId, title: "Reset the mailbox password" });
  const id = randomUUID();
  await adminDb().insert(integrations).values({
    id, tenantId, category: "ticketing", provider: "kelpie", name: "Kelpie",
    config: { baseUrl: "https://kelpie.example.au", region: "ap-southeast-2" },
    secretCiphertext: encryptSecret(JSON.stringify({ token: "klp_test" }), secretAad(id)),
    status: "healthy",
  });
});

afterAll(async () => {
  if (tenantId) await adminDb().delete(tenants).where(eq(tenants.id, tenantId));
  await adminDb().delete(user).where(eq(user.id, `kelpie-analyst-${run}`));
});

const link = async () => (await adminDb().select().from(kelpieCases).where(eq(kelpieCases.incidentId, incidentId)))[0];
const incident = async () => (await adminDb().select().from(incidents).where(eq(incidents.id, incidentId)))[0]!;

describe("Kelpie case management", () => {
  it("retries a failed push later without blocking", async () => {
    fake.down = true;
    const now = new Date();
    const counts = await syncKelpie({ connect, now });
    expect(counts).toMatchObject({ queued: 1, pushed: 0, failed: 1 });
    const failed = await link();
    expect(failed?.caseId).toBeNull();
    expect(failed?.lastError).toContain("503");
    expect(failed!.nextAttemptAt.getTime()).toBeGreaterThan(now.getTime());
    // Not due yet: nothing is sent.
    fake.down = false;
    expect((await syncKelpie({ connect, now })).pushed).toBe(0);
    expect(fake.creates).toHaveLength(0);
  });

  it("pushes the incident once with its observables and playbook tasks", async () => {
    const later = new Date(Date.now() + 3 * 3600_000);
    const counts = await syncKelpie({ connect, now: later });
    expect(counts.pushed).toBe(1);
    const linked = await link();
    expect(linked).toMatchObject({ caseId: "case_1", caseNumber: "KP-2026-0001", caseUrl: "https://kelpie.example.au/cases/case_1", lastError: null });
    expect(fake.creates[0]).toMatchObject({ sourceSystem: "blaksoc", sourceReference: incidentId, severity: "high" });
    expect(fake.creates[0]!.summary).toContain("Wazuh rule 550 matched on WEB-03");
    expect(fake.creates[0]!.summary).toContain("Wazuh rule level: 7/15");
    expect(fake.creates[0]!.summary).toContain("Wazuh alert: https://wazuh.example.au/app/discover");
    expect(fake.observables).toEqual([{ caseId: "case_1", type: "ip", value: "203.0.113.9", description: "From blakSOC detection", isIoc: true }]);
    expect(fake.comments).toEqual([{ caseId: "case_1", body: "Task from a blakSOC playbook: Reset the mailbox password" }]);
    const [task] = await adminDb().select().from(incidentTasks).where(eq(incidentTasks.incidentId, incidentId));
    expect(task?.kelpieCommentId).toBe("cm_1");

    // A second pass sends nothing new.
    await syncKelpie({ connect, now: later });
    expect(fake.creates).toHaveLength(1);
    expect(fake.observables).toHaveLength(1);
    expect(fake.comments).toHaveLength(1);

    const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, incidentId));
    expect(timeline.map((t) => t.title)).toContain("Kelpie case KP-2026-0001 opened");
  });

  it("refuses blakSOC case edits once Kelpie owns the tenant, but keeps customer notes", async () => {
    await expect(updateIncident(analyst(), incidentId, { status: "CONTAINED" })).rejects.toBeInstanceOf(KelpieManaged);
    await expect(updateIncident(analyst(), incidentId, { rootCause: "x" })).rejects.toThrow(/managed in Kelpie \(KP-2026-0001\)/);
    await expect(addTask(analyst(), incidentId, "Local task")).rejects.toBeInstanceOf(KelpieManaged);
    await expect(addNote(analyst(), incidentId, "SOC only", "internal")).rejects.toBeInstanceOf(KelpieManaged);
    const note = await addNote(analyst(), incidentId, "We are working on it.", "customer");
    expect(note.visibility).toBe("customer");
  });

  it("backfills an existing open case without replacing analyst text or repeating updates", async () => {
    fake.move("case_1", { summary: "Analyst investigation notes" });
    const later = new Date(Date.now() + 3 * 3600_000);
    await syncKelpie({ connect, now: later });
    const remote = await fake.getCase("case_1");
    expect(remote.summary).toContain("Analyst investigation notes");
    expect(remote.summary).toContain("[blakSOC detection context]");
    const version = remote.version;
    await syncKelpie({ connect, now: later });
    expect((await fake.getCase("case_1")).version).toBe(version);
  });

  it("mirrors Kelpie status, severity and closure back", async () => {
    const later = new Date(Date.now() + 3 * 3600_000);
    fake.move("case_1", { status: "contained", severity: "critical" });
    expect((await syncKelpie({ connect, now: later })).synced).toBe(1);
    let inc = await incident();
    expect(inc.status).toBe("CONTAINED");
    expect(inc.severity).toBe("critical");
    expect(inc.containedAt).not.toBeNull();

    // Unchanged version: no write.
    expect((await syncKelpie({ connect, now: later })).synced).toBe(0);

    fake.move("case_1", { status: "closed", closedAt: "2026-10-06T05:00:00.000Z" });
    await syncKelpie({ connect, now: later });
    inc = await incident();
    expect(inc.status).toBe("CLOSED");
    expect(inc.closedAt?.toISOString()).toBe("2026-10-06T05:00:00.000Z");

    const actions = (await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantId), gte(auditLog.at, started)))).map((a) => a.action);
    expect(actions).toEqual(expect.arrayContaining(["kelpie.case_push", "kelpie.case_sync"]));
  });
});
