/**
 * Data governance is enforced in the service layer and the worker:
 * non-AU AI and non-consented sightings are refused, changes need two stewards, and every steward hears about them.
 */
process.env.AI_DATA_RESIDENCY = "ANY"; // isolate the tenant profile from the platform-wide flag

import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import {
  aiInvocations, auditLog, dataGovernance, DEFAULT_TENANT_SETTINGS, integrations, intelMatches, notificationDeliveries, roleAssignments, roles, tenants, user,
} from "@/db/schema";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { runAssistant } from "@/lib/ai/assistant";
import { intelProviderFor, secretAad } from "@/lib/connectors/instances";
import { encryptSecret } from "@/lib/crypto";
import { assignRole } from "@/lib/services/admin";
import { decideGovernanceChange, governanceFor, GovernanceError, proposeGovernanceChange } from "@/lib/services/governance";
import { requestSighting, SightingRefused } from "@/lib/services/intel";
import { createSighting } from "@/worker/jobs/intel";

const run = randomUUID().slice(0, 8);
const STEWARD_A = `gov-a-${run}`;
const STEWARD_B = `gov-b-${run}`;
const STAFF = `gov-staff-${run}`;
let tenantId = "";
let soloId = "";

const all = new Set(BUILTIN_ROLES.find((r) => r.key === "platform_admin")!.permissions as Permission[]);

function staff(tenantIds: string[]): AccessContext {
  return {
    principal: { userId: STAFF, name: "SOC Staff", email: "staff@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: all }],
    tenantIds,
    tenants: tenantIds.map((id) => ({ id, slug: id, name: "Gov", kind: "customer" as const })),
  };
}

function steward(userId: string, tid: string): AccessContext {
  return {
    principal: { userId, name: userId, email: `${userId}@example.invalid`, isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "data_steward", tenantId: tid, permissions: new Set<Permission>(["portal:read", "report:read"]) }],
    tenantIds: [tid],
    tenants: [{ id: tid, slug: tid, name: "Gov", kind: "customer" }],
  };
}

const proposal = (over: Partial<{ residencyLock: boolean; ai: { assistant: boolean; triage_summary: boolean } }> = {}) => ({
  residencyLock: true,
  sightings: { attribution: "anonymised", maxTlp: "TLP:GREEN" },
  ai: { assistant: true, triage_summary: false },
  ...over,
});

async function emailFixture(tid: string) {
  const id = randomUUID();
  await adminDb().insert(integrations).values({
    id, tenantId: tid, category: "collaboration", provider: "email", name: "Steward email",
    config: { host: "fixture.invalid", port: 587, from: "rules@example.com", mode: "fixture" },
    secretCiphertext: encryptSecret(JSON.stringify({ username: "fixture", password: "fixture-key" }), secretAad(id)),
    status: "healthy",
  });
}

beforeAll(async () => {
  for (const r of BUILTIN_ROLES) {
    await adminDb().insert(roles).values({ ...r, permissions: [...r.permissions], builtin: true }).onConflictDoNothing();
  }
  for (const id of [STEWARD_A, STEWARD_B, STAFF]) {
    await adminDb().insert(user).values({ id, name: id, email: `${id}@example.invalid`, emailVerified: true });
  }
  const sharing = { createSightings: true, attribution: "anonymised" as const, maxTlp: "TLP:AMBER" as const };
  const [t] = await adminDb().insert(tenants).values({ slug: `gov-${run}`, name: "Gov Test Org", sectors: ["INDIGENOUS_BUSINESS"], settings: { ...DEFAULT_TENANT_SETTINGS, sharing } }).returning();
  const [solo] = await adminDb().insert(tenants).values({ slug: `gov-solo-${run}`, name: "Gov Solo Org", sectors: ["SMB"] }).returning();
  tenantId = t!.id;
  soloId = solo!.id;
  await adminDb().insert(roleAssignments).values([
    { userId: STEWARD_A, roleKey: "data_steward", tenantId },
    { userId: STEWARD_B, roleKey: "data_steward", tenantId },
    { userId: STEWARD_A, roleKey: "data_steward", tenantId: soloId },
    { userId: STAFF, roleKey: "platform_admin", tenantId: null },
  ]);
  await emailFixture(tenantId);
});

afterAll(async () => {
  await adminDb().delete(tenants).where(inArray(tenants.id, [tenantId, soloId].filter(Boolean)));
  await adminDb().delete(roleAssignments).where(inArray(roleAssignments.userId, [STEWARD_A, STEWARD_B, STAFF]));
  await adminDb().delete(user).where(inArray(user.id, [STEWARD_A, STEWARD_B, STAFF]));
});

describe("data governance enforcement", () => {
  it("governs a tenant with no profile row as most protective", async () => {
    expect(await governanceFor(tenantId)).toEqual({ residencyLock: true, sightings: null, ai: { assistant: false, triage_summary: false } });
  });

  it("refuses AI by default, and a non-AU provider under the residency lock", async () => {
    const aiId = randomUUID();
    const [ai] = await adminDb().insert(integrations).values({
      id: aiId, tenantId, category: "ai", provider: "openai-compatible", name: "Overseas model",
      secretCiphertext: encryptSecret(JSON.stringify({ apiKey: "unused" }), secretAad(aiId)),
      config: { baseUrl: "http://127.0.0.1:9/v1", model: "x", region: "us-east-1", country: "US" }, status: "healthy",
    }).returning();
    await expect(runAssistant(staff([tenantId]), { tenantId, message: "hello" })).rejects.toThrow(/have not turned on AI/);

    // AI on, residency lock still on: the US provider is refused before any call is made.
    await adminDb().insert(dataGovernance).values({ tenantId, profile: { residencyLock: true, sightings: null, ai: { assistant: true, triage_summary: false } } });
    await expect(runAssistant(staff([tenantId]), { tenantId, message: "hello" })).rejects.toThrow(/residency lock/);
    const calls = await adminDb().select().from(aiInvocations).where(eq(aiInvocations.tenantId, tenantId));
    expect(calls.map((c) => c.policyDecision).every((d) => d.startsWith("denied"))).toBe(true);
    expect(calls.length).toBe(2);
    await adminDb().delete(integrations).where(eq(integrations.id, ai!.id));
    await adminDb().delete(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
  });

  it("does not use an intel connector outside Australia under the lock", async () => {
    const [intel] = await adminDb().insert(integrations).values({
      tenantId, category: "threat_intel", provider: "opencti-fixture", name: "Overseas intel", config: { region: "us-east-1" }, status: "healthy",
    }).returning();
    // An allowed platform connector, if any, is used instead; never the overseas one.
    expect((await intelProviderFor(adminDb(), tenantId))?.row.id).not.toBe(intel!.id);
    await adminDb().insert(dataGovernance).values({ tenantId, profile: { residencyLock: false, sightings: null, ai: { assistant: false, triage_summary: false } } });
    expect((await intelProviderFor(adminDb(), tenantId))?.row.id).toBe(intel!.id);
    await adminDb().delete(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
    await adminDb().delete(integrations).where(eq(integrations.id, intel!.id));
  });

  it("refuses a sighting the stewards did not consent to, in the service and the worker", async () => {
    const summary = { observable: { type: "ipv4", value: "203.0.113.9" }, openctiId: "x", entityType: "IPv4-Addr", verdict: "malicious" as const, score: 90, confidence: 80, source: null, markings: [], labels: [], firstSeen: null, lastSeen: null, threats: [] };
    const [m] = await adminDb().insert(intelMatches).values({ tenantId, openctiId: "indicator--gov", verdict: "malicious", summary: summary as never }).returning();
    await expect(requestSighting(staff([tenantId]), m!.id)).rejects.toBeInstanceOf(SightingRefused);
    const [after] = await adminDb().select().from(intelMatches).where(eq(intelMatches.id, m!.id));
    expect(after!.sightingStatus).toBe("blocked_by_policy");
    const refused = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantId), eq(auditLog.action, "intel.sighting_refused")));
    expect(refused.length).toBe(1);

    // A queued job from before consent was withdrawn is still refused by the worker.
    await adminDb().update(intelMatches).set({ sightingStatus: "queued" }).where(eq(intelMatches.id, m!.id));
    await createSighting(tenantId, m!.id);
    const [worker] = await adminDb().select().from(intelMatches).where(eq(intelMatches.id, m!.id));
    expect(worker!.sightingStatus).toBe("blocked_by_policy");
    expect(worker!.sightingId).toBeNull();
  });

  it("needs two different stewards when the tenant has two, and tells every steward", async () => {
    await expect(proposeGovernanceChange(staff([tenantId]), tenantId, proposal(), "Board approved sharing")).rejects.toBeInstanceOf(AccessDenied);
    const change = await proposeGovernanceChange(steward(STEWARD_A, tenantId), tenantId, proposal(), "Board approved sharing");
    expect(change.status).toBe("pending");
    expect(change.required).toBe(2);
    expect((await governanceFor(tenantId)).sightings).toBeNull();

    await expect(decideGovernanceChange(steward(STEWARD_A, tenantId), change.id, "approve")).rejects.toMatchObject({ code: "self" });
    await expect(decideGovernanceChange(staff([tenantId]), change.id, "approve")).rejects.toBeInstanceOf(AccessDenied);
    expect((await decideGovernanceChange(steward(STEWARD_B, tenantId), change.id, "approve")).status).toBe("applied");

    const profile = await governanceFor(tenantId);
    expect(profile.ai.assistant).toBe(true);
    expect(profile.sightings).toMatchObject({ attribution: "anonymised", maxTlp: "TLP:GREEN" });
    expect(profile.sightings!.consentedBy.sort()).toEqual([STEWARD_A, STEWARD_B].sort());

    const actions = (await adminDb().select().from(auditLog).where(eq(auditLog.tenantId, tenantId))).map((a) => a.action);
    expect(actions).toEqual(expect.arrayContaining(["governance.propose", "governance.approve", "governance.apply", "governance.notify"]));
    const notes = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.tenantId, tenantId));
    const applied = notes.filter((n) => n.status === "sent");
    expect(new Set(applied.map((n) => n.destination))).toEqual(new Set([`${STEWARD_A}@example.invalid`, `${STEWARD_B}@example.invalid`]));

    await expect(decideGovernanceChange(steward(STEWARD_B, tenantId), change.id, "approve")).rejects.toBeInstanceOf(GovernanceError);
  });

  it("lets a sole steward change rules alone and records an unreachable notice as failed", async () => {
    const change = await proposeGovernanceChange(steward(STEWARD_A, soloId), soloId, proposal({ residencyLock: true }), "Turn on assistant");
    expect(change.status).toBe("applied");
    const notes = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.tenantId, soloId));
    expect(notes.length).toBeGreaterThan(0);
    expect(notes.every((n) => n.status === "failed")).toBe(true);
  });

  it("never lets platform staff hold the steward role", async () => {
    await expect(assignRole(staff([tenantId]), { userId: STAFF, roleKey: "data_steward", tenantId })).rejects.toThrow(/platform staff/);
  });
});
