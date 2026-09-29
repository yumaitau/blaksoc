/**
 * Training rooms replay authored scenarios through the demo provider.
 * Real providers are rejected in the service and by the database trigger.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, integrations, roleAssignments, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { msspOverview } from "@/lib/services/dashboard";
import { AccessDenied } from "@/lib/services/common";
import { createIntegration, linkTenant, updateIntegration } from "@/lib/services/integrations";
import { updateTenantSettings } from "@/lib/services/admin";
import { cosignTrainee, mentorProgress, openTrainingTenant, recordAction, startScenario, useHint } from "@/lib/services/training";
import { TrainingIsolationError } from "@/lib/training/isolation";
import { scenarioById } from "@/lib/training/scenarios";

const created: string[] = [];
const platformIntegrations: string[] = [];
const now = new Date("2026-07-01T00:00:00.000Z");

function platform(rows: { id: string; slug: string; name: string }[], permissions: string[]): AccessContext {
  return {
    principal: { userId: "train-mentor", name: "Training Mentor", email: "mentor@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "soc_manager", tenantId: null, permissions: new Set(permissions as never) }],
    tenantIds: rows.map((row) => row.id),
    tenants: rows.map((row) => ({ id: row.id, slug: row.slug, name: row.name, kind: "customer" as const })),
  };
}

const STAFF = ["tenant:manage", "integration:manage", "settings:manage", "alert:assign", "alert:triage", "mssp:read"];

function textOf(err: unknown): string {
  const bits: string[] = [];
  let cur: unknown = err;
  for (let i = 0; i < 5 && cur instanceof Error; i += 1) {
    bits.push(cur.message);
    cur = (cur as { cause?: unknown }).cause;
  }
  return bits.join("\n");
}

afterAll(async () => {
  if (platformIntegrations.length) await adminDb().delete(integrations).where(inArray(integrations.id, platformIntegrations));
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("analyst training", () => {
  it("keeps training tenants on the demo provider and scores trainees for mentors", async () => {
    const slug = `train-${randomUUID().slice(0, 8)}`;
    const opened = await openTrainingTenant(platform([], STAFF), { name: "Training room", slug });
    created.push(opened.tenantId);
    const room = { id: opened.tenantId, slug, name: "Training room" };
    const [demo] = await adminDb().select({ provider: integrations.provider, enabled: integrations.enabled }).from(integrations).where(eq(integrations.id, opened.integrationId));
    expect(demo).toEqual({ provider: "demo", enabled: false });

    const staff = platform([room], STAFF);
    await expect(createIntegration(staff, { tenantId: room.id, provider: "syslog", name: "Training firewall", config: { region: "ap-southeast-2" }, secrets: {} })).rejects.toBeInstanceOf(TrainingIsolationError);

    const [shared] = await adminDb().insert(integrations).values({ tenantId: null, category: "siem", provider: "syslog", name: "Shared firewall", config: {} }).returning({ id: integrations.id });
    platformIntegrations.push(shared!.id);
    await expect(linkTenant(staff, shared!.id, room.id, {})).rejects.toBeInstanceOf(TrainingIsolationError);

    try {
      await adminDb().insert(integrations).values({ tenantId: room.id, category: "siem", provider: "m365", name: "Real mail", config: {} });
      throw new Error("m365 insert succeeded");
    } catch (err) {
      expect(textOf(err)).toMatch(/training tenant/);
    }

    const customerSlug = `train-cust-${randomUUID().slice(0, 8)}`;
    const [customer] = await adminDb().insert(tenants).values({ slug: customerSlug, name: "Training Control", kind: "customer" }).returning();
    created.push(customer!.id);
    const customerRef = { id: customer!.id, slug: customerSlug, name: "Training Control" };
    const both = platform([room, customerRef], STAFF);
    const ownedSyslog = await createIntegration(both, { tenantId: customer!.id, provider: "syslog", name: "Clinic firewall", config: { region: "ap-southeast-2" }, secrets: {} });
    expect(ownedSyslog).toBeTruthy();
    await linkTenant(both, shared!.id, customer!.id, {});
    await expect(updateTenantSettings(both, customer!.id, { training: true })).rejects.toBeInstanceOf(TrainingIsolationError);
    const [saved] = await adminDb().select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, customer!.id));
    expect(saved!.settings.training).toBeUndefined();

    const trainee = platform([room], ["alert:triage"]);
    trainee.principal = { userId: "trainee-ada", name: "Ada", email: "ada@example.invalid", isBreakGlass: false };
    trainee.grants = [{ roleKey: "soc_analyst_l1", tenantId: null, permissions: new Set(["alert:triage"]) }];
    const bec = scenarioById("bec-payment")!;
    const started = await startScenario(trainee, room.id, "bec-payment", { id: "trainee-ada", name: "Ada" }, now);
    const [alert] = await adminDb().select({ title: alerts.title, source: alerts.source, ruleId: alerts.ruleId }).from(alerts).where(and(eq(alerts.tenantId, room.id), eq(alerts.externalId, "training:bec-payment:trainee-ada:0")));
    expect(alert).toEqual({ title: bec.events[0]!.title, source: "demo", ruleId: bec.events[0]!.ruleId });
    expect(await useHint(trainee, room.id, started.attemptId)).toBe(bec.hints[0]);
    await recordAction(trainee, room.id, started.attemptId, "triage");
    await recordAction(trainee, room.id, started.attemptId, "escalate");
    const becResult = await recordAction(trainee, room.id, started.attemptId, "note");
    expect(becResult).toMatchObject({ score: 90, status: "scored" });

    const lock = await startScenario(trainee, room.id, "ransomware-lock", { id: "trainee-ada", name: "Ada" }, now);
    await recordAction(trainee, room.id, lock.attemptId, "triage");
    await recordAction(trainee, room.id, lock.attemptId, "contain-request");
    const lockResult = await recordAction(trainee, room.id, lock.attemptId, "escalate");
    expect(lockResult).toMatchObject({ score: 100, status: "scored" });

    const mentor = platform([room, customerRef], STAFF);
    const progress = await mentorProgress(mentor, room.id);
    const ada = progress.trainees.find((row) => row.traineeId === "trainee-ada");
    expect(ada?.averageScore).toBe(95);
    expect(ada?.skills).toEqual(expect.arrayContaining([
      { skill: "alert:triage", passed: true },
      { skill: "incident:write", passed: true },
      { skill: "response:request", passed: true },
    ]));

    await startScenario(trainee, room.id, "bec-payment", { id: "trainee-ada", name: "Ada" }, now);
    const replayed = await adminDb().select({ id: alerts.id }).from(alerts).where(and(eq(alerts.tenantId, room.id), eq(alerts.externalId, "training:bec-payment:trainee-ada:0")));
    expect(replayed).toHaveLength(1);
    const again = await mentorProgress(mentor, room.id);
    expect(again.trainees.find((row) => row.traineeId === "trainee-ada")?.attempts).toBe(3);

    const outsider = platform([customerRef], ["alert:triage"]);
    await expect(startScenario(outsider, room.id, "bec-payment", { id: "trainee-ada", name: "Ada" }, now)).rejects.toBeInstanceOf(AccessDenied);
    await expect(mentorProgress(trainee, room.id)).rejects.toBeInstanceOf(AccessDenied);

    await cosignTrainee(mentor, room.id, "trainee-ada");
    const roles = await adminDb().select({ id: roleAssignments.id }).from(roleAssignments).where(eq(roleAssignments.userId, "trainee-ada"));
    expect(roles).toHaveLength(0);
    const signed = await mentorProgress(mentor, room.id);
    expect(signed.trainees.find((row) => row.traineeId === "trainee-ada")?.cosigned).toBe(true);

    const overview = await msspOverview(both);
    expect(overview.map((row) => row.id)).toContain(customer!.id);
    expect(overview.map((row) => row.id)).not.toContain(room.id);

    await expect(updateIntegration(both, opened.integrationId, { enabled: true })).rejects.toMatchObject({ code: "enable" });
  });
});
