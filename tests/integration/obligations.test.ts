import { inflateSync } from "node:zlib";
import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { auditLog, incidentTimeline, incidents, integrations, notificationDeliveries, obligationCases, reportingClocks, tenants } from "@/db/schema";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { secretAad } from "@/lib/connectors/instances";
import { encryptSecret } from "@/lib/crypto";
import { assessmentDue, clockDue } from "@/lib/obligations/clock";
import type { Applicability } from "@/lib/obligations/model";
import type { EscalationStep } from "@/lib/portal/escalation";
import { advanceIncidentEscalation, saveEscalationPolicy } from "@/lib/services/escalation";
import {
  ObligationError, createDraft, getObligation, markClockReported, obligationPdf, recordDecision, recordReferral, runDueClockReminders,
  runDueObligationReminders, startClock, startObligation, updateApplicability,
} from "@/lib/services/obligations";

const created: string[] = [];
const FROM = "+61400111000";
const MOBILE = "+61400999888";
const DAY = 86_400_000;
const HOUR = 3_600_000;
const YES: Applicability = { privacyAct: "yes", healthInformation: "yes", governmentContract: "no", soci: "unsure", ransomwareReporting: "unsure" };

function pdfPlain(bytes: Uint8Array) {
  const raw = Buffer.from(bytes);
  const latin = raw.toString("latin1");
  let out = "";
  const marker = /stream\r?\n/g;
  let match: RegExpExecArray | null;
  while ((match = marker.exec(latin))) {
    const start = match.index + match[0].length;
    const end = latin.indexOf("endstream", start);
    let chunk: Buffer = raw.subarray(start, end);
    if (chunk[chunk.length - 1] === 0x0a) chunk = chunk.subarray(0, -1);
    try {
      chunk = Buffer.from(inflateSync(chunk));
    } catch {
      // already plain
    }
    out += chunk.toString("latin1").replace(/<([0-9A-Fa-f\s]+)>/g, (_, hex: string) => Buffer.from(hex.replace(/\s/g, ""), "hex").toString("latin1"));
  }
  return out;
}

function ctx(tenantId: string, permissions: Permission[], userId: string, name: string): AccessContext {
  return {
    principal: { userId, name, email: `${userId}@example.invalid`, isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "ndb", name: "NDB Clinic", kind: "customer" }],
  };
}

function platform(tenantId: string): AccessContext {
  return {
    principal: { userId: "ndb-platform", name: "Platform", email: "ndb-platform@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set<Permission>(["incident:read", "incident:write", "settings:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "ndb", name: "NDB Clinic", kind: "customer" }],
  };
}

async function smsTenant() {
  const tenant = await freshTenant();
  await saveEscalationPolicy(platform(tenant.id), tenant.id, [{ severity: "high", channel: "sms", contacts: [MOBILE], minIntervalMs: 60_000, maxAttempts: 3 }]);
  const integrationId = randomUUID();
  await adminDb().insert(integrations).values({
    id: integrationId,
    tenantId: tenant.id,
    category: "collaboration",
    provider: "sms",
    name: "sms",
    enabled: true,
    config: { from: FROM, mode: "fixture", events: ["incident.created"] },
    secretCiphertext: encryptSecret(JSON.stringify({ apiKey: "fixture-key", apiSecret: "fixture-secret" }), secretAad(integrationId)),
  });
  return tenant;
}

async function freshTenant() {
  const slug = `ndb-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "NDB Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("breach obligations", () => {
  it("starts a 30-day clock, reminds through the escalation channel, and exports the evidence pack", async () => {
    const tenant = await freshTenant();
    const admin = ctx(tenant.id, ["portal:read", "incident:read", "response:approve"], "ndb-admin", "Ava Chen");
    const reader = ctx(tenant.id, ["portal:read", "incident:read"], "ndb-reader", "Reader");
    const [inc] = await adminDb().insert(incidents).values({ tenantId: tenant.id, title: "Mailbox misuse", severity: "high" }).returning();
    const steps: EscalationStep[] = [{ severity: "high", channel: "sms", contacts: [MOBILE], minIntervalMs: 60_000, maxAttempts: 3 }];
    await saveEscalationPolicy(platform(tenant.id), tenant.id, steps);
    const integrationId = randomUUID();
    await adminDb().insert(integrations).values({
      id: integrationId,
      tenantId: tenant.id,
      category: "collaboration",
      provider: "sms",
      name: "sms",
      enabled: true,
      config: { from: FROM, mode: "fixture", events: ["incident.created"] },
      secretCiphertext: encryptSecret(JSON.stringify({ apiKey: "fixture-key", apiSecret: "fixture-secret" }), secretAad(integrationId)),
    });

    const started = new Date(Date.now() - 8 * DAY);
    await expect(startObligation(reader, inc!.id, { startedAt: started, applicability: YES })).rejects.toBeInstanceOf(AccessDenied);
    await startObligation(admin, inc!.id, { startedAt: started, applicability: YES, insurerPolicy: "POL-18" });
    const view = await getObligation(admin, inc!.id);
    expect(view?.case.dueAt.toISOString()).toBe(assessmentDue(started).toISOString());
    expect(view?.case.applicability.healthInformation).toBe("yes");

    const reminded = await runDueObligationReminders();
    expect(reminded.find((row) => row.incidentId === inc!.id)?.reminderKey).toBe("7");
    const sent = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id));
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ status: "sent", channel: "sms", destination: MOBILE, providerRef: "fixture-sms" });
    expect(sent[0]?.detail).toMatchObject({ kind: "obligation", reminderKey: "7" });

    const paging = await advanceIncidentEscalation(tenant.id, inc!.id, Date.now());
    expect(paging.decision).toMatchObject({ action: "send", channel: "sms", contact: MOBILE });

    const beforeDraft = (await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id))).length;
    const draft = await createDraft(admin, inc!.id, "individuals");
    expect(draft.body).toContain("This is not legal advice.");
    expect(draft.body).toContain("has not been sent");
    expect(draft.body).toContain("The Indigenous advisory group has not reviewed this wording.");
    const afterDraft = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id));
    expect(afterDraft).toHaveLength(beforeDraft);

    await expect(recordReferral(admin, inc!.id, { key: "insurer" })).rejects.toBeInstanceOf(ObligationError);
    await recordReferral(admin, inc!.id, { key: "insurer", policyNumber: "POL-18" });
    await recordDecision(admin, inc!.id, { decision: "assessing", rationale: "Still checking who opened the mailbox." });

    const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, inc!.id));
    expect(timeline).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: "obligation", title: "Assessment clock started" }),
      expect.objectContaining({ category: "obligation", title: "Decision: assessing", detail: expect.stringContaining("Ava Chen") }),
      expect.objectContaining({ category: "obligation", title: "Clock reminder day 7" }),
    ]));

    const pdf = await obligationPdf(admin, inc!.id);
    const text = pdfPlain(pdf);
    expect(Buffer.from(pdf.subarray(0, 4)).toString("latin1")).toBe("%PDF");
    expect(text).toContain("not legal advice");
    expect(text).toContain("Ava Chen");
    expect(text).toContain("Still checking who opened the mailbox.");
    expect(text).toContain("POL-18");

    const audits = await adminDb().select().from(auditLog).where(eq(auditLog.tenantId, tenant.id));
    expect(audits.some((row) => row.action === "obligation.decision" && row.targetId === inc!.id)).toBe(true);
    expect(audits.some((row) => row.action === "notify.delivery" && row.targetId === inc!.id)).toBe(true);

    const hidden = await withScope({ tenantIds: [], platform: true }, (tx) => tx.select().from(obligationCases).where(eq(obligationCases.tenantId, tenant.id)));
    expect(hidden).toEqual([]);

    const [closed] = await adminDb().insert(incidents).values({ tenantId: tenant.id, title: "Already decided", severity: "high" }).returning();
    await startObligation(admin, closed!.id, { startedAt: new Date(Date.now() - 40 * DAY), applicability: YES });
    await recordDecision(admin, closed!.id, { decision: "not_eligible", rationale: "The file was recovered and nobody else opened it." });
    await runDueObligationReminders();
    const stopped = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, closed!.id));
    expect(stopped).toEqual([]);
  });

  it("starts SOCI and ransomware clocks from the recorded time, reminds before the deadline, and keeps them to the tenant", async () => {
    const tenant = await smsTenant();
    const admin = ctx(tenant.id, ["portal:read", "incident:read", "response:approve"], "soci-admin", "Ava Chen");
    const reader = ctx(tenant.id, ["portal:read", "incident:read"], "soci-reader", "Reader");
    const [inc] = await adminDb().insert(incidents).values({ tenantId: tenant.id, title: "Ransomware on the SCADA historian", severity: "high" }).returning();
    const now = Date.now();
    const aware = new Date(now - 7 * HOUR);

    await expect(startClock(admin, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "UTC" })).rejects.toMatchObject({ code: "missing" });
    await startObligation(admin, inc!.id, { startedAt: new Date(now), applicability: { ...YES, soci: "no", ransomwareReporting: "no" } });
    await expect(startClock(admin, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "UTC" })).rejects.toMatchObject({ code: "applicability" });
    await expect(startClock(admin, inc!.id, { kind: "ransomware_payment", startedAt: aware, timeZone: "UTC" })).rejects.toMatchObject({ code: "applicability" });
    await updateApplicability(admin, inc!.id, { ...YES, soci: "yes", ransomwareReporting: "no" });

    await expect(startClock(reader, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "UTC" })).rejects.toBeInstanceOf(AccessDenied);
    await expect(startClock(admin, inc!.id, { kind: "soci_critical", startedAt: new Date(now + DAY), timeZone: "UTC" })).rejects.toMatchObject({ code: "time" });
    await expect(startClock(admin, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "Europe/London" })).rejects.toMatchObject({ code: "time" });
    const clock = await startClock(admin, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "Australia/Sydney" });
    expect(clock.dueAt.toISOString()).toBe(clockDue("soci_critical", aware).toISOString());
    expect(clock.dueAt.getTime() - aware.getTime()).toBe(12 * HOUR);
    await expect(startClock(admin, inc!.id, { kind: "soci_critical", startedAt: aware, timeZone: "UTC" })).rejects.toMatchObject({ code: "exists" });
    // A SOCI responsible entity reports ransomware payments whatever its turnover.
    const payment = await startClock(admin, inc!.id, { kind: "ransomware_payment", startedAt: new Date(now - HOUR), timeZone: "Australia/Perth" });
    expect(payment.dueAt.getTime() - payment.startedAt.getTime()).toBe(72 * HOUR);

    // Seven hours after awareness the 6-hour reminder is due; nothing yet on the 72-hour payment clock.
    const first = (await runDueClockReminders(now)).filter((row) => row.incidentId === inc!.id);
    expect(first).toEqual([expect.objectContaining({ clock: "soci_critical", reminderKey: "6" })]);
    const sent = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id));
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ status: "sent", channel: "sms", destination: MOBILE, providerRef: "fixture-sms" });
    expect(sent[0]?.detail).toMatchObject({ kind: "obligation", clock: "soci_critical", reminderKey: "6" });

    expect((await runDueClockReminders(now + 60_000)).filter((row) => row.incidentId === inc!.id)).toEqual([]);
    const second = (await runDueClockReminders(now + 2 * HOUR + 60_000)).filter((row) => row.incidentId === inc!.id);
    expect(second).toEqual([expect.objectContaining({ clock: "soci_critical", reminderKey: "9" })]);

    // The SOCI reminders are not NDB reminders and do not count against the NDB clock.
    const view = await getObligation(admin, inc!.id);
    expect(view?.reminders).toEqual([]);
    expect(view?.clocks.find((row) => row.kind === "soci_critical")?.reminders.map((row) => row.key)).toEqual(["6", "9"]);
    expect((await runDueObligationReminders(now)).filter((row) => row.incidentId === inc!.id)).toEqual([]);

    const draft = await createDraft(admin, inc!.id, "soci_critical");
    expect(draft.body).toContain("This is not legal advice.");
    expect(draft.body).toContain("s30BC");
    expect(draft.body).toContain("does not submit this report");
    expect((await getObligation(admin, inc!.id))?.case.legalReview).toBe(true);
    expect(await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id))).toHaveLength(2);

    await markClockReported(admin, inc!.id, { kind: "soci_critical", reference: "ASD-REF-1" });
    await expect(markClockReported(admin, inc!.id, { kind: "soci_critical" })).rejects.toMatchObject({ code: "missing" });
    expect((await runDueClockReminders(now + 5 * HOUR)).filter((row) => row.incidentId === inc!.id && row.clock === "soci_critical")).toEqual([]);

    const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, inc!.id));
    expect(timeline).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: "obligation", title: "Clock started: SOCI critical cyber security incident (12 hours)" }),
      expect.objectContaining({ category: "obligation", title: "Clock reminder: SOCI critical cyber security incident (12 hours), 6 hours left" }),
      expect.objectContaining({ category: "obligation", title: "Marked reported: SOCI critical cyber security incident (12 hours)", detail: expect.stringContaining("ASD-REF-1") }),
    ]));
    const audits = await adminDb().select().from(auditLog).where(eq(auditLog.tenantId, tenant.id));
    for (const action of ["obligation.applicability", "obligation.clock_start", "obligation.clock_reported", "notify.delivery"]) {
      expect(audits.some((row) => row.action === action && row.targetId === inc!.id)).toBe(true);
    }
    expect(pdfPlain(await obligationPdf(admin, inc!.id))).toContain("s30BC");

    // Another tenant cannot see, start or mark these clocks, and RLS hides the rows.
    const other = await smsTenant();
    const outsider = ctx(other.id, ["portal:read", "incident:read", "incident:write"], "soci-outsider", "Outsider");
    await expect(getObligation(outsider, inc!.id)).rejects.toBeInstanceOf(AccessDenied);
    await expect(startClock(outsider, inc!.id, { kind: "soci_other", startedAt: aware, timeZone: "UTC" })).rejects.toBeInstanceOf(AccessDenied);
    await expect(markClockReported(outsider, inc!.id, { kind: "ransomware_payment" })).rejects.toBeInstanceOf(AccessDenied);
    const leaked = await withScope({ tenantIds: [other.id], platform: false }, (tx) => tx.select().from(reportingClocks).where(eq(reportingClocks.tenantId, tenant.id)));
    expect(leaked).toEqual([]);
    const own = await withScope({ tenantIds: [tenant.id], platform: false }, (tx) => tx.select().from(reportingClocks).where(eq(reportingClocks.tenantId, tenant.id)));
    expect(own).toHaveLength(2);
    await expect(withScope({ tenantIds: [other.id], platform: false }, (tx) => tx.insert(reportingClocks).values({
      tenantId: tenant.id, incidentId: inc!.id, caseId: clock.caseId, kind: "soci_other", startedAt: aware, dueAt: aware, timeZone: "UTC", startedBy: "Outsider",
    }))).rejects.toThrow();
  });
});
