import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { auditLog, incidentTimeline, incidents, integrations, notificationDeliveries, tenants } from "@/db/schema";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { secretAad } from "@/lib/connectors/instances";
import { encryptSecret } from "@/lib/crypto";
import type { EscalationStep } from "@/lib/portal/escalation";
import { advanceIncidentEscalation, runDueEscalations, saveEscalationPolicy } from "@/lib/services/escalation";
import { acknowledgeIncident } from "@/lib/services/incidents";

const created: string[] = [];
const FROM = "+61400111000";
const MOBILE = "+61400999888";

function platform(tenantId: string): AccessContext {
  return {
    principal: { userId: "esc-admin", name: "Esc Admin", email: "esc-admin@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set(["incident:read", "incident:write", "settings:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "esc", name: "Esc", kind: "customer" }],
  };
}

function customer(tenantId: string): AccessContext {
  return {
    principal: { userId: "esc-customer", name: "Customer Admin", email: "esc-customer@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(["portal:read", "incident:read"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "esc", name: "Esc", kind: "customer" }],
  };
}

async function freshTenant(name: string) {
  const slug = `esc-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name, kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

async function connector(tenantId: string, provider: "sms" | "voice", secrets: Record<string, string>) {
  const id = randomUUID();
  await adminDb().insert(integrations).values({
    id,
    tenantId,
    category: "collaboration",
    provider,
    name: provider,
    enabled: true,
    config: { from: FROM, mode: "fixture", events: ["incident.created"] },
    secretCiphertext: encryptSecret(JSON.stringify(secrets), secretAad(id)),
  });
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("escalation delivery", () => {
  it("texts the contact, rate-limits the retry, audits delivery, and stops after acknowledgement", async () => {
    const tenant = await freshTenant("Escalation Clinic");
    const [inc] = await adminDb().insert(incidents).values({ tenantId: tenant.id, title: "Mailbox misuse", severity: "high" }).returning();
    const steps: EscalationStep[] = [{ severity: "high", channel: "sms", contacts: [MOBILE], minIntervalMs: 60_000, maxAttempts: 3 }];
    await expect(saveEscalationPolicy(customer(tenant.id), tenant.id, steps)).rejects.toBeInstanceOf(AccessDenied);
    await saveEscalationPolicy(platform(tenant.id), tenant.id, steps);
    await connector(tenant.id, "sms", { apiKey: "fixture-key", apiSecret: "fixture-secret" });

    const t0 = Date.now();
    const first = (await runDueEscalations(t0)).find((row) => row.incidentId === inc!.id);
    expect(first?.decision).toMatchObject({ action: "send", channel: "sms", contact: MOBILE });

    const sent = () => adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id));
    expect(await sent()).toHaveLength(1);
    expect((await sent())[0]).toMatchObject({ status: "sent", channel: "sms", destination: MOBILE, provider: "sms", providerRef: "fixture-sms" });

    const again = await advanceIncidentEscalation(tenant.id, inc!.id, t0 + 1_000);
    expect(again.decision).toMatchObject({ action: "wait", reason: "rate_limited" });
    expect(await sent()).toHaveLength(1);

    const audits = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "notify.delivery"), eq(auditLog.targetId, inc!.id)));
    expect(audits).toHaveLength(1);
    expect(audits[0]?.detail).toMatchObject({ channel: "sms", status: "sent", destination: MOBILE });

    await expect(acknowledgeIncident(platform(tenant.id), inc!.id)).rejects.toBeInstanceOf(AccessDenied);
    const ack = await acknowledgeIncident(customer(tenant.id), inc!.id);
    expect(ack.already).toBe(false);
    const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, inc!.id));
    expect(timeline).toEqual(expect.arrayContaining([expect.objectContaining({ origin: "customer", category: "acknowledgement", title: "I've read this" })]));

    const stopped = await advanceIncidentEscalation(tenant.id, inc!.id, t0 + 120_000);
    expect(stopped.decision).toEqual({ action: "stop", reason: "acknowledged" });
    expect(await sent()).toHaveLength(1);

    const other = await freshTenant("Other Clinic");
    const hidden = await withScope({ tenantIds: [other.id], platform: false }, (tx) =>
      tx.select().from(notificationDeliveries).where(eq(notificationDeliveries.tenantId, tenant.id)),
    );
    expect(hidden).toEqual([]);
  });

  it("places a fixture voice call and audits it", async () => {
    const tenant = await freshTenant("Voice Clinic");
    const [inc] = await adminDb().insert(incidents).values({ tenantId: tenant.id, title: "After hours call", severity: "critical" }).returning();
    await saveEscalationPolicy(platform(tenant.id), tenant.id, [{ severity: "critical", channel: "voice", contacts: [MOBILE], minIntervalMs: 60_000, maxAttempts: 2 }]);
    await connector(tenant.id, "voice", { accountSid: "ACfixture", authToken: "fixture-token" });

    const result = await advanceIncidentEscalation(tenant.id, inc!.id, Date.now());
    expect(result.decision).toMatchObject({ action: "send", channel: "voice", contact: MOBILE });
    const [row] = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc!.id));
    expect(row).toMatchObject({ status: "sent", channel: "voice", provider: "voice", providerRef: "fixture-voice" });
    const [audit] = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "notify.delivery")));
    expect(audit?.detail).toMatchObject({ channel: "voice", status: "sent" });
  });
});
