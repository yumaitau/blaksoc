import { and, eq, inArray, ne } from "drizzle-orm";
import { z } from "zod";
import { adminDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import { escalationPolicies, incidentTimeline, incidents, integrations, notificationDeliveries, responseActions, tenants } from "@/db/schema";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { notifier } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { decideEscalation, type Channel, type EscalationDecision, type EscalationStep } from "@/lib/portal/escalation";
import { actionPhrase, incidentSentences } from "@/lib/portal/summary";
import { actor, inTenant } from "./common";

const stepSchema = z.object({
  severity: z.enum(["critical", "high", "medium", "low"]),
  channel: z.enum(["sms", "voice", "email"]),
  contacts: z.array(z.string().min(3)).min(1),
  minIntervalMs: z.number().int().positive(),
  maxAttempts: z.number().int().positive(),
});

export async function saveEscalationPolicy(ctx: AccessContext, tenantId: string, steps: EscalationStep[]) {
  const parsed = z.array(stepSchema).min(1).parse(steps);
  return inTenant(ctx, "incident:write", tenantId, async (tx) => {
    await tx
      .insert(escalationPolicies)
      .values({ tenantId, steps: parsed })
      .onConflictDoUpdate({ target: escalationPolicies.tenantId, set: { steps: parsed, updatedAt: new Date() } });
    await audit(tx, { ...actor(ctx), tenantId, action: "escalation.update", targetType: "tenant", targetId: tenantId, detail: { steps: parsed.length } });
  });
}

type Actor = { actorId: string | null; actorKind: "user" | "system" };

export async function advanceIncidentEscalation(tenantId: string, incidentId: string, now = Date.now()): Promise<{ incidentId: string; decision: EscalationDecision }> {
  return withScope(systemScope(tenantId), (tx) => advanceInTx(tx, tenantId, incidentId, now, { actorId: null, actorKind: "system" }));
}

async function advanceInTx(
  tx: Tx,
  tenantId: string,
  incidentId: string,
  now: number,
  who: Actor,
): Promise<{ incidentId: string; decision: EscalationDecision }> {
  const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, incidentId), eq(incidents.tenantId, tenantId)));
  if (!inc || inc.status === "CLOSED") return { incidentId, decision: { action: "stop", reason: "no_policy" } };

  const [policy] = await tx.select().from(escalationPolicies).where(eq(escalationPolicies.tenantId, tenantId));
  const parsed = z.array(stepSchema).safeParse(policy?.steps ?? []);
  const steps = parsed.success ? parsed.data : [];
  const [ack] = await tx
    .select({ id: incidentTimeline.id })
    .from(incidentTimeline)
    .where(and(eq(incidentTimeline.incidentId, incidentId), eq(incidentTimeline.category, "acknowledgement")))
    .limit(1);
  const prior = await tx
    .select()
    .from(notificationDeliveries)
    .where(and(eq(notificationDeliveries.incidentId, incidentId), inArray(notificationDeliveries.status, ["sent", "failed"])));

  const decision = decideEscalation({
    steps,
    severity: inc.severity,
    acknowledged: Boolean(ack),
    attempts: prior.map((row) => ({
      at: row.createdAt.getTime(),
      channel: row.channel as Channel,
      contact: row.destination,
      status: row.status === "failed" ? "failed" : "sent",
    })),
    now,
  });
  if (decision.action !== "send") return { incidentId, decision };

  const acts = await tx
    .select({ action: responseActions.action, status: responseActions.status })
    .from(responseActions)
    .where(and(eq(responseActions.incidentId, incidentId), eq(responseActions.tenantId, tenantId)));
  const phrases = acts.filter((a) => a.status === "SUCCEEDED").map((a) => actionPhrase(a.action));
  const sentences = incidentSentences({ title: inc.title, severity: inc.severity, status: inc.status, actions: phrases });
  const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, tenantId));
  const note = {
    event: "incident.escalation",
    tenant: { id: tenantId, name: tenantRow?.name ?? "Customer" },
    title: inc.title,
    severity: inc.severity,
    url: `${env().APP_URL}/portal/incidents/${inc.id}`,
    summary: sentences.join(" "),
    to: decision.contact,
  };

  const [row] = await tx
    .select()
    .from(integrations)
    .where(and(eq(integrations.tenantId, tenantId), eq(integrations.enabled, true), eq(integrations.provider, decision.channel)));

  let status: "sent" | "failed" = "failed";
  let providerRef: string | null = null;
  let detail = "no connector";
  if (row) {
    try {
      const sent = await notifier(row)?.deliver(note);
      if (!sent) detail = "connector is not a notifier";
      else {
        status = sent.status;
        providerRef = sent.providerRef;
        detail = sent.detail;
      }
    } catch (err) {
      detail = err instanceof Error ? err.message : "send failed";
    }
  }

  await tx.insert(notificationDeliveries).values({
    tenantId,
    incidentId,
    provider: row?.provider ?? decision.channel,
    channel: decision.channel,
    destination: decision.contact,
    status,
    providerRef,
    detail: { detail },
  });
  await audit(tx, {
    actorId: who.actorId,
    actorKind: who.actorKind,
    tenantId,
    action: "notify.delivery",
    targetType: "incident",
    targetId: incidentId,
    detail: { channel: decision.channel, status, provider: row?.provider ?? decision.channel, providerRef, destination: decision.contact },
  });
  return { incidentId, decision };
}

export async function runDueEscalations(now = Date.now()) {
  const open = await adminDb()
    .select({ incidentId: incidents.id, tenantId: incidents.tenantId })
    .from(incidents)
    .innerJoin(escalationPolicies, eq(escalationPolicies.tenantId, incidents.tenantId))
    .where(ne(incidents.status, "CLOSED"));
  const out: { incidentId: string; decision: EscalationDecision }[] = [];
  for (const row of open) out.push(await advanceIncidentEscalation(row.tenantId, row.incidentId, now));
  return out;
}
