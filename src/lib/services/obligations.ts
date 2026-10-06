import { and, asc, eq, inArray } from "drizzle-orm";
import { systemDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import { escalationPolicies, incidentTimeline, incidents, integrations, notificationDeliveries, obligationCases, obligationDrafts, tenants } from "@/db/schema";
import { AccessDenied, can, systemScope, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { audit } from "@/lib/audit";
import { notifier } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { assessmentDue, dueReminders } from "@/lib/obligations/clock";
import {
  ANSWERS, DECISIONS, DRAFT_KINDS, NOT_ADVICE, REFERRALS, draftBody,
  type Answer, type Applicability, type BreachDecision, type DraftKind, type ReferralKey,
} from "@/lib/obligations/model";
import { buildEvidencePack, type EvidencePackInput, type PackMark } from "@/lib/obligations/report";
import { decideEscalation, type Channel, type EscalationDecision, type EscalationStep } from "@/lib/portal/escalation";
import { toPdf } from "@/lib/reports/export";
import { actor, inTenant, scoped } from "./common";
import { addTimeline } from "./incidents";

export class ObligationError extends Error {
  constructor(readonly code: "incomplete" | "rationale" | "decision" | "referral" | "policy" | "draft" | "missing" | "exists") {
    super(code);
  }
}

function writePermission(ctx: AccessContext, tenantId: string): Permission {
  if (can(ctx, "incident:write", tenantId)) return "incident:write";
  if (can(ctx, "response:approve", tenantId)) return "response:approve";
  throw new AccessDenied("missing permission to record obligations");
}

function asAnswer(value: string): Answer {
  if (!(ANSWERS as readonly string[]).includes(value)) throw new ObligationError("incomplete");
  return value as Answer;
}

function rationaleOf(value: string) {
  const text = value.trim();
  if (!text || text.length > 4000) throw new ObligationError("rationale");
  return text;
}

function obligationKey(detail: unknown): string | null {
  if (!detail || typeof detail !== "object") return null;
  const row = detail as { kind?: unknown; reminderKey?: unknown };
  if (row.kind !== "obligation" || typeof row.reminderKey !== "string") return null;
  return row.reminderKey;
}

async function incidentFor(ctx: AccessContext, incidentId: string) {
  const inc = await scoped(ctx, "incident:read", async (tx, tenantIds) => {
    const [row] = await tx.select().from(incidents).where(and(eq(incidents.id, incidentId), inArray(incidents.tenantId, tenantIds)));
    return row;
  });
  if (!inc) throw new AccessDenied("incident not found");
  return inc;
}

async function note(tx: Tx, tenantId: string, incidentId: string, ctx: AccessContext, title: string, detail: string) {
  const origin = can(ctx, "incident:write", tenantId) ? "analyst" : "customer";
  await addTimeline(tx, { tenantId, incidentId, origin, category: "obligation", title, detail, actorId: ctx.principal.userId });
}

export async function startObligation(ctx: AccessContext, incidentId: string, input: { startedAt: Date; applicability: Applicability; insurerPolicy?: string }) {
  if (Number.isNaN(input.startedAt.getTime())) throw new ObligationError("incomplete");
  const applicability: Applicability = {
    privacyAct: asAnswer(input.applicability.privacyAct),
    healthInformation: asAnswer(input.applicability.healthInformation),
    governmentContract: asAnswer(input.applicability.governmentContract),
    soci: asAnswer(input.applicability.soci),
  };
  const insurerPolicy = (input.insurerPolicy ?? "").trim();
  if (insurerPolicy.length > 80) throw new ObligationError("policy");
  const inc = await incidentFor(ctx, incidentId);
  const dueAt = assessmentDue(input.startedAt);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [existing] = await tx.select({ id: obligationCases.id }).from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (existing) throw new ObligationError("exists");
    const [row] = await tx.insert(obligationCases).values({
      tenantId: inc.tenantId,
      incidentId: inc.id,
      startedAt: input.startedAt,
      dueAt,
      applicability,
      referrals: {},
      insurerPolicy: insurerPolicy || null,
    }).returning();
    await note(tx, inc.tenantId, inc.id, ctx, "Assessment clock started", `${ctx.principal.name}. Due ${dueAt.toISOString()}.`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.start", targetType: "incident", targetId: inc.id, detail: { dueAt: dueAt.toISOString() } });
    return row!;
  });
}

export async function recordHarm(ctx: AccessContext, incidentId: string, input: { seriousHarm: Answer; rationale: string }) {
  const seriousHarm = asAnswer(input.seriousHarm);
  const rationale = rationaleOf(input.rationale);
  const inc = await incidentFor(ctx, incidentId);
  const at = new Date();
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [row] = await tx.update(obligationCases).set({
      seriousHarm, seriousHarmRationale: rationale, seriousHarmBy: ctx.principal.name, seriousHarmAt: at,
    }).where(eq(obligationCases.incidentId, inc.id)).returning();
    if (!row) throw new ObligationError("missing");
    await note(tx, inc.tenantId, inc.id, ctx, `Serious harm: ${seriousHarm}`, `${ctx.principal.name}. ${rationale}`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.harm", targetType: "incident", targetId: inc.id, detail: { seriousHarm } });
    return row;
  });
}

export async function recordDecision(ctx: AccessContext, incidentId: string, input: { decision: BreachDecision; rationale: string }) {
  if (!(DECISIONS as readonly string[]).includes(input.decision)) throw new ObligationError("decision");
  const rationale = rationaleOf(input.rationale);
  const inc = await incidentFor(ctx, incidentId);
  const at = new Date();
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [row] = await tx.update(obligationCases).set({
      decision: input.decision, decisionRationale: rationale, decisionBy: ctx.principal.name, decisionAt: at,
    }).where(eq(obligationCases.incidentId, inc.id)).returning();
    if (!row) throw new ObligationError("missing");
    await note(tx, inc.tenantId, inc.id, ctx, `Decision: ${input.decision}`, `${ctx.principal.name}. ${rationale}`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.decision", targetType: "incident", targetId: inc.id, detail: { decision: input.decision } });
    return row;
  });
}

export async function recordReferral(ctx: AccessContext, incidentId: string, input: { key: ReferralKey; policyNumber?: string }) {
  if (!(REFERRALS as readonly string[]).includes(input.key)) throw new ObligationError("referral");
  const policyNumber = (input.policyNumber ?? "").trim();
  if (input.key === "insurer" && !policyNumber) throw new ObligationError("policy");
  if (policyNumber.length > 80) throw new ObligationError("policy");
  const inc = await incidentFor(ctx, incidentId);
  const mark: PackMark = { at: new Date().toISOString(), byName: ctx.principal.name, ...(policyNumber ? { policyNumber } : {}) };
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [current] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!current) throw new ObligationError("missing");
    const [row] = await tx.update(obligationCases).set({
      referrals: { ...current.referrals, [input.key]: mark },
      ...(input.key === "insurer" ? { insurerPolicy: policyNumber } : {}),
    }).where(eq(obligationCases.id, current.id)).returning();
    await note(tx, inc.tenantId, inc.id, ctx, `Referral: ${input.key}`, `${ctx.principal.name}. ${policyNumber}`.trim());
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.referral", targetType: "incident", targetId: inc.id, detail: { key: input.key } });
    return row!;
  });
}

export async function setLegalReview(ctx: AccessContext, incidentId: string, requested: boolean) {
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [row] = await tx.update(obligationCases).set({ legalReview: requested }).where(eq(obligationCases.incidentId, inc.id)).returning();
    if (!row) throw new ObligationError("missing");
    await note(tx, inc.tenantId, inc.id, ctx, requested ? "Legal review requested" : "Legal review cleared", ctx.principal.name);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.legal_review", targetType: "incident", targetId: inc.id, detail: { requested } });
    return row;
  });
}

export async function createDraft(ctx: AccessContext, incidentId: string, kind: DraftKind) {
  if (!(DRAFT_KINDS as readonly string[]).includes(kind)) throw new ObligationError("draft");
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [current] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!current) throw new ObligationError("missing");
    const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, inc.tenantId));
    const body = draftBody(kind, {
      tenantName: tenantRow?.name ?? "Organisation",
      incidentTitle: inc.title,
      startedAt: current.startedAt.toISOString(),
      dueAt: current.dueAt.toISOString(),
      applicability: current.applicability,
      seriousHarm: current.seriousHarm ?? "not recorded",
      seriousHarmRationale: current.seriousHarmRationale ?? "",
      decision: current.decision ?? "not recorded",
      decisionRationale: current.decisionRationale ?? "",
      authorName: ctx.principal.name,
    });
    const [draft] = await tx.insert(obligationDrafts).values({
      tenantId: inc.tenantId, incidentId: inc.id, caseId: current.id, kind, body, authorId: ctx.principal.userId, authorName: ctx.principal.name,
    }).returning();
    await note(tx, inc.tenantId, inc.id, ctx, `Draft saved: ${kind}`, `${ctx.principal.name}. ${NOT_ADVICE}`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.draft", targetType: "incident", targetId: inc.id, detail: { kind, sent: false } });
    return draft!;
  });
}

export async function getObligation(ctx: AccessContext, incidentId: string) {
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, "incident:read", inc.tenantId, async (tx) => {
    const [row] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!row) return null;
    const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, inc.tenantId));
    const drafts = await tx.select().from(obligationDrafts).where(eq(obligationDrafts.caseId, row.id)).orderBy(asc(obligationDrafts.createdAt));
    const deliveries = await tx.select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc.id));
    const reminders = deliveries.flatMap((item) => {
      const key = obligationKey(item.detail);
      if (!key) return [];
      return [{ key, at: item.createdAt.toISOString(), channel: item.channel, destination: item.destination, status: item.status }];
    });
    const events = await tx.select().from(incidentTimeline).where(and(eq(incidentTimeline.incidentId, inc.id), eq(incidentTimeline.category, "obligation"))).orderBy(asc(incidentTimeline.occurredAt));
    return { incident: inc, tenantName: tenantRow?.name ?? "Organisation", case: row, drafts, reminders, events };
  });
}

function toPack(view: NonNullable<Awaited<ReturnType<typeof getObligation>>>): EvidencePackInput {
  const row = view.case;
  return {
    tenantName: view.tenantName,
    incidentTitle: view.incident.title,
    generatedAt: new Date().toISOString(),
    startedAt: row.startedAt.toISOString(),
    dueAt: row.dueAt.toISOString(),
    applicability: row.applicability,
    seriousHarm: row.seriousHarm,
    seriousHarmRationale: row.seriousHarmRationale,
    seriousHarmBy: row.seriousHarmBy,
    seriousHarmAt: row.seriousHarmAt?.toISOString() ?? null,
    decision: row.decision,
    decisionRationale: row.decisionRationale,
    decisionBy: row.decisionBy,
    decisionAt: row.decisionAt?.toISOString() ?? null,
    legalReview: row.legalReview,
    insurerPolicy: row.insurerPolicy,
    referrals: row.referrals,
    reminders: view.reminders,
    drafts: view.drafts.map((item) => ({ kind: item.kind, body: item.body, createdAt: item.createdAt.toISOString(), authorName: item.authorName })),
    events: view.events.map((item) => ({ at: item.occurredAt.toISOString(), title: item.title, detail: item.detail })),
  };
}

export async function obligationPdf(ctx: AccessContext, incidentId: string) {
  const view = await getObligation(ctx, incidentId);
  if (!view) throw new ObligationError("missing");
  return toPdf("Breach assessment evidence pack", buildEvidencePack(toPack(view)));
}

type OpenCase = { incidentId: string; tenantId: string; startedAt: Date; dueAt: Date; decision: BreachDecision | null };

async function remindOne(tx: Tx, row: OpenCase, now: number): Promise<{ incidentId: string; reminderKey: string | null; decision: EscalationDecision } | null> {
  const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, row.incidentId), eq(incidents.tenantId, row.tenantId)));
  if (!inc) return null;
  const deliveries = await tx.select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc.id));
  const attempted = deliveries.flatMap((item) => {
    const key = obligationKey(item.detail);
    return key ? [key] : [];
  });
  const due = dueReminders(row.startedAt, new Date(now), attempted);
  if (!due.length) return null;
  const [policy] = await tx.select().from(escalationPolicies).where(eq(escalationPolicies.tenantId, row.tenantId));
  const steps = Array.isArray(policy?.steps) ? policy.steps as EscalationStep[] : [];
  const attempts = deliveries.flatMap((item) => {
    if (!obligationKey(item.detail)) return [];
    return [{
      at: item.createdAt.getTime(),
      channel: item.channel as Channel,
      contact: item.destination,
      status: item.status === "failed" ? "failed" as const : "sent" as const,
    }];
  });
  // "I've read this" stops incident paging. It must not stop the 30-day assessment clock.
  const decision = decideEscalation({ steps, severity: inc.severity, acknowledged: false, attempts, now });
  if (decision.action !== "send") return { incidentId: inc.id, reminderKey: null, decision };
  const key = due[0]!;
  const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, row.tenantId));
  const noteBody = {
    event: "obligation.reminder",
    tenant: { id: row.tenantId, name: tenantRow?.name ?? "Customer" },
    title: inc.title,
    severity: inc.severity,
    url: `${env().APP_URL}/portal/incidents/${inc.id}`,
    summary: `Assessment clock reminder, day ${key} of 30. Due ${row.dueAt.toISOString().slice(0, 10)}. This is not a notice to the OAIC. ${NOT_ADVICE}`,
    to: decision.contact,
  };
  const [connector] = await tx.select().from(integrations).where(and(eq(integrations.tenantId, row.tenantId), eq(integrations.enabled, true), eq(integrations.provider, decision.channel)));
  let status: "sent" | "failed" = "failed";
  let providerRef: string | null = null;
  let detail = "no connector";
  if (connector) {
    try {
      const sent = await notifier(connector)?.deliver(noteBody);
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
    tenantId: row.tenantId,
    incidentId: inc.id,
    provider: connector?.provider ?? decision.channel,
    channel: decision.channel,
    destination: decision.contact,
    status,
    providerRef,
    detail: { detail, kind: "obligation", reminderKey: key },
  });
  await addTimeline(tx, {
    tenantId: row.tenantId,
    incidentId: inc.id,
    origin: "machine",
    category: "obligation",
    title: `Clock reminder day ${key}`,
    detail: `${status} by ${decision.channel} to ${decision.contact}.`,
    actorId: null,
  });
  await audit(tx, {
    actorId: null,
    actorKind: "system",
    tenantId: row.tenantId,
    action: "notify.delivery",
    targetType: "incident",
    targetId: inc.id,
    detail: { channel: decision.channel, status, destination: decision.contact, kind: "obligation", reminderKey: key },
  });
  return { incidentId: inc.id, reminderKey: key, decision };
}

export async function runDueObligationReminders(now = Date.now()) {
  const open = await systemDb().select({
    incidentId: obligationCases.incidentId,
    tenantId: obligationCases.tenantId,
    startedAt: obligationCases.startedAt,
    dueAt: obligationCases.dueAt,
    decision: obligationCases.decision,
  }).from(obligationCases);
  const out: { incidentId: string; reminderKey: string | null; decision: EscalationDecision }[] = [];
  for (const row of open) {
    if (row.decision === "eligible" || row.decision === "not_eligible") continue;
    const result = await withScope(systemScope(row.tenantId), (tx) => remindOne(tx, row, now));
    if (result) out.push(result);
  }
  return out;
}
