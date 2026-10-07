import { and, asc, eq, gt, inArray, isNull } from "drizzle-orm";
import { systemDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  escalationPolicies, incidentTimeline, incidents, integrations, notificationDeliveries, obligationCases, obligationDrafts, reportingClocks, tenants,
} from "@/db/schema";
import { AccessDenied, can, systemScope, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { audit } from "@/lib/audit";
import { notifier } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import {
  CLOCK_KINDS, CLOCK_RULES, CLOCK_ZONES, DAY_MS, assessmentDue, clockDue, dueClockReminder, dueReminders, formatZoned, type ClockKind,
} from "@/lib/obligations/clock";
import {
  ANSWERS, CLOCK_INFO, DECISIONS, DRAFT_KINDS, NOT_ADVICE, REFERRALS, clockApplies, clockDraftBody, draftBody,
  type Answer, type Applicability, type BreachDecision, type DraftKind, type ReferralKey,
} from "@/lib/obligations/model";
import { buildEvidencePack, type EvidencePackInput, type PackMark, type PackReminder } from "@/lib/obligations/report";
import { decideEscalation, type Channel, type EscalationDecision, type EscalationStep } from "@/lib/portal/escalation";
import { toPdf } from "@/lib/reports/export";
import { actor, inTenant, scoped } from "./common";
import { addTimeline } from "./incidents";

export class ObligationError extends Error {
  constructor(readonly code: "incomplete" | "rationale" | "decision" | "referral" | "policy" | "draft" | "missing" | "exists" | "clock" | "time" | "applicability" | "reference") {
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

/** Obligation reminder deliveries. NDB rows carry no clock; SOCI and ransomware rows name theirs. */
function reminderOf(detail: unknown): { clock: string | null; key: string } | null {
  if (!detail || typeof detail !== "object") return null;
  const row = detail as { kind?: unknown; reminderKey?: unknown; clock?: unknown };
  if (row.kind !== "obligation" || typeof row.reminderKey !== "string") return null;
  return { clock: typeof row.clock === "string" ? row.clock : null, key: row.reminderKey };
}

function obligationKey(detail: unknown): string | null {
  const row = reminderOf(detail);
  return row && row.clock === null ? row.key : null;
}

function asApplicability(input: Applicability): Applicability {
  return {
    privacyAct: asAnswer(input.privacyAct),
    healthInformation: asAnswer(input.healthInformation),
    governmentContract: asAnswer(input.governmentContract),
    soci: asAnswer(input.soci),
    ransomwareReporting: asAnswer(input.ransomwareReporting),
  };
}

function asClock(kind: string): ClockKind {
  if (!(CLOCK_KINDS as readonly string[]).includes(kind)) throw new ObligationError("clock");
  return kind as ClockKind;
}

type Delivery = typeof notificationDeliveries.$inferSelect;

function asReminder(item: Delivery, key: string): PackReminder {
  return { key, at: item.createdAt.toISOString(), channel: item.channel, destination: item.destination, status: item.status };
}

function asAttempt(item: Delivery) {
  return {
    at: item.createdAt.getTime(),
    channel: item.channel as Channel,
    contact: item.destination,
    status: item.status === "failed" ? "failed" as const : "sent" as const,
  };
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
  const applicability = asApplicability(input.applicability);
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

/** Answers can change as the facts do. The old answers stay in the audit log. */
export async function updateApplicability(ctx: AccessContext, incidentId: string, input: Applicability) {
  const applicability = asApplicability(input);
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [current] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!current) throw new ObligationError("missing");
    const [row] = await tx.update(obligationCases).set({ applicability }).where(eq(obligationCases.id, current.id)).returning();
    await note(tx, inc.tenantId, inc.id, ctx, "Applicability updated", `${ctx.principal.name}. SOCI ${applicability.soci}. Ransomware payment reporting ${applicability.ransomwareReporting}.`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.applicability", targetType: "incident", targetId: inc.id, detail: { from: current.applicability, to: applicability } });
    return row!;
  });
}

/** Starts a SOCI or ransomware payment clock from the recorded awareness or payment time. */
export async function startClock(ctx: AccessContext, incidentId: string, input: { kind: ClockKind; startedAt: Date; timeZone: string }) {
  const kind = asClock(input.kind);
  if (Number.isNaN(input.startedAt.getTime()) || !(CLOCK_ZONES as readonly string[]).includes(input.timeZone)) throw new ObligationError("time");
  // Awareness and payment are things that already happened. A future start would hold reminders back.
  if (input.startedAt.getTime() > Date.now() + 5 * 60_000) throw new ObligationError("time");
  const inc = await incidentFor(ctx, incidentId);
  const dueAt = clockDue(kind, input.startedAt);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [current] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!current) throw new ObligationError("missing");
    if (!clockApplies(kind, current.applicability)) throw new ObligationError("applicability");
    const [existing] = await tx.select({ id: reportingClocks.id }).from(reportingClocks)
      .where(and(eq(reportingClocks.incidentId, inc.id), eq(reportingClocks.kind, kind))).limit(1);
    if (existing) throw new ObligationError("exists");
    const [row] = await tx.insert(reportingClocks).values({
      tenantId: inc.tenantId, incidentId: inc.id, caseId: current.id, kind, startedAt: input.startedAt, dueAt, timeZone: input.timeZone, startedBy: ctx.principal.name,
    }).returning();
    await note(tx, inc.tenantId, inc.id, ctx, `Clock started: ${CLOCK_INFO[kind].label}`, `${ctx.principal.name}. Due ${formatZoned(dueAt, input.timeZone)}.`);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.clock_start", targetType: "incident", targetId: inc.id, detail: { kind, startedAt: input.startedAt.toISOString(), dueAt: dueAt.toISOString() } });
    return row!;
  });
}

/** Records that a person submitted the report outside blakSOC. Stops the reminders. */
export async function markClockReported(ctx: AccessContext, incidentId: string, input: { kind: ClockKind; reference?: string }) {
  const kind = asClock(input.kind);
  const reference = (input.reference ?? "").trim();
  if (reference.length > 120) throw new ObligationError("reference");
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [row] = await tx.update(reportingClocks).set({ reportedAt: new Date(), reportedBy: ctx.principal.name, reportRef: reference || null })
      .where(and(eq(reportingClocks.incidentId, inc.id), eq(reportingClocks.kind, kind), isNull(reportingClocks.reportedAt))).returning();
    if (!row) throw new ObligationError("missing");
    await note(tx, inc.tenantId, inc.id, ctx, `Marked reported: ${CLOCK_INFO[kind].label}`, `${ctx.principal.name}. ${reference}`.trim());
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "obligation.clock_reported", targetType: "incident", targetId: inc.id, detail: { kind, reference: reference || null } });
    return row;
  });
}

export async function createDraft(ctx: AccessContext, incidentId: string, kind: DraftKind | ClockKind) {
  const isClock = (CLOCK_KINDS as readonly string[]).includes(kind);
  if (!isClock && !(DRAFT_KINDS as readonly string[]).includes(kind)) throw new ObligationError("draft");
  const inc = await incidentFor(ctx, incidentId);
  return inTenant(ctx, writePermission(ctx, inc.tenantId), inc.tenantId, async (tx) => {
    const [current] = await tx.select().from(obligationCases).where(eq(obligationCases.incidentId, inc.id)).limit(1);
    if (!current) throw new ObligationError("missing");
    const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, inc.tenantId));
    let clock: typeof reportingClocks.$inferSelect | undefined;
    if (isClock) {
      [clock] = await tx.select().from(reportingClocks).where(and(eq(reportingClocks.incidentId, inc.id), eq(reportingClocks.kind, kind as ClockKind))).limit(1);
      if (!clock) throw new ObligationError("missing");
    }
    const body = clock ? clockDraftBody(clock.kind, {
      tenantName: tenantRow?.name ?? "Organisation",
      incidentTitle: inc.title,
      startedAt: formatZoned(clock.startedAt, clock.timeZone),
      dueAt: formatZoned(clock.dueAt, clock.timeZone),
      applicability: current.applicability,
      authorName: ctx.principal.name,
    }) : draftBody(kind as DraftKind, {
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
    // A statutory report draft goes to a lawyer before anyone submits it.
    if (clock && !current.legalReview) {
      await tx.update(obligationCases).set({ legalReview: true }).where(eq(obligationCases.id, current.id));
      await note(tx, inc.tenantId, inc.id, ctx, "Legal review requested", `${ctx.principal.name}. Set by the ${CLOCK_INFO[clock.kind].label} draft.`);
    }
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
      return key ? [asReminder(item, key)] : [];
    });
    const clockRows = await tx.select().from(reportingClocks).where(eq(reportingClocks.incidentId, inc.id)).orderBy(asc(reportingClocks.createdAt));
    const clocks = clockRows.map((clock) => ({
      ...clock,
      reminders: deliveries.flatMap((item) => {
        const sent = reminderOf(item.detail);
        return sent && sent.clock === clock.kind ? [asReminder(item, sent.key)] : [];
      }),
    }));
    const events = await tx.select().from(incidentTimeline).where(and(eq(incidentTimeline.incidentId, inc.id), eq(incidentTimeline.category, "obligation"))).orderBy(asc(incidentTimeline.occurredAt));
    return { incident: inc, tenantName: tenantRow?.name ?? "Organisation", case: row, drafts, reminders, clocks, events };
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
    clocks: view.clocks.map((clock) => ({
      kind: clock.kind,
      startedAt: formatZoned(clock.startedAt, clock.timeZone),
      dueAt: formatZoned(clock.dueAt, clock.timeZone),
      startedBy: clock.startedBy,
      reportedAt: clock.reportedAt?.toISOString() ?? null,
      reportedBy: clock.reportedBy,
      reportRef: clock.reportRef,
      reminders: clock.reminders,
    })),
  };
}

export async function obligationPdf(ctx: AccessContext, incidentId: string) {
  const view = await getObligation(ctx, incidentId);
  if (!view) throw new ObligationError("missing");
  return toPdf("Breach assessment evidence pack", buildEvidencePack(toPack(view)));
}

type OpenCase = { incidentId: string; tenantId: string; startedAt: Date; dueAt: Date; decision: BreachDecision | null };
type Sendable = Extract<EscalationDecision, { action: "send" }>;
type Incident = typeof incidents.$inferSelect;

async function escalationSteps(tx: Tx, tenantId: string) {
  const [policy] = await tx.select().from(escalationPolicies).where(eq(escalationPolicies.tenantId, tenantId));
  return Array.isArray(policy?.steps) ? policy.steps as EscalationStep[] : [];
}

/** Sends one obligation reminder through the escalation channel and records it on the delivery log, timeline and audit log. */
async function deliverReminder(tx: Tx, inc: Incident, decision: Sendable, input: { summary: string; title: string; mark: { reminderKey: string; clock?: ClockKind } }) {
  const [tenantRow] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, inc.tenantId));
  const noteBody = {
    event: "obligation.reminder",
    tenant: { id: inc.tenantId, name: tenantRow?.name ?? "Customer" },
    title: inc.title,
    severity: inc.severity,
    url: `${env().APP_URL}/portal/incidents/${inc.id}`,
    summary: input.summary,
    to: decision.contact,
  };
  const [connector] = await tx.select().from(integrations).where(and(eq(integrations.tenantId, inc.tenantId), eq(integrations.enabled, true), eq(integrations.provider, decision.channel)));
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
    tenantId: inc.tenantId,
    incidentId: inc.id,
    provider: connector?.provider ?? decision.channel,
    channel: decision.channel,
    destination: decision.contact,
    status,
    providerRef,
    detail: { detail, kind: "obligation", ...input.mark },
  });
  await addTimeline(tx, {
    tenantId: inc.tenantId,
    incidentId: inc.id,
    origin: "machine",
    category: "obligation",
    title: input.title,
    detail: `${status} by ${decision.channel} to ${decision.contact}.`,
    actorId: null,
  });
  await audit(tx, {
    actorId: null,
    actorKind: "system",
    tenantId: inc.tenantId,
    action: "notify.delivery",
    targetType: "incident",
    targetId: inc.id,
    detail: { channel: decision.channel, status, destination: decision.contact, kind: "obligation", ...input.mark },
  });
}

async function remindOne(tx: Tx, row: OpenCase, now: number): Promise<{ incidentId: string; reminderKey: string | null; decision: EscalationDecision } | null> {
  const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, row.incidentId), eq(incidents.tenantId, row.tenantId)));
  if (!inc) return null;
  const deliveries = (await tx.select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc.id)))
    .filter((item) => obligationKey(item.detail));
  const due = dueReminders(row.startedAt, new Date(now), deliveries.map((item) => obligationKey(item.detail)!));
  if (!due.length) return null;
  const steps = await escalationSteps(tx, row.tenantId);
  // "I've read this" stops incident paging. It must not stop the 30-day assessment clock.
  const decision = decideEscalation({ steps, severity: inc.severity, acknowledged: false, attempts: deliveries.map(asAttempt), now });
  if (decision.action !== "send") return { incidentId: inc.id, reminderKey: null, decision };
  const key = due[0]!;
  await deliverReminder(tx, inc, decision, {
    summary: `Assessment clock reminder, day ${key} of 30. Due ${row.dueAt.toISOString().slice(0, 10)}. This is not a notice to the OAIC. ${NOT_ADVICE}`,
    title: `Clock reminder day ${key}`,
    mark: { reminderKey: key },
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

function hoursLeft(hours: number) {
  if (hours <= 0) return "deadline reached";
  return hours === 1 ? "1 hour left" : `${hours} hours left`;
}

type OpenClock = { incidentId: string; tenantId: string; kind: ClockKind; startedAt: Date; dueAt: Date; timeZone: string };

async function remindClock(tx: Tx, row: OpenClock, now: number): Promise<{ incidentId: string; clock: ClockKind; reminderKey: string | null; decision: EscalationDecision } | null> {
  const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, row.incidentId), eq(incidents.tenantId, row.tenantId)));
  if (!inc) return null;
  // Each clock keeps its own reminder history, so NDB and incident paging attempts do not use up its budget.
  const deliveries = (await tx.select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc.id)))
    .filter((item) => reminderOf(item.detail)?.clock === row.kind);
  const key = dueClockReminder(row.kind, row.startedAt, new Date(now), deliveries.map((item) => reminderOf(item.detail)!.key));
  if (!key) return null;
  const steps = await escalationSteps(tx, row.tenantId);
  // Acknowledging the incident does not stop a statutory clock either.
  const decision = decideEscalation({ steps, severity: inc.severity, acknowledged: false, attempts: deliveries.map(asAttempt), now });
  if (decision.action !== "send") return { incidentId: inc.id, clock: row.kind, reminderKey: null, decision };
  const info = CLOCK_INFO[row.kind];
  const left = hoursLeft(CLOCK_RULES[row.kind].hours - Number(key));
  await deliverReminder(tx, inc, decision, {
    summary: `${info.label}: ${left}. Due ${formatZoned(row.dueAt, row.timeZone)}. blakSOC has not made this report. ${NOT_ADVICE}`,
    title: `Clock reminder: ${info.label}, ${left}`,
    mark: { reminderKey: key, clock: row.kind },
  });
  return { incidentId: inc.id, clock: row.kind, reminderKey: key, decision };
}

export async function runDueClockReminders(now = Date.now()) {
  // Reported clocks are done. A day past the deadline, a reminder no longer helps anyone report on time.
  const open = await systemDb().select({
    incidentId: reportingClocks.incidentId,
    tenantId: reportingClocks.tenantId,
    kind: reportingClocks.kind,
    startedAt: reportingClocks.startedAt,
    dueAt: reportingClocks.dueAt,
    timeZone: reportingClocks.timeZone,
  }).from(reportingClocks).where(and(isNull(reportingClocks.reportedAt), gt(reportingClocks.dueAt, new Date(now - DAY_MS))));
  const out: { incidentId: string; clock: ClockKind; reminderKey: string | null; decision: EscalationDecision }[] = [];
  for (const row of open) {
    const result = await withScope(systemScope(row.tenantId), (tx) => remindClock(tx, row, now));
    if (result) out.push(result);
  }
  return out;
}
