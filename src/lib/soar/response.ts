import { and, asc, desc, eq, inArray, isNull, lt, or, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import type { Tx } from "@/db/client";
import { approvals, assetSources, integrations, playbookRuns, playbookRunSteps, responseActions, tenants, user } from "@/db/schema";
import { withScope } from "@/db/scope";
import { can, systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { eventProvider } from "@/lib/connectors/instances";
import type { ResponseActionState } from "@/lib/providers/types";
import { systemDb } from "@/db/client";
import { publish } from "@/lib/events";
import { queue, QUEUES, type QueueName } from "@/lib/queue";
import { expireDfirApproval, settleDfirApproval } from "@/lib/services/dfir";
import { addTimeline } from "@/lib/services/incidents";
import { AccessDenied } from "@/lib/services/common";
import { RESPONSE_ACTIONS, type ResponseActionKey } from "./actions";
import { decidePending, isPendingResult, type PendingResult } from "./pending";
import { logger } from "@/lib/obs/log";

export type RequestInput = {
  tenantId: string;
  action: ResponseActionKey;
  target: { assetId?: string; ip?: string; identity?: string; observable?: string; process?: string; ruleId?: string; grantId?: string };
  reason: string;
  requestedBy: string | null;
  requestedByKind: "user" | "playbook" | "ai";
  alertId?: string | null;
  incidentId?: string | null;
  playbookRunId?: string | null;
};

/**
 * Whether a response action waits for a human. Destructive actions always do, except
 * playbook requests on tenants whose platform admin enabled auto-containment. Anything a
 * model proposes waits, destructive or not: releasing an endpoint or unblocking an IOC on
 * a model's word is as consequential as blocking one.
 */
export function responseNeedsApproval(input: { destructive: boolean; requestedByKind: RequestInput["requestedByKind"]; autoContainment: boolean }) {
  if (input.requestedByKind === "ai") return { needsApproval: true, autoAllowed: false };
  const autoAllowed = input.requestedByKind === "playbook" && input.autoContainment;
  return { needsApproval: input.destructive && !autoAllowed, autoAllowed };
}

/** Creates a response action, with an approval gate when responseNeedsApproval says so. */
export async function requestResponseAction(tx: Tx, input: RequestInput) {
  const def = RESPONSE_ACTIONS[input.action];
  const [tenant] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, input.tenantId));
  if (!tenant) throw new AccessDenied("tenant not in scope");
  const { needsApproval, autoAllowed } = responseNeedsApproval({ destructive: def.destructive, requestedByKind: input.requestedByKind, autoContainment: tenant.settings.autoContainment });

  const [action] = await tx
    .insert(responseActions)
    .values({
      tenantId: input.tenantId,
      action: input.action,
      target: input.target,
      destructive: def.destructive,
      status: needsApproval ? "AWAITING_APPROVAL" : "APPROVED",
      reason: input.reason,
      requestedBy: input.requestedBy,
      requestedByKind: input.requestedByKind,
      alertId: input.alertId ?? null,
      incidentId: input.incidentId ?? null,
      playbookRunId: input.playbookRunId ?? null,
    })
    .returning();

  let approvalId: string | null = null;
  if (needsApproval) {
    const [ap] = await tx
      .insert(approvals)
      .values({
        tenantId: input.tenantId,
        kind: "response_action",
        refId: action!.id,
        summary: `${def.label}: ${describeTarget(input.target)} — ${input.reason}`,
        destructive: def.destructive,
        requestedBy: input.requestedBy,
        requestedByKind: input.requestedByKind,
        expiresAt: new Date(Date.now() + 24 * 3600_000),
      })
      .returning();
    approvalId = ap!.id;
    await tx.update(responseActions).set({ approvalId }).where(eq(responseActions.id, action!.id));
  }
  if (input.incidentId) {
    await addTimeline(tx, {
      tenantId: input.tenantId, incidentId: input.incidentId, origin: input.requestedByKind === "user" ? "analyst" : input.requestedByKind === "ai" ? "ai" : "machine",
      category: "response", title: `${def.label} ${needsApproval ? "requested (awaiting approval)" : "approved"}`, detail: describeTarget(input.target), actorId: input.requestedBy, refType: "response_action", refId: action!.id,
    });
  }
  await audit(tx, { actorId: input.requestedBy, actorKind: input.requestedByKind === "user" ? "user" : input.requestedByKind, tenantId: input.tenantId, action: "response.request", targetType: "response_action", targetId: action!.id, detail: { ...input, needsApproval, autoAllowed } });
  return { action: action!, approvalId, needsApproval };
}

export function describeTarget(t: RequestInput["target"]) {
  return [t.assetId && `asset ${t.assetId.slice(0, 8)}`, t.ip && `ip ${t.ip}`, t.identity && `identity ${t.identity}`, t.observable && `ioc ${t.observable}`, t.process && `process ${t.process}`, t.ruleId && `rule ${t.ruleId}`, t.grantId && `grant ${t.grantId}`].filter(Boolean).join(", ") || "n/a";
}

/** Analyst-initiated request from the UI. */
export async function requestFromUser(ctx: AccessContext, input: Omit<RequestInput, "requestedBy" | "requestedByKind">, via: "user" | "ai" = "user") {
  if (!can(ctx, "response:request", input.tenantId)) throw new AccessDenied("missing response:request");
  const res = await withScope({ tenantIds: [input.tenantId], platform: false }, (tx) => requestResponseAction(tx, { ...input, requestedBy: ctx.principal.userId, requestedByKind: via }));
  if (res.approvalId) await publish({ type: "approval.requested", tenantId: input.tenantId, id: res.approvalId, summary: RESPONSE_ACTIONS[input.action].label });
  else await queueExecute(input.tenantId, res.action.id);
  return res;
}

const requester = alias(user, "requester");
const decider = alias(user, "decider");

export async function listApprovals(ctx: AccessContext, status: "PENDING" | "ALL" = "PENDING") {
  const tenantIds = ctx.tenantIds.filter((t) => can(ctx, "response:approve", t) || can(ctx, "playbook:read", t));
  if (!tenantIds.length) return [];
  return withScope({ tenantIds, platform: false }, (tx) =>
    tx
      .select({ approval: approvals, tenantName: tenants.name, requesterName: requester.name, deciderName: decider.name, action: responseActions })
      .from(approvals)
      .innerJoin(tenants, eq(tenants.id, approvals.tenantId))
      .leftJoin(requester, eq(requester.id, approvals.requestedBy))
      .leftJoin(decider, eq(decider.id, approvals.decidedBy))
      .leftJoin(responseActions, and(eq(approvals.kind, "response_action"), eq(responseActions.id, approvals.refId)))
      .where(and(inArray(approvals.tenantId, tenantIds), status === "PENDING" ? eq(approvals.status, "PENDING") : undefined))
      // Pending: oldest first (closest to expiry). History: newest first.
      .orderBy(status === "PENDING" ? asc(approvals.createdAt) : desc(approvals.createdAt))
      .limit(200),
  );
}

/** Human decision on an approval gate. Approval of a response action queues execution. */
export async function decideApproval(ctx: AccessContext, approvalId: string, decision: "APPROVED" | "REJECTED", note: string) {
  const res = await withScope({ tenantIds: ctx.tenantIds, platform: false }, async (tx) => {
    // Locked so the expiry job and a human decision cannot both settle the same approval.
    const [ap] = await tx.select().from(approvals).where(eq(approvals.id, approvalId)).for("update");
    if (!ap) throw new AccessDenied("approval not found");
    if (!can(ctx, "response:approve", ap.tenantId)) throw new AccessDenied("missing response:approve");
    if (ap.status !== "PENDING") throw new Error(`approval already ${ap.status}`);
    // Expire inside the transaction and report after it commits; throwing here would roll the expiry back.
    if (ap.expiresAt && ap.expiresAt < new Date()) return { ap, act: null, expired: await expireApproval(tx, ap, new Date()) };
    await tx.update(approvals).set({ status: decision, decidedBy: ctx.principal.userId, decidedAt: new Date(), decisionNote: note }).where(and(eq(approvals.id, ap.id), eq(approvals.status, "PENDING")));
    await audit(tx, { actorId: ctx.principal.userId, actorKind: "user", tenantId: ap.tenantId, action: `approval.${decision.toLowerCase()}`, targetType: ap.kind, targetId: ap.refId, detail: { approvalId, note, requestedByKind: ap.requestedByKind } });

    if (ap.kind === "response_action") {
      const [act] = await tx.update(responseActions).set({ status: decision === "APPROVED" ? "APPROVED" : "REJECTED" }).where(eq(responseActions.id, ap.refId)).returning();
      if (act?.incidentId) {
        await addTimeline(tx, { tenantId: ap.tenantId, incidentId: act.incidentId, origin: "analyst", category: "response", title: `${RESPONSE_ACTIONS[act.action as ResponseActionKey]?.label ?? act.action} ${decision.toLowerCase()} by ${ctx.principal.name}`, detail: note || null, actorId: ctx.principal.userId, refType: "response_action", refId: act.id });
      }
      return { ap, act, expired: null };
    }
    if (ap.kind === "dfir_collection") {
      await settleDfirApproval(tx, ap.refId, decision, { userId: ctx.principal.userId, name: ctx.principal.name }, new Date());
      return { ap, act: null, expired: null };
    }
    return { ap, act: null, expired: null };
  });
  if (res.expired) {
    await afterExpiry(res.expired);
    throw new Error("approval expired");
  }
  if (res.ap.kind === "response_action" && decision === "APPROVED") {
    await queueExecute(res.ap.tenantId, res.ap.refId);
  }
  // Playbook runs waiting on this gate resume (or stop) in the worker.
  const runId = res.act?.playbookRunId ?? (res.ap.kind === "playbook_step" ? res.ap.refId : null);
  if (runId) await queueResume(res.ap.tenantId, runId, approvalId, decision);
  await publish({ type: "response.updated", tenantId: res.ap.tenantId, id: res.ap.refId, status: decision });
  return res.ap;
}

type ExpiredApproval = { tenantId: string; approvalId: string; refId: string; runId: string | null };

/**
 * Marks a lapsed approval EXPIRED and settles what waited on it the way a rejection would:
 * the response action is rejected, a DFIR collection is not run. Call inside a transaction.
 */
async function expireApproval(tx: Tx, ap: typeof approvals.$inferSelect, now: Date): Promise<ExpiredApproval | null> {
  const [row] = await tx.update(approvals).set({ status: "EXPIRED", decidedAt: now, decisionNote: "expired without a decision" }).where(and(eq(approvals.id, ap.id), eq(approvals.status, "PENDING"))).returning();
  if (!row) return null;
  await audit(tx, { actorId: null, actorKind: "system", tenantId: ap.tenantId, action: "approval.expired", targetType: ap.kind, targetId: ap.refId, detail: { approvalId: ap.id, requestedByKind: ap.requestedByKind } });
  let runId: string | null = ap.kind === "playbook_step" ? ap.refId : null;
  if (ap.kind === "response_action") {
    const [act] = await tx.update(responseActions).set({ status: "REJECTED" }).where(and(eq(responseActions.id, ap.refId), eq(responseActions.status, "AWAITING_APPROVAL"))).returning();
    if (act?.incidentId) {
      await addTimeline(tx, { tenantId: ap.tenantId, incidentId: act.incidentId, origin: "machine", category: "response", title: `${RESPONSE_ACTIONS[act.action as ResponseActionKey]?.label ?? act.action} expired without a decision`, refType: "response_action", refId: act.id });
    }
    runId = act?.playbookRunId ?? null;
  }
  if (ap.kind === "dfir_collection") await expireDfirApproval(tx, ap.refId);
  return { tenantId: ap.tenantId, approvalId: ap.id, refId: ap.refId, runId };
}

/** How many times recovery retries a job that has failed all its BullMQ attempts before giving up. */
export const MAX_RECOVERIES = 3;

/**
 * Add a job at most once per id. A waiting, active or completed job means the work is queued or
 * done. A failed job is retried up to MAX_RECOVERIES times; after that `onGiveUp` settles the work
 * so recovery stops selecting it.
 */
async function queueOnce(name: QueueName, jobName: string, data: Record<string, unknown>, jobId: string, onGiveUp: () => Promise<void>) {
  const q = queue(name);
  const existing = await q.getJob(jobId);
  if (!existing) return void (await q.add(jobName, data, { jobId }));
  if (!(await existing.isFailed())) return;
  const recoveries = Number(existing.data?.recoveries ?? 0);
  if (recoveries >= MAX_RECOVERIES) return onGiveUp();
  await existing.updateData({ ...existing.data, recoveries: recoveries + 1 });
  // A failed job has used all its BullMQ attempts; give each recovery a full set again.
  await existing.retry("failed", { resetAttemptsMade: true, resetAttemptsStarted: true });
}

/** Queue execution of an APPROVED response action. Safe to call more than once. */
export async function queueExecute(tenantId: string, actionId: string) {
  await queueOnce(QUEUES.response, "execute", { tenantId, actionId }, `execute-${actionId}`, async () => {
    await withScope(systemScope(tenantId), (tx) =>
      tx.update(responseActions).set({ status: "FAILED", result: { error: `execution job failed after ${MAX_RECOVERIES} recoveries` } }).where(and(eq(responseActions.id, actionId), eq(responseActions.status, "APPROVED"))),
    );
    logger.warn("gave up executing response action", { actionId, recoveries: MAX_RECOVERIES });
  });
}

/** Queue the worker to resume (or stop) a run after its gate was decided. Safe to call more than once. */
async function queueResume(tenantId: string, runId: string, approvalId: string, decision: "APPROVED" | "REJECTED", reason?: string) {
  await queueOnce(QUEUES.playbook, "resume", { tenantId, runId, approvalId, decision, ...(reason ? { reason } : {}) }, `resume-${runId}-${approvalId}`, async () => {
    await withScope(systemScope(tenantId), (tx) =>
      tx.update(playbookRuns).set({ status: "FAILED", error: `resume failed after ${MAX_RECOVERIES} recoveries`, finishedAt: new Date() }).where(and(eq(playbookRuns.id, runId), eq(playbookRuns.status, "WAITING_APPROVAL"))),
    );
    logger.warn("gave up resuming playbook run", { runId, recoveries: MAX_RECOVERIES });
  });
}

/** After the expiry commits: stop the waiting playbook run and tell live views. */
async function afterExpiry(e: ExpiredApproval) {
  if (e.runId) await queueResume(e.tenantId, e.runId, e.approvalId, "REJECTED", "approval expired");
  await publish({ type: "response.updated", tenantId: e.tenantId, id: e.refId, status: "EXPIRED" });
}

/** Follow-up work decided longer ago than this is closed, not run late: a stale isolate or disable is worse than none. */
export const RECOVERY_WINDOW_MS = 24 * 3600_000;
/** An action EXECUTING this long with no pending provider reference was interrupted (worker killed, write failed). */
export const EXECUTION_STALE_MS = 30 * 60_000;

/**
 * Work whose follow-up job may never have been queued (e.g. Redis was down after the commit):
 * runs still WAITING_APPROVAL on a settled gate, and APPROVED response actions that never started.
 * Queueing is idempotent per job id, so work already queued or done is not repeated. Anything
 * decided more than RECOVERY_WINDOW_MS ago is closed with an audit row instead of run late.
 */
export async function recoverStalledRuns(now = new Date()) {
  const cutoff = new Date(now.getTime() - RECOVERY_WINDOW_MS);
  const stalled = await systemDb()
    .select({ tenantId: playbookRuns.tenantId, runId: playbookRuns.id, approvalId: approvals.id, status: approvals.status, decidedAt: approvals.decidedAt })
    .from(playbookRuns)
    .innerJoin(playbookRunSteps, and(eq(playbookRunSteps.runId, playbookRuns.id), eq(playbookRunSteps.status, "WAITING_APPROVAL")))
    .innerJoin(approvals, eq(approvals.id, playbookRunSteps.approvalId))
    .where(and(eq(playbookRuns.status, "WAITING_APPROVAL"), inArray(approvals.status, ["APPROVED", "REJECTED", "EXPIRED"])))
    .limit(500);
  for (const row of stalled) {
    if (!row.decidedAt || row.decidedAt < cutoff) {
      await withScope(systemScope(row.tenantId), async (tx) => {
        const [run] = await tx.update(playbookRuns).set({ status: "CANCELLED", error: "gate settled over 24 hours ago without resuming; not continued", finishedAt: now }).where(and(eq(playbookRuns.id, row.runId), eq(playbookRuns.status, "WAITING_APPROVAL"))).returning({ id: playbookRuns.id });
        if (run) await audit(tx, { actorId: null, actorKind: "system", tenantId: row.tenantId, action: "playbook.stale_cancel", targetType: "playbook_run", targetId: row.runId, detail: { approvalId: row.approvalId, decision: row.status } });
      });
      continue;
    }
    await queueResume(row.tenantId, row.runId, row.approvalId, row.status === "APPROVED" ? "APPROVED" : "REJECTED", row.status === "EXPIRED" ? "approval expired" : undefined);
  }

  const approved = await systemDb()
    .select({ tenantId: responseActions.tenantId, id: responseActions.id, incidentId: responseActions.incidentId, action: responseActions.action, createdAt: responseActions.createdAt, decidedAt: approvals.decidedAt })
    .from(responseActions)
    .leftJoin(approvals, eq(approvals.id, responseActions.approvalId))
    .where(eq(responseActions.status, "APPROVED"))
    .limit(500);
  for (const row of approved) {
    // Approved by a human (decidedAt) or approved on creation (no gate: createdAt).
    const approvedAt = row.decidedAt ?? row.createdAt;
    if (approvedAt < cutoff) {
      await withScope(systemScope(row.tenantId), async (tx) => {
        const [act] = await tx.update(responseActions).set({ status: "FAILED", result: { message: "approved over 24 hours ago and never executed; request it again if still needed" } }).where(and(eq(responseActions.id, row.id), eq(responseActions.status, "APPROVED"))).returning({ id: responseActions.id });
        if (!act) return;
        if (row.incidentId) await addTimeline(tx, { tenantId: row.tenantId, incidentId: row.incidentId, origin: "machine", category: "response", title: `${actionLabel(row.action)} not executed: approval is stale`, refType: "response_action", refId: row.id });
        await audit(tx, { actorId: null, actorKind: "system", tenantId: row.tenantId, action: "response.stale_fail", targetType: "response_action", targetId: row.id, detail: { approvedAt: approvedAt.toISOString() } });
      });
      continue;
    }
    await queueExecute(row.tenantId, row.id);
  }

  // Interrupted executions: claimed long ago, never settled, and not waiting on a provider (those have their own timeout).
  const staleBefore = new Date(now.getTime() - EXECUTION_STALE_MS);
  const interrupted = await systemDb()
    .select({ tenantId: responseActions.tenantId, id: responseActions.id, incidentId: responseActions.incidentId, action: responseActions.action })
    .from(responseActions)
    .where(and(
      eq(responseActions.status, "EXECUTING"),
      sql`coalesce(${responseActions.result}->>'pending', 'false') <> 'true'`,
      or(lt(responseActions.claimedAt, staleBefore), and(isNull(responseActions.claimedAt), lt(responseActions.createdAt, staleBefore))),
    ))
    .limit(500);
  for (const row of interrupted) {
    await settleResponseAction(row.tenantId, row.id, row.incidentId, row.action, { ok: false, message: "execution was interrupted before blakSOC recorded a result; check the target system before requesting it again" });
  }
  return stalled.length + approved.length + interrupted.length;
}

/** Worker: expire every approval past its deadline, then repair runs left waiting on a settled gate. */
export async function expireDueApprovals(now: Date) {
  const due = await systemDb().select({ id: approvals.id, tenantId: approvals.tenantId }).from(approvals).where(and(eq(approvals.status, "PENDING"), lt(approvals.expiresAt, now))).limit(500);
  let expired = 0;
  for (const row of due) {
    const res = await withScope(systemScope(row.tenantId), async (tx) => {
      const [ap] = await tx.select().from(approvals).where(eq(approvals.id, row.id)).for("update");
      return ap ? expireApproval(tx, ap, now) : null;
    });
    if (!res) continue;
    expired++;
    // The expiry is committed; a queue failure here is repaired by recoverStalledRuns on the next pass.
    await afterExpiry(res).catch((err: unknown) => logger.warn("approval expiry follow-up failed", { approvalId: res.approvalId, err }));
  }
  const recovered = await recoverStalledRuns();
  return { expired, recovered };
}

/** Tenant-owned connector first, then a platform connector. Exact action wins. block_ioc may fall back to block_ip. */
async function findNetworkConnector(tenantId: string, action: string) {
  const candidates = await systemDb().select().from(integrations).where(and(eq(integrations.enabled, true), or(eq(integrations.tenantId, tenantId), isNull(integrations.tenantId))));
  const ordered = [...candidates.filter((row) => row.tenantId === tenantId), ...candidates.filter((row) => row.tenantId == null)];
  let fallback: (typeof ordered)[number] | undefined;
  for (const candidate of ordered) {
    try {
      const supported = eventProvider(candidate).supportedActions() as string[];
      if (supported.includes(action)) return { row: candidate, providerAction: action };
      if (!fallback && action === "block_ioc" && supported.includes("block_ip")) fallback = candidate;
    } catch {
      /* notifier and intel rows are not event providers */
    }
  }
  if (fallback) return { row: fallback, providerAction: "block_ip" };
  return undefined;
}

/** Worker: execute an APPROVED action against the integration that owns the target asset. */
export async function executeResponseAction(tenantId: string, actionId: string) {
  const scope = systemScope(tenantId);
  const act = await withScope(scope, async (tx) => (await tx.select().from(responseActions).where(eq(responseActions.id, actionId)))[0]);
  if (!act) throw new Error("action not found");
  if (act.status !== "APPROVED") return { skipped: true, status: act.status };
  // Claim the action: only one job moves it from APPROVED to EXECUTING, so a duplicate never runs it twice.
  const claimed = await withScope(scope, (tx) => tx.update(responseActions).set({ status: "EXECUTING", claimedAt: new Date() }).where(and(eq(responseActions.id, actionId), eq(responseActions.status, "APPROVED"))).returning({ id: responseActions.id }));
  if (!claimed.length) return { skipped: true, status: "EXECUTING" };
  let ok = false;
  let message = "";
  let integrationId: string | null = null;
  let providerRef: string | undefined;
  let pending: PendingResult | null = null;
  try {
    const target = act.target as RequestInput["target"];
    let externalId = "";
    let platform: string | undefined;
    let providerAction = act.action;
    let row: typeof integrations.$inferSelect | undefined;
    if (target.assetId) {
      const [src] = await withScope(scope, (tx) => tx.select().from(assetSources).where(eq(assetSources.assetId, target.assetId!)));
      if (!src) throw new Error("asset has no source integration capable of response");
      // Integration rows may be platform-owned; the worker reads them with the owner connection.
      const [found] = await systemDb().select().from(integrations).where(eq(integrations.id, src.integrationId));
      if (!found) throw new Error("integration missing");
      row = found;
      externalId = src.externalId;
      platform = (src.raw as { os?: { platform?: string } } | null)?.os?.platform;
    } else if (target.identity) {
      const candidates = await systemDb().select().from(integrations).where(and(eq(integrations.enabled, true), or(eq(integrations.tenantId, tenantId), isNull(integrations.tenantId))));
      for (const candidate of candidates) {
        try {
          const provider = eventProvider(candidate);
          if (provider.supportedActions().includes(act.action as never)) {
            row = candidate;
            externalId = target.identity;
            break;
          }
        } catch {
          /* notifier and intel rows are not event providers */
        }
      }
      if (!row) throw new Error(`${act.action} requires a connector with identity response capability (not yet configured)`);
    } else if (act.action === "block_ioc" || act.action === "unblock_ioc" || target.observable || target.ip) {
      const indicator = target.observable ?? target.ip;
      if (!indicator) throw new Error(`${act.action} needs an indicator`);
      const found = await findNetworkConnector(tenantId, act.action);
      if (!found) throw new Error(`${act.action} requires a connector with identity/network response capability (not yet configured)`);
      row = found.row;
      providerAction = found.providerAction;
      externalId = indicator;
    } else {
      throw new Error(`${act.action} requires a connector with identity/network response capability (not yet configured)`);
    }
    integrationId = row.id;
    const provider = eventProvider(row);
    const supported = provider.supportedActions() as string[];
    if (providerAction === act.action && act.action === "block_ioc" && !supported.includes("block_ioc") && supported.includes("block_ip")) providerAction = "block_ip";
    if (!supported.includes(providerAction)) throw new Error(`${row.name} does not support ${act.action}`);
    const r = await provider.executeResponseAction({ action: providerAction as never, assetExternalId: externalId, params: { srcip: target.ip ?? target.observable, indicator: target.observable ?? target.ip, arguments: target.process ? [target.process] : [], platform, ruleId: target.ruleId, grantId: target.grantId, actionId } });
    ok = r.ok;
    message = r.message;
    providerRef = r.providerRef;
    // Only providers that can report status may leave an action in flight; others are final as before.
    if (r.ok && r.pending && r.providerRef && provider.getResponseActionStatus) {
      pending = { message: r.message, providerRef: r.providerRef, pending: true, assetExternalId: externalId, dispatchedAt: new Date().toISOString() };
    }
  } catch (err) {
    message = (err as Error).message;
  }
  if (pending) {
    const inFlight = pending;
    await withScope(scope, async (tx) => {
      await tx.update(responseActions).set({ result: inFlight, integrationId }).where(eq(responseActions.id, actionId));
      if (act.incidentId) {
        await addTimeline(tx, { tenantId, incidentId: act.incidentId, origin: "machine", category: "response", title: `${actionLabel(act.action)} sent to endpoint`, detail: inFlight.message, refType: "response_action", refId: actionId });
      }
      await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "response.dispatch", targetType: "response_action", targetId: actionId, detail: { providerRef: inFlight.providerRef, message: inFlight.message } });
    });
    await publish({ type: "response.updated", tenantId, id: actionId, status: "EXECUTING" });
    return { ok: true, message, pending: true };
  }
  await settleResponseAction(tenantId, actionId, act.incidentId, act.action, { ok, message, integrationId, providerRef });
  return { ok, message };
}

function actionLabel(action: string) {
  return RESPONSE_ACTIONS[action as ResponseActionKey]?.label ?? action;
}

/** Final status for an EXECUTING action, with timeline and audit. A second caller finds nothing to settle. */
async function settleResponseAction(
  tenantId: string,
  actionId: string,
  incidentId: string | null,
  action: string,
  outcome: { ok: boolean; message: string; integrationId?: string | null; providerRef?: string },
) {
  const { ok, message, providerRef } = outcome;
  const status = ok ? "SUCCEEDED" : "FAILED";
  const settled = await withScope(systemScope(tenantId), async (tx) => {
    const [row] = await tx
      .update(responseActions)
      .set({ status, result: { message, ...(providerRef ? { providerRef } : {}) }, executedAt: new Date(), ...(outcome.integrationId !== undefined ? { integrationId: outcome.integrationId } : {}) })
      .where(and(eq(responseActions.id, actionId), eq(responseActions.status, "EXECUTING")))
      .returning({ id: responseActions.id });
    if (!row) return false;
    if (incidentId) {
      await addTimeline(tx, { tenantId, incidentId, origin: "machine", category: "response", title: `${actionLabel(action)} ${ok ? "succeeded" : "failed"}`, detail: message, refType: "response_action", refId: actionId });
    }
    await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "response.execute", targetType: "response_action", targetId: actionId, detail: { ok, message, ...(providerRef ? { providerRef } : {}) } });
    return true;
  });
  if (settled) await publish({ type: "response.updated", tenantId, id: actionId, status });
  return settled;
}

/**
 * Worker: ask asynchronous providers about actions still in flight. Each settles as SUCCEEDED or
 * FAILED when the endpoint reports, or FAILED once PENDING_TIMEOUT_MS passes without an answer.
 */
export async function pollPendingResponseActions(now = new Date(), log: (m: string) => void = () => {}) {
  const rows = await systemDb()
    .select()
    .from(responseActions)
    .where(and(eq(responseActions.status, "EXECUTING"), sql`${responseActions.result}->>'pending' = 'true'`));
  let settled = 0;
  for (const act of rows) {
    const result = act.result;
    if (!isPendingResult(result)) continue;
    let state: ResponseActionState | null = null;
    try {
      const [row] = act.integrationId ? await systemDb().select().from(integrations).where(eq(integrations.id, act.integrationId)) : [];
      if (!row) throw new Error("integration missing");
      const provider = eventProvider(row);
      if (!provider.getResponseActionStatus) throw new Error(`${row.name} cannot report action status`);
      state = await provider.getResponseActionStatus({ assetExternalId: result.assetExternalId, providerRef: result.providerRef });
    } catch (err) {
      log(`response ${act.id.slice(0, 8)} status check failed: ${(err as Error).message}`);
    }
    const decision = decidePending(state, new Date(result.dispatchedAt), now);
    if (decision.final) {
      if (await settleResponseAction(act.tenantId, act.id, act.incidentId, act.action, { ok: decision.ok, message: decision.message, providerRef: result.providerRef })) settled++;
    } else if (decision.state && (decision.state.state !== result.providerState || decision.state.message !== result.message)) {
      const next: PendingResult = { ...result, providerState: decision.state.state, message: decision.state.message };
      await withScope(systemScope(act.tenantId), (tx) => tx.update(responseActions).set({ result: next }).where(and(eq(responseActions.id, act.id), eq(responseActions.status, "EXECUTING"))));
    }
  }
  return { checked: rows.length, settled };
}
