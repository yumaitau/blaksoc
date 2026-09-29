import { and, asc, desc, eq, inArray, isNull, or } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import type { Tx } from "@/db/client";
import { approvals, assetSources, integrations, responseActions, tenants, user } from "@/db/schema";
import { withScope } from "@/db/scope";
import { can, systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { eventProvider } from "@/lib/connectors/instances";
import { adminDb } from "@/db/client";
import { publish } from "@/lib/events";
import { queue, QUEUES } from "@/lib/queue";
import { addTimeline } from "@/lib/services/incidents";
import { AccessDenied } from "@/lib/services/common";
import { RESPONSE_ACTIONS, type ResponseActionKey } from "./actions";

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
 * Creates a response action. Destructive actions always get a human approval gate,
 * except playbook-initiated actions on tenants whose admin explicitly enabled
 * auto-containment. AI-initiated actions are never auto-approved.
 */
export async function requestResponseAction(tx: Tx, input: RequestInput) {
  const def = RESPONSE_ACTIONS[input.action];
  const [tenant] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, input.tenantId));
  if (!tenant) throw new AccessDenied("tenant not in scope");
  const autoAllowed = input.requestedByKind === "playbook" && tenant.settings.autoContainment;
  const needsApproval = def.destructive && !autoAllowed;

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
  else await queue(QUEUES.response).add("execute", { tenantId: input.tenantId, actionId: res.action.id });
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
    const [ap] = await tx.select().from(approvals).where(eq(approvals.id, approvalId));
    if (!ap) throw new AccessDenied("approval not found");
    if (!can(ctx, "response:approve", ap.tenantId)) throw new AccessDenied("missing response:approve");
    if (ap.status !== "PENDING") throw new Error(`approval already ${ap.status}`);
    if (ap.expiresAt && ap.expiresAt < new Date()) {
      await tx.update(approvals).set({ status: "EXPIRED" }).where(eq(approvals.id, ap.id));
      throw new Error("approval expired");
    }
    await tx.update(approvals).set({ status: decision, decidedBy: ctx.principal.userId, decidedAt: new Date(), decisionNote: note }).where(eq(approvals.id, ap.id));
    await audit(tx, { actorId: ctx.principal.userId, actorKind: "user", tenantId: ap.tenantId, action: `approval.${decision.toLowerCase()}`, targetType: ap.kind, targetId: ap.refId, detail: { approvalId, note, requestedByKind: ap.requestedByKind } });

    if (ap.kind === "response_action") {
      const [act] = await tx.update(responseActions).set({ status: decision === "APPROVED" ? "APPROVED" : "REJECTED" }).where(eq(responseActions.id, ap.refId)).returning();
      if (act?.incidentId) {
        await addTimeline(tx, { tenantId: ap.tenantId, incidentId: act.incidentId, origin: "analyst", category: "response", title: `${RESPONSE_ACTIONS[act.action as ResponseActionKey]?.label ?? act.action} ${decision.toLowerCase()} by ${ctx.principal.name}`, detail: note || null, actorId: ctx.principal.userId, refType: "response_action", refId: act.id });
      }
      return { ap, act };
    }
    return { ap, act: null };
  });
  if (res.ap.kind === "response_action" && decision === "APPROVED") {
    await queue(QUEUES.response).add("execute", { tenantId: res.ap.tenantId, actionId: res.ap.refId });
  }
  // Playbook runs waiting on this gate resume (or stop) in the worker.
  const runId = res.act?.playbookRunId ?? (res.ap.kind === "playbook_step" ? res.ap.refId : null);
  if (runId) await queue(QUEUES.playbook).add("resume", { tenantId: res.ap.tenantId, runId, approvalId, decision });
  await publish({ type: "response.updated", tenantId: res.ap.tenantId, id: res.ap.refId, status: decision });
  return res.ap;
}

/** Worker: execute an APPROVED action against the integration that owns the target asset. */
export async function executeResponseAction(tenantId: string, actionId: string) {
  const scope = systemScope(tenantId);
  const act = await withScope(scope, async (tx) => (await tx.select().from(responseActions).where(eq(responseActions.id, actionId)))[0]);
  if (!act) throw new Error("action not found");
  if (act.status !== "APPROVED") return { skipped: true, status: act.status };

  await withScope(scope, (tx) => tx.update(responseActions).set({ status: "EXECUTING" }).where(eq(responseActions.id, actionId)));
  let ok = false;
  let message = "";
  let integrationId: string | null = null;
  try {
    const target = act.target as RequestInput["target"];
    let externalId = "";
    let platform: string | undefined;
    let row: typeof integrations.$inferSelect | undefined;
    if (target.assetId) {
      const [src] = await withScope(scope, (tx) => tx.select().from(assetSources).where(eq(assetSources.assetId, target.assetId!)));
      if (!src) throw new Error("asset has no source integration capable of response");
      // Integration rows may be platform-owned; the worker reads them with the owner connection.
      const [found] = await adminDb().select().from(integrations).where(eq(integrations.id, src.integrationId));
      if (!found) throw new Error("integration missing");
      row = found;
      externalId = src.externalId;
      platform = (src.raw as { os?: { platform?: string } } | null)?.os?.platform;
    } else if (target.identity) {
      const candidates = await adminDb().select().from(integrations).where(and(eq(integrations.enabled, true), or(eq(integrations.tenantId, tenantId), isNull(integrations.tenantId))));
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
    } else {
      throw new Error(`${act.action} requires a connector with identity/network response capability (not yet configured)`);
    }
    integrationId = row.id;
    const provider = eventProvider(row);
    const providerAction = act.action === "block_ioc" ? "block_ip" : act.action;
    if (!provider.supportedActions().includes(providerAction as never)) throw new Error(`${row.name} does not support ${act.action}`);
    const r = await provider.executeResponseAction({ action: providerAction as never, assetExternalId: externalId, params: { srcip: target.ip ?? target.observable, arguments: target.process ? [target.process] : [], platform, ruleId: target.ruleId, grantId: target.grantId } });
    ok = r.ok;
    message = r.message;
  } catch (err) {
    message = (err as Error).message;
  }
  await withScope(scope, async (tx) => {
    await tx.update(responseActions).set({ status: ok ? "SUCCEEDED" : "FAILED", result: { message }, executedAt: new Date(), integrationId }).where(eq(responseActions.id, actionId));
    if (act.incidentId) {
      await addTimeline(tx, { tenantId, incidentId: act.incidentId, origin: "machine", category: "response", title: `${RESPONSE_ACTIONS[act.action as ResponseActionKey]?.label ?? act.action} ${ok ? "succeeded" : "failed"}`, detail: message, refType: "response_action", refId: actionId });
    }
    await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "response.execute", targetType: "response_action", targetId: actionId, detail: { ok, message } });
  });
  await publish({ type: "response.updated", tenantId, id: actionId, status: ok ? "SUCCEEDED" : "FAILED" });
  return { ok, message };
}
