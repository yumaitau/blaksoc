import { and, eq, inArray, isNull, or } from "drizzle-orm";
import { systemDb, type Tx } from "@/db/client";
import {
  alerts, approvals, assets, incidentTasks, integrations, playbookRuns, playbookRunSteps, playbooks, tenants, type PlaybookStep, type PlaybookTrigger,
} from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { intelProviderFor, notifier } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { publish } from "@/lib/events";
import { lookupWithCache, summariseIntel } from "@/lib/intel/enrich";
import { queue, QUEUES } from "@/lib/queue";
import { addTimeline, createIncidentFromAlerts } from "@/lib/services/incidents";
import { isResponseAction, RESPONSE_ACTIONS } from "./actions";
import { allHold, evaluate, getPath } from "./conditions";
import { responseHintOf, type ResponseHint } from "./hint";
import { queueExecute, requestResponseAction } from "./response";

type RunCtx = Record<string, unknown> & { tenantId: string; alertId?: string; incidentId?: string };
type StepResult = { status: "SUCCEEDED" | "SKIPPED" | "WAITING_APPROVAL" | "FAILED"; output?: unknown; approvalId?: string; error?: string };
type StepHandler = (tx: Tx, step: PlaybookStep, run: { id: string; tenantId: string }, ctx: RunCtx) => Promise<StepResult>;

/** Non-destructive step handlers. Response actions are routed through the approval-gated path below. */
export const STEP_ACTIONS: Record<string, { label: string; handler: StepHandler }> = {
  "intel.enrich": {
    label: "Query OpenCTI",
    handler: async (_tx, _s, run, ctx) => {
      const intel = await intelProviderFor(systemDb(), run.tenantId);
      if (!intel) return { status: "SKIPPED", output: "no threat intel integration" };
      const obs = ((ctx.alert as { intel?: { matches?: { observable: { type: string; value: string } }[] } } | undefined)?.intel?.matches ?? []).map((m) => m.observable);
      const { matches } = await lookupWithCache(intel.provider, obs as never);
      ctx.intel = summariseIntel(matches);
      return { status: "SUCCEEDED", output: { verdict: (ctx.intel as { verdict: string }).verdict, matches: matches.length } };
    },
  },
  "asset.context": {
    label: "Check asset importance",
    handler: async (tx, _s, _run, ctx) => {
      const assetId = (ctx.alert as { assetId?: string } | undefined)?.assetId;
      if (!assetId) return { status: "SKIPPED", output: "alert has no asset" };
      const [a] = await tx.select().from(assets).where(eq(assets.id, assetId));
      ctx.asset = a ? { id: a.id, name: a.name, criticality: a.criticality, exposure: a.exposure, kind: a.kind, agentStatus: a.agentStatus } : null;
      return { status: "SUCCEEDED", output: ctx.asset };
    },
  },
  "endpoint.context": {
    label: "Gather endpoint context",
    handler: async (tx, _s, _run, ctx) => {
      const asset = ctx.asset as { id: string } | undefined;
      if (!asset) return { status: "SKIPPED", output: "no asset" };
      const [a] = await tx.select({ os: assets.os, ips: assets.ips, software: assets.software, agentStatus: assets.agentStatus, lastSeen: assets.lastSeen }).from(assets).where(eq(assets.id, asset.id));
      ctx.endpoint = a;
      return { status: "SUCCEEDED", output: a };
    },
  },
  "incident.create": {
    label: "Create incident",
    handler: async (tx, s, run, ctx) => {
      if (ctx.incidentId) return { status: "SKIPPED", output: "incident exists" };
      if (!ctx.alertId) return { status: "SKIPPED", output: "no alert" };
      const [a] = await tx.select({ incidentId: alerts.incidentId }).from(alerts).where(eq(alerts.id, ctx.alertId));
      if (a?.incidentId) {
        ctx.incidentId = a.incidentId;
        return { status: "SKIPPED", output: "alert already in incident" };
      }
      const inc = await createIncidentFromAlerts(null, { tenantId: run.tenantId, alertIds: [ctx.alertId], title: s.params?.title as string | undefined }, tx);
      ctx.incidentId = inc.id;
      await addTimeline(tx, { tenantId: run.tenantId, incidentId: inc.id, origin: "machine", category: "response", title: `Playbook opened incident`, refType: "playbook_run", refId: run.id });
      return { status: "SUCCEEDED", output: { incidentId: inc.id } };
    },
  },
  notify: {
    label: "Notify analyst",
    handler: async (tx, s, run, ctx) => {
      const rows = await systemDb()
        .select()
        .from(integrations)
        .where(and(inArray(integrations.category, ["collaboration", "ticketing"]), eq(integrations.enabled, true), or(eq(integrations.tenantId, run.tenantId), isNull(integrations.tenantId))));
      const [t] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, run.tenantId));
      const alert = ctx.alert as { title?: string; severity?: string } | undefined;
      let sent = 0;
      const failed: { integration: string; error: string }[] = [];
      for (const row of rows) {
        const n = notifier(row);
        if (!n) continue;
        await n.send({
          event: "playbook.notify",
          tenant: { id: run.tenantId, name: t?.name ?? "" },
          title: (s.params?.title as string) ?? alert?.title ?? "blakSOC notification",
          severity: alert?.severity,
          url: `${env().APP_URL}/soc/${ctx.incidentId ? `incidents/${ctx.incidentId}` : `alerts/${ctx.alertId}`}`,
          summary: (s.params?.message as string) ?? "Playbook requires analyst attention.",
        }).then(() => sent++).catch((err: unknown) => failed.push({ integration: row.name, error: err instanceof Error ? err.message : String(err) }));
      }
      // Partial delivery succeeds with the failures recorded; nothing delivered fails the step.
      if (failed.length && !sent) return { status: "FAILED", output: { channels: 0, failed }, error: `notification failed: ${failed.map((f) => `${f.integration}: ${f.error}`).join("; ")}` };
      return { status: "SUCCEEDED", output: { channels: sent, failed } };
    },
  },
  "approval.request": {
    label: "Request human approval",
    handler: async (tx, s, run) => {
      const [ap] = await tx
        .insert(approvals)
        .values({ tenantId: run.tenantId, kind: "playbook_step", refId: run.id, summary: (s.params?.summary as string) ?? `Playbook gate: ${s.name}`, destructive: false, requestedByKind: "playbook", expiresAt: new Date(Date.now() + 24 * 3600_000) })
        .returning();
      return { status: "WAITING_APPROVAL", approvalId: ap!.id };
    },
  },
  "record.note": {
    label: "Record actions",
    handler: async (tx, s, run, ctx) => {
      if (!ctx.incidentId) return { status: "SKIPPED" };
      await addTimeline(tx, { tenantId: run.tenantId, incidentId: ctx.incidentId, origin: "machine", category: "response", title: (s.params?.title as string) ?? "Playbook completed", detail: (s.params?.detail as string) ?? null, refType: "playbook_run", refId: run.id });
      return { status: "SUCCEEDED" };
    },
  },
  "task.create": {
    label: "Create customer tasks",
    handler: async (tx, s, run, ctx) => {
      if (!ctx.incidentId) return { status: "SKIPPED", output: "no incident" };
      const titles = Array.isArray(s.params?.titles) ? (s.params.titles as string[]) : [];
      for (const title of titles) await tx.insert(incidentTasks).values({ tenantId: run.tenantId, incidentId: ctx.incidentId, title });
      return { status: "SUCCEEDED", output: { tasks: titles.length } };
    },
  },
};

async function responseStep(tx: Tx, step: PlaybookStep, run: { id: string; tenantId: string }, ctx: RunCtx): Promise<StepResult> {
  if (!isResponseAction(step.action)) return { status: "FAILED", error: `unknown action ${step.action}` };
  const alert = ctx.alert as { id: string; assetId?: string | null; userName?: string | null; intel?: { matches?: { verdict: string; observable: { type: string; value: string } }[] } } | undefined;
  const badIp = alert?.intel?.matches?.find((m) => m.verdict === "malicious" && m.observable.type.startsWith("ip"))?.observable.value;
  const badIoc = alert?.intel?.matches?.find((m) => m.verdict === "malicious")?.observable.value;
  const hint = (alert as { responseHint?: ResponseHint } | undefined)?.responseHint;
  const identityAction = step.action === "disable_identity" || step.action === "revoke_sessions" || step.action === "require_mfa" || step.action === "remove_inbox_rule" || step.action === "revoke_oauth_grant" || step.action === "suspend_user" || step.action === "sign_out" || step.action === "reset_signin_cookies" || step.action === "revoke_oauth_token" || step.action === "reset_password";
  const target = {
    assetId: alert?.assetId ?? undefined,
    identity: identityAction ? (alert?.userName ?? undefined) : undefined,
    ip: step.action === "block_ip" ? badIp : undefined,
    observable: step.action === "block_ioc" || step.action === "unblock_ioc" ? (badIoc ?? (typeof step.params?.indicator === "string" ? step.params.indicator : undefined)) : undefined,
    process: step.action === "kill_process" ? (typeof step.params?.process === "string" ? step.params.process : hint?.process) : undefined,
    ruleId: hint?.ruleId,
    grantId: hint?.grantId,
  };
  const res = await requestResponseAction(tx, {
    tenantId: run.tenantId, action: step.action, target, reason: `Playbook step "${step.name}"`, requestedBy: null, requestedByKind: "playbook",
    alertId: ctx.alertId ?? null, incidentId: ctx.incidentId ?? null, playbookRunId: run.id,
  });
  if (res.needsApproval) return { status: "WAITING_APPROVAL", approvalId: res.approvalId!, output: { actionId: res.action.id } };
  await queueExecute(run.tenantId, res.action.id);
  return { status: "SUCCEEDED", output: { actionId: res.action.id, autoContainment: true } };
}

/** Catalogue for the playbook builder UI. */
export function stepCatalogue() {
  return [
    ...Object.entries(STEP_ACTIONS).map(([key, v]) => ({ key, label: v.label, destructive: false })),
    ...Object.entries(RESPONSE_ACTIONS).map(([key, v]) => ({ key, label: v.label, destructive: v.destructive })),
  ];
}

/** Start runs for every enabled playbook whose trigger matches. */
export async function evaluateTriggers(tenantId: string, event: PlaybookTrigger["event"], payload: { alertId?: string; incidentId?: string }) {
  const started: string[] = [];
  await withScope(systemScope(tenantId), async (tx) => {
    const books = await tx.select().from(playbooks).where(and(eq(playbooks.enabled, true), or(eq(playbooks.tenantId, tenantId), isNull(playbooks.tenantId))));
    const [alert] = payload.alertId ? await tx.select().from(alerts).where(eq(alerts.id, payload.alertId)) : [];
    const [asset] = alert?.assetId ? await tx.select().from(assets).where(eq(assets.id, alert.assetId)) : [];
    const responseHint = responseHintOf(alert?.raw);
    const ctx: RunCtx = { tenantId, alertId: payload.alertId, incidentId: payload.incidentId ?? alert?.incidentId ?? undefined, alert: alert ? { ...alert, raw: undefined, responseHint } : undefined, asset };
    for (const pb of books) {
      if (pb.trigger.event !== event || !allHold(pb.trigger.conditions, ctx)) continue;
      const [run] = await tx
        .insert(playbookRuns)
        .values({ tenantId, playbookId: pb.id, playbookVersion: pb.version, steps: pb.steps, trigger: { event, ...payload }, context: ctx, alertId: payload.alertId ?? null, incidentId: ctx.incidentId ?? null })
        .returning({ id: playbookRuns.id });
      await audit(tx, { actorId: null, actorKind: "playbook", tenantId, action: "playbook.start", targetType: "playbook_run", targetId: run!.id, detail: { playbook: pb.name, event } });
      started.push(run!.id);
    }
  });
  for (const runId of started) await queue(QUEUES.playbook).add("advance", { tenantId, runId });
  return started;
}

/** Execute steps until completion or an approval gate. Idempotent per step index. */
export async function advanceRun(tenantId: string, runId: string) {
  return withScope(systemScope(tenantId), async (tx) => {
    const [run] = await tx.select().from(playbookRuns).where(eq(playbookRuns.id, runId)).for("update");
    if (!run || run.status !== "RUNNING") return run?.status;
    const [pb] = await tx.select().from(playbooks).where(eq(playbooks.id, run.playbookId));
    // Run the steps this run started with, not whatever the playbook says after a later edit.
    const steps = run.steps ?? pb!.steps;
    const ctx = run.context as RunCtx;
    let idx = run.stepIndex;
    for (; idx < steps.length; idx++) {
      const step = steps[idx]!;
      if (step.when && !evaluate(step.when, ctx)) {
        await tx.insert(playbookRunSteps).values({ tenantId, runId, stepId: step.id, action: step.action, status: "SKIPPED", output: { reason: `condition ${step.when.field} ${step.when.op} ${JSON.stringify(step.when.value)} not met` }, finishedAt: new Date() });
        continue;
      }
      let result: StepResult;
      try {
        const handler = STEP_ACTIONS[step.action]?.handler;
        result = handler ? await handler(tx, step, run, ctx) : await responseStep(tx, step, run, ctx);
        if (result.status === "SUCCEEDED" && step.requireApproval && !result.approvalId) {
          const gate = await STEP_ACTIONS["approval.request"]!.handler(tx, { ...step, params: { summary: `Approve continuation after "${step.name}"` } }, run, ctx);
          result = { ...gate, output: result.output };
        }
      } catch (err) {
        result = { status: "FAILED", error: (err as Error).message };
      }
      await tx.insert(playbookRunSteps).values({ tenantId, runId, stepId: step.id, action: step.action, status: result.status, output: (result.output ?? null) as never, error: result.error ?? null, approvalId: result.approvalId ?? null, finishedAt: result.status === "WAITING_APPROVAL" ? null : new Date() });
      if (result.status === "WAITING_APPROVAL") {
        await tx.update(playbookRuns).set({ status: "WAITING_APPROVAL", stepIndex: idx, context: ctx, incidentId: ctx.incidentId ?? null }).where(eq(playbookRuns.id, runId));
        await publish({ type: "approval.requested", tenantId, id: result.approvalId!, summary: `${pb!.name}: ${step.name}` });
        return "WAITING_APPROVAL";
      }
      if (result.status === "FAILED" && !step.continueOnError) {
        await tx.update(playbookRuns).set({ status: "FAILED", stepIndex: idx, context: ctx, error: result.error, finishedAt: new Date() }).where(eq(playbookRuns.id, runId));
        return "FAILED";
      }
    }
    await tx.update(playbookRuns).set({ status: "SUCCEEDED", stepIndex: idx, context: ctx, incidentId: ctx.incidentId ?? null, finishedAt: new Date() }).where(eq(playbookRuns.id, runId));
    return "SUCCEEDED";
  });
}

/**
 * Called after a human decides on a gate for this run. Acts only when the run is waiting on this
 * exact gate: a late or repeated resume for an earlier gate must never carry the run past a later one.
 */
export async function resumeRun(tenantId: string, runId: string, approvalId: string, decision: "APPROVED" | "REJECTED", reason = "approval rejected") {
  const next = await withScope(systemScope(tenantId), async (tx) => {
    const [run] = await tx.select().from(playbookRuns).where(eq(playbookRuns.id, runId)).for("update");
    if (!run || run.status !== "WAITING_APPROVAL") return null;
    const [gate] = await tx
      .select({ id: playbookRunSteps.id })
      .from(playbookRunSteps)
      .where(and(eq(playbookRunSteps.runId, runId), eq(playbookRunSteps.approvalId, approvalId), eq(playbookRunSteps.status, "WAITING_APPROVAL")))
      .limit(1);
    if (!gate) return null;
    await tx.update(playbookRunSteps).set({ status: decision === "APPROVED" ? "SUCCEEDED" : "REJECTED", finishedAt: new Date() }).where(eq(playbookRunSteps.id, gate.id));
    if (decision === "REJECTED") {
      await tx.update(playbookRuns).set({ status: "CANCELLED", error: reason, finishedAt: new Date() }).where(eq(playbookRuns.id, runId));
      return null;
    }
    await tx.update(playbookRuns).set({ status: "RUNNING", stepIndex: run.stepIndex + 1 }).where(eq(playbookRuns.id, runId));
    return runId;
  });
  if (next) await queue(QUEUES.playbook).add("advance", { tenantId, runId });
}

export { getPath };
