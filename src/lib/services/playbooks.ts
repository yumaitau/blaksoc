import { and, desc, eq, inArray, isNull, or, sql, type SQL } from "drizzle-orm";
import { z } from "zod";
import { alerts, approvals, assets, playbookRuns, playbookRunSteps, playbooks, responseActions, tenants } from "@/db/schema";
import { withScope, type DbScope } from "@/db/scope";
import { can, dbScope, tenantsWith, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { queue, QUEUES } from "@/lib/queue";
import { stepCatalogue } from "@/lib/soar/engine";
import { responseHintOf } from "@/lib/soar/hint";
import { actor, AccessDenied, scoped } from "./common";

export const TRIGGER_EVENTS = ["alert.created", "alert.enriched", "incident.created", "manual"] as const;
export const CONDITION_OPS = ["eq", "neq", "gte", "lte", "in", "contains"] as const;

const condition = z.object({ field: z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9_.]+$/, "field must be a dotted path"), op: z.enum(CONDITION_OPS), value: z.unknown() });

const stepSchema = z.object({
  id: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/),
  action: z.string().refine((a) => stepCatalogue().some((s) => s.key === a), "unknown action"),
  name: z.string().trim().min(1).max(160),
  params: z.record(z.string(), z.unknown()).optional(),
  when: condition.optional(),
  requireApproval: z.boolean().optional(),
  continueOnError: z.boolean().optional(),
});

export const playbookInput = z.object({
  id: z.string().uuid().optional(),
  tenantId: z.string().uuid().nullable(),
  name: z.string().trim().min(1).max(160),
  description: z.string().trim().max(2000).nullish(),
  trigger: z.object({ event: z.enum(TRIGGER_EVENTS), conditions: z.array(condition).max(20) }),
  steps: z
    .array(stepSchema)
    .min(1)
    .max(50)
    .superRefine((steps, c) => {
      const seen = new Set<string>();
      steps.forEach((s, i) => {
        if (seen.has(s.id)) c.addIssue({ code: "custom", path: [i, "id"], message: `duplicate step id ${s.id}` });
        seen.add(s.id);
      });
    }),
});
export type PlaybookInput = z.input<typeof playbookInput>;

/** Global playbooks need platform staff with playbook:write; tenant ones need playbook:write on that tenant. */
function writeScope(ctx: AccessContext, tenantId: string | null): DbScope {
  if (tenantId) {
    if (!can(ctx, "playbook:write", tenantId)) throw new AccessDenied("missing playbook:write");
    return dbScope(ctx, [tenantId]);
  }
  if (!ctx.isPlatform || !can(ctx, "playbook:write")) throw new AccessDenied("global playbooks require platform playbook:write");
  return { tenantIds: [], platform: true };
}

export function canWritePlaybook(ctx: AccessContext, tenantId: string | null) {
  return tenantId ? can(ctx, "playbook:write", tenantId) : ctx.isPlatform && can(ctx, "playbook:write");
}

/** Owners the caller may create playbooks for. `null` = global template. */
export function playbookOwners(ctx: AccessContext) {
  const ids = tenantsWith(ctx, "playbook:write");
  return [
    ...(canWritePlaybook(ctx, null) ? [{ id: null, name: "Global (all customers)" }] : []),
    ...ctx.tenants.filter((t) => ids.includes(t.id)).map((t) => ({ id: t.id as string | null, name: t.name })),
  ];
}

const lastRun = (col: "status" | "started_at") =>
  sql.raw(`(select r.${col} from playbook_runs r where r.playbook_id = playbooks.id order by r.started_at desc limit 1)`);

export async function listPlaybooks(ctx: AccessContext) {
  return scoped(ctx, "playbook:read", (tx, ids) =>
    tx
      .select({
        id: playbooks.id, tenantId: playbooks.tenantId, tenantName: tenants.name, name: playbooks.name, description: playbooks.description,
        trigger: playbooks.trigger, steps: playbooks.steps, enabled: playbooks.enabled, version: playbooks.version, updatedAt: playbooks.updatedAt,
        lastRunStatus: sql<string | null>`${lastRun("status")}`,
        lastRunAt: sql<Date | null>`${lastRun("started_at")}`.mapWith(playbookRuns.startedAt),
      })
      .from(playbooks)
      .leftJoin(tenants, eq(tenants.id, playbooks.tenantId))
      .where(or(isNull(playbooks.tenantId), ids.length ? inArray(playbooks.tenantId, ids) : undefined))
      .orderBy(sql`${playbooks.tenantId} nulls first`, playbooks.name),
  );
}

export async function getPlaybook(ctx: AccessContext, id: string) {
  return scoped(ctx, "playbook:read", async (tx, ids) => {
    const [row] = await tx
      .select({ playbook: playbooks, tenantName: tenants.name })
      .from(playbooks)
      .leftJoin(tenants, eq(tenants.id, playbooks.tenantId))
      .where(and(eq(playbooks.id, id), or(isNull(playbooks.tenantId), ids.length ? inArray(playbooks.tenantId, ids) : undefined)));
    return row ? { ...row.playbook, tenantName: row.tenantName } : null;
  });
}

/** Create or edit. Edits bump the version; the owner (tenant/global) is fixed at creation. */
export async function savePlaybook(ctx: AccessContext, raw: PlaybookInput) {
  const input = playbookInput.parse(raw);
  let tenantId = input.tenantId;
  if (input.id) {
    const cur = await getPlaybook(ctx, input.id);
    if (!cur) throw new AccessDenied("playbook not found");
    tenantId = cur.tenantId;
  }
  return withScope(writeScope(ctx, tenantId), async (tx) => {
    const values = { name: input.name, description: input.description || null, trigger: input.trigger, steps: input.steps };
    if (input.id) {
      const [row] = await tx
        .update(playbooks)
        .set({ ...values, version: sql`${playbooks.version} + 1`, updatedAt: new Date() })
        .where(eq(playbooks.id, input.id))
        .returning({ id: playbooks.id, version: playbooks.version });
      if (!row) throw new AccessDenied("playbook not found");
      await audit(tx, { ...actor(ctx), tenantId, action: "playbook.update", targetType: "playbook", targetId: row.id, detail: { name: input.name, version: row.version, steps: input.steps.map((s) => s.action) } });
      return row.id;
    }
    const [row] = await tx.insert(playbooks).values({ ...values, tenantId, enabled: false, createdBy: ctx.principal.userId }).returning({ id: playbooks.id });
    await audit(tx, { ...actor(ctx), tenantId, action: "playbook.create", targetType: "playbook", targetId: row!.id, detail: { name: input.name, steps: input.steps.map((s) => s.action) } });
    return row!.id;
  });
}

export async function setPlaybookEnabled(ctx: AccessContext, id: string, enabled: boolean) {
  const cur = await getPlaybook(ctx, id);
  if (!cur) throw new AccessDenied("playbook not found");
  await withScope(writeScope(ctx, cur.tenantId), async (tx) => {
    await tx.update(playbooks).set({ enabled, updatedAt: new Date() }).where(eq(playbooks.id, id));
    await audit(tx, { ...actor(ctx), tenantId: cur.tenantId, action: enabled ? "playbook.enable" : "playbook.disable", targetType: "playbook", targetId: id, detail: { name: cur.name } });
  });
}

export async function listRuns(ctx: AccessContext, f: { playbookId?: string; tenantIds?: string[]; limit?: number } = {}) {
  return scoped(
    ctx,
    "playbook:read",
    (tx, ids) => {
      const where: SQL[] = [inArray(playbookRuns.tenantId, ids)];
      if (f.playbookId) where.push(eq(playbookRuns.playbookId, f.playbookId));
      return tx
        .select({
          id: playbookRuns.id, tenantId: playbookRuns.tenantId, tenantName: tenants.name, playbookId: playbookRuns.playbookId, playbookName: playbooks.name,
          playbookVersion: playbookRuns.playbookVersion, status: playbookRuns.status, event: sql<string>`${playbookRuns.trigger}->>'event'`,
          alertId: playbookRuns.alertId, incidentId: playbookRuns.incidentId, error: playbookRuns.error, startedAt: playbookRuns.startedAt, finishedAt: playbookRuns.finishedAt,
        })
        .from(playbookRuns)
        .innerJoin(tenants, eq(tenants.id, playbookRuns.tenantId))
        .innerJoin(playbooks, eq(playbooks.id, playbookRuns.playbookId))
        .where(and(...where))
        .orderBy(desc(playbookRuns.startedAt))
        .limit(Math.min(f.limit ?? 100, 500));
    },
    f.tenantIds,
  );
}

export async function getRun(ctx: AccessContext, id: string) {
  return scoped(ctx, "playbook:read", async (tx, ids) => {
    const [row] = await tx
      .select({ run: playbookRuns, tenantName: tenants.name, playbookName: playbooks.name, playbookSteps: playbooks.steps, playbookVersion: playbooks.version, alertTitle: alerts.title })
      .from(playbookRuns)
      .innerJoin(tenants, eq(tenants.id, playbookRuns.tenantId))
      .innerJoin(playbooks, eq(playbooks.id, playbookRuns.playbookId))
      .leftJoin(alerts, eq(alerts.id, playbookRuns.alertId))
      .where(and(eq(playbookRuns.id, id), inArray(playbookRuns.tenantId, ids)));
    if (!row) return null;
    const steps = await tx.select().from(playbookRunSteps).where(eq(playbookRunSteps.runId, id)).orderBy(playbookRunSteps.startedAt);
    const approvalIds = steps.map((s) => s.approvalId).filter((x): x is string => !!x);
    const [gates, actions] = await Promise.all([
      approvalIds.length ? tx.select().from(approvals).where(inArray(approvals.id, approvalIds)) : Promise.resolve([]),
      tx.select().from(responseActions).where(eq(responseActions.playbookRunId, id)).orderBy(responseActions.createdAt),
    ]);
    const { context: _ctx, steps: pinnedSteps, ...run } = row.run;
    // playbookSteps are the steps this run executes: its own snapshot, or the live playbook for runs older than the snapshot.
    return { ...run, tenantName: row.tenantName, playbookName: row.playbookName, playbookSteps: pinnedSteps ?? row.playbookSteps, stepsPinned: pinnedSteps != null, currentVersion: row.playbookVersion, alertTitle: row.alertTitle, steps, approvals: gates, responseActions: actions };
  });
}

/**
 * Start a run against an alert on analyst request. Trigger conditions are not evaluated:
 * the analyst chose to run it. Steps still pass through the engine's approval gates.
 */
export async function runPlaybookManually(ctx: AccessContext, playbookId: string, input: { alertId: string }) {
  const alertId = z.string().uuid().parse(input.alertId);
  const pb = await getPlaybook(ctx, playbookId);
  if (!pb) throw new AccessDenied("playbook not found");
  const runId = await scoped(ctx, "playbook:run", async (tx, ids) => {
    const [alert] = await tx.select().from(alerts).where(and(eq(alerts.id, alertId), inArray(alerts.tenantId, ids)));
    if (!alert) throw new AccessDenied("alert not found or missing playbook:run");
    if (pb.tenantId && pb.tenantId !== alert.tenantId) throw new Error("This playbook belongs to a different customer than the alert.");
    const [asset] = alert.assetId ? await tx.select().from(assets).where(eq(assets.id, alert.assetId)) : [];
    const runCtx = { tenantId: alert.tenantId, alertId, incidentId: alert.incidentId ?? undefined, alert: { ...alert, raw: undefined, responseHint: responseHintOf(alert.raw) }, asset };
    const [run] = await tx
      .insert(playbookRuns)
      .values({ tenantId: alert.tenantId, playbookId, playbookVersion: pb.version, steps: pb.steps, trigger: { event: "manual", alertId, requestedBy: ctx.principal.userId }, context: runCtx, alertId, incidentId: alert.incidentId })
      .returning({ id: playbookRuns.id, tenantId: playbookRuns.tenantId });
    await audit(tx, { ...actor(ctx), tenantId: alert.tenantId, action: "playbook.run_manual", targetType: "playbook_run", targetId: run!.id, detail: { playbook: pb.name, playbookId, alertId } });
    return run!;
  }, [pb.tenantId].filter((x): x is string => !!x));
  await queue(QUEUES.playbook).add("advance", { tenantId: runId.tenantId, runId: runId.id });
  return runId.id;
}
