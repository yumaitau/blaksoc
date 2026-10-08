import { and, asc, desc, eq, gt, inArray, or, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import { systemDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  alerts, assets, noiseRules, patternAnnotations, platformSettings, serviceIdentities, tenants, tuningActions, user, type NoiseRuleStatus,
} from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { DISPOSITION_SAMPLE_CAP, DISPOSITION_WINDOW_DAYS, EMPTY_COUNTS, type DispositionCounts, type DispositionStats } from "@/lib/tuning/disposition";
import { TuningRefused } from "@/lib/tuning/errors";
import {
  describeScope, effectiveStatus, expiryFrom, firstMatch, globMatch, MAX_EXPIRY_DAYS, MAX_TITLE_PATTERN, overridesNoise, passiveReasonFor, shortHost, type NoiseScope,
} from "@/lib/tuning/noise";
import { actor, AccessDenied, inTenant, scoped, userRef } from "./common";

const DAY = 86_400_000;
/** Open alerts "Mark as noise" and approval move to the passive lane at most, newest first. */
export const BACKFILL_LIMIT = 5000;
const OPEN_FOR_NOISE = ["NEW", "TRIAGING"] as const;

export type NoiseRuleRow = typeof noiseRules.$inferSelect;

// ---------------------------------------------------------------------------------------------------------------
// Disposition memory (ingest)

export type DispositionKey = { tenantId: string; source: string; ruleId: string; assetId: string | null };

/**
 * What analysts decided about this tenant's rule over the last 90 days (the newest DISPOSITION_SAMPLE_CAP
 * alerts, through alerts_disposition), with the same counts for one asset. An ESCALATED alert that automatic
 * grouping escalated is not a human decision and counts as `other`.
 */
export async function dispositionStats(tx: Tx, key: DispositionKey, now = new Date()): Promise<DispositionStats> {
  const since = new Date(now.getTime() - DISPOSITION_WINDOW_DAYS * DAY);
  const rows = await tx.execute<{ outcome: keyof DispositionCounts; n: number; on_asset: number }>(sql`
    with r as (
      select id, status, asset_id, incident_id from alerts
      where tenant_id = ${key.tenantId} and source = ${key.source} and rule_id = ${key.ruleId}
        and occurred_at >= ${since.toISOString()}::timestamptz and occurred_at <= ${now.toISOString()}::timestamptz
      order by occurred_at desc
      limit ${DISPOSITION_SAMPLE_CAP}
    )
    select case
        when status = 'FALSE_POSITIVE' then 'falsePositive'
        when status = 'RESOLVED' then 'resolved'
        when status = 'CONTAINED' then 'contained'
        when status = 'ESCALATED' and not exists (
          select 1 from incident_alerts ia where ia.incident_id = r.incident_id and ia.alert_id = r.id and ia.origin = 'auto'
        ) then 'escalated'
        else 'other' end as outcome,
      count(*)::int as n,
      count(*) filter (where asset_id = ${key.assetId}::uuid)::int as on_asset
    from r group by 1`);
  const rule: DispositionCounts = { ...EMPTY_COUNTS };
  const asset: DispositionCounts = { ...EMPTY_COUNTS };
  for (const r of rows) {
    rule[r.outcome] = Number(r.n);
    asset[r.outcome] = Number(r.on_asset);
  }
  return { rule, asset: key.assetId ? asset : null };
}

// ---------------------------------------------------------------------------------------------------------------
// Noise rules at ingest

/** Approved, unexpired rules for one tenant's rule id. Cheap: the partial index noise_rules_match. */
export async function liveNoiseRules(tx: Tx, tenantId: string, source: string, ruleId: string, now = new Date()) {
  return tx
    .select()
    .from(noiseRules)
    .where(and(eq(noiseRules.tenantId, tenantId), eq(noiseRules.source, source), eq(noiseRules.ruleId, ruleId), eq(noiseRules.status, "active"), gt(noiseRules.expiresAt, now)))
    .orderBy(asc(noiseRules.createdAt));
}

export async function recordNoiseHits(tx: Tx, ruleId: string, n: number, now = new Date()) {
  if (n <= 0) return;
  await tx.update(noiseRules).set({ hitCount: sql`${noiseRules.hitCount} + ${n}`, lastHitAt: now }).where(eq(noiseRules.id, ruleId));
}

/** The host an existing alert came from: its asset, else the agent name the source reported. */
const alertHost = sql<string | null>`coalesce(${assets.hostname}, ${assets.name}, ${alerts.raw} #>> '{agent,name}', ${alerts.raw} ->> 'hostname')`;

/**
 * Move the tenant's open (NEW/TRIAGING) active alerts that `rule` matches to the passive lane, plus
 * `includeId` whatever its status. Status is never changed. Returns the ids moved.
 */
export async function applyToOpenAlerts(tx: Tx, rule: NoiseRuleRow, now: Date, includeId?: string): Promise<string[]> {
  const candidates = await tx
    .select({ id: alerts.id, source: alerts.source, ruleId: alerts.ruleId, assetId: alerts.assetId, hostname: alertHost, title: alerts.title, severity: alerts.severity, intelVerdict: alerts.intelVerdict })
    .from(alerts)
    .leftJoin(assets, eq(assets.id, alerts.assetId))
    .where(and(
      eq(alerts.tenantId, rule.tenantId), eq(alerts.source, rule.source), eq(alerts.ruleId, rule.ruleId), eq(alerts.lane, "active"),
      or(inArray(alerts.status, [...OPEN_FOR_NOISE]), includeId ? eq(alerts.id, includeId) : undefined),
      rule.assetId && !rule.hostname ? eq(alerts.assetId, rule.assetId) : undefined,
    ))
    .orderBy(desc(alerts.occurredAt))
    .limit(BACKFILL_LIMIT);
  const ids = candidates.filter((c) => firstMatch([rule], c, now)).map((c) => c.id);
  for (let i = 0; i < ids.length; i += 1000) {
    await tx
      .update(alerts)
      .set({ lane: "passive", passiveReason: passiveReasonFor(rule.reason), noiseRuleId: rule.id, updatedAt: now })
      .where(inArray(alerts.id, ids.slice(i, i + 1000)));
  }
  await recordNoiseHits(tx, rule.id, ids.length, now);
  return ids;
}

/** Same scope, still proposed or live: a second rule would only split the hit count. */
async function assertNoDuplicate(tx: Tx, tenantId: string, scope: NoiseScope, now: Date) {
  const rows = await tx
    .select({ id: noiseRules.id, status: noiseRules.status, expiresAt: noiseRules.expiresAt, assetId: noiseRules.assetId, hostname: noiseRules.hostname, titlePattern: noiseRules.titlePattern })
    .from(noiseRules)
    .where(and(eq(noiseRules.tenantId, tenantId), eq(noiseRules.source, scope.source), eq(noiseRules.ruleId, scope.ruleId), inArray(noiseRules.status, ["proposed", "active"])));
  const same = rows.find((r) => r.expiresAt > now && r.assetId === scope.assetId && r.hostname === scope.hostname && (r.titlePattern ?? null) === (scope.titlePattern ?? null));
  if (same) throw new TuningRefused(`A ${same.status} noise rule already covers ${describeScope(scope)}.`, 409);
}

function cleanPattern(p: string | null | undefined): string | null {
  const v = p?.trim() ?? "";
  if (!v || /^\*+$/.test(v)) return null;
  if (v.length > MAX_TITLE_PATTERN) throw new TuningRefused(`The title pattern is longer than ${MAX_TITLE_PATTERN} characters.`, 422);
  return v;
}

function expiry(days: number | undefined, now: Date, max = MAX_EXPIRY_DAYS): Date {
  if (days != null && days > max) throw new TuningRefused(`Noise rules expire within ${max} days.`, 422);
  try {
    return expiryFrom(days, now);
  } catch (err) {
    throw new TuningRefused((err as Error).message, 422);
  }
}

async function alertTenant(ctx: AccessContext, alertId: string): Promise<string> {
  const row = await scoped(ctx, "alert:read", (tx, tenantIds) =>
    tx.select({ tenantId: alerts.tenantId }).from(alerts).where(and(eq(alerts.id, alertId), inArray(alerts.tenantId, tenantIds))).then((r) => r[0]),
  );
  if (!row) throw new AccessDenied("alert not found");
  return row.tenantId;
}

// ---------------------------------------------------------------------------------------------------------------
// Analyst actions

export type MarkNoiseInput = { scope: "host" | "tenant"; reason: string; expiresInDays?: number; titlePattern?: string | null };

/**
 * "Mark as noise…" on an alert: an active rule (the analyst's decision is the approval), applied to this
 * alert and the tenant's other open matching alerts. Nothing is closed; status stays as it was.
 */
export async function markAsNoise(ctx: AccessContext, alertId: string, input: MarkNoiseInput) {
  const reason = input.reason.trim();
  if (reason.length < 5 || reason.length > 1000) throw new TuningRefused("Give a reason of 5–1000 characters; it is shown on every alert the rule affects.", 422);
  const tenantId = await alertTenant(ctx, alertId);
  return inTenant(ctx, "alert:tune", tenantId, async (tx) => {
    const [a] = await tx
      .select({ id: alerts.id, source: alerts.source, ruleId: alerts.ruleId, title: alerts.title, assetId: alerts.assetId, hostname: alertHost, intelVerdict: alerts.intelVerdict, assetName: assets.name })
      .from(alerts)
      .leftJoin(assets, eq(assets.id, alerts.assetId))
      .where(and(eq(alerts.id, alertId), eq(alerts.tenantId, tenantId)));
    if (!a) throw new AccessDenied("alert not found");
    if (!a.ruleId) throw new TuningRefused("This alert has no source rule id, so a noise rule cannot target it precisely.", 422);
    if (overridesNoise(a)) throw new TuningRefused("Threat intelligence rates this alert's indicators malicious or suspicious, so it cannot be treated as noise.", 422);
    const host = shortHost(a.hostname);
    if (input.scope === "host" && !a.assetId && !host) throw new TuningRefused("blakSOC does not know which host raised this alert. Choose all hosts instead.", 422);
    const scope: NoiseScope = {
      source: a.source, ruleId: a.ruleId, assetId: input.scope === "host" ? a.assetId : null, hostname: input.scope === "host" ? host : null, titlePattern: cleanPattern(input.titlePattern),
    };
    if (scope.titlePattern && !globMatch(scope.titlePattern, a.title)) throw new TuningRefused("The title pattern does not match this alert's title.", 422);
    const now = new Date();
    const expiresAt = expiry(input.expiresInDays, now);
    await assertNoDuplicate(tx, tenantId, scope, now);
    const me = userRef(ctx);
    const [rule] = await tx
      .insert(noiseRules)
      .values({ tenantId, ...scope, reason, status: "active", createdBy: ctx.principal.userId, createdByKind: ctx.principal.kind === "service" ? "service" : "user", approvedBy: me, decidedAt: now, expiresAt })
      .returning();
    const moved = await applyToOpenAlerts(tx, rule!, now, a.id);
    await audit(tx, {
      ...actor(ctx), tenantId, action: "noise_rule.create", targetType: "noise_rule", targetId: rule!.id,
      detail: { scope: describeScope(scope, input.scope === "host" ? a.assetName ?? host : null), reason, expiresAt: expiresAt.toISOString(), fromAlertId: a.id, alertIds: moved },
    });
    return { id: rule!.id, moved: moved.length };
  });
}

/** Noise rules in the caller's tuning scope: proposals first, then live rules by expiry, then the rest. */
export async function listNoiseRules(ctx: AccessContext, tenantIds?: string[]) {
  const approver = alias(user, "approver");
  const creator = alias(user, "creator");
  return scoped(
    ctx,
    "alert:tune",
    async (tx, ids) => {
      const rows = await tx
        .select({
          rule: noiseRules, tenantName: tenants.name, assetName: assets.name,
          createdByName: sql<string | null>`coalesce(${creator.name}, ${serviceIdentities.name})`, approvedByName: approver.name,
        })
        .from(noiseRules)
        .innerJoin(tenants, eq(tenants.id, noiseRules.tenantId))
        .leftJoin(assets, eq(assets.id, noiseRules.assetId))
        .leftJoin(creator, eq(creator.id, noiseRules.createdBy))
        .leftJoin(serviceIdentities, and(eq(noiseRules.createdByKind, "service"), sql`${serviceIdentities.id}::text = ${noiseRules.createdBy}`))
        .leftJoin(approver, eq(approver.id, noiseRules.approvedBy))
        .where(inArray(noiseRules.tenantId, ids))
        .orderBy(sql`case when ${noiseRules.status} = 'proposed' then 0 when ${noiseRules.status} = 'active' and ${noiseRules.expiresAt} > now() then 1 else 2 end`, asc(noiseRules.expiresAt))
        .limit(500);
      const now = new Date();
      return rows.map((r) => ({ ...r, status: effectiveStatus(r.rule, now) }));
    },
    tenantIds,
  );
}

/** Lock a rule in its tenant after checking alert:tune there. */
async function withRule<T>(ctx: AccessContext, id: string, fn: (tx: Tx, rule: NoiseRuleRow, now: Date) => Promise<T>): Promise<T> {
  // Read before a scope exists so the tenant is known; the change itself runs under RLS.
  const [head] = await systemDb().select({ tenantId: noiseRules.tenantId }).from(noiseRules).where(eq(noiseRules.id, id));
  if (!head || !can(ctx, "alert:tune", head.tenantId)) throw new AccessDenied("noise rule not found");
  return inTenant(ctx, "alert:tune", head.tenantId, async (tx) => {
    const [rule] = await tx.select().from(noiseRules).where(eq(noiseRules.id, id)).for("update");
    if (!rule) throw new AccessDenied("noise rule not found");
    return fn(tx, rule, new Date());
  });
}

const ruleAudit = (ctx: AccessContext, rule: NoiseRuleRow, action: string, detail: Record<string, unknown>) => ({
  ...actor(ctx), tenantId: rule.tenantId, action, targetType: "noise_rule", targetId: rule.id,
  detail: { scope: describeScope(rule), reason: rule.reason, ...detail },
});

/** A proposal takes effect only here: a person approves it, and it is applied to open alerts like a new rule. */
export async function approveNoiseRule(ctx: AccessContext, id: string) {
  return withRule(ctx, id, async (tx, rule, now) => {
    if (rule.status !== "proposed") throw new TuningRefused(`Only proposed rules can be approved; this one is ${effectiveStatus(rule, now)}.`, 409);
    if (rule.expiresAt <= now) throw new TuningRefused("This proposal's expiry has passed. Reject it; a new proposal can follow.", 409);
    const [live] = await tx.update(noiseRules).set({ status: "active", approvedBy: userRef(ctx), decidedAt: now, updatedAt: now }).where(eq(noiseRules.id, id)).returning();
    const moved = await applyToOpenAlerts(tx, live!, now);
    await audit(tx, ruleAudit(ctx, rule, "noise_rule.approve", { proposedBy: rule.createdBy, proposedByKind: rule.createdByKind, alertIds: moved }));
    return { moved: moved.length };
  });
}

export async function rejectNoiseRule(ctx: AccessContext, id: string) {
  return withRule(ctx, id, async (tx, rule, now) => {
    if (rule.status !== "proposed") throw new TuningRefused(`Only proposed rules can be rejected; this one is ${effectiveStatus(rule, now)}.`, 409);
    await tx.update(noiseRules).set({ status: "rejected", approvedBy: userRef(ctx), decidedAt: now, updatedAt: now }).where(eq(noiseRules.id, id));
    await audit(tx, ruleAudit(ctx, rule, "noise_rule.reject", { proposedBy: rule.createdBy, proposedByKind: rule.createdByKind }));
  });
}

/** Stops matching now. Alerts it already made passive stay passive (with their reason) until moved back. */
export async function expireNoiseRule(ctx: AccessContext, id: string) {
  return withRule(ctx, id, (tx, rule, now) => expireRuleIn(tx, ctx, rule, now));
}

async function expireRuleIn(tx: Tx, ctx: AccessContext, rule: NoiseRuleRow, now: Date) {
  const status = effectiveStatus(rule, now);
  if (status !== "active" && status !== "proposed") throw new TuningRefused(`This rule is already ${status}.`, 409);
  await tx.update(noiseRules).set({ status: "expired", expiresAt: now, updatedAt: now }).where(eq(noiseRules.id, rule.id));
  await audit(tx, ruleAudit(ctx, rule, "noise_rule.expire", { was: status, expiresAt: rule.expiresAt.toISOString() }));
}

/** New expiry `days` from now, never beyond 180 days and never earlier than the current one. */
export async function extendNoiseRule(ctx: AccessContext, id: string, days: number) {
  return withRule(ctx, id, async (tx, rule, now) => {
    if (effectiveStatus(rule, now) !== "active") throw new TuningRefused("Only active rules can be extended. Create a new rule instead.", 409);
    const to = expiry(days, now);
    if (to <= rule.expiresAt) throw new TuningRefused("That would not extend the rule. Use “Expire now” to end it early.", 422);
    await tx.update(noiseRules).set({ expiresAt: to, updatedAt: now }).where(eq(noiseRules.id, id));
    await audit(tx, ruleAudit(ctx, rule, "noise_rule.extend", { from: rule.expiresAt.toISOString(), to: to.toISOString() }));
    return { expiresAt: to };
  });
}

/** Passive → active queue. Asking for more attention is always allowed with triage rights. */
export async function moveAlertsToActive(ctx: AccessContext, ids: string[]) {
  if (!ids.length) return 0;
  return scoped(ctx, "alert:triage", async (tx, tenantIds) => {
    const targets = await tx
      .select({ id: alerts.id, tenantId: alerts.tenantId, lane: alerts.lane, noiseRuleId: alerts.noiseRuleId, passiveReason: alerts.passiveReason })
      .from(alerts)
      .where(and(inArray(alerts.id, ids), inArray(alerts.tenantId, tenantIds)));
    if (targets.length !== new Set(ids).size) throw new AccessDenied("one or more alerts are outside your scope");
    const passive = targets.filter((t) => t.lane === "passive");
    if (!passive.length) return 0;
    const now = new Date();
    await tx.update(alerts).set({ lane: "active", passiveReason: null, noiseRuleId: null, updatedAt: now }).where(inArray(alerts.id, passive.map((t) => t.id)));
    for (const t of passive) {
      await audit(tx, { ...actor(ctx), tenantId: t.tenantId, action: "alert.lane", targetType: "alert", targetId: t.id, detail: { from: "passive", lane: "active", noiseRuleId: t.noiseRuleId, reason: t.passiveReason } });
    }
    return passive.length;
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Hermes: the act switch, undo, and what analysts see of it

export const HERMES_ACT_KEY = "hermes.allow_act";

/** Off unless a person turned it on. Read with the system role: the API caller may be tenant-bound. */
export async function hermesMayAct(): Promise<boolean> {
  const [row] = await systemDb().select({ value: platformSettings.value }).from(platformSettings).where(eq(platformSettings.key, HERMES_ACT_KEY));
  return (row?.value as { enabled?: unknown } | undefined)?.enabled === true;
}

export async function hermesSwitchState() {
  const [row] = await systemDb().select().from(platformSettings).where(eq(platformSettings.key, HERMES_ACT_KEY));
  return { enabled: (row?.value as { enabled?: unknown } | undefined)?.enabled === true, updatedAt: row?.updatedAt ?? null, updatedBy: row?.updatedBy ?? null };
}

/** Platform staff who may let automation act: SOC managers and platform administrators. */
export const canControlHermes = (ctx: AccessContext) =>
  ctx.isPlatform && ctx.grants.some((g) => g.tenantId === null && g.permissions.has("alert:tune") && g.permissions.has("response:approve"));

export async function setHermesMayAct(ctx: AccessContext, enabled: boolean) {
  if (!canControlHermes(ctx)) throw new AccessDenied("platform alert:tune and response:approve are required");
  await withScope({ tenantIds: [], platform: true }, async (tx) => {
    await tx
      .insert(platformSettings)
      .values({ key: HERMES_ACT_KEY, value: { enabled }, updatedBy: ctx.principal.userId })
      .onConflictDoUpdate({ target: platformSettings.key, set: { value: { enabled }, updatedBy: ctx.principal.userId, updatedAt: new Date() } });
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tuning.switch", targetType: "platform_setting", targetId: HERMES_ACT_KEY, detail: { enabled } });
  });
}

/**
 * Undo an agent action. A closure reopens (to NEW) the alerts it closed that are still false positives; a noise
 * rule is expired and its passive alerts return to the active queue. Annotations and purges cannot be undone.
 */
export async function undoTuningAction(ctx: AccessContext, id: string) {
  const [head] = await systemDb().select({ tenantId: tuningActions.tenantId }).from(tuningActions).where(eq(tuningActions.id, id));
  if (!head || !can(ctx, "alert:tune", head.tenantId)) throw new AccessDenied("tuning action not found");
  return inTenant(ctx, "alert:tune", head.tenantId, async (tx) => {
    const [act] = await tx.select().from(tuningActions).where(eq(tuningActions.id, id)).for("update");
    if (!act) throw new AccessDenied("tuning action not found");
    if (act.undoneAt) throw new TuningRefused("This action was already undone.", 409);
    const now = new Date();
    let restored = 0;
    if (act.kind === "close") {
      restored = (
        await tx
          .update(alerts)
          .set({ status: "NEW", updatedAt: now })
          .where(and(eq(alerts.tuningActionId, act.id), eq(alerts.status, "FALSE_POSITIVE")))
          .returning({ id: alerts.id })
      ).length;
    } else if (act.kind === "noise_rule") {
      if (act.noiseRuleId) {
        const [rule] = await tx.select().from(noiseRules).where(eq(noiseRules.id, act.noiseRuleId)).for("update");
        if (rule && ["active", "proposed"].includes(effectiveStatus(rule, now))) await expireRuleIn(tx, ctx, rule, now);
        restored = (
          await tx
            .update(alerts)
            .set({ lane: "active", passiveReason: null, noiseRuleId: null, updatedAt: now })
            .where(and(eq(alerts.noiseRuleId, act.noiseRuleId), eq(alerts.lane, "passive")))
            .returning({ id: alerts.id })
        ).length;
      }
    } else {
      throw new TuningRefused(`A${act.kind === "annotate" ? "n annotation" : " purge"} cannot be undone.`, 409);
    }
    await tx.update(tuningActions).set({ undoneAt: now, undoneBy: ctx.principal.userId, undoneByKind: ctx.principal.kind === "service" ? "service" : "user" }).where(eq(tuningActions.id, id));
    await audit(tx, { ...actor(ctx), tenantId: act.tenantId, action: "tuning.undo", targetType: "tuning_action", targetId: act.id, detail: { kind: act.kind, restored } });
    return { restored };
  });
}

/** Agent actions for analysts (names resolved), newest first. */
export async function listTuningActions(ctx: AccessContext, tenantIds?: string[], limit = 100) {
  return scoped(
    ctx,
    "alert:tune",
    (tx, ids) =>
      tx
        .select({
          action: tuningActions, tenantName: tenants.name, actorName: serviceIdentities.name, undoneByName: user.name,
          reopened: sql<number>`(select count(*)::int from alerts a where a.tuning_action_id = ${tuningActions.id} and a.status <> 'FALSE_POSITIVE')`,
        })
        .from(tuningActions)
        .innerJoin(tenants, eq(tenants.id, tuningActions.tenantId))
        .leftJoin(serviceIdentities, sql`${serviceIdentities.id}::text = ${tuningActions.actorId}`)
        .leftJoin(user, eq(user.id, tuningActions.undoneBy))
        .where(inArray(tuningActions.tenantId, ids))
        .orderBy(desc(tuningActions.createdAt))
        .limit(limit),
    tenantIds,
  );
}

/** The agent's notes on the alert's pattern (same tenant, source and rule), newest first. */
export async function annotationsForAlert(ctx: AccessContext, alert: { tenantId: string; source: string; ruleId: string | null }) {
  if (!alert.ruleId || !can(ctx, "alert:read", alert.tenantId)) return [];
  return inTenant(ctx, "alert:read", alert.tenantId, (tx) =>
    tx
      .select({ id: patternAnnotations.id, text: patternAnnotations.text, confidence: patternAnnotations.confidence, createdAt: patternAnnotations.createdAt })
      .from(patternAnnotations)
      .where(and(eq(patternAnnotations.tenantId, alert.tenantId), eq(patternAnnotations.source, alert.source), eq(patternAnnotations.ruleId, alert.ruleId!)))
      .orderBy(desc(patternAnnotations.createdAt))
      .limit(5),
  );
}

/** The agent action that closed this alert, if any, for its detail page. */
export async function closingAction(ctx: AccessContext, alert: { tenantId: string; tuningActionId: string | null }) {
  if (!alert.tuningActionId) return null;
  const [row] = await inTenant(ctx, "alert:read", alert.tenantId, (tx) =>
    tx
      .select({ id: tuningActions.id, params: tuningActions.params, createdAt: tuningActions.createdAt, undoneAt: tuningActions.undoneAt, reversibleUntil: tuningActions.reversibleUntil })
      .from(tuningActions)
      .where(eq(tuningActions.id, alert.tuningActionId!)),
  );
  return row ?? null;
}

/** Recent agent notes across the caller's tenants, for the tuning page. */
export async function recentAnnotations(ctx: AccessContext, tenantIds?: string[]) {
  return scoped(
    ctx,
    "alert:tune",
    (tx, ids) =>
      tx
        .select({ id: patternAnnotations.id, tenantName: tenants.name, source: patternAnnotations.source, ruleId: patternAnnotations.ruleId, text: patternAnnotations.text, confidence: patternAnnotations.confidence, createdAt: patternAnnotations.createdAt })
        .from(patternAnnotations)
        .innerJoin(tenants, eq(tenants.id, patternAnnotations.tenantId))
        .where(inArray(patternAnnotations.tenantId, ids))
        .orderBy(desc(patternAnnotations.createdAt))
        .limit(30),
    tenantIds,
  );
}

export type NoiseRuleListRow = Awaited<ReturnType<typeof listNoiseRules>>[number];
export type TuningActionListRow = Awaited<ReturnType<typeof listTuningActions>>[number];
export const NOISE_STATUSES: NoiseRuleStatus[] = ["proposed", "active", "expired", "rejected"];
