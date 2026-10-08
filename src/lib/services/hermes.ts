import { and, asc, desc, eq, gt, gte, inArray, isNotNull, isNull, lte, ne, notInArray, sql, type SQL } from "drizzle-orm";
import { systemDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, hermesMemoryNotes, hermesReports, noiseRules, patternAnnotations, platformSettings, tenants, tuningActions, tuningPatterns, type HermesNoteSource } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { audit } from "@/lib/audit";
import { env } from "@/lib/env";
import { TuningRefused } from "@/lib/tuning/errors";
import { AGENT_RULE_MAX_SEVERITY, CLOSABLE_SEVERITIES, GUARDRAILS, guardrailRefusal, type PatternEvidence } from "@/lib/tuning/guardrails";
import { checkMemoryNotes, memoryDiff, noteProblem, type MemoryNoteInput } from "@/lib/tuning/memory";
import { expiryFrom, NOISE_OVERRIDE_VERDICTS } from "@/lib/tuning/noise";
import { stripControl } from "@/lib/tuning/pii";
import { PATTERN_ID, patternIdFor, pseudonymKey, tenantRefFor } from "@/lib/tuning/pseudonym";
import { ruleMetadata, safeToken } from "@/lib/tuning/rule-meta";
import { actor, AccessDenied, inTenant, scoped } from "./common";
import { PURGE_BATCH, removeAlertGraph } from "./retention";
import { applyToOpenAlerts, hermesMayAct } from "./tuning";

/**
 * The tuning API behind /api/v1/tuning (Hermes, an AI agent). Two rules hold throughout:
 * - Out: aggregates and opaque ids only. No title, description, raw event, host, user, address, email,
 *   tenant name or asset name ever leaves through these functions.
 * - In: every action is checked here against GUARDRAILS and the platform "Allow Hermes to act" switch.
 *   The caller's claims about a pattern count for nothing.
 */

const DAY = 86_400_000;
export const PATTERN_CAP = 2000;
const SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const;

let cachedKey: Buffer | undefined;
const key = () => (cachedKey ??= pseudonymKey(env().BETTER_AUTH_SECRET));
const patternKey = (tenantId: string, source: string, ruleId: string) => `${tenantId}\0${source}\0${ruleId}`;
const iso = (ms: number | null) => (ms == null ? null : new Date(ms).toISOString());
const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;

/** Customer tenants in scope, never training workspaces. */
async function liveTenants(tx: Tx, ids: string[]): Promise<string[]> {
  if (!ids.length) return [];
  const rows = await tx
    .select({ id: tenants.id })
    .from(tenants)
    .where(and(inArray(tenants.id, ids), sql`coalesce((${tenants.settings}->>'training')::boolean, false) = false`));
  return rows.map((r) => r.id);
}

type Counts = { falsePositive: number; resolved: number; escalated: number; open: number; passive: number };

/** Patterns (tenant, source, rule id) with at least one alert in the last `days`, as aggregates. */
export async function listPatterns(ctx: AccessContext, days: number, now = new Date()) {
  return scoped(ctx, "tuning:read", async (tx, scopeIds) => {
    const ids = await liveTenants(tx, scopeIds);
    const since = new Date(now.getTime() - days * DAY);
    const empty = { windowDays: days, generatedAt: now.toISOString(), truncated: false, patterns: [], fleet: [] };
    if (!ids.length) return empty;
    const inWindow = and(inArray(alerts.tenantId, ids), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now), isNotNull(alerts.ruleId));
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, sql<number>`count(*) filter (where ${alerts.severity} = ${sql.raw(`'${s}'`)})::int`])) as Record<(typeof SEVERITIES)[number], SQL<number>>;

    const base = await tx
      .select({
        tenantId: alerts.tenantId, source: alerts.source, ruleId: sql<string>`${alerts.ruleId}`,
        total: sql<number>`count(*)::int`, ...bySeverity,
        distinctAssets: sql<number>`count(distinct ${alerts.assetId})::int`,
        distinctUsers: sql<number>`count(distinct lower(${alerts.userName}))::int`,
        incidentsOpened: sql<number>`count(distinct ${alerts.incidentId})::int`,
        firstSeen: sql<number>`(extract(epoch from min(${alerts.occurredAt})) * 1000)::float8`,
        lastSeen: sql<number>`(extract(epoch from max(${alerts.occurredAt})) * 1000)::float8`,
      })
      .from(alerts)
      .where(inWindow)
      .groupBy(alerts.tenantId, alerts.source, alerts.ruleId)
      .orderBy(desc(sql`count(*)`))
      .limit(PATTERN_CAP + 1);
    const truncated = base.length > PATTERN_CAP;
    // Identifiers that could be a host, an address or an email are never handed out (or acted on).
    const listed = base.slice(0, PATTERN_CAP).filter((p) => safeToken(p.source) && safeToken(p.ruleId, 128));
    if (!listed.length) return { ...empty, truncated };
    const wanted = new Set(listed.map((p) => patternKey(p.tenantId, p.source, p.ruleId)));
    const pick = <T extends { tenantId: string; source: string; ruleId: string | null }>(rows: T[]) => {
      const m = new Map<string, T[]>();
      for (const r of rows) {
        const k = patternKey(r.tenantId, r.source, r.ruleId ?? "");
        if (!wanted.has(k)) continue;
        m.set(k, [...(m.get(k) ?? []), r]);
      }
      return m;
    };

    const buckets = pick(
      await tx
        .select({
          tenantId: alerts.tenantId, source: alerts.source, ruleId: alerts.ruleId,
          day: sql<string>`to_char(${alerts.occurredAt} at time zone 'UTC', 'YYYY-MM-DD')`,
          hour: sql<number>`extract(hour from ${alerts.occurredAt} at time zone 'UTC')::int`,
          n: sql<number>`count(*)::int`,
        })
        .from(alerts)
        .where(inWindow)
        .groupBy(sql`1`, sql`2`, sql`3`, sql`4`, sql`5`),
    );

    const since30 = new Date(now.getTime() - 30 * DAY);
    const since90 = new Date(now.getTime() - 90 * DAY);
    const f = (cond: SQL, from: Date) => sql<number>`count(*) filter (where ${cond} and ${alerts.occurredAt} >= ${ts(from)})::int`;
    const outcome = (from: Date) => ({
      // Analysts' decisions only: Hermes' own closures would otherwise feed its next week's evidence.
      falsePositive: f(sql`${alerts.status} = 'FALSE_POSITIVE' and ${alerts.tuningActionId} is null`, from),
      resolved: f(sql`${alerts.status} = 'RESOLVED'`, from),
      escalated: f(sql`${alerts.status} in ('ESCALATED','CONTAINED')`, from),
      open: f(sql`${alerts.status} in ('NEW','TRIAGING','INVESTIGATING')`, from),
      passive: f(sql`${alerts.lane} = 'passive'`, from),
    });
    const o30 = outcome(since30);
    const o90 = outcome(since90);
    const dispositions = pick(
      await tx
        .select({
          tenantId: alerts.tenantId, source: alerts.source, ruleId: alerts.ruleId,
          fp30: o30.falsePositive, resolved30: o30.resolved, escalated30: o30.escalated, open30: o30.open, passive30: o30.passive,
          fp90: o90.falsePositive, resolved90: o90.resolved, escalated90: o90.escalated, open90: o90.open, passive90: o90.passive,
        })
        .from(alerts)
        .where(and(inArray(alerts.tenantId, ids), gte(alerts.occurredAt, since90), lte(alerts.occurredAt, now), isNotNull(alerts.ruleId)))
        .groupBy(alerts.tenantId, alerts.source, alerts.ruleId),
    );

    const triage = pick(
      [...(await tx.execute<{ tenant_id: string; source: string; rule_id: string; median: number | null }>(sql`
        select a.tenant_id, a.source, a.rule_id,
          percentile_cont(0.5) within group (order by extract(epoch from f.first_at - a.ingested_at) / 60) as median
        from alerts a
        join (
          select target_id, min(at) as first_at from audit_log
          where tenant_id in ${ids} and action = 'alert.update' and target_type = 'alert' and at >= ${ts(since)}
          group by target_id
        ) f on f.target_id = a.id::text
        where a.tenant_id in ${ids} and a.occurred_at >= ${ts(since)} and a.rule_id is not null
        group by 1, 2, 3`))].map((r) => ({ tenantId: r.tenant_id, source: r.source, ruleId: r.rule_id, median: r.median == null ? null : Number(r.median) })),
    );

    const overrides = pick(
      await tx
        .select({
          tenantId: tuningActions.tenantId, source: tuningActions.source, ruleId: tuningActions.ruleId,
          undone: sql<number>`count(*) filter (where ${tuningActions.undoneAt} is not null)::int`,
          reopened: sql<number>`coalesce(sum((select count(*) from alerts a where a.tuning_action_id = ${tuningActions.id} and a.status <> 'FALSE_POSITIVE')) filter (where ${tuningActions.undoneAt} is null and ${tuningActions.kind} = 'close'), 0)::int`,
        })
        .from(tuningActions)
        .where(inArray(tuningActions.tenantId, ids))
        .groupBy(tuningActions.tenantId, tuningActions.source, tuningActions.ruleId),
    );

    const rules = pick(
      await tx
        .select({ tenantId: noiseRules.tenantId, source: noiseRules.source, ruleId: noiseRules.ruleId, id: noiseRules.id, status: noiseRules.status, expiresAt: noiseRules.expiresAt, hitCount: noiseRules.hitCount })
        .from(noiseRules)
        .where(and(inArray(noiseRules.tenantId, ids), eq(noiseRules.status, "active"), gt(noiseRules.expiresAt, now)))
        .orderBy(desc(noiseRules.createdAt)),
    );

    const notes = pick(
      await tx
        .select({ tenantId: patternAnnotations.tenantId, source: patternAnnotations.source, ruleId: patternAnnotations.ruleId, id: patternAnnotations.id, text: patternAnnotations.text, confidence: patternAnnotations.confidence, createdAt: patternAnnotations.createdAt })
        .from(patternAnnotations)
        .where(and(inArray(patternAnnotations.tenantId, ids), gte(patternAnnotations.createdAt, since90)))
        .orderBy(desc(patternAnnotations.createdAt)),
    );

    // Only these fields of the newest event: never descriptions or logs.
    const meta = pick(
      await tx
        .selectDistinctOn([alerts.tenantId, alerts.source, alerts.ruleId], {
          tenantId: alerts.tenantId, source: alerts.source, ruleId: alerts.ruleId, techniques: alerts.attackTechniques, siemSeverity: alerts.siemSeverity,
          raw: sql<unknown>`jsonb_build_object('rule', jsonb_build_object('level', ${alerts.raw} #> '{rule,level}', 'groups', ${alerts.raw} #> '{rule,groups}', 'mitre', jsonb_build_object('id', ${alerts.raw} #> '{rule,mitre,id}')), 'decoder', jsonb_build_object('name', ${alerts.raw} #> '{decoder,name}'))`,
        })
        .from(alerts)
        .where(inWindow)
        .orderBy(alerts.tenantId, alerts.source, alerts.ruleId, desc(alerts.occurredAt)),
    );

    // Rules that fire in the same tenant in the same UTC hour, across the fleet: `count` such tenant-hours, `tenants` distinct tenants.
    const coFiring = await tx.execute<{ source: string; rule_id: string; co_source: string; co_rule_id: string; n: number; tenants: number }>(sql`
      with b as (
        select distinct tenant_id, source, rule_id, date_trunc('hour', occurred_at) as h
        from alerts
        where tenant_id in ${ids} and occurred_at >= ${ts(since)} and occurred_at <= ${ts(now)} and rule_id is not null
      )
      select a.source, a.rule_id, c.source as co_source, c.rule_id as co_rule_id, count(*)::int as n, count(distinct a.tenant_id)::int as tenants
      from b a join b c on c.tenant_id = a.tenant_id and c.h = a.h and (c.source, c.rule_id) <> (a.source, a.rule_id)
      group by 1, 2, 3, 4`);

    // UTC days from the (partial) first day of the window to today, oldest first: sum(byDay) = total.
    const dayList = Array.from({ length: days + 1 }, (_, i) => new Date(since.getTime() + i * DAY).toISOString().slice(0, 10)).filter((d, i, a) => a.indexOf(d) === i);
    const patterns = listed.map((p) => {
      const k = patternKey(p.tenantId, p.source, p.ruleId);
      const perDay = new Map<string, number>();
      const byHourOfDay = Array.from({ length: 24 }, () => 0);
      for (const b of buckets.get(k) ?? []) {
        perDay.set(b.day, (perDay.get(b.day) ?? 0) + b.n);
        byHourOfDay[b.hour] = (byHourOfDay[b.hour] ?? 0) + b.n;
      }
      const d = dispositions.get(k)?.[0];
      const window = (w: 30 | 90): Counts =>
        d
          ? w === 30
            ? { falsePositive: d.fp30, resolved: d.resolved30, escalated: d.escalated30, open: d.open30, passive: d.passive30 }
            : { falsePositive: d.fp90, resolved: d.resolved90, escalated: d.escalated90, open: d.open90, passive: d.passive90 }
          : { falsePositive: 0, resolved: 0, escalated: 0, open: 0, passive: 0 };
      const o = overrides.get(k)?.[0];
      const rule = rules.get(k)?.[0];
      const m = meta.get(k)?.[0];
      const ruleMeta = ruleMetadata(m?.raw, m?.techniques ?? []);
      return {
        patternId: patternIdFor(key(), p.tenantId, p.source, p.ruleId),
        tenantRef: tenantRefFor(key(), p.tenantId),
        source: p.source,
        ruleId: p.ruleId,
        // Wazuh's rule level, else the source's native severity; 0 when neither is known.
        ruleLevel: ruleMeta.level ?? m?.siemSeverity ?? 0,
        ruleGroups: ruleMeta.groups,
        mitre: ruleMeta.mitre,
        severity: Object.fromEntries(SEVERITIES.map((s) => [s, p[s]])) as Record<(typeof SEVERITIES)[number], number>,
        counts: { total: p.total, byDay: dayList.map((date) => perDay.get(date) ?? 0), byHourOfDay },
        distinctAssets: p.distinctAssets,
        distinctUsers: p.distinctUsers,
        dispositions: { d30: window(30), d90: window(90) },
        incidentsOpened: p.incidentsOpened,
        analystOverrides: (o?.undone ?? 0) + (o?.reopened ?? 0),
        medianMinutesToFirstTriage: triage.get(k)?.[0]?.median ?? null,
        firstSeen: iso(p.firstSeen),
        lastSeen: iso(p.lastSeen),
        noiseRule: rule ? { id: rule.id, status: rule.status, expiresAt: rule.expiresAt.toISOString(), hitCount: rule.hitCount } : null,
        // Only the agent writes annotations today; people's notes on alerts are not handed out.
        annotations: (notes.get(k) ?? []).slice(0, 5).map((n) => ({ confidence: n.confidence, createdAt: n.createdAt.toISOString(), authorKind: "service" as const, text: n.text })),
      };
    });

    // The registry lets a caller act only on ids it was given (and lets blakSOC resolve them).
    for (let i = 0; i < listed.length; i += 500) {
      await tx
        .insert(tuningPatterns)
        .values(listed.slice(i, i + 500).map((p) => ({ id: patternIdFor(key(), p.tenantId, p.source, p.ruleId), tenantId: p.tenantId, source: p.source, ruleId: p.ruleId })))
        .onConflictDoNothing();
    }

    const fleetMap = new Map<string, { source: string; ruleId: string; tenantsAffected: number; total: number }>();
    for (const p of listed) {
      const k = `${p.source}\0${p.ruleId}`;
      const cur = fleetMap.get(k) ?? { source: p.source, ruleId: p.ruleId, tenantsAffected: 0, total: 0 };
      cur.tenantsAffected++;
      cur.total += p.total;
      fleetMap.set(k, cur);
    }
    const co = new Map<string, { source: string; ruleId: string; count: number; tenants: number }[]>();
    for (const r of coFiring) {
      if (!safeToken(r.co_source) || !safeToken(r.co_rule_id, 128)) continue;
      const k = `${r.source}\0${r.rule_id}`;
      co.set(k, [...(co.get(k) ?? []), { source: r.co_source, ruleId: r.co_rule_id, count: Number(r.n), tenants: Number(r.tenants) }]);
    }
    const fleet = [...fleetMap.entries()]
      .map(([k, v]) => ({ ...v, coFiring: (co.get(k) ?? []).sort((a, b) => b.count - a.count).slice(0, 5) }))
      .sort((a, b) => b.tenantsAffected - a.tenantsAffected || b.total - a.total);

    return { windowDays: days, generatedAt: now.toISOString(), truncated, patterns, fleet };
  });
}

export type PatternRow = typeof tuningPatterns.$inferSelect;

/** A pattern id the caller was given, in a tenant where it holds `permission`. */
async function resolvePattern(ctx: AccessContext, patternId: string, permission: Permission): Promise<PatternRow> {
  if (!can(ctx, permission)) throw new AccessDenied(`missing ${permission}`);
  if (!PATTERN_ID.test(patternId)) throw new TuningRefused("Unknown pattern. List patterns first.", 404);
  // Read before a scope exists so the tenant is known; everything after runs under RLS.
  const [p] = await systemDb().select().from(tuningPatterns).where(eq(tuningPatterns.id, patternId));
  if (!p || !can(ctx, permission, p.tenantId)) throw new TuningRefused("Unknown pattern. List patterns first.", 404);
  return p;
}

const patternRef = (p: PatternRow) => ({ patternId: p.id, tenantRef: tenantRefFor(key(), p.tenantId), source: p.source, ruleId: p.ruleId });

export async function annotatePattern(ctx: AccessContext, patternId: string, input: { text: string; confidence: "low" | "medium" | "high" }) {
  const p = await resolvePattern(ctx, patternId, "tuning:annotate");
  const text = stripControl(input.text).trim();
  if (!text) throw new TuningRefused("The annotation is empty.", 422);
  return inTenant(ctx, "tuning:annotate", p.tenantId, async (tx) => {
    const now = new Date();
    const [note] = await tx
      .insert(patternAnnotations)
      .values({ tenantId: p.tenantId, patternId: p.id, source: p.source, ruleId: p.ruleId, text, confidence: input.confidence, createdBy: ctx.principal.userId, createdAt: now })
      .returning({ id: patternAnnotations.id });
    const [act] = await tx
      .insert(tuningActions)
      .values({ tenantId: p.tenantId, kind: "annotate", patternId: p.id, source: p.source, ruleId: p.ruleId, params: { confidence: input.confidence, annotationId: note!.id }, actorId: ctx.principal.userId, createdAt: now })
      .returning({ id: tuningActions.id });
    await audit(tx, { ...actor(ctx), tenantId: p.tenantId, action: "tuning.annotate", targetType: "tuning_action", targetId: act!.id, detail: { patternId: p.id, source: p.source, ruleId: p.ruleId, confidence: input.confidence, length: text.length } });
    return { id: note!.id, actionId: act!.id, createdAt: now.toISOString() };
  });
}

async function assertMayAct() {
  if (!(await hermesMayAct())) {
    throw new TuningRefused("Hermes may not act: “Allow Hermes to act” is off on the Hermes page in blakSOC. Reading and annotating still work.", 409, "hermes_actions_disabled");
  }
}

/** One acting request at a time across the platform, so the weekly caps cannot be raced. */
const lockActs = (tx: Tx) => tx.execute(sql`select pg_advisory_xact_lock(hashtext('blaksoc.tuning.act'))`);

/** What people decided about the pattern: the only evidence guardrails accept. */
export async function patternEvidence(tx: Tx, p: { tenantId: string; source: string; ruleId: string }, now = new Date()): Promise<PatternEvidence> {
  const since90 = new Date(now.getTime() - GUARDRAILS.lookbackDays * DAY);
  const since30 = new Date(now.getTime() - GUARDRAILS.quietDays * DAY);
  const [r] = await tx
    .select({
      humanClosed: sql<number>`count(*) filter (where ${alerts.status} in ('RESOLVED','FALSE_POSITIVE') and ${alerts.tuningActionId} is null)::int`,
      humanFalsePositive: sql<number>`count(*) filter (where ${alerts.status} = 'FALSE_POSITIVE' and ${alerts.tuningActionId} is null)::int`,
      escalatedRecently: sql<number>`count(*) filter (where ${alerts.occurredAt} >= ${ts(since30)} and (${alerts.status} in ('ESCALATED','CONTAINED') or ${alerts.incidentId} is not null))::int`,
    })
    .from(alerts)
    .where(and(eq(alerts.tenantId, p.tenantId), eq(alerts.source, p.source), eq(alerts.ruleId, p.ruleId), gte(alerts.occurredAt, since90), lte(alerts.occurredAt, now)));
  return { humanClosed: r?.humanClosed ?? 0, humanFalsePositive: r?.humanFalsePositive ?? 0, escalatedRecently: r?.escalatedRecently ?? 0 };
}

async function assertGuardrails(tx: Tx, p: PatternRow, now: Date) {
  const evidence = await patternEvidence(tx, p, now);
  const refusal = guardrailRefusal(evidence);
  if (refusal) throw new TuningRefused(refusal, 422, "guardrail", { evidence });
  return evidence;
}

/** Agent closures across the platform in the last 7 days (undone ones still count). */
async function closuresThisWeek(now: Date): Promise<number> {
  const [r] = await systemDb()
    .select({ n: sql<number>`coalesce(sum(${tuningActions.affectedCount}), 0)::int` })
    .from(tuningActions)
    .where(and(eq(tuningActions.kind, "close"), gte(tuningActions.createdAt, new Date(now.getTime() - 7 * DAY))));
  return r?.n ?? 0;
}

/**
 * Close the pattern's open, low-stakes alerts as false positives: NEW or TRIAGING, informational to medium,
 * not on an incident, no threat-intel match. Each closure is undoable from blakSOC for as long as the alert exists.
 */
export async function closePattern(ctx: AccessContext, patternId: string, input: { reason: string; maxAlerts?: number }) {
  const p = await resolvePattern(ctx, patternId, "tuning:act");
  await assertMayAct();
  return inTenant(ctx, "tuning:act", p.tenantId, async (tx) => {
    await lockActs(tx);
    const now = new Date();
    const evidence = await assertGuardrails(tx, p, now);
    const budget = GUARDRAILS.maxClosuresPerWeek - (await closuresThisWeek(now));
    if (budget <= 0) throw new TuningRefused(`The weekly limit of ${GUARDRAILS.maxClosuresPerWeek} automated closures is reached.`, 409, "cap_reached");
    const limit = Math.min(input.maxAlerts ?? GUARDRAILS.maxCloseAlerts, GUARDRAILS.maxCloseAlerts, budget);
    const targets = await tx
      .select({ id: alerts.id })
      .from(alerts)
      .where(and(
        eq(alerts.tenantId, p.tenantId), eq(alerts.source, p.source), eq(alerts.ruleId, p.ruleId),
        inArray(alerts.status, ["NEW", "TRIAGING"]), inArray(alerts.severity, [...CLOSABLE_SEVERITIES]), isNull(alerts.incidentId),
        notInArray(alerts.intelVerdict, [...NOISE_OVERRIDE_VERDICTS]),
      ))
      .orderBy(asc(alerts.occurredAt))
      .limit(limit)
      .for("update", { skipLocked: true });
    if (!targets.length) return { actionId: null, affected: 0, reversibleUntil: null };
    const reversibleUntil = new Date(now.getTime() + GUARDRAILS.undoWindowDays * DAY);
    const reason = stripControl(input.reason).trim();
    const [act] = await tx
      .insert(tuningActions)
      .values({ tenantId: p.tenantId, kind: "close", patternId: p.id, source: p.source, ruleId: p.ruleId, params: { reason, maxAlerts: input.maxAlerts ?? null, evidence }, affectedCount: targets.length, actorId: ctx.principal.userId, createdAt: now, reversibleUntil })
      .returning({ id: tuningActions.id });
    const ids = targets.map((t) => t.id);
    for (let i = 0; i < ids.length; i += 1000) {
      // updated_at = the action's time: purge later checks no one has touched the alert since.
      await tx.update(alerts).set({ status: "FALSE_POSITIVE", tuningActionId: act!.id, updatedAt: now }).where(and(inArray(alerts.id, ids.slice(i, i + 1000)), inArray(alerts.status, ["NEW", "TRIAGING"])));
    }
    await audit(tx, { ...actor(ctx), tenantId: p.tenantId, action: "tuning.close", targetType: "tuning_action", targetId: act!.id, detail: { patternId: p.id, source: p.source, ruleId: p.ruleId, affected: ids.length, reason, evidence } });
    return { actionId: act!.id, affected: ids.length, reversibleUntil: reversibleUntil.toISOString() };
  });
}

/** An active noise rule for the whole pattern (no host scope), capped at medium severity, ≤ 30 days. */
export async function createAgentNoiseRule(ctx: AccessContext, input: { patternId: string; reason: string; expiresInDays?: number }) {
  const p = await resolvePattern(ctx, input.patternId, "tuning:act");
  await assertMayAct();
  const days = input.expiresInDays ?? GUARDRAILS.maxRuleDays;
  if (!Number.isInteger(days) || days < 1 || days > GUARDRAILS.maxRuleDays) throw new TuningRefused(`expiresInDays must be 1–${GUARDRAILS.maxRuleDays}.`, 422);
  return inTenant(ctx, "tuning:act", p.tenantId, async (tx) => {
    await lockActs(tx);
    const now = new Date();
    const evidence = await assertGuardrails(tx, p, now);
    const [week] = await tx
      .select({ n: sql<number>`count(*)::int` })
      .from(tuningActions)
      .where(and(eq(tuningActions.tenantId, p.tenantId), eq(tuningActions.kind, "noise_rule"), gte(tuningActions.createdAt, new Date(now.getTime() - 7 * DAY))));
    if ((week?.n ?? 0) >= GUARDRAILS.maxRulesPerTenantPerWeek) throw new TuningRefused(`The limit of ${GUARDRAILS.maxRulesPerTenantPerWeek} automated noise rules per customer per 7 days is reached.`, 409, "cap_reached");
    const [dupe] = await tx
      .select({ id: noiseRules.id })
      .from(noiseRules)
      .where(and(
        eq(noiseRules.tenantId, p.tenantId), eq(noiseRules.source, p.source), eq(noiseRules.ruleId, p.ruleId), inArray(noiseRules.status, ["proposed", "active"]), gt(noiseRules.expiresAt, now),
        isNull(noiseRules.assetId), isNull(noiseRules.hostname), isNull(noiseRules.titlePattern),
      ));
    if (dupe) throw new TuningRefused("A noise rule already covers this pattern.", 409, "duplicate", { noiseRuleId: dupe.id });
    const reason = stripControl(input.reason).trim();
    const expiresAt = expiryFrom(days, now);
    const [rule] = await tx
      .insert(noiseRules)
      .values({
        tenantId: p.tenantId, source: p.source, ruleId: p.ruleId, assetId: null, hostname: null, titlePattern: null, maxSeverity: AGENT_RULE_MAX_SEVERITY, reason,
        evidence: `${evidence.humanFalsePositive} of ${evidence.humanClosed} alerts closed by analysts in ${GUARDRAILS.lookbackDays} days were false positives; no escalation in ${GUARDRAILS.quietDays} days.`,
        status: "active", createdBy: ctx.principal.userId, createdByKind: "service", decidedAt: now, expiresAt,
      })
      .returning();
    const [act] = await tx
      .insert(tuningActions)
      .values({ tenantId: p.tenantId, kind: "noise_rule", patternId: p.id, source: p.source, ruleId: p.ruleId, params: { reason, expiresInDays: days, evidence }, actorId: ctx.principal.userId, noiseRuleId: rule!.id, createdAt: now })
      .returning({ id: tuningActions.id });
    const moved = await applyToOpenAlerts(tx, rule!, now);
    await tx.update(tuningActions).set({ affectedCount: moved.length }).where(eq(tuningActions.id, act!.id));
    await audit(tx, {
      ...actor(ctx), tenantId: p.tenantId, action: "noise_rule.create", targetType: "noise_rule", targetId: rule!.id,
      detail: { via: "tuning_api", actionId: act!.id, patternId: p.id, scope: `rule ${p.ruleId} from ${p.source} on every host, up to ${AGENT_RULE_MAX_SEVERITY}`, reason, expiresAt: expiresAt.toISOString(), alertIds: moved },
    });
    return { noiseRuleId: rule!.id, actionId: act!.id, expiresAt: expiresAt.toISOString(), movedToPassive: moved.length };
  });
}

/**
 * Delete alerts the agent closed at least 7 days ago that nobody has touched since, through the retention
 * path (batched, graph cleaned, each batch audited). Nothing inside the undo window is ever deleted.
 */
export async function purgePattern(ctx: AccessContext, patternId: string) {
  const p = await resolvePattern(ctx, patternId, "tuning:act");
  await assertMayAct();
  const now = new Date();
  const cutoff = new Date(now.getTime() - GUARDRAILS.undoWindowDays * DAY);
  let deleted = 0;
  for (;;) {
    const n = await inTenant(ctx, "tuning:act", p.tenantId, async (tx) => {
      const batch = await tx
        .select({ id: alerts.id })
        .from(alerts)
        .innerJoin(tuningActions, eq(tuningActions.id, alerts.tuningActionId))
        .where(and(
          eq(alerts.tenantId, p.tenantId), eq(tuningActions.tenantId, p.tenantId), eq(tuningActions.source, p.source), eq(tuningActions.ruleId, p.ruleId),
          eq(tuningActions.kind, "close"), isNull(tuningActions.undoneAt), lte(tuningActions.reversibleUntil, now), lte(tuningActions.createdAt, cutoff),
          // Still the agent's closure: not reopened, re-closed or otherwise changed by a person since.
          eq(alerts.status, "FALSE_POSITIVE"), isNull(alerts.incidentId), lte(alerts.updatedAt, tuningActions.createdAt),
        ))
        .limit(PURGE_BATCH)
        .for("update", { of: alerts, skipLocked: true });
      if (!batch.length) return 0;
      const ids = (await tx.delete(alerts).where(and(inArray(alerts.id, batch.map((b) => b.id)), isNull(alerts.incidentId))).returning({ id: alerts.id })).map((r) => r.id);
      if (!ids.length) return 0;
      await removeAlertGraph(tx, p.tenantId, ids);
      await audit(tx, { ...actor(ctx), tenantId: p.tenantId, action: "tuning.purge", targetType: "tenant", targetId: p.tenantId, detail: { patternId: p.id, source: p.source, ruleId: p.ruleId, deleted: ids.length, closedBefore: cutoff.toISOString() } });
      return ids.length;
    });
    deleted += n;
    if (n < PURGE_BATCH) break;
  }
  if (!deleted) {
    const [pending] = await inTenant(ctx, "tuning:act", p.tenantId, (tx) =>
      tx
        .select({ n: sql<number>`count(*)::int` })
        .from(alerts)
        .innerJoin(tuningActions, eq(tuningActions.id, alerts.tuningActionId))
        .where(and(eq(tuningActions.tenantId, p.tenantId), eq(tuningActions.source, p.source), eq(tuningActions.ruleId, p.ruleId), eq(tuningActions.kind, "close"), isNull(tuningActions.undoneAt), gt(tuningActions.reversibleUntil, now), eq(alerts.status, "FALSE_POSITIVE"))),
    );
    if (pending?.n) {
      throw new TuningRefused(`${pending.n} alert(s) were closed less than ${GUARDRAILS.undoWindowDays} days ago and stay for the undo window. Nothing older is left to purge.`, 409, "undo_window");
    }
    return { actionId: null, deleted: 0 };
  }
  const [act] = await inTenant(ctx, "tuning:act", p.tenantId, (tx) =>
    tx.insert(tuningActions).values({ tenantId: p.tenantId, kind: "purge", patternId: p.id, source: p.source, ruleId: p.ruleId, params: { closedBefore: cutoff.toISOString() }, affectedCount: deleted, actorId: ctx.principal.userId, createdAt: now }).returning({ id: tuningActions.id }),
  );
  return { actionId: act!.id, deleted };
}

/** The agent's past actions and how people responded to them. No names: undoers are reported by kind. */
export async function listAgentActions(ctx: AccessContext, since: Date) {
  return scoped(ctx, "tuning:read", async (tx, ids) => {
    const rows = await tx
      .select({ a: tuningActions, reopened: sql<number>`(select count(*)::int from alerts x where x.tuning_action_id = ${tuningActions.id} and x.status <> 'FALSE_POSITIVE')` })
      .from(tuningActions)
      .where(and(inArray(tuningActions.tenantId, ids), gte(tuningActions.createdAt, since)))
      .orderBy(desc(tuningActions.createdAt))
      .limit(1000);
    return rows.map(({ a, reopened }) => ({
      id: a.id, kind: a.kind, ...patternRef({ id: a.patternId, tenantId: a.tenantId, source: a.source, ruleId: a.ruleId, createdAt: a.createdAt }),
      createdAt: a.createdAt.toISOString(),
      affected: a.affectedCount,
      undoneAt: a.undoneAt?.toISOString() ?? null,
      reopenedCount: a.kind === "close" ? reopened : 0,
      // Refused requests are not stored as actions (they are in the audit trail as api.request with their status).
      status: a.undoneAt ? ("undone" as const) : ("applied" as const),
    }));
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Reports and memory: platform-level, for a platform identity (agent) or platform staff (UI)

const PLATFORM = { tenantIds: [], platform: true } as const;

/** A platform-wide grant of `permission`: tenant-bound identities cannot read or write platform tuning data. */
function assertPlatform(ctx: AccessContext, permission: Permission) {
  if (!ctx.isPlatform || !ctx.grants.some((g) => g.tenantId === null && g.permissions.has(permission))) {
    throw new AccessDenied(`a platform-wide ${permission} grant is required`);
  }
}

export const REPORT_MAX_BYTES = 50 * 1024;

export type ReportInput = { periodStart: Date; periodEnd: Date; markdown: string; stats: { executed: number; refused: number; dryRun: number; patternsReviewed: number } };

export async function createReport(ctx: AccessContext, input: ReportInput) {
  assertPlatform(ctx, "tuning:report");
  const markdown = stripControl(input.markdown);
  if (Buffer.byteLength(markdown, "utf8") > REPORT_MAX_BYTES) throw new TuningRefused(`The report is larger than ${REPORT_MAX_BYTES / 1024} KB.`, 413);
  if (/<\/?[A-Za-z][^>]*>/.test(markdown)) throw new TuningRefused("Reports are plain markdown; HTML is not accepted.", 422);
  if (input.periodEnd < input.periodStart) throw new TuningRefused("periodEnd is before periodStart.", 422);
  return withScope(PLATFORM, async (tx) => {
    const [row] = await tx
      .insert(hermesReports)
      .values({ periodStart: input.periodStart, periodEnd: input.periodEnd, markdown, stats: input.stats, createdBy: ctx.principal.userId })
      .returning({ id: hermesReports.id, createdAt: hermesReports.createdAt });
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tuning.report", targetType: "hermes_report", targetId: row!.id, detail: { periodStart: input.periodStart.toISOString(), periodEnd: input.periodEnd.toISOString(), stats: input.stats, bytes: Buffer.byteLength(markdown, "utf8") } });
    return { id: row!.id, createdAt: row!.createdAt.toISOString() };
  });
}

/** Newest first. The agent reads its own (tuning:report); platform staff read them on the Hermes page. */
export async function listReports(ctx: AccessContext, limit = 10, permission: Permission = "tuning:report") {
  assertPlatform(ctx, permission);
  return withScope(PLATFORM, (tx) => tx.select().from(hermesReports).orderBy(desc(hermesReports.createdAt)).limit(Math.min(Math.max(limit, 1), 100)));
}

export const MEMORY_VERSION_KEY = "hermes.memory_version";

const versionOf = (value: unknown) => {
  const v = (value as { version?: unknown } | null)?.version;
  return typeof v === "number" && Number.isInteger(v) ? v : 0;
};

/** Lock the version row (creating it at 0) so concurrent writers queue. */
async function lockVersion(tx: Tx): Promise<number> {
  await tx.insert(platformSettings).values({ key: MEMORY_VERSION_KEY, value: { version: 0 } }).onConflictDoNothing();
  const [row] = await tx.select({ value: platformSettings.value }).from(platformSettings).where(eq(platformSettings.key, MEMORY_VERSION_KEY)).for("update");
  return versionOf(row?.value);
}

async function bumpVersion(tx: Tx, to: number, by: string) {
  await tx.update(platformSettings).set({ value: { version: to }, updatedBy: by, updatedAt: new Date() }).where(eq(platformSettings.key, MEMORY_VERSION_KEY));
}

export async function getMemory(ctx: AccessContext, permission: Permission = "tuning:read") {
  assertPlatform(ctx, permission);
  return withScope(PLATFORM, async (tx) => {
    const [row] = await tx.select({ value: platformSettings.value }).from(platformSettings).where(eq(platformSettings.key, MEMORY_VERSION_KEY));
    const notes = await tx.select().from(hermesMemoryNotes).orderBy(asc(hermesMemoryNotes.createdAt), asc(hermesMemoryNotes.id));
    return {
      version: versionOf(row?.value),
      notes: notes.map((n) => ({ id: n.id, kind: n.kind, text: n.text, createdAt: n.createdAt.toISOString(), updatedAt: n.updatedAt.toISOString() })),
    };
  });
}

/**
 * Replace the agent's own notes (model and outcome) in one step, if `version` is still current: entries with
 * an id update that note, entries without one are new, and the agent's notes left out are removed. Analysts'
 * (human) notes are kept whatever the agent sends. Audited as counts, never text.
 */
export async function putMemory(ctx: AccessContext, input: { version: number; notes: MemoryNoteInput[] }) {
  assertPlatform(ctx, "tuning:memory");
  const checked = checkMemoryNotes(input.notes);
  if (!checked.ok) throw new TuningRefused(checked.message, 422, "invalid_note");
  return withScope(PLATFORM, async (tx) => {
    const current = await lockVersion(tx);
    if (current !== input.version) throw new TuningRefused("Memory changed since it was read. Read it again and reapply your changes.", 409, "version_conflict", { currentVersion: current });
    const existing = await tx.select().from(hermesMemoryNotes).where(ne(hermesMemoryNotes.kind, "human"));
    const old = new Map(existing.map((n) => [n.id, n]));
    const unknown = checked.notes.find((n) => n.id && !old.has(n.id));
    if (unknown) throw new TuningRefused(`Note ${unknown.id} is not one of the agent's notes. Omit the id to add a new note.`, 422, "invalid_note");
    const diff = memoryDiff(existing, checked.notes);
    const keep = new Set(checked.notes.map((n) => n.id).filter(Boolean));
    const gone = existing.filter((n) => !keep.has(n.id)).map((n) => n.id);
    if (gone.length) await tx.delete(hermesMemoryNotes).where(inArray(hermesMemoryNotes.id, gone));
    const now = new Date();
    for (const n of checked.notes) {
      const o = n.id ? old.get(n.id) : undefined;
      if (!o) await tx.insert(hermesMemoryNotes).values({ kind: n.kind, text: n.text, createdBy: ctx.principal.userId, createdAt: now, updatedAt: now });
      else if (o.text !== n.text || o.kind !== n.kind) await tx.update(hermesMemoryNotes).set({ kind: n.kind, text: n.text, updatedAt: now }).where(eq(hermesMemoryNotes.id, o.id));
    }
    const version = current + 1;
    await bumpVersion(tx, version, ctx.principal.userId);
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tuning.memory", targetType: "hermes_memory", targetId: "hermes", detail: { version, ...diff } });
    return { version, ...diff };
  });
}

/** Platform staff who look after Hermes (its memory, its reports, undo). */
export const isHermesStaff = (ctx: AccessContext) => ctx.isPlatform && ctx.grants.some((g) => g.tenantId === null && g.permissions.has("alert:tune"));

function assertStaff(ctx: AccessContext) {
  if (!isHermesStaff(ctx)) throw new AccessDenied("platform alert:tune is required");
}

/** An analyst's lesson for the agent. Same identifier rules as the agent's own notes. */
export async function addHumanNote(ctx: AccessContext, input: { text: string }) {
  assertStaff(ctx);
  const text = stripControl(input.text).trim();
  const problem = noteProblem(text);
  if (problem) throw new TuningRefused(`The note ${problem}.`, 422);
  return withScope(PLATFORM, async (tx) => {
    const version = (await lockVersion(tx)) + 1;
    const [row] = await tx.insert(hermesMemoryNotes).values({ kind: "human" satisfies HermesNoteSource, text, createdBy: ctx.principal.userId }).returning({ id: hermesMemoryNotes.id });
    await bumpVersion(tx, version, ctx.principal.userId);
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tuning.memory_note_add", targetType: "hermes_memory", targetId: row!.id, detail: { version, kind: "human", length: text.length } });
    return { id: row!.id, version };
  });
}

export async function deleteMemoryNote(ctx: AccessContext, id: string) {
  assertStaff(ctx);
  return withScope(PLATFORM, async (tx) => {
    const version = (await lockVersion(tx)) + 1;
    const [gone] = await tx.delete(hermesMemoryNotes).where(eq(hermesMemoryNotes.id, id)).returning({ id: hermesMemoryNotes.id, kind: hermesMemoryNotes.kind });
    if (!gone) throw new TuningRefused("That note no longer exists.", 404);
    await bumpVersion(tx, version, ctx.principal.userId);
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tuning.memory_note_delete", targetType: "hermes_memory", targetId: gone.id, detail: { version, kind: gone.kind } });
    return { version };
  });
}
