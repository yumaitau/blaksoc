import { and, desc, eq, gte, inArray, isNotNull, isNull, lte, ne, notExists, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { systemDb } from "@/db/client";
import {
  alerts, assets, attackTechniques, correlationCursors, correlationFindings, correlationRuleSettings, incidentAlerts, incidentGroupExclusions, incidents,
} from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { evaluateRules, type CorrelationFinding, type CorrelationRule } from "@/lib/correlation/engine";
import { alertFromFinding, contributingIds, CORRELATION_SOURCE, eventFromAlert } from "@/lib/correlation/events";
import { planGroups, type GroupPlan } from "@/lib/correlation/grouping";
import { BUILTIN_RULES, ruleById } from "@/lib/correlation/rules";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { evaluateTriggers } from "@/lib/soar/engine";
import { actor, AccessDenied, inTenant } from "./common";
import { addTimeline, createIncidentFromAlerts, linkAlerts } from "./incidents";

const HOUR = 3_600_000;
/** First run for a tenant starts this far back. */
const FIRST_RUN = 24 * HOUR;
/** Never look back further than this, however stale the cursor. */
const MAX_LOOKBACK = 7 * 24 * HOUR;
/** Alerts per evaluation; enough for a busy tenant's window, bounded for the worker. */
const MAX_EVENTS = 5000;
export const GROUP_WINDOW = 6 * HOUR;
const GROUP_LOOKBACK = 48 * HOUR;
const OPEN_ALERT = ["NEW", "TRIAGING", "INVESTIGATING"] as const;

/** Look-back a rule needs so a re-run reproduces its findings (window, suppression, corroboration). */
function span(rule: CorrelationRule): number {
  const suppress = rule.suppressFor ?? (rule.clause.type === "count" || rule.clause.type === "risk" ? rule.clause.within : 0);
  return rule.clause.within + suppress + Math.max(0, ...(rule.require ?? []).map((r) => r.within ?? 0));
}

export function rulesFor(overrides: { ruleId: string; enabled: boolean }[], stage: CorrelationRule["stage"] = "alerts"): CorrelationRule[] {
  const set = new Map(overrides.map((o) => [o.ruleId, o.enabled]));
  return BUILTIN_RULES.filter((r) => r.stage === stage && (set.get(r.id) ?? r.enabledByDefault));
}

/**
 * Evaluate the tenant's enabled rules over its stored alerts since the cursor (minus each rule's look-back),
 * raise each new finding through the normal ingest path, and move the cursor. Findings already stored are
 * skipped by dedupe key, so overlapping windows and retries never raise a finding twice.
 */
export async function runCorrelation(tenantId: string, now = new Date()): Promise<{ evaluated: number; findings: number; created: number }> {
  const { rules, events, existing, findings } = await withScope(systemScope(tenantId), async (tx) => {
    const overrides = await tx.select({ ruleId: correlationRuleSettings.ruleId, enabled: correlationRuleSettings.enabled }).from(correlationRuleSettings).where(eq(correlationRuleSettings.tenantId, tenantId));
    const rules = rulesFor(overrides);
    const [cursor] = await tx.select().from(correlationCursors).where(eq(correlationCursors.tenantId, tenantId));
    const from = Math.min(cursor?.evaluatedThrough.getTime() ?? now.getTime() - FIRST_RUN, now.getTime());
    const start = new Date(Math.max(from - Math.max(0, ...rules.map(span)), now.getTime() - MAX_LOOKBACK));
    const newest = rules.length
      ? await tx
          .select({
            id: alerts.id, source: alerts.source, ruleId: alerts.ruleId, title: alerts.title, category: alerts.category, severity: alerts.severity, riskScore: alerts.riskScore,
            userName: alerts.userName, assetId: alerts.assetId, hostname: sql<string | null>`coalesce(${assets.hostname}, ${assets.name})`, attackTechniques: alerts.attackTechniques,
            raw: alerts.raw, occurredAt: alerts.occurredAt,
          })
          .from(alerts)
          .leftJoin(assets, eq(assets.id, alerts.assetId))
          // Correlated alerts are outputs, not inputs: feeding them back would let a rule fire on itself.
          .where(and(eq(alerts.tenantId, tenantId), ne(alerts.source, CORRELATION_SOURCE), gte(alerts.occurredAt, start), lte(alerts.occurredAt, now)))
          // Over the cap, keep the newest: they are the ones that can still complete a rule.
          .orderBy(desc(alerts.occurredAt), desc(alerts.id))
          .limit(MAX_EVENTS)
      : [];
    const events = newest.reverse().map(eventFromAlert);
    const findings = evaluateRules(rules, events, now.getTime());
    const keys = findings.map((f) => f.dedupeKey);
    const existing = keys.length
      ? new Set((await tx.select({ key: correlationFindings.dedupeKey }).from(correlationFindings).where(and(eq(correlationFindings.tenantId, tenantId), inArray(correlationFindings.dedupeKey, keys)))).map((r) => r.key))
      : new Set<string>();
    return { rules, events, existing, findings };
  });

  let created = 0;
  for (const f of findings) {
    if (existing.has(f.dedupeKey)) continue;
    if (await persistFinding(tenantId, rules.find((r) => r.id === f.ruleId)!, f)) created++;
  }
  await withScope(systemScope(tenantId), (tx) =>
    tx.insert(correlationCursors).values({ tenantId, evaluatedThrough: now }).onConflictDoUpdate({ target: correlationCursors.tenantId, set: { evaluatedThrough: now, updatedAt: new Date() } }),
  );
  return { evaluated: events.length, findings: findings.length, created };
}

/** Correlated alert through ingest (risk, OCSF, SSE), then the finding row. Safe to repeat after a crash between the two. */
async function persistFinding(tenantId: string, rule: CorrelationRule, f: CorrelationFinding): Promise<boolean> {
  const res = await ingestAlert({ tenantId, integrationId: null, source: CORRELATION_SOURCE, alert: alertFromFinding(rule, f), intel: null });
  const inserted = await withScope(systemScope(tenantId), async (tx) => {
    const [row] = await tx
      .insert(correlationFindings)
      .values({
        tenantId, ruleId: f.ruleId, ruleVersion: f.ruleVersion, dedupeKey: f.dedupeKey, entity: f.entity, alertId: res.alertId,
        firstAt: new Date(f.firstAt), lastAt: new Date(f.lastAt), matches: f.matches, explanation: f.explanation,
      })
      .onConflictDoNothing()
      .returning({ id: correlationFindings.id });
    if (row) {
      await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "correlation.finding", targetType: "alert", targetId: res.alertId, detail: { ruleId: f.ruleId, ruleVersion: f.ruleVersion, dedupeKey: f.dedupeKey, eventIds: f.eventIds } });
    }
    return !!row;
  });
  if (res.created) await evaluateTriggers(tenantId, "alert.created", { alertId: res.alertId });
  return inserted;
}

/**
 * Group the tenant's open, unlinked alerts into incidents (see planGroups). Each plan is applied in its own
 * transaction and re-checked there, so an analyst acting between plan and apply wins.
 */
export async function runGrouping(tenantId: string, now = new Date()): Promise<{ plans: number; linked: number; opened: number }> {
  const plans = await withScope(systemScope(tenantId), async (tx) => {
    const since = new Date(now.getTime() - GROUP_LOOKBACK);
    const cols = { id: alerts.id, occurredAt: alerts.occurredAt, userName: alerts.userName, assetId: alerts.assetId, techniques: alerts.attackTechniques, source: alerts.source, raw: alerts.raw };
    const candidates = await tx
      .select({ ...cols, incidentId: sql<string | null>`null` })
      .from(alerts)
      .where(and(
        eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now), isNull(alerts.incidentId), inArray(alerts.status, [...OPEN_ALERT]),
        notExists(tx.select({ one: sql`1` }).from(incidentGroupExclusions).where(eq(incidentGroupExclusions.alertId, alerts.id))),
      ))
      .orderBy(desc(alerts.occurredAt))
      .limit(MAX_EVENTS);
    if (!candidates.length) return [];
    const anchored = await tx
      .select({ ...cols, incidentId: alerts.incidentId })
      .from(alerts)
      .innerJoin(incidents, eq(incidents.id, alerts.incidentId))
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), isNotNull(alerts.incidentId), ne(incidents.status, "CLOSED")))
      .orderBy(desc(alerts.occurredAt))
      .limit(MAX_EVENTS);
    const all = [...candidates, ...anchored];
    const ids = [...new Set(all.flatMap((a) => a.techniques.flatMap((t) => [t.toUpperCase(), t.toUpperCase().split(".")[0]!])))];
    const tactics = ids.length ? await tx.select({ id: attackTechniques.id, tactics: attackTechniques.tactics }).from(attackTechniques).where(inArray(attackTechniques.id, ids)) : [];
    return planGroups(
      all.map((a) => ({
        id: a.id, occurredAt: a.occurredAt.getTime(), userName: a.userName, assetId: a.assetId, techniques: a.techniques, incidentId: a.incidentId,
        relatedIds: a.source === CORRELATION_SOURCE ? contributingIds(a.raw) : undefined,
      })),
      { windowMs: GROUP_WINDOW, tactics: Object.fromEntries(tactics.map((t) => [t.id, t.tactics])) },
    );
  });

  let linked = 0;
  let opened = 0;
  for (const plan of plans) {
    const res = await withScope(systemScope(tenantId), (tx) => applyPlan(tx, tenantId, plan));
    if (!res) continue;
    linked += plan.alertIds.length;
    if (res.opened) opened++;
  }
  return { plans: plans.length, linked, opened };
}

async function applyPlan(tx: Tx, tenantId: string, plan: GroupPlan): Promise<{ incidentId: string; opened: boolean } | null> {
  const rows = await tx.select().from(alerts).where(and(eq(alerts.tenantId, tenantId), inArray(alerts.id, plan.alertIds), isNull(alerts.incidentId), inArray(alerts.status, [...OPEN_ALERT])));
  if (rows.length !== plan.alertIds.length) return null;
  let incidentId = plan.incidentId;
  if (incidentId) {
    const [inc] = await tx.select({ status: incidents.status }).from(incidents).where(eq(incidents.id, incidentId));
    if (!inc || inc.status === "CLOSED") return null;
    await linkAlerts(tx, incidentId, tenantId, rows);
    await tx.update(incidents).set({ updatedAt: new Date() }).where(eq(incidents.id, incidentId));
  } else {
    const [taken] = await tx.select({ id: incidents.id }).from(incidents).where(and(eq(incidents.tenantId, tenantId), eq(incidents.groupingKey, plan.groupingKey!)));
    if (taken) return null;
    const inc = await createIncidentFromAlerts(null, { tenantId, alertIds: plan.alertIds, description: `Grouped automatically: ${plan.reason.summary}.`, actorKind: "system" }, tx);
    await tx.update(incidents).set({ groupingKey: plan.groupingKey }).where(eq(incidents.id, inc.id));
    incidentId = inc.id;
  }
  for (const a of rows) {
    await tx.update(incidentAlerts).set({ origin: "auto", reason: plan.reason, priorStatus: a.status }).where(and(eq(incidentAlerts.incidentId, incidentId), eq(incidentAlerts.alertId, a.id)));
  }
  await addTimeline(tx, {
    tenantId, incidentId, origin: "machine", category: "grouping",
    title: plan.incidentId ? `Grouped ${rows.length} related alert${rows.length === 1 ? "" : "s"} automatically` : `Opened by automatic grouping of ${rows.length} alerts`,
    detail: plan.reason.summary,
  });
  await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "incident.auto_group", targetType: "incident", targetId: incidentId, detail: { alertIds: plan.alertIds, groupingKey: plan.groupingKey, reason: plan.reason.summary } });
  return { incidentId, opened: !plan.incidentId };
}

/** Scheduled entry point: every tenant with recent alerts. One tenant failing never stops the rest. */
export async function runCorrelationAll(log: (m: string) => void, now = new Date()) {
  const tenants = await systemDb().selectDistinct({ id: alerts.tenantId }).from(alerts).where(gte(alerts.occurredAt, new Date(now.getTime() - GROUP_LOOKBACK)));
  for (const { id } of tenants) {
    try {
      const c = await runCorrelation(id, now);
      const g = await runGrouping(id, now);
      if (c.created || g.linked) log(`tenant ${id.slice(0, 8)}: +${c.created} correlated, ${g.linked} alerts grouped (${g.opened} new incidents)`);
    } catch (e) {
      log(`correlation ${id.slice(0, 8)} failed: ${(e as Error).message}`);
    }
  }
}

export async function listCorrelationRules(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "detection:read", tenantId, async (tx) => {
    const overrides = await tx.select().from(correlationRuleSettings).where(eq(correlationRuleSettings.tenantId, tenantId));
    return BUILTIN_RULES.map((r) => ({
      id: r.id, version: r.version, title: r.title, description: r.description, severity: r.severity, stage: r.stage, clause: r.clause.type, techniques: r.techniques,
      enabled: overrides.find((o) => o.ruleId === r.id)?.enabled ?? r.enabledByDefault,
    }));
  });
}

export async function setCorrelationRuleEnabled(ctx: AccessContext, tenantId: string, ruleId: string, enabled: boolean) {
  if (!ruleById(ruleId)) throw new AccessDenied("unknown correlation rule");
  return inTenant(ctx, "detection:write", tenantId, async (tx) => {
    await tx
      .insert(correlationRuleSettings)
      .values({ tenantId, ruleId, enabled, updatedBy: ctx.principal.userId })
      .onConflictDoUpdate({ target: [correlationRuleSettings.tenantId, correlationRuleSettings.ruleId], set: { enabled, updatedBy: ctx.principal.userId, updatedAt: new Date() } });
    await audit(tx, { ...actor(ctx), tenantId, action: "correlation.rule_toggle", targetType: "correlation_rule", targetId: ruleId, detail: { enabled } });
  });
}
