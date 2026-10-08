import { and, asc, desc, eq, gte, ilike, inArray, isNotNull, isNull, or, sql, type SQL } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { alertObservables, alerts, assets, incidents, integrations, intelMatches, observables, patternAnnotations, responseActions, savedViews, tenants, tuningActions, user } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { publish } from "@/lib/events";
import type { HermesFilter } from "@/lib/tuning/hermes-ui";
import { actor, AccessDenied, scoped } from "./common";
import { contributingDetections, sourceAlertUrl } from "./incident-context";

export const ALERT_STATUSES = ["NEW", "TRIAGING", "INVESTIGATING", "ESCALATED", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];
export const SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const;

export type AlertFilters = {
  tenantIds?: string[];
  status?: AlertStatus[];
  severity?: (typeof SEVERITIES)[number][];
  assignee?: "me" | "unassigned" | string;
  intel?: "match";
  /** Matches an intel label (case-insensitive), e.g. AUSTRALIA. */
  intelLabel?: string;
  q?: string;
  technique?: string;
  category?: string;
  minRisk?: number;
  sinceHours?: number;
  /** `active` is the triage queue, `passive` known noise; omitted means both. */
  lane?: "active" | "passive";
  /** Hermes closed it (even if since reopened), annotated its pattern, or either. */
  hermes?: HermesFilter;
  /** The alerts one Hermes (tuning) action touched: its closures, its noise rule's passive alerts, or its annotated pattern. */
  hermesAction?: string;
  sort?: "risk" | "newest" | "oldest";
  limit?: number;
  offset?: number;
};

/**
 * Free-text match for the alert queue. Full-text search over the generated `alerts.search_vector`
 * (title, user, category, rule id, source, description; migration 0033) accepts web-search syntax:
 * quoted phrases, `or`, and `-word`. Substring matches on title, user and asset name are kept, so
 * a partial host or user name still finds its alerts.
 */
export function alertTextMatch(q: string): SQL {
  const text = q.slice(0, 500);
  const like = `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
  return or(
    sql`"alerts"."search_vector" @@ websearch_to_tsquery('simple', ${text})`,
    ilike(alerts.title, like),
    ilike(alerts.userName, like),
    ilike(assets.name, like),
  )!;
}

/** The alert's pattern (tenant, source, rule) has a Hermes note. Index pattern_annotations_pattern. */
const hasHermesNote = sql<boolean>`exists (select 1 from ${patternAnnotations} pa where pa.tenant_id = ${alerts.tenantId} and pa.source = ${alerts.source} and pa.rule_id = ${alerts.ruleId})`;

/** Alerts one tuning action touched; false when the action is outside the caller's scope or gone. */
async function hermesActionMatch(tx: Tx, actionId: string, tenantIds: string[]): Promise<SQL> {
  const [a] = await tx
    .select({ kind: tuningActions.kind, tenantId: tuningActions.tenantId, source: tuningActions.source, ruleId: tuningActions.ruleId, noiseRuleId: tuningActions.noiseRuleId })
    .from(tuningActions)
    .where(and(eq(tuningActions.id, actionId), inArray(tuningActions.tenantId, tenantIds)));
  if (a?.kind === "close") return eq(alerts.tuningActionId, actionId);
  if (a?.kind === "noise_rule" && a.noiseRuleId) return eq(alerts.noiseRuleId, a.noiseRuleId);
  if (a?.kind === "annotate") return and(eq(alerts.tenantId, a.tenantId), eq(alerts.source, a.source), eq(alerts.ruleId, a.ruleId))!;
  return sql`false`;
}

export async function listAlerts(ctx: AccessContext, f: AlertFilters = {}) {
  return scoped(
    ctx,
    "alert:read",
    async (tx, tenantIds) => {
      const where: SQL[] = [inArray(alerts.tenantId, tenantIds)];
      if (f.status?.length) where.push(inArray(alerts.status, f.status));
      if (f.severity?.length) where.push(inArray(alerts.severity, f.severity));
      if (f.assignee === "me") where.push(eq(alerts.assigneeId, ctx.principal.userId));
      else if (f.assignee === "unassigned") where.push(isNull(alerts.assigneeId));
      else if (f.assignee) where.push(eq(alerts.assigneeId, f.assignee));
      if (f.intel === "match") where.push(inArray(alerts.intelVerdict, ["malicious", "suspicious"]));
      if (f.intelLabel) {
        where.push(sql`${alerts.intel} @? ${`$.matches[*].labels[*] ? (@ like_regex "${f.intelLabel.replace(/[^A-Za-z0-9_ -]/g, "")}" flag "i")`}::jsonpath`);
      }
      if (f.q) where.push(alertTextMatch(f.q));
      if (f.technique) where.push(sql`exists (select 1 from unnest(${alerts.attackTechniques}) t where t like ${`${f.technique}%`})`);
      if (f.category) where.push(eq(alerts.category, f.category));
      if (f.minRisk != null) where.push(gte(alerts.riskScore, f.minRisk));
      if (f.lane) where.push(eq(alerts.lane, f.lane));
      if (f.hermes === "closed") where.push(isNotNull(alerts.tuningActionId));
      else if (f.hermes === "annotated") where.push(hasHermesNote);
      else if (f.hermes === "any") where.push(or(isNotNull(alerts.tuningActionId), hasHermesNote)!);
      if (f.hermesAction) where.push(await hermesActionMatch(tx, f.hermesAction, tenantIds));
      if (f.sinceHours) where.push(gte(alerts.occurredAt, new Date(Date.now() - f.sinceHours * 3600_000)));
      const order = f.sort === "newest" ? [desc(alerts.occurredAt)] : f.sort === "oldest" ? [asc(alerts.occurredAt)] : [desc(alerts.riskScore), desc(alerts.occurredAt)];

      const rows = await tx
        .select({
          id: alerts.id,
          tenantId: alerts.tenantId,
          tenantName: tenants.name,
          title: alerts.title,
          severity: alerts.severity,
          riskScore: alerts.riskScore,
          riskFactors: alerts.riskFactors,
          status: alerts.status,
          source: alerts.source,
          ruleId: alerts.ruleId,
          // Null for alerts blakSOC raised itself, and for shared integrations RLS hides from the viewer.
          integrationName: integrations.name,
          category: alerts.category,
          assetId: alerts.assetId,
          assetName: assets.name,
          assetCriticality: assets.criticality,
          userName: alerts.userName,
          intelVerdict: alerts.intelVerdict,
          attackTechniques: alerts.attackTechniques,
          occurredAt: alerts.occurredAt,
          assigneeId: alerts.assigneeId,
          assigneeName: user.name,
          incidentId: alerts.incidentId,
          lane: alerts.lane,
          passiveReason: alerts.passiveReason,
          noiseRuleId: alerts.noiseRuleId,
          tuningActionId: alerts.tuningActionId,
          hermesUndoneAt: tuningActions.undoneAt,
          hermesNote: hasHermesNote,
        })
        .from(alerts)
        .innerJoin(tenants, eq(tenants.id, alerts.tenantId))
        .leftJoin(assets, eq(assets.id, alerts.assetId))
        .leftJoin(user, eq(user.id, alerts.assigneeId))
        .leftJoin(integrations, eq(integrations.id, alerts.integrationId))
        // Only through the alert's own closure: a primary-key lookup for the few rows Hermes closed.
        .leftJoin(tuningActions, eq(tuningActions.id, alerts.tuningActionId))
        .where(and(...where))
        .orderBy(...order)
        .limit(Math.min(f.limit ?? 100, 500))
        .offset(f.offset ?? 0);
      const [{ total } = { total: 0 }] = await tx
        .select({ total: sql<number>`count(*)::int` })
        .from(alerts)
        .leftJoin(assets, eq(assets.id, alerts.assetId))
        .where(and(...where));
      return { rows, total };
    },
    f.tenantIds,
  );
}

export async function getAlert(ctx: AccessContext, id: string) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const [a] = await tx
      .select({ alert: alerts, tenantName: tenants.name, assigneeName: user.name })
      .from(alerts)
      .innerJoin(tenants, eq(tenants.id, alerts.tenantId))
      .leftJoin(user, eq(user.id, alerts.assigneeId))
      .where(and(eq(alerts.id, id), inArray(alerts.tenantId, tenantIds)));
    if (!a) return null;
    const [asset] = a.alert.assetId ? await tx.select().from(assets).where(eq(assets.id, a.alert.assetId)) : [];
    const obs = await tx
      .select({ id: observables.id, type: observables.type, value: observables.value, verdict: observables.verdict, sightings: observables.sightings, field: alertObservables.field })
      .from(alertObservables)
      .innerJoin(observables, eq(observables.id, alertObservables.observableId))
      .where(eq(alertObservables.alertId, id));
    const related = a.alert.assetId || a.alert.userName
      ? await tx
          .select({ id: alerts.id, title: alerts.title, severity: alerts.severity, riskScore: alerts.riskScore, status: alerts.status, lane: alerts.lane, occurredAt: alerts.occurredAt })
          .from(alerts)
          .where(and(
            eq(alerts.tenantId, a.alert.tenantId),
            sql`${alerts.id} <> ${id}`,
            or(a.alert.assetId ? eq(alerts.assetId, a.alert.assetId) : sql`false`, a.alert.userName ? eq(alerts.userName, a.alert.userName) : sql`false`),
            gte(alerts.occurredAt, new Date(a.alert.occurredAt.getTime() - 72 * 3600_000)),
          ))
          .orderBy(desc(alerts.occurredAt))
          .limit(20)
      : [];
    const [incident] = a.alert.incidentId
      ? await tx.select({ id: incidents.id, ref: incidents.ref, title: incidents.title, status: incidents.status }).from(incidents).where(eq(incidents.id, a.alert.incidentId))
      : [];
    const actions = await tx.select().from(responseActions).where(eq(responseActions.alertId, id)).orderBy(desc(responseActions.createdAt));
    // Raw payload is SOC-only; customers see normalised fields.
    const alert = can(ctx, "alert:triage", a.alert.tenantId) ? a.alert : { ...a.alert, raw: null };
    const [integration] = a.alert.integrationId ? await tx.select({ config: integrations.config }).from(integrations).where(eq(integrations.id, a.alert.integrationId)) : [];
    const wazuhUrl = can(ctx, "alert:triage", a.alert.tenantId) ? sourceAlertUrl(a.alert, integration?.config ?? null) : null;
    const contributing = can(ctx, "alert:triage", a.alert.tenantId) && a.alert.source === "blaksoc-correlation" ? await contributingDetections(tx, a.alert.tenantId, a.alert.raw) : [];
    return { ...a, alert, asset: asset ?? null, observables: obs, related, incident: incident ?? null, actions, wazuhUrl, contributing };
  });
}

export async function updateAlerts(ctx: AccessContext, ids: string[], patch: { status?: AlertStatus; assigneeId?: string | null }) {
  if (!ids.length) return 0;
  const permission = patch.assigneeId !== undefined && patch.assigneeId !== ctx.principal.userId ? "alert:assign" : "alert:triage";
  return scoped(ctx, permission, async (tx, tenantIds) => {
    const targets = await tx.select({ id: alerts.id, tenantId: alerts.tenantId, status: alerts.status }).from(alerts).where(and(inArray(alerts.id, ids), inArray(alerts.tenantId, tenantIds)));
    if (targets.length !== ids.length) throw new AccessDenied("one or more alerts are outside your scope");
    await tx
      .update(alerts)
      .set({ ...(patch.status ? { status: patch.status } : {}), ...(patch.assigneeId !== undefined ? { assigneeId: patch.assigneeId } : {}), updatedAt: new Date() })
      .where(inArray(alerts.id, ids));
    for (const t of targets) {
      await audit(tx, { ...actor(ctx), tenantId: t.tenantId, action: "alert.update", targetType: "alert", targetId: t.id, detail: { from: t.status, ...patch } });
    }
    for (const t of targets) await publish({ type: "alert.updated", tenantId: t.tenantId, id: t.id, status: patch.status ?? t.status });
    return targets.length;
  });
}

export async function intelMatchesFor(ctx: AccessContext, opts: { sinceHours?: number; limit?: number; tenantIds?: string[] } = {}) {
  return scoped(
    ctx,
    "intel:read",
    (tx, tenantIds) =>
      tx
        .select({ id: intelMatches.id, tenantId: intelMatches.tenantId, tenantName: tenants.name, alertId: intelMatches.alertId, verdict: intelMatches.verdict, score: intelMatches.score, summary: intelMatches.summary, matchedAt: intelMatches.matchedAt, sightingStatus: intelMatches.sightingStatus })
        .from(intelMatches)
        .innerJoin(tenants, eq(tenants.id, intelMatches.tenantId))
        .where(and(inArray(intelMatches.tenantId, tenantIds), gte(intelMatches.matchedAt, new Date(Date.now() - (opts.sinceHours ?? 168) * 3600_000))))
        .orderBy(desc(intelMatches.matchedAt))
        .limit(opts.limit ?? 50),
    opts.tenantIds,
  );
}

/** Built-in queue views plus the user's own and shared views. */
export const BUILTIN_VIEWS: { name: string; filters: Record<string, string> }[] = [
  { name: "Critical Unassigned", filters: { severity: "critical", assignee: "unassigned", status: "NEW,TRIAGING" } },
  { name: "Threat Intel Matches", filters: { intel: "match" } },
  { name: "Australian Threat Activity", filters: { intelLabel: "australia" } },
  { name: "Ransomware", filters: { technique: "T1486" } },
  { name: "Identity Alerts", filters: { category: "authentication_success" } },
  { name: "Endpoint Alerts", filters: { category: "windows" } },
  { name: "My Queue", filters: { assignee: "me", status: "TRIAGING,INVESTIGATING,ESCALATED" } },
];

export async function listSavedViews(ctx: AccessContext, route: string) {
  const { db } = await import("@/db/client");
  const mine = await db()
    .select()
    .from(savedViews)
    .where(and(eq(savedViews.route, route), or(eq(savedViews.userId, ctx.principal.userId), eq(savedViews.shared, true))));
  return [...BUILTIN_VIEWS.map((v) => ({ id: `builtin:${v.name}`, name: v.name, filters: v.filters, builtin: true })), ...mine.map((v) => ({ id: v.id, name: v.name, filters: v.filters, builtin: false }))];
}

export async function saveView(ctx: AccessContext, route: string, name: string, filters: Record<string, string>, shared: boolean) {
  const { db } = await import("@/db/client");
  const [row] = await db().insert(savedViews).values({ userId: ctx.principal.userId, route, name, filters, shared }).returning();
  return row!;
}
