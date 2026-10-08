import { and, desc, eq, gte, inArray, or, sql } from "drizzle-orm";
import {
  alerts, auditLog, correlationFindings, incidentAlerts, incidents, integrations, kelpieCases, playbookRuns, responseActions, serviceIdentities, user,
} from "@/db/schema";
import { alertHistory as buildHistory, type AlertAuditRow } from "@/lib/alerts/history";
import { floorSentence, ingestDelay, severityReason, sourceFields, topFactors } from "@/lib/alerts/provenance";
import { can, type AccessContext } from "@/lib/auth/access";
import { connectorDef } from "@/lib/connectors/registry";
import { ruleById } from "@/lib/correlation/rules";
import { env } from "@/lib/env";
import { minSeverityFor } from "@/lib/integrations/alert-floor";
import { scoped } from "./common";
import { kelpieIntegration } from "./kelpie";

/** History rows shown per alert. */
const HISTORY_LIMIT = 200;

/**
 * Where an alert came from and how it became one: source integration and rule, event vs storage time,
 * severity mapping and floor, risk, normalisation, intel, and what happened next (correlation, incident,
 * Kelpie case). Needs alert:read on the alert's tenant. Fields read from `raw` follow getAlert: SOC
 * (alert:triage) only.
 */
export async function alertProvenance(ctx: AccessContext, id: string) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const [a] = await tx
      .select({
        id: alerts.id, tenantId: alerts.tenantId, integrationId: alerts.integrationId, source: alerts.source, externalId: alerts.externalId, ruleId: alerts.ruleId,
        siemSeverity: alerts.siemSeverity, severity: alerts.severity, riskScore: alerts.riskScore, riskFactors: alerts.riskFactors,
        intel: alerts.intel, intelVerdict: alerts.intelVerdict, incidentId: alerts.incidentId, raw: alerts.raw,
        ocsfClass: sql<string | null>`${alerts.ocsf} ->> 'class_name'`,
        ocsfSourceClass: sql<string | null>`${alerts.ocsfSourceEvent} ->> 'class_name'`,
        normalizationVersion: alerts.normalizationVersion, occurredAt: alerts.occurredAt, ingestedAt: alerts.ingestedAt,
      })
      .from(alerts)
      .where(and(eq(alerts.id, id), inArray(alerts.tenantId, tenantIds)));
    if (!a) return null;
    const raw = can(ctx, "alert:triage", a.tenantId) ? a.raw : null;

    // RLS hides a platform-owned (shared) integration from customer users; the alert still says one was used.
    const [row] = a.integrationId
      ? await tx.select({ id: integrations.id, tenantId: integrations.tenantId, name: integrations.name, provider: integrations.provider, config: integrations.config, enabled: integrations.enabled }).from(integrations).where(eq(integrations.id, a.integrationId))
      : [];
    const integration = row
      ? {
          id: row.id,
          name: row.name,
          provider: connectorDef(row.provider)?.name ?? row.provider,
          enabled: row.enabled,
          shared: !row.tenantId,
          // The integration's floor today (it may have changed since ingest). Sigma hits bypass the poll and its floor.
          floor: a.source === "blaksoc-sigma" ? null : floorSentence(minSeverityFor(row)),
          canOpen: row.tenantId ? can(ctx, "integration:read", row.tenantId) : ctx.isPlatform && can(ctx, "integration:read"),
        }
      : null;

    // Findings this alert was raised from (it is the correlated alert) or fed into (it is a contributing event).
    const findingCols = { id: correlationFindings.id, ruleId: correlationFindings.ruleId, alertId: correlationFindings.alertId, explanation: correlationFindings.explanation, createdAt: correlationFindings.createdAt };
    const findings = await tx
      .select(findingCols)
      .from(correlationFindings)
      .where(and(
        eq(correlationFindings.tenantId, a.tenantId),
        or(eq(correlationFindings.alertId, id), sql`${correlationFindings.matches} @> ${JSON.stringify([{ events: [{ id }] }])}::jsonb`),
      ))
      .orderBy(desc(correlationFindings.createdAt))
      .limit(20);
    const ruleTitle = (ruleId: string) => ruleById(ruleId)?.title ?? ruleId;
    const raisedBy = findings.find((f) => f.alertId === id);
    const contributedTo = findings.filter((f) => f.alertId !== id).map((f) => ({ id: f.id, rule: ruleTitle(f.ruleId), alertId: f.alertId, at: f.createdAt }));

    const [incident] = a.incidentId
      ? await tx
          .select({ id: incidents.id, ref: incidents.ref, title: incidents.title, status: incidents.status, origin: incidentAlerts.origin, reason: incidentAlerts.reason, linkedAt: incidentAlerts.linkedAt })
          .from(incidents)
          .leftJoin(incidentAlerts, and(eq(incidentAlerts.incidentId, incidents.id), eq(incidentAlerts.alertId, id)))
          .where(eq(incidents.id, a.incidentId))
      : [];
    const [kelpie] = incident ? await tx.select({ caseId: kelpieCases.caseId, caseNumber: kelpieCases.caseNumber, caseUrl: kelpieCases.caseUrl, lastError: kelpieCases.lastError }).from(kelpieCases).where(eq(kelpieCases.incidentId, incident.id)) : [];
    let kelpieUrl = kelpie?.caseUrl ?? null;
    if (kelpie?.caseId && !kelpieUrl) {
      const base = env().KELPIE_URL ?? ((await kelpieIntegration(tx, a.tenantId))?.config as { baseUrl?: unknown } | undefined)?.baseUrl;
      if (typeof base === "string") kelpieUrl = `${base.replace(/\/+$/, "")}/cases/${encodeURIComponent(kelpie.caseId)}`;
    }

    return {
      where: {
        integration,
        /** Set when the alert names an integration the viewer cannot see (a shared platform one). */
        hiddenIntegration: !!a.integrationId && !row,
        source: a.source,
        externalId: a.externalId,
        ruleId: a.ruleId,
        fields: sourceFields(a.source, raw),
        rawWithheld: a.raw != null && raw == null,
      },
      when: { occurredAt: a.occurredAt, ingestedAt: a.ingestedAt, delay: ingestDelay(a.occurredAt, a.ingestedAt) },
      how: {
        severity: a.severity,
        reason: severityReason({ ...a, raw }, raisedBy ? ruleTitle(raisedBy.ruleId) : null),
        riskScore: a.riskScore,
        topFactors: topFactors(a.riskFactors),
        factorCount: a.riskFactors.length,
        ocsf: a.ocsfClass ? { finding: a.ocsfClass, sourceEvent: a.ocsfSourceClass, version: a.normalizationVersion } : null,
        intel: { verdict: a.intelVerdict, checkedAt: a.intel?.checkedAt ?? null, matches: a.intel?.matches.length ?? 0 },
        raisedBy: raisedBy ? { rule: ruleTitle(raisedBy.ruleId), explanation: raisedBy.explanation } : null,
      },
      next: {
        contributedTo,
        incident: incident
          ? {
              id: incident.id, ref: incident.ref, title: incident.title, status: incident.status,
              origin: incident.origin, reason: incident.reason?.summary ?? null, linkedAt: incident.linkedAt,
              kelpie: kelpie ? { caseNumber: kelpie.caseNumber, url: kelpieUrl, pending: !kelpie.caseId, lastError: kelpie.lastError } : null,
            }
          : null,
      },
    };
  });
}

export type AlertProvenance = NonNullable<Awaited<ReturnType<typeof alertProvenance>>>;

/**
 * Audit trail for one alert: rows targeting it, its response actions and playbook runs, and incident
 * membership changes that name it. Gated on alert:read rather than audit:read so the analysts working the
 * alert see who did what; the query never leaves this alert and only derived sentences are returned
 * (no raw `detail`, no IPs).
 */
export async function alertHistory(ctx: AccessContext, id: string) {
  return scoped(ctx, "alert:read", async (tx, tenantIds) => {
    const [a] = await tx
      .select({
        tenantId: alerts.tenantId, severity: alerts.severity, source: alerts.source, ingestedAt: alerts.ingestedAt, integrationName: integrations.name,
        lane: alerts.lane, passiveReason: alerts.passiveReason, tuningActionId: alerts.tuningActionId,
      })
      .from(alerts)
      .leftJoin(integrations, eq(integrations.id, alerts.integrationId))
      .where(and(eq(alerts.id, id), inArray(alerts.tenantId, tenantIds)));
    if (!a) return null;
    const actions = await tx.select({ id: responseActions.id, action: responseActions.action }).from(responseActions).where(eq(responseActions.alertId, id));
    const runs = await tx.select({ id: playbookRuns.id }).from(playbookRuns).where(eq(playbookRuns.alertId, id));

    const rows: AlertAuditRow[] = await tx
      .select({
        id: auditLog.id, at: auditLog.at, action: auditLog.action, actorId: auditLog.actorId, actorKind: auditLog.actorKind,
        actorName: sql<string | null>`coalesce(${user.name}, ${serviceIdentities.name})`, targetType: auditLog.targetType, targetId: auditLog.targetId, detail: auditLog.detail,
      })
      .from(auditLog)
      .leftJoin(user, eq(user.id, auditLog.actorId))
      .leftJoin(serviceIdentities, and(eq(auditLog.actorKind, "service"), sql`${serviceIdentities.id}::text = ${auditLog.actorId}`))
      .where(and(
        eq(auditLog.tenantId, a.tenantId),
        // Nothing about the alert predates it; the bound keeps the (tenant_id, at) index useful. A minute covers clock skew.
        gte(auditLog.at, new Date(a.ingestedAt.getTime() - 60_000)),
        or(
          and(eq(auditLog.targetType, "alert"), eq(auditLog.targetId, id)),
          and(eq(auditLog.targetType, "incident"), sql`${auditLog.detail} -> 'alertIds' @> ${JSON.stringify([id])}::jsonb`),
          // Noise rules list the open alerts they moved to the passive lane when created or approved.
          and(eq(auditLog.targetType, "noise_rule"), sql`${auditLog.detail} -> 'alertIds' @> ${JSON.stringify([id])}::jsonb`),
          a.tuningActionId ? and(eq(auditLog.targetType, "tuning_action"), eq(auditLog.targetId, a.tuningActionId)) : undefined,
          actions.length ? and(eq(auditLog.targetType, "response_action"), inArray(auditLog.targetId, actions.map((r) => r.id))) : undefined,
          runs.length ? and(eq(auditLog.targetType, "playbook_run"), inArray(auditLog.targetId, runs.map((r) => r.id))) : undefined,
        ),
      ))
      .orderBy(auditLog.id)
      .limit(HISTORY_LIMIT);

    const detailOf = (r: AlertAuditRow) => (r.detail && typeof r.detail === "object" ? (r.detail as Record<string, unknown>) : {});
    const userIds = [...new Set(rows.map((r) => detailOf(r).assigneeId).filter((v): v is string => typeof v === "string"))];
    const incidentIds = [...new Set(rows.filter((r) => r.targetType === "incident" && r.targetId).map((r) => r.targetId!))];
    const names = userIds.length ? await tx.select({ id: user.id, name: user.name }).from(user).where(inArray(user.id, userIds)) : [];
    const refs = incidentIds.length ? await tx.select({ id: incidents.id, ref: incidents.ref }).from(incidents).where(inArray(incidents.id, incidentIds)) : [];

    return {
      entries: buildHistory(a, rows, {
        users: new Map(names.map((u) => [u.id, u.name])),
        incidents: new Map(refs.map((i) => [i.id, i.ref])),
        responseActions: new Map(actions.map((r) => [r.id, r.action])),
      }),
      truncated: rows.length === HISTORY_LIMIT,
    };
  });
}
