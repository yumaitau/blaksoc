import { and, desc, eq, gte, inArray, ne, notInArray, sql } from "drizzle-orm";
import { advisories, alerts, approvals, assets, incidents, intelMatches, responseActions, tenants, user, vulnerabilities } from "@/db/schema";
import { db } from "@/db/client";
import type { AccessContext } from "@/lib/auth/access";
import { scoped } from "./common";
import { vulnSummary } from "./vulnerabilities";

const OPEN_ALERT = ["RESOLVED", "FALSE_POSITIVE"] as const;

/** Everything on the SOC dashboard answers: what's happening, what matters, who's affected, what next, what was done. */
export async function socDashboard(ctx: AccessContext, tenantIds?: string[]) {
  const since24 = new Date(Date.now() - 24 * 3600_000);
  const data = await scoped(
    ctx,
    "dashboard:read",
    async (tx, ids) => {
      const openAlert = and(inArray(alerts.tenantId, ids), notInArray(alerts.status, [...OPEN_ALERT]));
      const [counts] = await tx
        .select({
          critical: sql<number>`count(*) filter (where ${alerts.severity} = 'critical' or ${alerts.riskScore} >= 80)::int`,
          awaitingTriage: sql<number>`count(*) filter (where ${alerts.status} = 'NEW')::int`,
          unassigned: sql<number>`count(*) filter (where ${alerts.assigneeId} is null)::int`,
          intelMatched: sql<number>`count(*) filter (where ${alerts.intelVerdict} in ('malicious','suspicious'))::int`,
          open: sql<number>`count(*)::int`,
        })
        .from(alerts)
        .where(openAlert);

      const topAlerts = await tx
        .select({ id: alerts.id, title: alerts.title, riskScore: alerts.riskScore, severity: alerts.severity, tenantName: tenants.name, assetName: assets.name, occurredAt: alerts.occurredAt, intelVerdict: alerts.intelVerdict, status: alerts.status })
        .from(alerts)
        .innerJoin(tenants, eq(tenants.id, alerts.tenantId))
        .leftJoin(assets, eq(assets.id, alerts.assetId))
        .where(and(openAlert, eq(alerts.status, "NEW")))
        .orderBy(desc(alerts.riskScore))
        .limit(8);

      const activeIncidents = await tx
        .select({ id: incidents.id, ref: incidents.ref, title: incidents.title, severity: incidents.severity, status: incidents.status, tenantName: tenants.name, ownerName: user.name, slaDueAt: incidents.slaDueAt, updatedAt: incidents.updatedAt })
        .from(incidents)
        .innerJoin(tenants, eq(tenants.id, incidents.tenantId))
        .leftJoin(user, eq(user.id, incidents.ownerId))
        .where(and(inArray(incidents.tenantId, ids), ne(incidents.status, "CLOSED")))
        .orderBy(desc(incidents.riskScore))
        .limit(8);

      const customersAtRisk = await tx
        .select({
          tenantId: tenants.id, name: tenants.name,
          risk: sql<number>`coalesce(max(${alerts.riskScore}) filter (where ${alerts.status} not in ('RESOLVED','FALSE_POSITIVE')), 0)::int`,
          open: sql<number>`count(${alerts.id}) filter (where ${alerts.status} not in ('RESOLVED','FALSE_POSITIVE'))::int`,
        })
        .from(tenants)
        .leftJoin(alerts, eq(alerts.tenantId, tenants.id))
        .where(and(inArray(tenants.id, ids), eq(tenants.kind, "customer")))
        .groupBy(tenants.id)
        .orderBy(desc(sql`3`))
        .limit(6);

      const intelHits = await tx
        .select({ id: intelMatches.id, alertId: intelMatches.alertId, tenantName: tenants.name, verdict: intelMatches.verdict, summary: intelMatches.summary, matchedAt: intelMatches.matchedAt })
        .from(intelMatches)
        .innerJoin(tenants, eq(tenants.id, intelMatches.tenantId))
        .where(and(inArray(intelMatches.tenantId, ids), gte(intelMatches.matchedAt, since24)))
        .orderBy(desc(intelMatches.matchedAt))
        .limit(8);

      const topInfra = await tx
        .select({ value: sql<string>`${intelMatches.summary}->'observable'->>'value'`, type: sql<string>`${intelMatches.summary}->'observable'->>'type'`, hits: sql<number>`count(*)::int`, tenants: sql<number>`count(distinct ${intelMatches.tenantId})::int`, verdict: sql<string>`max(${intelMatches.verdict})` })
        .from(intelMatches)
        .where(and(inArray(intelMatches.tenantId, ids), gte(intelMatches.matchedAt, new Date(Date.now() - 7 * 86400_000))))
        .groupBy(sql`1`, sql`2`)
        .orderBy(desc(sql`3`))
        .limit(6);

      const attackActivity = await tx
        .select({ technique: sql<string>`unnest(${alerts.attackTechniques})`, n: sql<number>`count(*)::int` })
        .from(alerts)
        .where(and(inArray(alerts.tenantId, ids), gte(alerts.occurredAt, since24)))
        .groupBy(sql`1`)
        .orderBy(desc(sql`2`))
        .limit(8);

      const workload = await tx
        .select({ userId: user.id, name: user.name, alerts: sql<number>`count(*)::int` })
        .from(alerts)
        .innerJoin(user, eq(user.id, alerts.assigneeId))
        .where(openAlert)
        .groupBy(user.id)
        .orderBy(desc(sql`3`))
        .limit(8);

      const containment = await tx
        .select({ id: responseActions.id, action: responseActions.action, status: responseActions.status, tenantName: tenants.name, createdAt: responseActions.createdAt, incidentId: responseActions.incidentId, requestedByKind: responseActions.requestedByKind })
        .from(responseActions)
        .innerJoin(tenants, eq(tenants.id, responseActions.tenantId))
        .where(inArray(responseActions.tenantId, ids))
        .orderBy(desc(responseActions.createdAt))
        .limit(8);

      const [pending] = await tx.select({ n: sql<number>`count(*)::int` }).from(approvals).where(and(inArray(approvals.tenantId, ids), eq(approvals.status, "PENDING")));

      const vulnerableCritical = await tx
        .select({ id: assets.id, name: assets.name, tenantName: tenants.name, criticality: assets.criticality, exposure: assets.exposure, urgent: sql<number>`count(*)::int` })
        .from(assets)
        .innerJoin(tenants, eq(tenants.id, assets.tenantId))
        .innerJoin(vulnerabilities, and(eq(vulnerabilities.assetId, assets.id), eq(vulnerabilities.status, "open"), gte(vulnerabilities.priorityScore, 60)))
        .where(and(inArray(assets.tenantId, ids), gte(assets.criticality, 4)))
        .groupBy(assets.id, tenants.name)
        .orderBy(desc(sql`6`))
        .limit(6);

      return { counts: counts!, topAlerts, activeIncidents, customersAtRisk, intelHits, topInfra, attackActivity, workload, containment, pendingApprovals: pending?.n ?? 0, vulnerableCritical };
    },
    tenantIds,
  );
  const vulns = await vulnSummary(ctx, tenantIds).catch(() => null);
  // Advisories are global public intel, not tenant data.
  const australian = await db().select().from(advisories).orderBy(desc(advisories.publishedAt)).limit(6);
  return { ...data, vulns, australian };
}

/** MSSP roll-up: one row per customer. */
export async function msspOverview(ctx: AccessContext) {
  return scoped(ctx, "mssp:read", (tx, ids) =>
    tx
      .select({
        id: tenants.id, slug: tenants.slug, name: tenants.name, sectors: tenants.sectors, deploymentMode: tenants.deploymentMode,
        risk: sql<number>`coalesce((select max(a.risk_score) from alerts a where a.tenant_id = tenants.id and a.status not in ('RESOLVED','FALSE_POSITIVE')), 0)::int`,
        alerts: sql<number>`(select count(*) from alerts a where a.tenant_id = tenants.id and a.status not in ('RESOLVED','FALSE_POSITIVE'))::int`,
        criticalAlerts: sql<number>`(select count(*) from alerts a where a.tenant_id = tenants.id and a.status = 'NEW' and a.risk_score >= 70)::int`,
        incidents: sql<number>`(select count(*) from incidents i where i.tenant_id = tenants.id and i.status <> 'CLOSED')::int`,
        endpoints: sql<number>`(select count(*) from assets s where s.tenant_id = tenants.id and s.kind in ('endpoint','server'))::int`,
        endpointsOffline: sql<number>`(select count(*) from assets s where s.tenant_id = tenants.id and s.kind in ('endpoint','server') and s.agent_status is not null and s.agent_status <> 'active')::int`,
        kevExposure: sql<number>`(select count(*) from vulnerabilities v join cve_intel c on c.cve = v.cve where v.tenant_id = tenants.id and v.status = 'open' and c.kev)::int`,
        lastAlertAt: sql<Date | null>`(select max(a.occurred_at) from alerts a where a.tenant_id = tenants.id)`,
        healthAlerts: sql<number>`(select count(*) from alerts a where a.tenant_id = tenants.id and a.source = 'health' and a.status not in ('RESOLVED','FALSE_POSITIVE'))::int`,
      })
      .from(tenants)
      .where(and(inArray(tenants.id, ids), eq(tenants.kind, "customer"), sql`coalesce((${tenants.settings}->>'training')::boolean, false) = false`))
      .orderBy(desc(sql`6`)),
  );
}
