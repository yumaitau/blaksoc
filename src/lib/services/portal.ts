import { and, desc, eq, gte, inArray, ne, sql } from "drizzle-orm";
import { advisories, alerts, approvals, assets, cveIntel, incidents, incidentTimeline, reports, responseActions, tenants, vulnerabilities } from "@/db/schema";
import { withScope } from "@/db/scope";
import { can, type AccessContext } from "@/lib/auth/access";
import { actionPhrase, incidentSentences } from "@/lib/portal/summary";
import { AccessDenied } from "./common";

/** Customers read their own portal; SOC staff may view any customer's portal they can reach. */
export function canViewPortal(ctx: AccessContext, tenantId: string) {
  return can(ctx, "portal:read", tenantId) || (ctx.isPlatform && can(ctx, "dashboard:read", tenantId));
}

export function customerForPortal(ctx: AccessContext, workspace: { id: string; kind: string } | null | undefined) {
  if (workspace && workspace.kind === "customer" && canViewPortal(ctx, workspace.id)) {
    return ctx.tenants.find((t) => t.id === workspace.id) ?? null;
  }
  return ctx.tenants.find((t) => t.kind === "customer" && canViewPortal(ctx, t.id)) ?? null;
}

/**
 * Executive view of one customer. Deliberately returns only customer-appropriate fields:
 * no risk-factor internals, raw events, analyst notes or AI output.
 */
export async function portalOverview(ctx: AccessContext, tenantId: string) {
  if (!canViewPortal(ctx, tenantId)) throw new AccessDenied("missing portal:read");
  const since30 = new Date(Date.now() - 30 * 86400_000);
  return withScope({ tenantIds: [tenantId], platform: false }, async (tx) => {
    const [tenant] = await tx.select({ id: tenants.id, name: tenants.name, sectors: tenants.sectors }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant) return null;

    const [alertStats] = await tx
      .select({
        openRisk: sql<number>`coalesce(max(${alerts.riskScore}) filter (where ${alerts.status} not in ('RESOLVED','FALSE_POSITIVE')), 0)::int`,
        open: sql<number>`count(*) filter (where ${alerts.status} not in ('RESOLVED','FALSE_POSITIVE'))::int`,
        last30: sql<number>`count(*) filter (where ${alerts.occurredAt} >= ${since30.toISOString()}::timestamptz)::int`,
        closed30: sql<number>`count(*) filter (where ${alerts.occurredAt} >= ${since30.toISOString()}::timestamptz and ${alerts.status} in ('RESOLVED','FALSE_POSITIVE'))::int`,
      })
      .from(alerts)
      .where(eq(alerts.tenantId, tenantId));

    const activeIncidents = await tx
      .select({ id: incidents.id, ref: incidents.ref, title: incidents.title, severity: incidents.severity, status: incidents.status, riskScore: incidents.riskScore, createdAt: incidents.createdAt, updatedAt: incidents.updatedAt })
      .from(incidents)
      .where(and(eq(incidents.tenantId, tenantId), ne(incidents.status, "CLOSED")))
      .orderBy(desc(incidents.riskScore), desc(incidents.updatedAt))
      .limit(10);

    const [endpoints] = await tx
      .select({
        total: sql<number>`count(*)::int`,
        online: sql<number>`count(*) filter (where ${assets.agentStatus} = 'active')::int`,
        offline: sql<number>`count(*) filter (where ${assets.agentStatus} is not null and ${assets.agentStatus} <> 'active')::int`,
        unmanaged: sql<number>`count(*) filter (where ${assets.agentStatus} is null)::int`,
      })
      .from(assets)
      .where(and(eq(assets.tenantId, tenantId), inArray(assets.kind, ["endpoint", "server"])));
    const offlineEndpoints = await tx
      .select({ id: assets.id, name: assets.name, lastSeen: assets.lastSeen })
      .from(assets)
      .where(and(eq(assets.tenantId, tenantId), inArray(assets.kind, ["endpoint", "server"]), sql`${assets.agentStatus} is not null and ${assets.agentStatus} <> 'active'`))
      .orderBy(desc(assets.criticality))
      .limit(5);

    const topVulns = await tx
      .select({
        cve: vulnerabilities.cve,
        title: sql<string | null>`max(${vulnerabilities.title})`,
        priority: sql<number>`max(${vulnerabilities.priorityScore})::int`,
        affectedAssets: sql<number>`count(distinct ${vulnerabilities.assetId})::int`,
        criticalAssets: sql<number>`count(distinct ${vulnerabilities.assetId}) filter (where ${assets.criticality} >= 4)::int`,
        internetFacing: sql<number>`count(distinct ${vulnerabilities.assetId}) filter (where ${assets.exposure} = 'internet')::int`,
        kev: sql<boolean>`coalesce(bool_or(${cveIntel.kev}), false)`,
        kevDueDate: sql<string | null>`max(${cveIntel.kevDueDate})`,
        kevRansomware: sql<boolean>`coalesce(bool_or(${cveIntel.kevRansomware}), false)`,
        epss: sql<number | null>`max(${cveIntel.epss})`,
      })
      .from(vulnerabilities)
      .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
      .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
      .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open")))
      .groupBy(vulnerabilities.cve)
      .orderBy(desc(sql`max(${vulnerabilities.priorityScore})`))
      .limit(5);

    const recentAlerts = await tx
      .select({ id: alerts.id, title: alerts.title, severity: alerts.severity, status: alerts.status, occurredAt: alerts.occurredAt })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since30)))
      .orderBy(desc(alerts.occurredAt))
      .limit(8);

    const actions = await tx
      .select({ id: responseActions.id, action: responseActions.action, status: responseActions.status, createdAt: responseActions.createdAt, executedAt: responseActions.executedAt, incidentId: responseActions.incidentId, assetName: assets.name, identity: sql<string | null>`${responseActions.target}->>'identity'` })
      .from(responseActions)
      .leftJoin(assets, sql`${assets.id}::text = ${responseActions.target}->>'assetId'`)
      .where(eq(responseActions.tenantId, tenantId))
      .orderBy(desc(responseActions.createdAt))
      .limit(8);

    const [pending] = await tx.select({ n: sql<number>`count(*)::int` }).from(approvals).where(and(eq(approvals.tenantId, tenantId), eq(approvals.status, "PENDING")));

    const [latestReport] = await tx.select({ id: reports.id, title: reports.title, createdAt: reports.createdAt }).from(reports).where(eq(reports.tenantId, tenantId)).orderBy(desc(reports.createdAt)).limit(1);

    // Same relevance rule as advisoriesForTenant: sector overlap or a CVE present in the estate.
    const threats = await tx
      .select({ id: advisories.id, title: advisories.title, url: advisories.url, source: advisories.source, summary: advisories.summary, publishedAt: advisories.publishedAt, cves: advisories.cves, tags: advisories.tags,
        affectsEstate: sql<boolean>`exists (select 1 from vulnerabilities v where v.tenant_id = ${tenantId} and v.status = 'open' and v.cve = any(${advisories.cves}))` })
      .from(advisories)
      .where(sql`${advisories.tags} && string_to_array(${["AUSTRALIA", ...tenant.sectors].join(",")}, ',')
        or exists (select 1 from vulnerabilities v where v.tenant_id = ${tenantId} and v.status = 'open' and v.cve = any(${advisories.cves}))`)
      .orderBy(desc(advisories.publishedAt))
      .limit(6);
    const [kev] = await tx
      .select({ cves: sql<number>`count(distinct ${vulnerabilities.cve})::int` })
      .from(vulnerabilities)
      .innerJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
      .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open"), eq(cveIntel.kev, true)));

    const overallRisk = Math.max(alertStats?.openRisk ?? 0, ...activeIncidents.map((i) => i.riskScore), topVulns[0]?.priority ?? 0);

    const data = {
      tenant,
      overallRisk,
      alertStats: alertStats!,
      activeIncidents,
      endpoints: endpoints!,
      offlineEndpoints,
      topVulns,
      recentAlerts,
      actions,
      pendingApprovals: pending?.n ?? 0,
      latestReport: latestReport ?? null,
      threats,
      kevCves: kev?.cves ?? 0,
    };
    return { ...data, recommendations: portalRecommendations(data) };
  });
}

export type Recommendation = { priority: "urgent" | "high" | "routine"; text: string; href: string };

/** Deterministic next steps derived from the overview. No model output. */
export function portalRecommendations(d: {
  topVulns: { cve: string; kev: boolean; kevDueDate: string | null; affectedAssets: number; internetFacing: number; priority: number }[];
  endpoints: { offline: number; unmanaged: number };
  activeIncidents: { id: string; ref: number; status: string }[];
  pendingApprovals: number;
}): Recommendation[] {
  const out: Recommendation[] = [];
  if (d.pendingApprovals) out.push({ priority: "urgent", text: `Decide ${d.pendingApprovals} containment request${d.pendingApprovals === 1 ? "" : "s"} awaiting your approval.`, href: "/soc/approvals" });
  for (const v of d.topVulns.filter((v) => v.kev).slice(0, 3)) {
    const where = v.internetFacing ? ` (${v.internetFacing} internet-facing)` : "";
    const due = v.kevDueDate ? ` Government remediation deadline: ${v.kevDueDate}.` : "";
    out.push({ priority: "urgent", text: `Patch ${v.cve} on ${v.affectedAssets} system${v.affectedAssets === 1 ? "" : "s"}${where}. It is being actively exploited.${due}`, href: `/vulnerabilities?cve=${v.cve}` });
  }
  const nonKevHigh = d.topVulns.filter((v) => !v.kev && v.priority >= 60);
  if (nonKevHigh.length) out.push({ priority: "high", text: `Schedule patching for ${nonKevHigh.map((v) => v.cve).join(", ")}.`, href: "/vulnerabilities" });
  if (d.endpoints.offline) out.push({ priority: "high", text: `Reconnect ${d.endpoints.offline} offline security agent${d.endpoints.offline === 1 ? "" : "s"}. The SOC cannot see or protect those systems.`, href: "/assets?kind=endpoint" });
  if (d.endpoints.unmanaged) out.push({ priority: "routine", text: `Install the security agent on ${d.endpoints.unmanaged} unmanaged system${d.endpoints.unmanaged === 1 ? "" : "s"}.`, href: "/assets" });
  const open = d.activeIncidents.filter((i) => i.status === "OPEN" || i.status === "INVESTIGATING");
  if (open.length) out.push({ priority: "high", text: `Review ${open.length} open incident${open.length === 1 ? "" : "s"} with the SOC and confirm any business impact.`, href: `/portal/incidents/${open[0]!.id}` });
  return out;
}

/** One incident in plain language, plus whether the customer has already acknowledged it. */
export async function portalIncident(ctx: AccessContext, incidentId: string) {
  const tenantIds = ctx.tenantIds.filter((id) => canViewPortal(ctx, id));
  if (!tenantIds.length || !/^[0-9a-f-]{36}$/i.test(incidentId)) return null;
  return withScope({ tenantIds, platform: false }, async (tx) => {
    const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, incidentId), inArray(incidents.tenantId, tenantIds)));
    if (!inc) return null;
    const [tenant] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, inc.tenantId));
    const acts = await tx
      .select({ action: responseActions.action, status: responseActions.status })
      .from(responseActions)
      .where(and(eq(responseActions.incidentId, inc.id), eq(responseActions.tenantId, inc.tenantId)));
    const phrases = acts.filter((a) => a.status === "SUCCEEDED").map((a) => actionPhrase(a.action));
    const [ack] = await tx
      .select({ occurredAt: incidentTimeline.occurredAt })
      .from(incidentTimeline)
      .where(and(eq(incidentTimeline.incidentId, inc.id), eq(incidentTimeline.category, "acknowledgement")))
      .limit(1);
    return {
      tenantId: inc.tenantId,
      tenantName: tenant?.name ?? "Your organisation",
      incident: { id: inc.id, ref: inc.ref, title: inc.title, severity: inc.severity, status: inc.status, updatedAt: inc.updatedAt },
      sentences: incidentSentences({ title: inc.title, severity: inc.severity, status: inc.status, actions: phrases }),
      acknowledgedAt: ack?.occurredAt ?? null,
    };
  });
}
