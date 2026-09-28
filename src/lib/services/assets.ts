import { and, desc, eq, ilike, inArray, ne, or, sql, type SQL } from "drizzle-orm";
import { alerts, assets, assetSources, incidentLinks, incidents, integrations, intelMatches, tenants, vulnerabilities } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { actor, AccessDenied, scoped } from "./common";

export async function listAssets(ctx: AccessContext, f: { tenantIds?: string[]; kind?: string; q?: string; minCriticality?: number; limit?: number } = {}) {
  return scoped(
    ctx,
    "asset:read",
    (tx, tenantIds) => {
      const where: SQL[] = [inArray(assets.tenantId, tenantIds)];
      if (f.kind) where.push(eq(assets.kind, f.kind as never));
      if (f.q) where.push(or(ilike(assets.name, `%${f.q}%`), ilike(assets.hostname, `%${f.q}%`), sql`${f.q} = any(${assets.ips})`)!);
      if (f.minCriticality) where.push(sql`${assets.criticality} >= ${f.minCriticality}`);
      return tx
        .select({
          id: assets.id, tenantId: assets.tenantId, tenantName: tenants.name, kind: assets.kind, name: assets.name, hostname: assets.hostname, ips: assets.ips, os: assets.os,
          owner: assets.owner, criticality: assets.criticality, exposure: assets.exposure, agentStatus: assets.agentStatus, riskScore: assets.riskScore, lastSeen: assets.lastSeen,
          openAlerts: sql<number>`(select count(*)::int from ${alerts} a where a.asset_id = ${assets.id} and a.status not in ('RESOLVED','FALSE_POSITIVE'))`,
          openVulns: sql<number>`(select count(*)::int from ${vulnerabilities} v where v.asset_id = ${assets.id} and v.status = 'open')`,
          sources: sql<number>`(select count(*)::int from ${assetSources} s where s.asset_id = ${assets.id})`,
        })
        .from(assets)
        .innerJoin(tenants, eq(tenants.id, assets.tenantId))
        .where(and(...where))
        .orderBy(desc(assets.riskScore), desc(assets.criticality), assets.name)
        .limit(f.limit ?? 500);
    },
    f.tenantIds,
  );
}

export async function getAsset(ctx: AccessContext, id: string) {
  return scoped(ctx, "asset:read", async (tx, tenantIds) => {
    const [row] = await tx.select({ asset: assets, tenantName: tenants.name }).from(assets).innerJoin(tenants, eq(tenants.id, assets.tenantId)).where(and(eq(assets.id, id), inArray(assets.tenantId, tenantIds)));
    if (!row) return null;
    const [sources, alertRows, vulns, incs, sightings, identities] = await Promise.all([
      tx.select({ integration: integrations.name, provider: integrations.provider, externalId: assetSources.externalId, lastSyncedAt: assetSources.lastSyncedAt }).from(assetSources).leftJoin(integrations, eq(integrations.id, assetSources.integrationId)).where(eq(assetSources.assetId, id)),
      tx.select({ id: alerts.id, title: alerts.title, severity: alerts.severity, riskScore: alerts.riskScore, status: alerts.status, occurredAt: alerts.occurredAt, userName: alerts.userName }).from(alerts).where(eq(alerts.assetId, id)).orderBy(desc(alerts.occurredAt)).limit(50),
      tx.select().from(vulnerabilities).where(eq(vulnerabilities.assetId, id)).orderBy(desc(vulnerabilities.priorityScore)).limit(100),
      tx.selectDistinct({ id: incidents.id, ref: incidents.ref, title: incidents.title, status: incidents.status, severity: incidents.severity }).from(incidentLinks).innerJoin(incidents, eq(incidents.id, incidentLinks.incidentId)).where(and(eq(incidentLinks.kind, "asset"), eq(incidentLinks.refId, id))),
      tx.select({ id: intelMatches.id, verdict: intelMatches.verdict, summary: intelMatches.summary, matchedAt: intelMatches.matchedAt }).from(intelMatches).innerJoin(alerts, eq(alerts.id, intelMatches.alertId)).where(eq(alerts.assetId, id)).orderBy(desc(intelMatches.matchedAt)).limit(25),
      tx.selectDistinct({ userName: alerts.userName }).from(alerts).where(and(eq(alerts.assetId, id), ne(alerts.userName, ""))).limit(25),
    ]);
    return { ...row, sources, alerts: alertRows, vulnerabilities: vulns, incidents: incs, sightings, identities: identities.map((i) => i.userName).filter(Boolean) as string[] };
  });
}

export async function updateAsset(ctx: AccessContext, id: string, patch: { criticality?: number; exposure?: string; owner?: string | null; tags?: string[]; privileged?: boolean }) {
  if (patch.criticality != null && (patch.criticality < 1 || patch.criticality > 5)) throw new Error("criticality must be 1–5");
  return scoped(ctx, "asset:write", async (tx, tenantIds) => {
    const [a] = await tx.update(assets).set(patch).where(and(eq(assets.id, id), inArray(assets.tenantId, tenantIds))).returning();
    if (!a) throw new AccessDenied("asset not found");
    await audit(tx, { ...actor(ctx), tenantId: a.tenantId, action: "asset.update", targetType: "asset", targetId: id, detail: patch });
    return a;
  });
}
