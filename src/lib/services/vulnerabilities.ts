import { and, desc, eq, inArray, sql, type SQL } from "drizzle-orm";
import { assets, cveIntel, tenants, vulnerabilities } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { actor, AccessDenied, scoped } from "./common";

/** Patch-first view: grouped by CVE per tenant, ranked by blakSOC priority with evidence. */
export async function patchPriorities(ctx: AccessContext, f: { tenantIds?: string[]; kevOnly?: boolean; limit?: number } = {}) {
  return scoped(
    ctx,
    "vuln:read",
    (tx, tenantIds) => {
      const where: SQL[] = [inArray(vulnerabilities.tenantId, tenantIds), eq(vulnerabilities.status, "open")];
      if (f.kevOnly) where.push(eq(cveIntel.kev, true));
      return tx
        .select({
          tenantId: vulnerabilities.tenantId,
          tenantName: tenants.name,
          cve: vulnerabilities.cve,
          title: sql<string>`max(${vulnerabilities.title})`,
          maxPriority: sql<number>`max(${vulnerabilities.priorityScore})::int`,
          affectedAssets: sql<number>`count(distinct ${vulnerabilities.assetId})::int`,
          criticalAssets: sql<number>`count(distinct ${vulnerabilities.assetId}) filter (where ${assets.criticality} >= 4)::int`,
          internetFacing: sql<number>`count(distinct ${vulnerabilities.assetId}) filter (where ${assets.exposure} = 'internet')::int`,
          packages: sql<string[]>`array_agg(distinct ${vulnerabilities.packageName})`,
          cvss: sql<number | null>`max(${vulnerabilities.cvss})`,
          epss: cveIntel.epss,
          epssPercentile: cveIntel.epssPercentile,
          kev: cveIntel.kev,
          kevDueDate: cveIntel.kevDueDate,
          kevRansomware: cveIntel.kevRansomware,
          openctiRefs: cveIntel.openctiRefs,
          factors: sql<unknown>`(array_agg(${vulnerabilities.priorityFactors} order by ${vulnerabilities.priorityScore} desc))[1]`,
        })
        .from(vulnerabilities)
        .innerJoin(tenants, eq(tenants.id, vulnerabilities.tenantId))
        .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
        .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
        .where(and(...where))
        .groupBy(vulnerabilities.tenantId, tenants.name, vulnerabilities.cve, cveIntel.cve)
        .orderBy(desc(sql`max(${vulnerabilities.priorityScore})`), desc(sql`count(distinct ${vulnerabilities.assetId})`))
        .limit(f.limit ?? 200);
    },
    f.tenantIds,
  );
}

export async function vulnerabilityDetail(ctx: AccessContext, tenantId: string, cve: string) {
  return scoped(
    ctx,
    "vuln:read",
    async (tx) => {
      const [intel] = await tx.select().from(cveIntel).where(eq(cveIntel.cve, cve));
      const rows = await tx
        .select({ vuln: vulnerabilities, assetName: assets.name, criticality: assets.criticality, exposure: assets.exposure })
        .from(vulnerabilities)
        .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
        .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.cve, cve)))
        .orderBy(desc(vulnerabilities.priorityScore));
      return { intel: intel ?? null, instances: rows };
    },
    [tenantId],
  );
}

export async function setVulnStatus(ctx: AccessContext, ids: string[], status: "open" | "patched" | "accepted", note?: string) {
  return scoped(ctx, "vuln:write", async (tx, tenantIds) => {
    const rows = await tx.update(vulnerabilities).set({ status }).where(and(inArray(vulnerabilities.id, ids), inArray(vulnerabilities.tenantId, tenantIds))).returning({ id: vulnerabilities.id, tenantId: vulnerabilities.tenantId });
    if (rows.length !== ids.length) throw new AccessDenied("some vulnerabilities are outside your scope");
    for (const r of rows) await audit(tx, { ...actor(ctx), tenantId: r.tenantId, action: "vuln.status", targetType: "vulnerability", targetId: r.id, detail: { status, note } });
    return rows.length;
  });
}

export const vulnSummary = (ctx: AccessContext, tenantIds?: string[]) =>
  scoped(
    ctx,
    "vuln:read",
    async (tx, ids) => {
      const [r] = await tx
        .select({
          open: sql<number>`count(*)::int`,
          kev: sql<number>`count(*) filter (where ${cveIntel.kev})::int`,
          criticalAssetsAffected: sql<number>`count(distinct ${vulnerabilities.assetId}) filter (where ${assets.criticality} >= 4 and ${vulnerabilities.priorityScore} >= 60)::int`,
          urgent: sql<number>`count(*) filter (where ${vulnerabilities.priorityScore} >= 70)::int`,
        })
        .from(vulnerabilities)
        .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
        .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
        .where(and(inArray(vulnerabilities.tenantId, ids), eq(vulnerabilities.status, "open")));
      return r!;
    },
    tenantIds,
  );
