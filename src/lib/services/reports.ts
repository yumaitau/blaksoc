import { and, desc, eq, inArray } from "drizzle-orm";
import { reports, tenants } from "@/db/schema";
import { assertCan, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { buildReport, saveReport, type ReportKind } from "@/lib/reports/generate";
import { cobrandLabel } from "./partner";
import { actor, AccessDenied, inTenant, scoped } from "./common";

export async function listReports(ctx: AccessContext, tenantIds?: string[]) {
  return scoped(
    ctx,
    "report:read",
    (tx, ids) =>
      tx
        .select({ id: reports.id, tenantId: reports.tenantId, tenantName: tenants.name, kind: reports.kind, title: reports.title, periodStart: reports.periodStart, periodEnd: reports.periodEnd, createdAt: reports.createdAt })
        .from(reports)
        .innerJoin(tenants, eq(tenants.id, reports.tenantId))
        .where(inArray(reports.tenantId, ids))
        .orderBy(desc(reports.createdAt))
        .limit(200),
    tenantIds,
  );
}

export async function getReport(ctx: AccessContext, id: string) {
  return scoped(ctx, "report:read", async (tx, ids) => (await tx.select().from(reports).where(and(eq(reports.id, id), inArray(reports.tenantId, ids))))[0] ?? null);
}

export async function generateReport(ctx: AccessContext, tenantId: string, kind: ReportKind, opts: { incidentId?: string; span?: "month" | "quarter" } = {}) {
  assertCan(ctx, "report:generate", tenantId);
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const content = await buildReport(tx, tenantId, kind, opts);
    const cobrand = await cobrandLabel(tenantId);
    const r = await saveReport(tx, tenantId, kind, cobrand ? { ...content, cobrand } : content, ctx.principal.userId);
    await audit(tx, { ...actor(ctx), tenantId, action: "report.generate", targetType: "report", targetId: r.id, detail: { kind } });
    return r;
  });
}

export { AccessDenied };
