import { and, desc, gte, inArray, sql } from "drizzle-orm";
import { alerts, e8Assessments, tenants } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import type { StrategyId } from "@/lib/essential-eight/requirements";
import { levelsOf, type Level } from "@/lib/essential-eight/score";
import { scoped } from "./common";

export const COMPLIANCE_WINDOWS = [7, 30, 90] as const;
export type ComplianceWindow = (typeof COMPLIANCE_WINDOWS)[number];

export type RefSignal = { id: string; alerts: number; open: number; highOrCritical: number; customers: number; lastSeen: string };
export type CustomerE8 = {
  tenantId: string;
  name: string;
  /** Latest self-assessed maturity per strategy; null when the customer has not been assessed or it is not visible. */
  assessed: Partial<Record<StrategyId, Level>> | null;
  assessedAt: string | null;
  alerts: Partial<Record<StrategyId, number>>;
};

const OPEN = sql`${alerts.status} not in ('RESOLVED', 'FALSE_POSITIVE')`;

/**
 * ISM controls and Essential Eight strategies that detections were mapped to (Wedgetail sends both), set
 * beside each customer's latest Essential Eight assessment. Counts are evidence that a control area is
 * being exercised or attacked. They never rate a control as met.
 */
export async function complianceSignals(ctx: AccessContext, tenantIds: readonly string[] | undefined, days: ComplianceWindow) {
  const since = new Date(Date.now() - days * 86_400_000);
  return scoped(ctx, "alert:read", async (tx, scope) => {
    const inWindow = and(inArray(alerts.tenantId, scope), gte(alerts.occurredAt, since), sql`${alerts.lane} = 'active'`);
    const summarise = async (column: typeof alerts.ismControls | typeof alerts.e8Strategies) => [...await tx.execute<RefSignal>(sql`
      select ref as id, count(*)::int as alerts, count(*) filter (where ${OPEN})::int as open,
        count(*) filter (where ${alerts.severity} in ('high', 'critical'))::int as "highOrCritical",
        count(distinct ${alerts.tenantId})::int as customers,
        to_char(max(${alerts.occurredAt}) at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') as "lastSeen"
      from ${alerts} cross join lateral unnest(${column}) as ref
      where ${inWindow}
      group by ref order by count(*) desc, ref`)];

    const [ism, e8, perCustomer, mapped, customerRows] = await Promise.all([
      summarise(alerts.ismControls),
      summarise(alerts.e8Strategies),
      tx.execute<{ tenantId: string; id: string; n: number }>(sql`
        select ${alerts.tenantId} as "tenantId", ref as id, count(*)::int as n
        from ${alerts} cross join lateral unnest(${alerts.e8Strategies}) as ref
        where ${inWindow} group by 1, 2`).then((rows) => [...rows]),
      tx.select({ total: sql<number>`count(*)::int`, mapped: sql<number>`count(*) filter (where cardinality(${alerts.ismControls}) > 0 or cardinality(${alerts.e8Strategies}) > 0)::int` })
        .from(alerts).where(inWindow),
      tx.select({ id: tenants.id, name: tenants.name }).from(tenants)
        .where(and(inArray(tenants.id, scope), sql`${tenants.kind} = 'customer'`, sql`${tenants.status} = 'active'`, sql`coalesce((${tenants.settings}->>'training')::boolean, false) = false`))
        .orderBy(tenants.name),
    ]);

    const assessable = customerRows.filter((t) => can(ctx, "report:read", t.id)).map((t) => t.id);
    const latest = assessable.length
      ? await tx.selectDistinctOn([e8Assessments.tenantId], { tenantId: e8Assessments.tenantId, assessedAt: e8Assessments.assessedAt, result: e8Assessments.result })
        .from(e8Assessments).where(inArray(e8Assessments.tenantId, assessable)).orderBy(e8Assessments.tenantId, desc(e8Assessments.assessedAt))
      : [];
    const assessments = new Map(latest.map((row) => [row.tenantId, row]));
    const customers: CustomerE8[] = customerRows.map((t) => {
      const row = assessments.get(t.id);
      const alertsFor = Object.fromEntries(perCustomer.filter((r) => r.tenantId === t.id).map((r) => [r.id, r.n])) as Partial<Record<StrategyId, number>>;
      return {
        tenantId: t.id,
        name: t.name,
        assessed: row ? levelsOf(row.result.ratings) : null,
        assessedAt: row?.assessedAt.toISOString() ?? null,
        alerts: alertsFor,
      };
    });

    return {
      since: since.toISOString(),
      days,
      ism,
      e8,
      customers,
      alerts: mapped[0]?.total ?? 0,
      mappedAlerts: mapped[0]?.mapped ?? 0,
    };
  }, tenantIds);
}
