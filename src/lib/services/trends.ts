import { and, desc, eq, gte, inArray, lte, sql } from "drizzle-orm";
import { alerts, assets, incidents, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { inTenant, scoped } from "./common";

export type TrendVolume = { day: string; count: number };
export type TenantTrends = {
  days: number;
  volume: TrendVolume[];
  topDetections: { ruleId: string; count: number }[];
  noisyAssets: { assetId: string; name: string; count: number }[];
  seats: number;
  agents: { active: number; offline: number; unknown: number };
  /** Mean minutes from the linked alert's occurred_at to incidents.created_at. Null when none. */
  mttaMinutes: number | null;
  /** Mean minutes from incidents.created_at to closed_at for incidents closed in the window. Null when none. */
  mttrMinutes: number | null;
};

export type CustomerTrend = {
  id: string;
  name: string;
  slug: string;
  alerts: number;
  mttrMinutes: number | null;
  offline: number;
  seats: number;
};

function sinceFor(now: Date, days: number) {
  return new Date(now.getTime() - days * 86_400_000);
}

function num(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : 0;
}

function numOrNull(value: unknown): number | null {
  if (value == null) return null;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

/** UTC calendar days from `since` through `now`, with a zero where SQL returned no row. */
function fillDays(rows: { day: string; count: number }[], since: Date, now: Date): TrendVolume[] {
  const counts = new Map(rows.map((row) => [row.day, num(row.count)]));
  const out: TrendVolume[] = [];
  const cursor = new Date(Date.UTC(since.getUTCFullYear(), since.getUTCMonth(), since.getUTCDate()));
  const end = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  while (cursor.getTime() <= end) {
    const day = cursor.toISOString().slice(0, 10);
    out.push({ day, count: counts.get(day) ?? 0 });
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return out;
}

/**
 * 90-day operational trends for one tenant. `alert:read` so a customer admin can open
 * their own summary. MTTA uses the incident open time, not ingested_at or updated_at.
 */
export async function tenantTrends(ctx: AccessContext, tenantId: string, now = new Date(), days = 90): Promise<TenantTrends> {
  const since = sinceFor(now, days);
  return inTenant(ctx, "alert:read", tenantId, async (tx) => {
    const volumeRows = await tx
      .select({
        day: sql<string>`to_char(date_trunc('day', ${alerts.occurredAt} at time zone 'UTC'), 'YYYY-MM-DD')`,
        count: sql<number>`count(*)::int`,
      })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now)))
      .groupBy(sql`1`)
      .orderBy(sql`1`);

    const topDetections = await tx
      .select({
        ruleId: sql<string>`coalesce(${alerts.ruleId}, 'unspecified')`,
        count: sql<number>`count(*)::int`,
      })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now)))
      .groupBy(sql`1`)
      .orderBy(desc(sql`2`), sql`1`)
      .limit(8);

    const noisyAssets = await tx
      .select({
        assetId: assets.id,
        name: assets.name,
        count: sql<number>`count(*)::int`,
      })
      .from(alerts)
      .innerJoin(assets, eq(assets.id, alerts.assetId))
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now)))
      .groupBy(assets.id, assets.name)
      .orderBy(desc(sql`3`), assets.name)
      .limit(8);

    const [seatRow] = await tx
      .select({
        seats: sql<number>`count(*) filter (where ${assets.kind} in ('endpoint', 'server'))::int`,
        active: sql<number>`count(*) filter (where ${assets.kind} in ('endpoint', 'server') and ${assets.agentStatus} = 'active')::int`,
        offline: sql<number>`count(*) filter (where ${assets.kind} in ('endpoint', 'server') and ${assets.agentStatus} is not null and ${assets.agentStatus} <> 'active')::int`,
        unknown: sql<number>`count(*) filter (where ${assets.kind} in ('endpoint', 'server') and ${assets.agentStatus} is null)::int`,
      })
      .from(assets)
      .where(eq(assets.tenantId, tenantId));

    const [mttaRow] = await tx
      .select({
        minutes: sql<number | null>`avg(extract(epoch from (${incidents.createdAt} - ${alerts.occurredAt})) / 60.0)`,
      })
      .from(alerts)
      .innerJoin(incidents, eq(incidents.id, alerts.incidentId))
      .where(and(eq(alerts.tenantId, tenantId), gte(alerts.occurredAt, since), lte(alerts.occurredAt, now)));

    const [mttrRow] = await tx
      .select({
        minutes: sql<number | null>`avg(extract(epoch from (${incidents.closedAt} - ${incidents.createdAt})) / 60.0)`,
      })
      .from(incidents)
      .where(and(eq(incidents.tenantId, tenantId), gte(incidents.closedAt, since), lte(incidents.closedAt, now)));

    return {
      days,
      volume: fillDays(volumeRows, since, now),
      topDetections: topDetections.map((row) => ({ ruleId: row.ruleId, count: num(row.count) })),
      noisyAssets: noisyAssets.map((row) => ({ assetId: row.assetId, name: row.name, count: num(row.count) })),
      seats: num(seatRow?.seats),
      agents: { active: num(seatRow?.active), offline: num(seatRow?.offline), unknown: num(seatRow?.unknown) },
      mttaMinutes: numOrNull(mttaRow?.minutes),
      mttrMinutes: numOrNull(mttrRow?.minutes),
    };
  });
}

/** MSSP comparison across customers in scope. Live queue counts stay on msspOverview. */
export async function customerTrends(ctx: AccessContext, now = new Date(), days = 90): Promise<CustomerTrend[]> {
  const since = sinceFor(now, days);
  const sinceIso = since.toISOString();
  const nowIso = now.toISOString();
  return scoped(ctx, "mssp:read", async (tx, ids) => {
    if (!ids.length) return [];
    const rows = await tx
      .select({
        id: tenants.id,
        name: tenants.name,
        slug: tenants.slug,
        alerts: sql<number>`(select count(*) from alerts a where a.tenant_id = tenants.id and a.occurred_at >= ${sinceIso}::timestamptz and a.occurred_at <= ${nowIso}::timestamptz)::int`,
        mttrMinutes: sql<number | null>`(select avg(extract(epoch from (i.closed_at - i.created_at)) / 60.0) from incidents i where i.tenant_id = tenants.id and i.closed_at is not null and i.closed_at >= ${sinceIso}::timestamptz and i.closed_at <= ${nowIso}::timestamptz)`,
        offline: sql<number>`(select count(*) from assets s where s.tenant_id = tenants.id and s.kind in ('endpoint', 'server') and s.agent_status is not null and s.agent_status <> 'active')::int`,
        seats: sql<number>`(select count(*) from assets s where s.tenant_id = tenants.id and s.kind in ('endpoint', 'server'))::int`,
      })
      .from(tenants)
      .where(and(inArray(tenants.id, ids), eq(tenants.kind, "customer")))
      .orderBy(desc(sql`4`), tenants.name);
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      slug: row.slug,
      alerts: num(row.alerts),
      mttrMinutes: numOrNull(row.mttrMinutes),
      offline: num(row.offline),
      seats: num(row.seats),
    }));
  });
}
