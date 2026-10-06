import { and, eq, gte, inArray, lt, sql } from "drizzle-orm";
import { systemDb, type DbOrTx } from "@/db/client";
import { alerts, assets, integrations, tenantPlans, tenants, usageDaily } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { asTier, assertEntitled, collectionAllowed, type Capability, type Tier } from "@/lib/billing/catalogue";
import { buildQuote, readSupplierAbn, type Quote } from "@/lib/billing/invoice";
import { actor, inTenant, scoped } from "./common";

export type Plan = {
  tenantId: string;
  tier: Tier;
  nonprofit: boolean;
  pilotEndsAt: Date | null;
  discountBps: number;
};

export type PlanInput = {
  tier: Tier;
  nonprofit?: boolean;
  discountBps?: number;
  pilotEndsAt?: Date | null;
};

export type UsageTotals = {
  protectedUsers: number;
  endpoints: number;
  domains: number;
  bytesIngested: number;
};

export type UsageRow = {
  id: string;
  name: string;
  slug: string;
  plan: Plan;
  usage: UsageTotals;
};

const num = (v: unknown) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
};

/** UTC calendar day, YYYY-MM-DD. Metering buckets use this, not the server's local zone. */
export function utcDay(d = new Date()): string {
  return d.toISOString().slice(0, 10);
}

function monthWindow(month: string): { start: string; end: string } {
  const [y, m] = month.split("-").map(Number);
  const end = new Date(Date.UTC(y!, m!, 1)).toISOString().slice(0, 10);
  return { start: `${month}-01`, end };
}

/** No row means Essentials. Fail closed for a tenant nobody has priced yet. */
export async function loadPlan(tx: DbOrTx, tenantId: string): Promise<Plan> {
  const [row] = await tx.select().from(tenantPlans).where(eq(tenantPlans.tenantId, tenantId));
  if (!row) return { tenantId, tier: "essentials", nonprofit: false, pilotEndsAt: null, discountBps: 0 };
  return { tenantId, tier: asTier(row.tier), nonprofit: row.nonprofit, pilotEndsAt: row.pilotEndsAt, discountBps: row.discountBps };
}

export async function plansByTenant(): Promise<Map<string, Tier>> {
  const rows = await systemDb().select({ tenantId: tenantPlans.tenantId, tier: tenantPlans.tier }).from(tenantPlans);
  return new Map(rows.map((r) => [r.tenantId, asTier(r.tier)]));
}

export async function requireCapability(tx: DbOrTx, tenantId: string, capability: Capability): Promise<void> {
  const plan = await loadPlan(tx, tenantId);
  assertEntitled(plan.tier, capability);
}

/**
 * Pause or resume tenant-owned integrations to match the tier.
 * Rows an admin disabled (paused_by_plan false) stay off. Platform-owned rows are not touched,
 * so a shared Wazuh cluster keeps running for the other tenants.
 */
export async function applyPlan(tx: DbOrTx, tenantId: string, tier: Tier): Promise<void> {
  const rows = await tx
    .select({ id: integrations.id, provider: integrations.provider, enabled: integrations.enabled, pausedByPlan: integrations.pausedByPlan })
    .from(integrations)
    .where(eq(integrations.tenantId, tenantId));
  for (const row of rows) {
    const allowed = collectionAllowed(tier, row.provider);
    if (!allowed && row.enabled) {
      await tx.update(integrations).set({ enabled: false, pausedByPlan: true }).where(eq(integrations.id, row.id));
    } else if (allowed && row.pausedByPlan) {
      await tx.update(integrations).set({ enabled: true, pausedByPlan: false }).where(eq(integrations.id, row.id));
    }
  }
}

export async function setTenantPlan(ctx: AccessContext, tenantId: string, input: PlanInput): Promise<Plan> {
  const nonprofit = input.nonprofit ?? false;
  const discountBps = input.discountBps ?? 0;
  const pilotEndsAt = input.pilotEndsAt ?? null;
  return inTenant(ctx, "settings:manage", tenantId, async (tx) => {
    await tx
      .insert(tenantPlans)
      .values({ tenantId, tier: input.tier, nonprofit, discountBps, pilotEndsAt, updatedAt: new Date() })
      .onConflictDoUpdate({
        target: tenantPlans.tenantId,
        set: { tier: input.tier, nonprofit, discountBps, pilotEndsAt, updatedAt: new Date() },
      });
    await applyPlan(tx, tenantId, input.tier);
    await audit(tx, {
      ...actor(ctx),
      tenantId,
      action: "plan.update",
      targetType: "tenant_plan",
      targetId: tenantId,
      detail: { tier: input.tier, nonprofit, discountBps, pilotEndsAt: pilotEndsAt?.toISOString() ?? null },
    });
    return loadPlan(tx, tenantId);
  });
}

/**
 * Snapshot protected users (identities that are not disabled), endpoints, and domains.
 * Bytes are octet_length of the raw JSON ingested on that UTC day. Stored alerts stay either way.
 */
export async function meterTenant(tx: DbOrTx, tenantId: string, day = utcDay()): Promise<UsageTotals> {
  const start = new Date(`${day}T00:00:00.000Z`);
  const end = new Date(start.getTime() + 86_400_000);
  const [counts] = await tx
    .select({
      protectedUsers: sql<number>`(count(*) filter (where ${assets.kind} = 'identity' and ${assets.agentStatus} is distinct from 'disabled'))::int`,
      endpoints: sql<number>`(count(*) filter (where ${assets.kind} = 'endpoint'))::int`,
      domains: sql<number>`(count(*) filter (where ${assets.kind} = 'domain'))::int`,
    })
    .from(assets)
    .where(eq(assets.tenantId, tenantId));
  const [bytes] = await tx
    .select({ n: sql<string>`coalesce(sum(octet_length((${alerts.raw})::text)), 0)::float8` })
    .from(alerts)
    .where(and(eq(alerts.tenantId, tenantId), gte(alerts.ingestedAt, start), lt(alerts.ingestedAt, end)));
  const usage: UsageTotals = {
    protectedUsers: num(counts?.protectedUsers),
    endpoints: num(counts?.endpoints),
    domains: num(counts?.domains),
    bytesIngested: num(bytes?.n),
  };
  await tx
    .insert(usageDaily)
    .values({ tenantId, day, ...usage, meteredAt: new Date() })
    .onConflictDoUpdate({ target: [usageDaily.tenantId, usageDaily.day], set: { ...usage, meteredAt: new Date() } });
  return usage;
}

/**
 * Users, devices and domains are the latest snapshot in the month.
 * Bytes are the sum of the daily buckets (the volume actually ingested).
 */
export async function monthUsage(tx: DbOrTx, tenantId: string, month: string): Promise<UsageTotals> {
  const { start, end } = monthWindow(month);
  const rows = await tx
    .select()
    .from(usageDaily)
    .where(and(eq(usageDaily.tenantId, tenantId), gte(usageDaily.day, start), lt(usageDaily.day, end)));
  let bytes = 0;
  let latest: (typeof rows)[number] | undefined;
  for (const row of rows) {
    bytes += num(row.bytesIngested);
    if (!latest || row.day > latest.day) latest = row;
  }
  return {
    protectedUsers: latest ? num(latest.protectedUsers) : 0,
    endpoints: latest ? num(latest.endpoints) : 0,
    domains: latest ? num(latest.domains) : 0,
    bytesIngested: bytes,
  };
}

export async function usageDashboard(ctx: AccessContext, month = utcDay().slice(0, 7)): Promise<UsageRow[]> {
  return scoped(ctx, "mssp:read", async (tx, tenantIds) => {
    if (!tenantIds.length) return [];
    const customers = await tx
      .select({ id: tenants.id, name: tenants.name, slug: tenants.slug })
      .from(tenants)
      .where(and(eq(tenants.kind, "customer"), inArray(tenants.id, tenantIds)));
    const rows: UsageRow[] = [];
    for (const customer of customers) {
      await meterTenant(tx, customer.id);
      rows.push({ ...customer, plan: await loadPlan(tx, customer.id), usage: await monthUsage(tx, customer.id, month) });
    }
    rows.sort((a, b) => a.name.localeCompare(b.name));
    return rows;
  });
}

export async function customerUsage(ctx: AccessContext, tenantId: string, month = utcDay().slice(0, 7)): Promise<{ plan: Plan; usage: UsageTotals }> {
  return inTenant(ctx, "portal:read", tenantId, async (tx) => {
    await meterTenant(tx, tenantId);
    return { plan: await loadPlan(tx, tenantId), usage: await monthUsage(tx, tenantId, month) };
  });
}

export async function quoteFor(ctx: AccessContext, tenantId: string, asOf = new Date()): Promise<Quote | { error: "abn" } | null> {
  const supplierAbn = readSupplierAbn();
  if (!supplierAbn) return { error: "abn" };
  return inTenant(ctx, "mssp:read", tenantId, async (tx) => {
    const [tenant] = await tx.select({ name: tenants.name, kind: tenants.kind }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant || tenant.kind !== "customer") return null;
    const plan = await loadPlan(tx, tenantId);
    return buildQuote({
      supplierAbn,
      customerName: tenant.name,
      tier: plan.tier,
      nonprofit: plan.nonprofit,
      discountBps: plan.discountBps,
      pilotEndsAt: plan.pilotEndsAt,
      asOf,
    });
  });
}
