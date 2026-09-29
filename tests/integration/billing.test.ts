/**
 * Plans, downgrade, and metering against a fresh tenant.
 * User, device and domain expectations are the rows this file inserts.
 * Bytes are compared with a separate octet_length query, not the meter's return value copied forward.
 */
import { randomUUID } from "node:crypto";
import { and, eq, gte, inArray, lt, sql } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assets, integrations, tenants, usageDaily } from "@/db/schema";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { EntitlementError } from "@/lib/billing/catalogue";
import { buildQuote } from "@/lib/billing/invoice";
import { meterTenant, monthUsage, quoteFor, requireCapability, setTenantPlan } from "@/lib/services/billing";

const created: string[] = [];
const sharedIds: string[] = [];
const ABN = "51824753556";

function platform(tenantId: string, name: string): AccessContext {
  return {
    principal: { userId: "plan-test-admin", name: "Plan Admin", email: "plan-admin@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set(["settings:manage", "mssp:read"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "plan-test", name, kind: "customer" }],
  };
}

function customer(tenantId: string): AccessContext {
  return {
    principal: { userId: "plan-test-customer", name: "Customer Admin", email: "customer@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(["portal:read", "user:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "plan-test", name: "Customer", kind: "customer" }],
  };
}

async function freshTenant(name: string) {
  const slug = `plan-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name, kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (sharedIds.length) await adminDb().delete(integrations).where(inArray(integrations.id, sharedIds));
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("tenant plan downgrade", () => {
  it("keeps stored alerts and pauses only the features the new tier removed", async () => {
    const tenant = await freshTenant("Downgrade Clinic");
    const db = adminDb();
    await expect(requireCapability(db, tenant.id, "m365_monitoring")).resolves.toBeUndefined();
    await expect(requireCapability(db, tenant.id, "wazuh_endpoint")).rejects.toBeInstanceOf(EntitlementError);
    await expect(requireCapability(db, tenant.id, "velociraptor_dfir")).rejects.toBeInstanceOf(EntitlementError);

    const [wazuh] = await db.insert(integrations).values({ tenantId: tenant.id, category: "endpoint", provider: "wazuh", name: "Wazuh", enabled: true }).returning();
    const [entra] = await db.insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "entra", name: "Entra", enabled: true }).returning();
    const [hook] = await db.insert(integrations).values({ tenantId: tenant.id, category: "ticketing", provider: "webhook", name: "Hook", enabled: true }).returning();
    const [adminOff] = await db.insert(integrations).values({ tenantId: tenant.id, category: "endpoint", provider: "wazuh", name: "Wazuh admin off", enabled: false, pausedByPlan: false }).returning();
    const [shared] = await db.insert(integrations).values({ tenantId: null, category: "siem", provider: "wazuh", name: `Shared ${tenant.slug}`, enabled: true }).returning();
    sharedIds.push(shared!.id);
    const [alert] = await db.insert(alerts).values({
      tenantId: tenant.id, source: "wazuh", externalId: `keep-${tenant.slug}`, title: "Kept alert", severity: "low", occurredAt: new Date(), raw: { keep: true },
    }).returning();

    const ctx = platform(tenant.id, tenant.name);
    await setTenantPlan(ctx, tenant.id, { tier: "standard" });
    await setTenantPlan(ctx, tenant.id, { tier: "essentials" });

    const rows = await db.select().from(integrations).where(inArray(integrations.id, [wazuh!.id, entra!.id, hook!.id, adminOff!.id, shared!.id]));
    const byId = new Map(rows.map((r) => [r.id, r]));
    expect(byId.get(wazuh!.id)).toMatchObject({ enabled: false, pausedByPlan: true });
    expect(byId.get(entra!.id)).toMatchObject({ enabled: true, pausedByPlan: false });
    expect(byId.get(hook!.id)).toMatchObject({ enabled: true, pausedByPlan: false });
    expect(byId.get(adminOff!.id)).toMatchObject({ enabled: false, pausedByPlan: false });
    expect(byId.get(shared!.id)).toMatchObject({ enabled: true, pausedByPlan: false });
    const [kept] = await db.select().from(alerts).where(eq(alerts.id, alert!.id));
    expect(kept?.title).toBe("Kept alert");
    await expect(requireCapability(db, tenant.id, "wazuh_endpoint")).rejects.toBeInstanceOf(EntitlementError);

    await setTenantPlan(ctx, tenant.id, { tier: "standard" });
    const resumed = await db.select().from(integrations).where(inArray(integrations.id, [wazuh!.id, adminOff!.id]));
    const resumedById = new Map(resumed.map((r) => [r.id, r]));
    expect(resumedById.get(wazuh!.id)).toMatchObject({ enabled: true, pausedByPlan: false });
    expect(resumedById.get(adminOff!.id)).toMatchObject({ enabled: false, pausedByPlan: false });

    await setTenantPlan(ctx, tenant.id, { tier: "plus" });
    await expect(requireCapability(db, tenant.id, "velociraptor_dfir")).resolves.toBeUndefined();
    await expect(requireCapability(db, tenant.id, "board_reporting")).resolves.toBeUndefined();
    await expect(setTenantPlan(customer(tenant.id), tenant.id, { tier: "essentials" })).rejects.toBeInstanceOf(AccessDenied);
    await expect(requireCapability(db, tenant.id, "velociraptor_dfir")).resolves.toBeUndefined();
  });
});

describe("usage metering", () => {
  it("matches inserted counts and stays within 1% of source bytes", async () => {
    const tenant = await freshTenant("Meter Clinic");
    const db = adminDb();
    const day = "2026-09-29";
    const identities = [
      ...Array.from({ length: 9 }, (_, i) => ({ tenantId: tenant.id, kind: "identity" as const, name: `user-${i}`, agentStatus: "active" })),
      { tenantId: tenant.id, kind: "identity" as const, name: "user-null", agentStatus: null },
      { tenantId: tenant.id, kind: "identity" as const, name: "user-disabled", agentStatus: "disabled" },
    ];
    await db.insert(assets).values([
      ...identities,
      ...Array.from({ length: 4 }, (_, i) => ({ tenantId: tenant.id, kind: "endpoint" as const, name: `pc-${i}` })),
      { tenantId: tenant.id, kind: "server" as const, name: "file-server" },
      ...Array.from({ length: 3 }, (_, i) => ({ tenantId: tenant.id, kind: "domain" as const, name: `dom-${i}.example` })),
    ]);
    const todayRaw = { padding: "x".repeat(50_000), n: 1 };
    const yesterdayRaw = { padding: "y".repeat(80_000), n: 2 };
    await db.insert(alerts).values([
      {
        tenantId: tenant.id, source: "entra", externalId: `today-${tenant.slug}`, title: "Today", severity: "low",
        occurredAt: new Date(`${day}T01:00:00.000Z`), ingestedAt: new Date(`${day}T01:00:00.000Z`), raw: todayRaw,
      },
      {
        tenantId: tenant.id, source: "entra", externalId: `yesterday-${tenant.slug}`, title: "Yesterday", severity: "low",
        occurredAt: new Date("2026-09-28T12:00:00.000Z"), ingestedAt: new Date("2026-09-28T12:00:00.000Z"), raw: yesterdayRaw,
      },
    ]);

    const usage = await meterTenant(db, tenant.id, day);
    expect(usage.protectedUsers).toBe(10);
    expect(usage.endpoints).toBe(4);
    expect(usage.domains).toBe(3);

    const start = new Date(`${day}T00:00:00.000Z`);
    const end = new Date(start.getTime() + 86_400_000);
    const [source] = await db
      .select({ n: sql<string>`coalesce(sum(octet_length(raw::text)), 0)::float8` })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenant.id), gte(alerts.ingestedAt, start), lt(alerts.ingestedAt, end)));
    const sourceBytes = Number(source!.n);
    expect(sourceBytes).toBeGreaterThan(50_000);
    expect(Math.abs(usage.bytesIngested - sourceBytes) / sourceBytes).toBeLessThanOrEqual(0.01);

    await db.insert(usageDaily).values({ tenantId: tenant.id, day: "2026-09-02", protectedUsers: 2, endpoints: 1, domains: 1, bytesIngested: 1000 });
    const month = await monthUsage(db, tenant.id, "2026-09");
    expect(month.protectedUsers).toBe(10);
    expect(month.endpoints).toBe(4);
    expect(month.domains).toBe(3);
    expect(month.bytesIngested).toBe(usage.bytesIngested + 1000);
  });
});

describe("quote export", () => {
  it("refuses a quote with no supplier ABN and prices the stored plan when one is set", async () => {
    const tenant = await freshTenant("Quote Clinic");
    const ctx = platform(tenant.id, tenant.name);
    const asOf = new Date("2026-09-29T00:00:00.000Z");
    const previous = process.env.BLAKSOC_SUPPLIER_ABN;
    try {
      delete process.env.BLAKSOC_SUPPLIER_ABN;
      expect(await quoteFor(ctx, tenant.id, asOf)).toEqual({ error: "abn" });
      process.env.BLAKSOC_SUPPLIER_ABN = ABN;
      await setTenantPlan(ctx, tenant.id, { tier: "essentials", nonprofit: true, discountBps: 0, pilotEndsAt: null });
      const quote = await quoteFor(ctx, tenant.id, asOf);
      expect(quote).toEqual(buildQuote({
        supplierAbn: ABN, customerName: tenant.name, tier: "essentials", nonprofit: true, discountBps: 0, pilotEndsAt: null, asOf,
      }));
      await expect(quoteFor(customer(tenant.id), tenant.id, asOf)).rejects.toBeInstanceOf(AccessDenied);
    } finally {
      if (previous === undefined) delete process.env.BLAKSOC_SUPPLIER_ABN;
      else process.env.BLAKSOC_SUPPLIER_ABN = previous;
    }
  });
});
