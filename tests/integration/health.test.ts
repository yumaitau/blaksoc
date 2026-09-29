import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, assets, detectionDeployments, dmarcReports, healthBaselines, integrations, monitoredDomains, sigmaRules, sites, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import { buildReport } from "@/lib/reports/generate";
import { msspOverview } from "@/lib/services/dashboard";
import { HealthError, runHealthForTenant, setHealthPolicy, setSiteSilentHours } from "@/lib/services/health";
import { AccessDenied } from "@/lib/services/common";

const created: string[] = [];
const now = new Date("2026-06-01T00:00:00.000Z");
const ago = (hours: number) => new Date(now.getTime() - hours * 3_600_000);

function staff(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "health-staff", name: "Health Staff", email: "health@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{
      roleKey: "platform_admin",
      tenantId: null,
      permissions: new Set(["settings:manage", "user:manage", "mssp:read", "report:generate"]),
    }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "Health Clinic", kind: "customer" }],
  };
}

function customer(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "health-customer", name: "Clinic Admin", email: "clinic@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{
      roleKey: "customer_admin",
      tenantId,
      permissions: new Set(["user:manage", "asset:read"]),
    }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "Health Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `health-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Health Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

async function openHealth(tenantId: string) {
  return adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), inArray(alerts.status, ["NEW", "TRIAGING", "INVESTIGATING", "ESCALATED", "CONTAINED"])));
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("telemetry health", () => {
  it("dedupes silent-agent alerts, resolves on check-in, and honours site then tenant limits", async () => {
    const tenant = await freshTenant();
    const ctx = staff(tenant.id, tenant.slug);
    const clinic = customer(tenant.id, tenant.slug);
    const [low] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Camp", bandwidthProfile: "low" }).returning();
    const [town] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Town", bandwidthProfile: "standard" }).returning();
    const [quiet] = await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: low!.id, kind: "endpoint", name: "Camp PC", hostname: "camp-pc", agentStatus: "active", lastSeen: ago(80) }).returning();
    await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: low!.id, kind: "endpoint", name: "Recent", hostname: "recent", agentStatus: "active", lastSeen: ago(20) });
    const [desk] = await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: town!.id, kind: "endpoint", name: "Desk", hostname: "desk", agentStatus: "active", lastSeen: ago(30) }).returning();
    await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: low!.id, kind: "endpoint", name: "No sensor", hostname: "inventory", lastSeen: ago(80) });

    await runHealthForTenant(tenant.id, now);
    await runHealthForTenant(tenant.id, now);
    let rows = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.source, "health")));
    const silent = rows.filter((row) => row.externalId.startsWith("health:silent:"));
    expect(silent.map((row) => row.assetId).sort()).toEqual([desk!.id, quiet!.id].sort());
    expect(silent.every((row) => row.status === "NEW")).toBe(true);

    await adminDb().update(assets).set({ lastSeen: now }).where(eq(assets.id, quiet!.id));
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${quiet!.id}`));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("RESOLVED");

    await adminDb().update(assets).set({ lastSeen: ago(80) }).where(eq(assets.id, quiet!.id));
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${quiet!.id}`));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("NEW");

    await adminDb().update(alerts).set({ status: "FALSE_POSITIVE" }).where(eq(alerts.externalId, `health:silent:${desk!.id}`));
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${desk!.id}`));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("FALSE_POSITIVE");

    await expect(setHealthPolicy(clinic, tenant.id, { silentHours: 100 })).rejects.toBeInstanceOf(AccessDenied);
    expect(await setHealthPolicy(ctx, tenant.id, { silentHours: 100 })).toMatchObject({ silentHours: 100 });
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${quiet!.id}`));
    expect(rows[0]?.status).toBe("RESOLVED");

    expect(await setSiteSilentHours(clinic, tenant.id, low!.id, 10)).toBe(10);
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${quiet!.id}`));
    expect(rows[0]?.status).toBe("NEW");

    await setSiteSilentHours(clinic, tenant.id, low!.id, null);
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${quiet!.id}`));
    expect(rows[0]?.status).toBe("RESOLVED");

    const [front] = await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: town!.id, kind: "server", name: "Front", hostname: "front", agentStatus: "active", lastSeen: ago(12) }).returning();
    await runHealthForTenant(tenant.id, now);
    expect(await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${front!.id}`))).toHaveLength(0);
    await setSiteSilentHours(clinic, tenant.id, town!.id, 10);
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${front!.id}`));
    expect(rows[0]?.status).toBe("NEW");
    await expect(setSiteSilentHours(clinic, tenant.id, town!.id, 0)).rejects.toBeInstanceOf(HealthError);
  });

  it("flags stale polls, DMARC, and Sigma runs, and a coverage drop until it recovers", async () => {
    const tenant = await freshTenant();
    const ctx = staff(tenant.id, tenant.slug);
    const [m365] = await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "m365", name: "M365", enabled: true, lastSuccessAt: ago(2) }).returning();
    const [google] = await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "google-workspace", name: "Google", enabled: true, lastSuccessAt: new Date(now.getTime() - 10 * 60_000) }).returning();
    await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "entra", name: "Entra", enabled: false, lastSuccessAt: null });
    const [recentPoll] = await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "m365", name: "M365 recent", enabled: true, lastSuccessAt: new Date(now.getTime() - 30 * 60_000) }).returning();
    const [bare] = await adminDb().insert(monitoredDomains).values({ tenantId: tenant.id, name: "bare.example", source: "attested", verificationToken: "t1" }).returning();
    const [freshDomain] = await adminDb().insert(monitoredDomains).values({ tenantId: tenant.id, name: "fresh.example", source: "attested", verificationToken: "t2" }).returning();
    const [oldDomain] = await adminDb().insert(monitoredDomains).values({ tenantId: tenant.id, name: "old.example", source: "attested", verificationToken: "t3" }).returning();
    const summary = { reportId: "r", org: "example", domain: "fresh.example", rows: [], pass: 1, fail: 0, unknownSenders: 0 };
    await adminDb().insert(dmarcReports).values({ tenantId: tenant.id, domainName: "fresh.example", reportId: "fresh-1", summary, ingestedAt: now });
    await adminDb().insert(dmarcReports).values({ tenantId: tenant.id, domainName: "old.example", reportId: "old-1", summary: { ...summary, domain: "old.example" }, ingestedAt: ago(50) });

    const [ruleA] = await adminDb().insert(sigmaRules).values({ tenantId: tenant.id, sigmaId: "a", title: "Script", attackTechniques: ["T1059", "T1110"], enabled: true }).returning();
    const [ruleB] = await adminDb().insert(sigmaRules).values({ tenantId: tenant.id, sigmaId: "b", title: "Phish", attackTechniques: ["T1566"], enabled: true }).returning();
    const [stale] = await adminDb().insert(detectionDeployments).values({ ruleId: ruleA!.id, tenantId: tenant.id, version: 1, query: "select 1", status: "active", lastRunAt: ago(30) }).returning();
    await adminDb().insert(detectionDeployments).values({ ruleId: ruleB!.id, tenantId: tenant.id, version: 1, query: "select 1", status: "active", lastRunAt: now });
    const [pausedRule] = await adminDb().insert(sigmaRules).values({ tenantId: tenant.id, sigmaId: "c", title: "Paused", attackTechniques: ["T1003"], enabled: true }).returning();
    await adminDb().insert(detectionDeployments).values({ ruleId: pausedRule!.id, tenantId: tenant.id, version: 1, query: "select 1", status: "paused", lastRunAt: ago(80) });

    await runHealthForTenant(tenant.id, now);
    let open = await openHealth(tenant.id);
    expect(open.map((row) => row.externalId).sort()).toEqual([
      `health:dmarc:${bare!.id}`,
      `health:dmarc:${oldDomain!.id}`,
      `health:poll:${m365!.id}`,
      `health:sigma:${stale!.id}`,
    ].sort());
    const [base] = await adminDb().select().from(healthBaselines).where(eq(healthBaselines.tenantId, tenant.id));
    expect(base).toMatchObject({ techniqueCount: 3, ruleCount: 2 });

    await adminDb().update(sigmaRules).set({ enabled: false }).where(eq(sigmaRules.id, ruleB!.id));
    await runHealthForTenant(tenant.id, now);
    await runHealthForTenant(tenant.id, now);
    open = await openHealth(tenant.id);
    const coverage = open.filter((row) => row.externalId === `health:coverage:${tenant.id}`);
    expect(coverage).toHaveLength(1);
    const [held] = await adminDb().select().from(healthBaselines).where(eq(healthBaselines.tenantId, tenant.id));
    expect(held).toMatchObject({ techniqueCount: 3, ruleCount: 2 });

    await adminDb().update(sigmaRules).set({ enabled: true }).where(eq(sigmaRules.id, ruleB!.id));
    await runHealthForTenant(tenant.id, now);
    open = await openHealth(tenant.id);
    expect(open.some((row) => row.externalId.startsWith("health:coverage:"))).toBe(false);

    await adminDb().update(sigmaRules).set({ attackTechniques: ["T1059"] }).where(eq(sigmaRules.id, ruleA!.id));
    await runHealthForTenant(tenant.id, now);
    open = await openHealth(tenant.id);
    expect(open.some((row) => row.externalId === `health:coverage:${tenant.id}`)).toBe(true);
    await adminDb().update(sigmaRules).set({ attackTechniques: ["T1059", "T1110"] }).where(eq(sigmaRules.id, ruleA!.id));
    await runHealthForTenant(tenant.id, now);
    open = await openHealth(tenant.id);
    expect(open.some((row) => row.externalId.startsWith("health:coverage:"))).toBe(false);

    await adminDb().update(integrations).set({ lastSuccessAt: now }).where(eq(integrations.id, m365!.id));
    await adminDb().update(detectionDeployments).set({ lastRunAt: now }).where(eq(detectionDeployments.id, stale!.id));
    await adminDb().insert(dmarcReports).values({ tenantId: tenant.id, domainName: "bare.example", reportId: "bare-1", summary: { ...summary, domain: "bare.example" }, ingestedAt: now });
    await setHealthPolicy(ctx, tenant.id, { dmarcStaleHours: 72, pollLagMinutes: 20, sigmaStaleHours: 48 });
    await runHealthForTenant(tenant.id, now);
    open = await openHealth(tenant.id);
    expect(open.map((row) => row.externalId)).toEqual([`health:poll:${recentPoll!.id}`]);
    expect(open.some((row) => row.externalId === `health:poll:${google!.id}`)).toBe(false);

    await setHealthPolicy(ctx, tenant.id, { pollLagMinutes: 60 });
    await runHealthForTenant(tenant.id, now);
    expect(await openHealth(tenant.id)).toHaveLength(0);
    const [resolvedOld] = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:dmarc:${oldDomain!.id}`));
    expect(resolvedOld?.status).toBe("RESOLVED");
    const [freshRow] = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:dmarc:${freshDomain!.id}`));
    expect(freshRow).toBeUndefined();
  });

  it("shows degraded customers on the MSSP roll-up and a Coverage section on the weekly report", async () => {
    const tenant = await freshTenant();
    const ctx = staff(tenant.id, tenant.slug);
    const [site] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Town", bandwidthProfile: "standard" }).returning();
    await adminDb().insert(assets).values({ tenantId: tenant.id, siteId: site!.id, kind: "endpoint", name: "Desk", hostname: "desk", agentStatus: "active", lastSeen: ago(30) });
    await runHealthForTenant(tenant.id, now);

    const degraded = await msspOverview(ctx);
    expect(degraded.find((row) => row.id === tenant.id)?.healthAlerts).toBe(1);

    await adminDb().update(assets).set({ lastSeen: now }).where(eq(assets.tenantId, tenant.id));
    await runHealthForTenant(tenant.id, now);
    const recovered = await msspOverview(ctx);
    expect(recovered.find((row) => row.id === tenant.id)?.healthAlerts).toBe(0);

    await adminDb().update(assets).set({ lastSeen: ago(30) }).where(eq(assets.tenantId, tenant.id));
    await runHealthForTenant(tenant.id, now);
    const report = await withScope(systemScope(tenant.id), (tx) => buildReport(tx, tenant.id, "weekly", { end: now }));
    const coverage = report.sections.filter((section) => section.heading === "Coverage");
    expect(coverage).toHaveLength(1);
    expect(coverage[0]?.body).toContain("1 endpoints seen this week");
    expect(coverage[0]?.body).toContain("1 open health alerts");
  });
});
