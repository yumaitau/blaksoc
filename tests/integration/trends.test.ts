/**
 * Operational trends against rows this file inserts. Calls tenantTrends,
 * customerTrends, and provision_dashboard_reader. Times the shipped aggregate.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { and, eq, inArray, sql } from "drizzle-orm";
import postgres from "postgres";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, incidents, tenants } from "@/db/schema";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { env } from "@/lib/env";
import { customerTrends, tenantTrends } from "@/lib/services/trends";

const created: string[] = [];
const roles: string[] = [];
let admin: ReturnType<typeof postgres> | undefined;

function adminSql() {
  if (!admin) admin = postgres(env().DATABASE_ADMIN_URL, { max: 1, prepare: false, onnotice: () => {} });
  return admin;
}

function customer(tenantId: string, name: string): AccessContext {
  const permissions = new Set<Permission>(["alert:read", "portal:read"]);
  return {
    principal: { userId: "trend-customer", name: "Clinic Admin", email: "clinic@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "trend", name, kind: "customer" }],
  };
}

function platform(rows: { id: string; name: string }[]): AccessContext {
  const permissions = new Set<Permission>(["mssp:read", "alert:read", "dashboard:read"]);
  return {
    principal: { userId: "trend-platform", name: "SOC Manager", email: "soc@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "soc_manager", tenantId: null, permissions }],
    tenantIds: rows.map((row) => row.id),
    tenants: rows.map((row) => ({ id: row.id, slug: row.id.slice(0, 8), name: row.name, kind: "customer" as const })),
  };
}

async function freshTenant(name: string, kind: "customer" | "partner" = "customer") {
  const slug = `tr-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name, kind }).returning();
  created.push(row!.id);
  return row!;
}

function readerRole(tenantId: string) {
  return `dash_${tenantId.replaceAll("-", "")}`;
}

async function provision(tenantId: string, password: string) {
  if (!/^[0-9a-f-]{36}$/i.test(tenantId) || !/^[0-9a-f]{48}$/.test(password)) throw new Error("bad provision input");
  try {
    await adminSql().unsafe(`CALL provision_dashboard_reader('${tenantId}'::uuid, '${password}')`).simple();
  } catch (err) {
    const message = err instanceof Error ? err.message.replaceAll(password, "[redacted]") : "provision failed";
    throw new Error(message);
  }
  const role = readerRole(tenantId);
  if (!roles.includes(role)) roles.push(role);
  return role;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
  for (const role of roles) {
    if (!/^dash_[0-9a-f]{32}$/.test(role)) continue;
    try {
      await adminSql().unsafe(`DROP OWNED BY ${role}`).simple();
    } catch {
      // Role may already be gone.
    }
    try {
      await adminSql().unsafe(`DROP ROLE IF EXISTS ${role}`).simple();
    } catch {
      // A leftover session can block the drop. The name stays in roles for the log.
    }
  }
  await admin?.end();
});

describe("operational trends", () => {
  it("points grafana at provision_dashboard_reader and does not commit a password", () => {
    const yaml = readFileSync("deploy/grafana/provisioning/datasources/tenant.yaml", "utf8");
    expect(yaml).toContain("provision_dashboard_reader");
    expect(yaml).toContain("NOBYPASSRLS");
    expect(yaml).toContain("${DASHBOARD_READER_PASSWORD}");
    const dash = readFileSync("deploy/grafana/dashboards/tenant-ops.json", "utf8");
    expect(dash).toContain("occurred_at");
    expect(dash).toContain("rule_id");
    expect(JSON.parse(dash).title).toBe("Tenant operations");
  });

  it("aggregates 90 days for 50 seats without mixing the other tenant", async () => {
    const now = new Date();
    const stamp = now.toISOString();
    const tenant = await freshTenant("Trend Clinic");
    const other = await freshTenant("Other Clinic");
    await adminDb().execute(sql`
      INSERT INTO assets (tenant_id, kind, name, agent_status)
      SELECT ${tenant.id}::uuid, 'endpoint', 'seat-' || g,
             CASE WHEN g < 30 THEN 'active' WHEN g < 40 THEN 'offline' ELSE NULL END
      FROM generate_series(0, 49) AS g
    `);
    await adminDb().execute(sql`
      INSERT INTO alerts (tenant_id, source, external_id, rule_id, title, severity, asset_id, occurred_at)
      SELECT ${tenant.id}::uuid, 'fixture', 'trend-' || g,
             CASE WHEN g < 500 THEN 'rule-hot' ELSE 'rule-' || (g % 9) END,
             'Trend ' || g,
             'low',
             a.id,
             ${stamp}::timestamptz - ((g % 90) * interval '1 day') - ((g % 24) * interval '1 hour')
      FROM generate_series(0, 4499) AS g
      JOIN assets a ON a.tenant_id = ${tenant.id}::uuid AND a.name = 'seat-' || CASE WHEN g < 200 THEN 0 ELSE g % 50 END
    `);
    await adminDb().execute(sql`
      INSERT INTO alerts (tenant_id, source, external_id, rule_id, title, severity, occurred_at)
      VALUES (${other.id}::uuid, 'fixture', 'trend-other', 'rule-other', 'Other alert', 'low', ${stamp}::timestamptz - interval '1 day')
    `);
    const [incident] = await adminDb().insert(incidents).values({
      tenantId: tenant.id,
      title: "Trend case",
      severity: "high",
      status: "CLOSED",
      createdAt: new Date(now.getTime() - 90 * 60_000),
      closedAt: new Date(now.getTime() - 30 * 60_000),
    }).returning();
    await adminDb().update(alerts).set({
      incidentId: incident!.id,
      occurredAt: new Date(now.getTime() - 120 * 60_000),
    }).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.externalId, "trend-0")));

    const started = performance.now();
    const trends = await tenantTrends(customer(tenant.id, tenant.name), tenant.id, now, 90);
    const elapsed = performance.now() - started;
    console.info(`TREND_MS ${elapsed.toFixed(1)}`);

    expect(trends.volume.reduce((sum, row) => sum + row.count, 0)).toBe(4500);
    expect(trends.seats).toBe(50);
    expect(trends.agents).toEqual({ active: 30, offline: 10, unknown: 10 });
    expect(trends.topDetections[0]?.ruleId).toBe("rule-hot");
    expect(trends.topDetections[0]?.count).toBe(500);
    expect(trends.noisyAssets[0]?.name).toBe("seat-0");
    expect(trends.noisyAssets[0]!.count).toBeGreaterThan(trends.noisyAssets[1]?.count ?? 0);
    expect(trends.mttaMinutes).toBeCloseTo(30, 1);
    expect(trends.mttrMinutes).toBeCloseTo(60, 1);
    expect(elapsed, `tenantTrends took ${elapsed.toFixed(1)} ms`).toBeLessThan(2000);

    const otherTrends = await tenantTrends(customer(other.id, other.name), other.id, now, 90);
    expect(otherTrends.volume.reduce((sum, row) => sum + row.count, 0)).toBe(1);
    expect(otherTrends.seats).toBe(0);
    expect(otherTrends.mttaMinutes).toBeNull();
    expect(otherTrends.mttrMinutes).toBeNull();
    await expect(tenantTrends(customer(tenant.id, tenant.name), other.id, now, 90)).rejects.toBeInstanceOf(AccessDenied);

    const roll = await customerTrends(platform([{ id: tenant.id, name: tenant.name }, { id: other.id, name: other.name }]), now, 90);
    expect(roll.find((row) => row.id === tenant.id)).toMatchObject({ alerts: 4500, seats: 50, offline: 10 });
    expect(roll.find((row) => row.id === tenant.id)?.mttrMinutes).toBeCloseTo(60, 1);
    expect(roll.find((row) => row.id === other.id)).toMatchObject({ alerts: 1, seats: 0, offline: 0 });
    expect(roll.find((row) => row.id === other.id)?.mttrMinutes).toBeNull();
  }, 60_000);

  it("keeps a dashboard reader on its tenant after the session GUCs point elsewhere", async () => {
    const now = new Date();
    const stamp = now.toISOString();
    const tenant = await freshTenant("Reader Clinic");
    const other = await freshTenant("Hidden Clinic");
    await adminDb().execute(sql`
      INSERT INTO alerts (tenant_id, source, external_id, rule_id, title, severity, occurred_at)
      SELECT ${tenant.id}::uuid, 'fixture', 'read-' || g, 'rule-a', 'Reader alert', 'low', ${stamp}::timestamptz - interval '1 day'
      FROM generate_series(0, 1) AS g
    `);
    const [hidden] = await adminDb().insert(alerts).values({
      tenantId: other.id,
      source: "fixture",
      externalId: "hidden-1",
      ruleId: "rule-b",
      title: "Hidden alert",
      severity: "low",
      occurredAt: new Date(now.getTime() - 86_400_000),
    }).returning();

    const password = randomBytes(24).toString("hex");
    const role = await provision(tenant.id, password);
    const [priv] = await adminSql()<{ rolsuper: boolean; rolbypassrls: boolean; rolcanlogin: boolean }[]>`
      select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname = ${role}
    `;
    expect(priv).toMatchObject({ rolsuper: false, rolbypassrls: false, rolcanlogin: true });

    const url = new URL(env().DATABASE_ADMIN_URL);
    url.username = role;
    url.password = password;
    const reader = postgres(url.toString(), { max: 1, prepare: false, onnotice: () => {} });
    try {
      const [own] = await reader<{ n: number }[]>`select count(*)::int as n from alerts`;
      expect(own!.n).toBe(2);
      await reader.unsafe(`select set_config('app.tenant_ids', '${other.id}', false), set_config('app.grant_ids', '${other.id}', false), set_config('app.platform', 'on', false)`);
      const [still] = await reader<{ n: number }[]>`select count(*)::int as n from alerts`;
      expect(still!.n).toBe(2);
      const [hiddenCount] = await reader<{ n: number }[]>`select count(*)::int as n from alerts where id = ${hidden!.id}`;
      expect(hiddenCount!.n).toBe(0);
      await expect(reader`select role_name from dashboard_readers`).rejects.toThrow(/permission denied/i);
    } finally {
      await reader.end();
    }

    const partner = await freshTenant("Trend Partner", "partner");
    const partnerPassword = randomBytes(24).toString("hex");
    await expect(provision(partner.id, partnerPassword)).rejects.toThrow(/customer tenant/);
    const [partnerRole] = await adminSql()<{ n: number }[]>`select count(*)::int as n from pg_roles where rolname = ${readerRole(partner.id)}`;
    expect(partnerRole!.n).toBe(0);
  });
});
