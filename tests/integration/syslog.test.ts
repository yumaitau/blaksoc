import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { POST } from "@/app/api/ingest/syslog/route";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { integrations, syslogArchive, syslogEvents, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { eventProvider } from "@/lib/connectors/instances";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { meterTenant, utcDay } from "@/lib/services/billing";
import { AccessDenied } from "@/lib/services/common";
import { createIntegration } from "@/lib/services/integrations";
import { acceptSyslog, archiveColdForTenant, createSyslogSource } from "@/lib/services/syslog";
import { SYSLOG_LINES } from "../fixtures/syslog";

const created: string[] = [];

function staff(tenantId: string, permissions: Permission[]): AccessContext {
  return {
    principal: { userId: "syslog-staff", name: "Net Admin", email: "net@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "syslog", name: "Creek Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `syslog-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Creek Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

function post(token: string, body: string, ip = "203.0.113.10", proto?: string) {
  const headers: Record<string, string> = { authorization: `Bearer ${token}`, "x-forwarded-for": ip };
  if (proto) headers["x-forwarded-proto"] = proto;
  return POST(new Request("https://soc.example/api/ingest/syslog", { method: "POST", headers, body }));
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("syslog ingest", () => {
  it("routes each token to its own tenant and meters the bytes through the alert pipeline", async () => {
    const a = await freshTenant();
    const b = await freshTenant();
    const manage = ["integration:manage"] as Permission[];
    await expect(createSyslogSource(staff(a.id, ["report:read"]), a.id, { name: "Front firewall" })).rejects.toBeInstanceOf(AccessDenied);

    const platform: AccessContext = {
      principal: { userId: "syslog-platform", name: "Platform", email: "plat@example.invalid", isBreakGlass: false },
      isPlatform: true,
      grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set<Permission>(["integration:manage"]) }],
      tenantIds: [],
      tenants: [],
    };
    await expect(createIntegration(platform, { tenantId: null, provider: "syslog", name: "Shared syslog", config: { region: "ap-southeast-2" }, secrets: {} })).rejects.toThrow(/one tenant/);

    const other = await freshTenant();
    const stamped = await createIntegration(staff(a.id, manage), {
      tenantId: a.id,
      provider: "syslog",
      name: "Firewall syslog",
      config: { region: "ap-southeast-2", tenantId: other.id },
      secrets: {},
    });
    const [saved] = await adminDb().select().from(integrations).where(eq(integrations.id, stamped));
    expect(saved!.config.tenantId).toBe(a.id);

    const sourceA = await createSyslogSource(staff(a.id, manage), a.id, { name: "Front firewall", allowIps: ["203.0.113.10"] });
    const sourceB = await createSyslogSource(staff(b.id, manage), b.id, { name: "Branch firewall" });

    expect((await post(sourceA.token, SYSLOG_LINES.fortinet, "198.51.100.9")).status).toBe(403);
    expect((await post("not-a-token", SYSLOG_LINES.fortinet)).status).toBe(401);
    expect((await post(sourceA.token, SYSLOG_LINES.fortinet, "203.0.113.10", "http")).status).toBe(400);

    const accepted = await post(sourceA.token, `${SYSLOG_LINES.fortinet}\nnot a firewall line`);
    expect(accepted.status).toBe(202);
    expect(await accepted.json()).toEqual({ accepted: 1, rejected: 1 });
    expect((await post(sourceB.token, SYSLOG_LINES.sophos, "198.51.100.50")).status).toBe(202);

    const [intA] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, a.id), eq(integrations.provider, "syslog")));
    const [intB] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, b.id), eq(integrations.provider, "syslog")));
    const alertsA = (await eventProvider(intA!).getAlerts({ limit: 20 })).alerts;
    const alertsB = (await eventProvider(intB!).getAlerts({ limit: 20 })).alerts;
    expect(alertsA.map((row) => row.raw.line)).toEqual([SYSLOG_LINES.fortinet]);
    expect(alertsB.map((row) => row.raw.line)).toEqual([SYSLOG_LINES.sophos]);
    expect(alertsA[0]!.routingKeys).toEqual([`tenant:${a.id}`]);

    const seen = await withScope(systemScope(a.id), (tx) => tx.select().from(syslogEvents));
    expect(seen.every((row) => row.tenantId === a.id)).toBe(true);
    expect(seen.some((row) => row.line === SYSLOG_LINES.sophos)).toBe(false);

    const ingested = await ingestAlert({ tenantId: a.id, integrationId: intA!.id, source: "syslog", alert: alertsA[0]!, intel: null });
    expect(ingested.created).toBe(true);
    const usageA = await meterTenant(adminDb(), a.id, utcDay());
    const usageB = await meterTenant(adminDb(), b.id, utcDay());
    expect(usageA.bytesIngested).toBeGreaterThanOrEqual(Buffer.byteLength(SYSLOG_LINES.fortinet));
    expect(usageB.bytesIngested).toBe(0);
  });

  it("keeps a recent line hot and archives a line older than 30 days in an AU region", async () => {
    const tenant = await freshTenant();
    const source = await createSyslogSource(staff(tenant.id, ["integration:manage"]), tenant.id, { name: "Old firewall" });
    const old = new Date(Date.now() - 31 * 86_400_000);
    await acceptSyslog({ token: source.token, sourceIp: "", body: SYSLOG_LINES.draytek, now: old });
    await expect(archiveColdForTenant(tenant.id, new Date(), "us-east-1")).rejects.toThrow(/Australia/);

    const [integration] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, tenant.id), eq(integrations.provider, "syslog")));
    expect((await eventProvider(integration!).getAlerts({ limit: 10 })).alerts).toHaveLength(1);

    expect(await archiveColdForTenant(tenant.id, new Date(), "ap-southeast-2")).toBe(1);
    await acceptSyslog({ token: source.token, sourceIp: "", body: SYSLOG_LINES.mikrotik });
    const hot = (await eventProvider(integration!).getAlerts({ limit: 10 })).alerts;
    expect(hot.map((row) => row.raw.line)).toEqual([SYSLOG_LINES.mikrotik]);

    const [copy] = await withScope(systemScope(tenant.id), (tx) => tx.select().from(syslogArchive));
    expect(copy).toMatchObject({ region: "ap-southeast-2", body: SYSLOG_LINES.draytek });
    expect(copy!.objectKey).toContain(`syslog/${tenant.id}/`);
  });
});
