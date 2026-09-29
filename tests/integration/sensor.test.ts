/**
 * Network sensor image plus enrolment. The build script is executed.
 * Health goes through runHealthForTenant. Alerts go through acceptSyslog.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assets, sites, syslogEvents, syslogSources, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { runHealthForTenant } from "@/lib/services/health";
import { AccessDenied } from "@/lib/services/common";
import { enrolNetworkSensor, recordSensorSeen, SensorError, setSensorRuleset } from "@/lib/services/sensor";
import { acceptSyslog } from "@/lib/services/syslog";
import { SYSLOG_LINES } from "../fixtures/syslog";

const root = fileURLToPath(new URL("../..", import.meta.url));
const created: string[] = [];
const now = new Date("2026-07-01T00:00:00.000Z");
const ago = (hours: number) => new Date(now.getTime() - hours * 3_600_000);

function staff(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "sensor-staff", name: "Sensor Staff", email: "sensor@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set(["integration:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "Sensor Clinic", kind: "customer" }],
  };
}

function customer(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "sensor-customer", name: "Clinic Admin", email: "clinic-sensor@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(["asset:read"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "Sensor Clinic", kind: "customer" }],
  };
}

async function freshTenant(kind: "customer" | "partner" = "customer") {
  const slug = `sensor-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Sensor Clinic", kind }).returning();
  created.push(row!.id);
  return row!;
}

function build(args: string[]) {
  const out = mkdtempSync(join(tmpdir(), "blaksoc-sensor-"));
  try {
    execFileSync("sh", [join(root, "deploy/sensor/build.sh"), "--out", out, ...args], { cwd: root, stdio: "pipe" });
    return {
      out,
      yaml: readFileSync(join(out, "suricata.yaml"), "utf8"),
      rules: readFileSync(join(out, "update-rules.sh"), "utf8"),
    };
  } catch (error) {
    rmSync(out, { recursive: true, force: true });
    throw error;
  }
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("network sensor image", () => {
  it("builds Suricata with ET Open and no payload capture", () => {
    const privacy = readFileSync(join(root, "deploy/sensor/PRIVACY.md"), "utf8").toLowerCase();
    const bom = readFileSync(join(root, "deploy/sensor/BOM.md"), "utf8");
    expect(privacy).toContain("no payload capture by default");
    expect(privacy).toContain("alerts only");
    expect(bom.toLowerCase()).toContain("x86");
    expect(bom.toLowerCase()).toContain("arm");
    expect(bom.toLowerCase()).toContain("span");
    expect(bom.toLowerCase()).toContain("tap");
    expect(bom).not.toMatch(/\$\s?\d/);

    const standard = build(["--capture", "span"]);
    const low = build(["--bandwidth", "low"]);
    const tap = build(["--capture", "tap", "--zeek"]);
    try {
      for (const yaml of [standard.yaml, low.yaml, tap.yaml]) {
        expect(yaml).toContain("payload: no");
        expect(yaml).toContain("payload-printable: no");
        expect(yaml).toContain("http-body: no");
        expect(yaml).toContain("http-body-printable: no");
        expect(yaml).toContain("et-open.rules");
        expect(yaml).not.toContain("payload: yes");
        expect(yaml).not.toContain("pcap-log");
        expect(yaml).not.toContain("file-store");
      }
      expect(standard.yaml).toContain("interface: span0");
      expect(standard.yaml.toLowerCase()).toContain("mirror");
      expect(standard.yaml).toMatch(/^\s+- flow$/m);
      expect(standard.yaml).toMatch(/^\s+- dns$/m);
      expect(standard.yaml).toMatch(/^\s+- tls$/m);
      expect(standard.yaml).toContain("forwarding: alerts-and-metadata");
      expect(low.yaml).toContain("forwarding: alerts");
      expect(low.yaml).not.toMatch(/^\s+- flow$/m);
      expect(low.yaml).not.toMatch(/^\s+- dns$/m);
      expect(low.yaml).not.toMatch(/^\s+- tls$/m);
      expect(tap.yaml).toContain("interface: tap0");
      expect(tap.yaml.toLowerCase()).toContain("inline tap");
      expect(existsSync(join(standard.out, "zeek", "local.zeek"))).toBe(false);
      expect(readFileSync(join(tap.out, "zeek", "local.zeek"), "utf8").toLowerCase()).toContain("payloads are not logged");
      expect(standard.rules).toContain("suricata-update");
      expect(standard.rules).not.toContain("payload: yes");
      const bad = mkdtempSync(join(tmpdir(), "blaksoc-sensor-bad-"));
      expect(() => execFileSync("sh", [join(root, "deploy/sensor/build.sh"), "--out", bad, "--bandwidth", "satellite"], { cwd: root, stdio: "pipe" })).toThrow();
      rmSync(bad, { recursive: true, force: true });
    } finally {
      rmSync(standard.out, { recursive: true, force: true });
      rmSync(low.out, { recursive: true, force: true });
      rmSync(tap.out, { recursive: true, force: true });
    }
  });
});

describe("network sensor health", () => {
  it("enrols a sensor, forwards through syslog, and applies the silence limits", async () => {
    const tenant = await freshTenant();
    const ctx = staff(tenant.id, tenant.slug);
    const [low] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Camp", bandwidthProfile: "low" }).returning();
    const [town] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Town", bandwidthProfile: "standard" }).returning();
    const townSensor = await enrolNetworkSensor(ctx, tenant.id, { siteId: town!.id, name: "Town tap", hostname: "town-tap", lastSeen: ago(30) });
    const edge = await enrolNetworkSensor(ctx, tenant.id, { siteId: town!.id, name: "Edge", hostname: "edge-tap", lastSeen: ago(24) });
    const fresh = await enrolNetworkSensor(ctx, tenant.id, { siteId: low!.id, name: "Camp fresh", hostname: "camp-fresh", lastSeen: ago(1) });
    const mid = await enrolNetworkSensor(ctx, tenant.id, { siteId: low!.id, name: "Camp mid", hostname: "camp-mid", lastSeen: ago(48) });
    const old = await enrolNetworkSensor(ctx, tenant.id, { siteId: low!.id, name: "Camp old", hostname: "camp-old", lastSeen: ago(80), capture: "tap" });

    expect(townSensor.forwarding).toBe("alerts-and-metadata");
    expect(mid.forwarding).toBe("alerts");
    expect(townSensor.token).not.toBe(mid.token);
    const [townAsset] = await adminDb().select().from(assets).where(eq(assets.id, townSensor.assetId));
    expect(townAsset?.kind).toBe("network_device");
    expect(townAsset?.tags).toEqual(["network-sensor"]);
    expect(townAsset?.agentStatus).toBe("active");
    expect(JSON.stringify(townAsset?.attributes)).not.toContain(townSensor.token);
    expect(townAsset?.attributes.sensor).toMatchObject({ forwarding: "alerts-and-metadata", payloadCapture: false, syslogSourceId: townSensor.syslogSourceId });

    const [printer] = await adminDb().insert(assets).values({
      tenantId: tenant.id, siteId: low!.id, kind: "network_device", name: "Printer", hostname: "printer", agentStatus: "active", lastSeen: ago(80),
    }).returning();
    const [spare] = await adminDb().insert(assets).values({
      tenantId: tenant.id, siteId: town!.id, kind: "network_device", name: "Spare tap", hostname: "spare-tap", tags: ["network-sensor"], lastSeen: ago(80),
    }).returning();

    await runHealthForTenant(tenant.id, now);
    await runHealthForTenant(tenant.id, now);
    let rows = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.source, "health")));
    const silent = rows.filter((row) => row.externalId.startsWith("health:silent:"));
    expect(silent.map((row) => row.assetId).sort()).toEqual([townSensor.assetId, old.assetId].sort());
    expect(silent.find((row) => row.assetId === townSensor.assetId)?.title).toBe("Sensor silent: town-tap");
    expect(silent.every((row) => row.status === "NEW")).toBe(true);
    expect(silent.map((row) => row.assetId)).not.toContain(edge.assetId);
    expect(silent.map((row) => row.assetId)).not.toContain(fresh.assetId);
    expect(silent.map((row) => row.assetId)).not.toContain(mid.assetId);
    expect(silent.map((row) => row.assetId)).not.toContain(printer!.id);
    expect(silent.map((row) => row.assetId)).not.toContain(spare!.id);

    await recordSensorSeen(ctx, tenant.id, old.assetId, now);
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${old.assetId}`));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("RESOLVED");

    await recordSensorSeen(ctx, tenant.id, old.assetId, ago(80));
    await runHealthForTenant(tenant.id, now);
    rows = await adminDb().select().from(alerts).where(eq(alerts.externalId, `health:silent:${old.assetId}`));
    expect(rows[0]?.status).toBe("NEW");

    expect(await setSensorRuleset(ctx, tenant.id, townSensor.assetId, "et-open-2026")).toBe("et-open-2026");
    const [ruled] = await adminDb().select({ attributes: assets.attributes }).from(assets).where(eq(assets.id, townSensor.assetId));
    expect(ruled?.attributes.sensor).toMatchObject({ ruleset: "et-open-2026", payloadCapture: false, forwarding: "alerts-and-metadata" });

    const ingested = await acceptSyslog({ token: townSensor.token, sourceIp: "203.0.113.10", body: SYSLOG_LINES.fortinet, now });
    expect(ingested).toEqual({ accepted: 1, rejected: 0 });
    const events = await adminDb().select({ id: syslogEvents.id }).from(syslogEvents).where(eq(syslogEvents.tenantId, tenant.id));
    expect(events).toHaveLength(1);
    const sources = await adminDb().select({ id: syslogSources.id }).from(syslogSources).where(eq(syslogSources.tenantId, tenant.id));
    expect(sources).toHaveLength(5);

    const other = await freshTenant();
    await runHealthForTenant(other.id, now);
    expect(await adminDb().select().from(alerts).where(eq(alerts.tenantId, other.id))).toHaveLength(0);
    await expect(enrolNetworkSensor(staff(other.id, other.slug), tenant.id, { siteId: town!.id, name: "Cross" })).rejects.toBeInstanceOf(AccessDenied);
    await expect(enrolNetworkSensor(customer(tenant.id, tenant.slug), tenant.id, { siteId: town!.id, name: "Denied" })).rejects.toBeInstanceOf(AccessDenied);

    const partner = await freshTenant("partner");
    const [hq] = await adminDb().insert(sites).values({ tenantId: partner.id, name: "HQ" }).returning();
    await expect(enrolNetworkSensor(staff(partner.id, partner.slug), partner.id, { siteId: hq!.id, name: "Nope" })).rejects.toMatchObject({ code: "kind" });
    await expect(enrolNetworkSensor(ctx, tenant.id, { siteId: randomUUID(), name: "Missing" })).rejects.toBeInstanceOf(SensorError);
  });
});
