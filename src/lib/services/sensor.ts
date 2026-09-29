import { and, eq } from "drizzle-orm";
import { assets, sites, tenants } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { actor, inTenant } from "./common";
import { createSyslogSource } from "./syslog";

/** Asset tag for an enrolled Suricata/Zeek sensor. Other network devices are not sensors. */
export const NETWORK_SENSOR_TAG = "network-sensor";

export class SensorError extends Error {
  constructor(readonly code: "missing" | "name" | "kind" | "capture") {
    super(code);
    this.name = "SensorError";
  }
}

export type SensorCapture = "span" | "tap";
export type SensorForwarding = "alerts" | "alerts-and-metadata";

/** Low-bandwidth sites (satellite or congested) forward alerts only. */
export function forwardingFor(profile: string): SensorForwarding {
  return profile === "low" ? "alerts" : "alerts-and-metadata";
}

function sensorRecord(attributes: Record<string, unknown>): Record<string, unknown> {
  const sensor = attributes.sensor;
  if (!sensor || typeof sensor !== "object" || Array.isArray(sensor)) return {};
  return { ...(sensor as Record<string, unknown>) };
}

/**
 * Enrol one sensor on a customer site and open a syslog source for its alerts.
 * Payload capture is stored off. The token is returned once and is not written on the asset.
 */
export async function enrolNetworkSensor(
  ctx: AccessContext,
  tenantId: string,
  input: { siteId: string; name: string; hostname?: string; lastSeen?: Date; capture?: SensorCapture },
): Promise<{ assetId: string; syslogSourceId: string; token: string; forwarding: SensorForwarding }> {
  const name = input.name.trim();
  if (name.length < 1 || name.length > 80) throw new SensorError("name");
  const hostname = (input.hostname ?? name).trim() || name;
  const capture = input.capture ?? "span";
  if (capture !== "span" && capture !== "tap") throw new SensorError("capture");
  const lastSeen = input.lastSeen ?? new Date();
  if (Number.isNaN(lastSeen.getTime())) throw new SensorError("name");

  const site = await inTenant(ctx, "integration:manage", tenantId, async (tx) => {
    const [tenant] = await tx.select({ kind: tenants.kind }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant || tenant.kind !== "customer") throw new SensorError("kind");
    const [row] = await tx.select({ id: sites.id, bandwidthProfile: sites.bandwidthProfile }).from(sites).where(and(eq(sites.id, input.siteId), eq(sites.tenantId, tenantId)));
    if (!row) throw new SensorError("missing");
    return row;
  });

  const forwarding = forwardingFor(site.bandwidthProfile);
  const source = await createSyslogSource(ctx, tenantId, { name: `sensor:${name}`.slice(0, 80) });
  const assetId = await inTenant(ctx, "integration:manage", tenantId, async (tx) => {
    const [asset] = await tx
      .insert(assets)
      .values({
        tenantId,
        siteId: site.id,
        kind: "network_device",
        name,
        hostname,
        agentStatus: "active",
        lastSeen,
        tags: [NETWORK_SENSOR_TAG],
        attributes: { sensor: { forwarding, payloadCapture: false, capture, syslogSourceId: source.id } },
      })
      .returning({ id: assets.id });
    if (!asset) throw new SensorError("missing");
    await audit(tx, {
      ...actor(ctx),
      tenantId,
      action: "sensor.enrol",
      targetType: "asset",
      targetId: asset.id,
      detail: { name, siteId: site.id, forwarding, capture, syslogSourceId: source.id },
    });
    return asset.id;
  });
  return { assetId, syslogSourceId: source.id, token: source.token, forwarding };
}

/** Record a ruleset version. Does not download rules and does not enable payload capture. */
export async function setSensorRuleset(ctx: AccessContext, tenantId: string, assetId: string, version: string): Promise<string> {
  const ruleset = version.trim();
  if (ruleset.length < 1 || ruleset.length > 64) throw new SensorError("name");
  return inTenant(ctx, "integration:manage", tenantId, async (tx) => {
    const [asset] = await tx.select().from(assets).where(and(eq(assets.id, assetId), eq(assets.tenantId, tenantId)));
    if (!asset || !asset.tags.includes(NETWORK_SENSOR_TAG)) throw new SensorError("missing");
    const sensor = { ...sensorRecord(asset.attributes), ruleset, payloadCapture: false };
    await tx.update(assets).set({ attributes: { ...asset.attributes, sensor } }).where(eq(assets.id, asset.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "sensor.ruleset", targetType: "asset", targetId: asset.id, detail: { ruleset } });
    return ruleset;
  });
}

/** Check-in. runHealthForTenant treats a late check-in as silence using the site bandwidth limit. */
export async function recordSensorSeen(ctx: AccessContext, tenantId: string, assetId: string, seenAt = new Date()): Promise<Date> {
  if (Number.isNaN(seenAt.getTime())) throw new SensorError("name");
  return inTenant(ctx, "integration:manage", tenantId, async (tx) => {
    const [asset] = await tx.select({ id: assets.id, tags: assets.tags }).from(assets).where(and(eq(assets.id, assetId), eq(assets.tenantId, tenantId)));
    if (!asset || !asset.tags.includes(NETWORK_SENSOR_TAG)) throw new SensorError("missing");
    await tx.update(assets).set({ lastSeen: seenAt, agentStatus: "active" }).where(eq(assets.id, asset.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "sensor.seen", targetType: "asset", targetId: asset.id, detail: { seenAt: seenAt.toISOString() } });
    return seenAt;
  });
}
