import { and, arrayContains, eq, inArray, notInArray, or } from "drizzle-orm";
import { adminDb } from "@/db/client";
import type { Tx } from "@/db/client";
import { alerts, assets, detectionDeployments, dmarcReports, healthBaselines, integrations, monitoredDomains, sigmaRules, sites, tenants, type HealthPolicy } from "@/db/schema";
import { assertCan, systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { coverageDropped, healthOf, isSilent, olderThan, silentHours } from "@/lib/health/rules";
import { withScope } from "@/db/scope";
import { AccessDenied, actor, inTenant } from "./common";
import { NETWORK_SENSOR_TAG } from "./sensor";

const POLL_PROVIDERS = ["m365", "entra", "google-workspace"] as const;
const HOUR_MS = 3_600_000;

export class HealthError extends Error {
  constructor(readonly code: "missing" | "hours") {
    super(code);
  }
}

export type HealthPatch = Partial<{
  silentHours: number | null;
  pollLagMinutes: number | null;
  dmarcStaleHours: number | null;
  sigmaStaleHours: number | null;
}>;

function hours(value: number | null): number | null {
  if (value == null) return null;
  if (!Number.isInteger(value) || value < 1 || value > 8_760) throw new HealthError("hours");
  return value;
}

function mergePolicy(prev: HealthPolicy | undefined, patch: HealthPatch): HealthPolicy {
  const next: HealthPolicy = { ...(prev ?? {}) };
  const keys = ["silentHours", "pollLagMinutes", "dmarcStaleHours", "sigmaStaleHours"] as const;
  for (const key of keys) {
    if (patch[key] === undefined) continue;
    const value = hours(patch[key] ?? null);
    if (value == null) delete next[key];
    else next[key] = value;
  }
  return next;
}

/** Tenant-wide limits. Stored on the tenant settings document. */
export async function setHealthPolicy(ctx: AccessContext, tenantId: string, patch: HealthPatch) {
  if (!ctx.isPlatform) throw new AccessDenied("platform settings:manage required");
  assertCan(ctx, "settings:manage", tenantId);
  return withScope({ tenantIds: [tenantId], platform: true }, async (tx) => {
    const [tenant] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant) throw new HealthError("missing");
    const health = mergePolicy(tenant.settings.health, patch);
    const settings = { ...tenant.settings, health };
    await tx.update(tenants).set({ settings }).where(eq(tenants.id, tenantId));
    await audit(tx, { ...actor(ctx), tenantId, action: "health.policy", targetType: "tenant", targetId: tenantId, detail: { health } });
    return health;
  });
}

/** Per-site silence override. Null clears it and the profile default applies again. */
export async function setSiteSilentHours(ctx: AccessContext, tenantId: string, siteId: string, value: number | null) {
  const silent = hours(value);
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [site] = await tx.select().from(sites).where(and(eq(sites.id, siteId), eq(sites.tenantId, tenantId)));
    if (!site) throw new HealthError("missing");
    await tx.update(sites).set({ silentHours: silent }).where(eq(sites.id, site.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "health.site", targetType: "site", targetId: site.id, detail: { silentHours: silent } });
    return silent;
  });
}

type Wanted = { title: string; assetId?: string };

function stamp(value: Date | string | null | undefined): Date | null {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function raise(tx: Tx, tenantId: string, externalId: string, item: Wanted, now: Date) {
  const [existing] = await tx
    .select({ id: alerts.id, status: alerts.status })
    .from(alerts)
    .where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), eq(alerts.externalId, externalId)));
  if (!existing) {
    await tx.insert(alerts).values({
      tenantId,
      source: "health",
      externalId,
      title: item.title,
      severity: "medium",
      occurredAt: now,
      status: "NEW",
      category: "health",
      assetId: item.assetId ?? null,
    });
    return;
  }
  if (existing.status !== "RESOLVED") return;
  await tx.update(alerts).set({ status: "NEW", title: item.title, occurredAt: now, updatedAt: now, assetId: item.assetId ?? null }).where(eq(alerts.id, existing.id));
}

async function recover(tx: Tx, tenantId: string, externalId: string, now: Date) {
  await tx
    .update(alerts)
    .set({ status: "RESOLVED", updatedAt: now })
    .where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), eq(alerts.externalId, externalId), notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"])));
}

async function evaluate(tx: Tx, tenantId: string, now: Date) {
  const [tenant] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
  if (!tenant) return;
  const policy = healthOf(tenant.settings);
  const wanted = new Map<string, Wanted>();

  const siteRows = await tx.select().from(sites).where(eq(sites.tenantId, tenantId));
  const siteById = new Map(siteRows.map((site) => [site.id, site]));
  // Enrolled network sensors share the agent silence limit. Other network devices stay out.
  const sensors = await tx
    .select({
      id: assets.id,
      name: assets.name,
      hostname: assets.hostname,
      siteId: assets.siteId,
      agentStatus: assets.agentStatus,
      lastSeen: assets.lastSeen,
      kind: assets.kind,
    })
    .from(assets)
    .where(
      and(
        eq(assets.tenantId, tenantId),
        or(
          inArray(assets.kind, ["endpoint", "server"]),
          and(eq(assets.kind, "network_device"), arrayContains(assets.tags, [NETWORK_SENSOR_TAG])),
        ),
      ),
    );
  for (const asset of sensors) {
    const externalId = `health:silent:${asset.id}`;
    const site = asset.siteId ? siteById.get(asset.siteId) : undefined;
    const limit = silentHours({ profile: site?.bandwidthProfile ?? "standard", siteHours: site?.silentHours ?? null, tenantHours: policy.silentHours });
    if (asset.agentStatus != null && isSilent(stamp(asset.lastSeen) ?? now, limit, now)) {
      const label = asset.kind === "network_device" ? "Sensor silent" : "Agent silent";
      wanted.set(externalId, { title: `${label}: ${asset.hostname || asset.name}`, assetId: asset.id });
    }
  }

  const polls = await tx
    .select({ id: integrations.id, provider: integrations.provider, name: integrations.name, lastSuccessAt: integrations.lastSuccessAt })
    .from(integrations)
    .where(and(eq(integrations.tenantId, tenantId), eq(integrations.enabled, true), inArray(integrations.provider, [...POLL_PROVIDERS])));
  for (const row of polls) {
    if (olderThan(stamp(row.lastSuccessAt), policy.pollLagMinutes * 60_000, now)) {
      wanted.set(`health:poll:${row.id}`, { title: `Polling lag: ${row.name}` });
    }
  }

  const domains = await tx.select({ id: monitoredDomains.id, name: monitoredDomains.name }).from(monitoredDomains).where(eq(monitoredDomains.tenantId, tenantId));
  const reports = await tx.select({ domainName: dmarcReports.domainName, ingestedAt: dmarcReports.ingestedAt }).from(dmarcReports).where(eq(dmarcReports.tenantId, tenantId));
  const freshest = new Map<string, Date>();
  for (const report of reports) {
    const seen = stamp(report.ingestedAt);
    if (!seen) continue;
    const key = report.domainName.toLowerCase();
    const prev = freshest.get(key);
    if (!prev || seen > prev) freshest.set(key, seen);
  }
  for (const domain of domains) {
    const seen = freshest.get(domain.name.toLowerCase()) ?? null;
    if (olderThan(seen, policy.dmarcStaleHours * HOUR_MS, now)) {
      wanted.set(`health:dmarc:${domain.id}`, { title: `DMARC ingest stale: ${domain.name}` });
    }
  }

  const deployed = await tx
    .select({
      id: detectionDeployments.id,
      status: detectionDeployments.status,
      lastRunAt: detectionDeployments.lastRunAt,
      title: sigmaRules.title,
      techniques: sigmaRules.attackTechniques,
      enabled: sigmaRules.enabled,
    })
    .from(detectionDeployments)
    .innerJoin(sigmaRules, eq(sigmaRules.id, detectionDeployments.ruleId))
    .where(eq(detectionDeployments.tenantId, tenantId));
  const coveredTechniques = new Set<string>();
  let enabledRules = 0;
  for (const row of deployed) {
    if (row.status === "active" && olderThan(stamp(row.lastRunAt), policy.sigmaStaleHours * HOUR_MS, now)) {
      wanted.set(`health:sigma:${row.id}`, { title: `Detection has not run: ${row.title}` });
    }
    if (row.status === "active" && row.enabled) {
      enabledRules += 1;
      for (const technique of row.techniques) if (technique) coveredTechniques.add(technique);
    }
  }

  const [baseline] = await tx.select().from(healthBaselines).where(eq(healthBaselines.tenantId, tenantId));
  const techniques = coveredTechniques.size;
  const dropped = baseline != null && (coverageDropped(baseline.techniqueCount, techniques) || coverageDropped(baseline.ruleCount, enabledRules));
  if (dropped) {
    wanted.set(`health:coverage:${tenantId}`, { title: "Detection coverage fell" });
  } else {
    await tx
      .insert(healthBaselines)
      .values({ tenantId, techniqueCount: techniques, ruleCount: enabledRules, updatedAt: now })
      .onConflictDoUpdate({ target: healthBaselines.tenantId, set: { techniqueCount: techniques, ruleCount: enabledRules, updatedAt: now } });
  }

  const open = await tx
    .select({ externalId: alerts.externalId })
    .from(alerts)
    .where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"])));
  for (const row of open) {
    if (!wanted.has(row.externalId)) await recover(tx, tenantId, row.externalId, now);
  }
  for (const [externalId, item] of wanted) await raise(tx, tenantId, externalId, item, now);
}

/** One customer. Tests call this directly so a sweep cannot touch other tenants. */
export async function runHealthForTenant(tenantId: string, now = new Date()) {
  await withScope(systemScope(tenantId), (tx) => evaluate(tx, tenantId, now));
}

/** Worker hook. Runs after connector probes. */
export async function runDueHealth(now = new Date()) {
  const rows = await adminDb().select({ id: tenants.id }).from(tenants).where(eq(tenants.kind, "customer"));
  for (const row of rows) await runHealthForTenant(row.id, now);
}
