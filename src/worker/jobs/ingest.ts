import { and, eq, inArray } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { assetSources, assets, detectionDeployments, integrations, integrationTenantLinks, sigmaRules, vulnerabilities } from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { collectingTenantIds, collectionAllowed, type Tier } from "@/lib/billing/catalogue";
import { eventProvider, intelProviderFor, type IntegrationRow } from "@/lib/connectors/instances";
import { connectorDef } from "@/lib/connectors/registry";
import { plansByTenant } from "@/lib/services/billing";
import { DemoProvider } from "@/lib/providers/demo";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { syncAssets } from "@/lib/pipeline/assets";
import { queue, QUEUES } from "@/lib/queue";
import { redis } from "@/lib/redis";
import { evaluateTriggers } from "@/lib/soar/engine";
import { wazuhLevelToSeverity } from "@/lib/providers/wazuh";
import { logger } from "@/lib/obs/log";
import { ingestAlerts, ingestLag, integrationPolls } from "@/lib/obs/metrics";

type Log = (m: string) => void;

async function eventIntegrations(): Promise<IntegrationRow[]> {
  const rows = await systemDb().select().from(integrations).where(and(eq(integrations.enabled, true), inArray(integrations.category, ["siem", "endpoint", "identity"])));
  return rows.filter((r) => connectorDef(r.provider)?.capabilities.includes("events"));
}

/** Which tenants a SIEM integration serves: its owner, or its tenant links for shared clusters. */
async function tenantLinks(row: IntegrationRow) {
  if (row.tenantId) return [{ tenantId: row.tenantId, selector: {} as { agentGroups?: string[] } }];
  return systemDb().select({ tenantId: integrationTenantLinks.tenantId, selector: integrationTenantLinks.selector }).from(integrationTenantLinks).where(eq(integrationTenantLinks.integrationId, row.id));
}

async function tierOfTenant(): Promise<(id: string) => Tier> {
  const plans = await plansByTenant();
  return (id) => plans.get(id) ?? "essentials";
}

function allowedLinks<T extends { tenantId: string }>(links: T[], tierOf: (id: string) => Tier, provider: string): T[] {
  const live = new Set(collectingTenantIds(provider, links, tierOf));
  return links.filter((l) => live.has(l.tenantId));
}

type PollKind = "alerts" | "assets" | "health";

async function markHealth(row: IntegrationRow, kind: PollKind, ok: boolean, error?: string) {
  const now = new Date();
  integrationPolls().inc({ integration: row.id, provider: row.provider, kind, outcome: ok ? "ok" : "error" });
  if (!ok) logger.warn("integration poll failed", { integrationId: row.id, provider: row.provider, kind, error });
  await systemDb()
    .update(integrations)
    .set(ok ? { status: "healthy", lastSuccessAt: now } : { status: "error", lastError: error ?? "unknown", lastErrorAt: now })
    .where(eq(integrations.id, row.id));
}

/** Inventory sync: provider agents → unified assets, routed to tenants by agent group. */
export async function syncAllAssets(log: Log) {
  const tierOf = await tierOfTenant();
  for (const row of await eventIntegrations()) {
    const links = allowedLinks(await tenantLinks(row), tierOf, row.provider);
    if (!links.length) continue;
    try {
      const provider = eventProvider(row);
      for (const link of links) {
        const keys = (link.selector.agentGroups ?? []).map((g) => `group:${g}`);
        const list = await provider.getAssets(keys.length ? keys : undefined);
        const mine = keys.length ? list.filter((a) => a.routingKeys.some((k) => keys.includes(k))) : list;
        await withScope(systemScope(link.tenantId), (tx) => syncAssets(tx, link.tenantId, row.id, mine, row.provider === "demo" ? "wazuh" : row.provider));
        log(`assets ${row.name} → tenant ${link.tenantId.slice(0, 8)}: ${mine.length}`);
      }
      await markHealth(row, "assets", true);
    } catch (e) {
      await markHealth(row, "assets", false, (e as Error).message);
    }
  }
}

/** Vulnerability states from providers that support them. */
export async function syncAllVulnerabilities(log: Log) {
  const tierOf = await tierOfTenant();
  for (const row of await eventIntegrations()) {
    const provider = eventProvider(row);
    if (!provider.getVulnerabilities) continue;
    try {
      const sources = await systemDb().select().from(assetSources).where(eq(assetSources.integrationId, row.id));
      const byExt = new Map(sources.map((s) => [s.externalId, s]));
      const vulns = await provider.getVulnerabilities();
      const byTenant = new Map<string, typeof vulns>();
      for (const v of vulns) {
        const s = byExt.get(v.assetExternalId);
        if (!s) continue;
        byTenant.set(s.tenantId, [...(byTenant.get(s.tenantId) ?? []), v]);
      }
      for (const [tenantId, list] of byTenant) {
        if (!collectionAllowed(tierOf(tenantId), row.provider)) continue;
        await withScope(systemScope(tenantId), async (tx) => {
          for (const v of list) {
            const assetId = byExt.get(v.assetExternalId)!.assetId;
            await tx
              .insert(vulnerabilities)
              .values({ tenantId, assetId, cve: v.cve, title: v.title, packageName: v.packageName ?? "", packageVersion: v.packageVersion, fixedVersion: v.fixedVersion, cvss: v.cvss, source: row.provider })
              .onConflictDoUpdate({ target: [vulnerabilities.tenantId, vulnerabilities.assetId, vulnerabilities.cve, vulnerabilities.packageName], set: { lastSeen: new Date(), cvss: v.cvss, packageVersion: v.packageVersion } });
          }
        });
        await queue(QUEUES.intel).add("rescore", { tenantId });
      }
      log(`vulns ${row.name}: ${vulns.length}`);
    } catch (e) {
      logger.warn("vulnerability sync failed", { integrationId: row.id, provider: row.provider, err: e });
    }
  }
}

/**
 * Poll each SIEM for new alerts since its cursor, route each alert to its tenant by
 * agent, and run it through enrichment → risk → queue → playbook triggers.
 */
export async function pollAlerts(log: Log) {
  const tierOf = await tierOfTenant();
  for (const row of await eventIntegrations()) {
    try {
      const provider = eventProvider(row);
      const links = await tenantLinks(row);
      const live = new Set(collectingTenantIds(row.provider, links, tierOf));
      // Leave the cursor where it is when nobody on this integration may collect.
      if (!live.size) continue;
      // Route by the provider's asset id; built from asset inventory (system-level map).
      const sources = await systemDb().select({ externalId: assetSources.externalId, tenantId: assetSources.tenantId }).from(assetSources).where(eq(assetSources.integrationId, row.id));
      const agentTenant = new Map(sources.map((s) => [s.externalId, s.tenantId]));
      const fallbackTenant = row.tenantId ?? (links.length === 1 ? links[0]!.tenantId : null);

      let alerts;
      let cursorKey: string | null = null;
      let nextCursor: string | null = null;
      if (provider instanceof DemoProvider) {
        // Demo: a trickle of synthetic alerts so the live queue moves.
        alerts = Math.random() < 0.5 ? provider.generate(1) : [];
      } else {
        cursorKey = `cursor:alerts:${row.id}`;
        const cursor = await redis().get(cursorKey);
        const res = await provider.getAlerts({ since: new Date(Date.now() - 24 * 3600_000), afterCursor: cursor ?? undefined, limit: 500 });
        alerts = res.alerts;
        nextCursor = res.cursor;
      }

      const intelCache = new Map<string, Awaited<ReturnType<typeof intelProviderFor>>>();
      let n = 0;
      const labels = { integration: row.id, provider: row.provider };
      for (const a of alerts) {
        const tenantId = (a.assetExternalId && agentTenant.get(a.assetExternalId)) || fallbackTenant;
        if (!tenantId || !live.has(tenantId)) {
          ingestAlerts().inc({ ...labels, outcome: "unrouted" });
          continue;
        }
        if (!intelCache.has(tenantId)) intelCache.set(tenantId, await intelProviderFor(systemDb(), tenantId));
        const res = await ingestAlert({ tenantId, integrationId: row.id, source: row.provider === "demo" ? "wazuh" : row.provider, alert: a, intel: intelCache.get(tenantId)?.provider ?? null });
        ingestAlerts().inc({ ...labels, outcome: res.created ? "created" : "duplicate" });
        if (res.created) {
          n++;
          const occurred = a.occurredAt instanceof Date ? a.occurredAt.getTime() : NaN;
          if (Number.isFinite(occurred)) ingestLag().observe(labels, Math.max(0, Date.now() - occurred) / 1000);
          await evaluateTriggers(tenantId, "alert.created", { alertId: res.alertId });
        }
      }
      if (n) log(`alerts ${row.name}: +${n}`);
      if (cursorKey && nextCursor) await redis().set(cursorKey, nextCursor);
      await markHealth(row, "alerts", true);
    } catch (e) {
      await markHealth(row, "alerts", false, (e as Error).message);
    }
  }
}

/** Scheduled Sigma deployments: run each active query against its tenant's SIEM. */
export async function runDetections() {
  const tierOf = await tierOfTenant();
  const deps = await systemDb()
    .select({ d: detectionDeployments, rule: sigmaRules })
    .from(detectionDeployments)
    .innerJoin(sigmaRules, eq(sigmaRules.id, detectionDeployments.ruleId))
    .where(and(eq(detectionDeployments.status, "active"), eq(sigmaRules.enabled, true)));
  for (const { d, rule } of deps) {
    if (!d.integrationId) continue;
    const [row] = await systemDb().select().from(integrations).where(eq(integrations.id, d.integrationId));
    if (!row || row.provider === "demo") continue;
    if (!collectionAllowed(tierOf(d.tenantId), row.provider)) continue;
    try {
      const provider = eventProvider(row);
      // The provider runs this rule itself (e.g. Tawny); its hits arrive through the alert poll.
      if (provider.deployDetection) continue;
      const agents = await systemDb().select({ externalId: assetSources.externalId }).from(assetSources).where(and(eq(assetSources.integrationId, row.id), eq(assetSources.tenantId, d.tenantId)));
      const since = d.lastRunAt ?? new Date(Date.now() - 15 * 60_000);
      const res = await provider.searchEvents({ query: d.query, since, routingKeys: agents.map((a) => `agent:${a.externalId}`), limit: 100 });
      const intel = await intelProviderFor(systemDb(), d.tenantId);
      for (const ev of res.events) {
        const e = ev as { _id: string; timestamp?: string; agent?: { id?: string; name?: string } };
        const level = { informational: 3, low: 5, medium: 8, high: 11, critical: 14 }[rule.severity];
        const r = await ingestAlert({
          tenantId: d.tenantId,
          integrationId: row.id,
          source: "blaksoc-sigma",
          intel: intel?.provider ?? null,
          alert: {
            externalId: `${rule.id}:${e._id}`, ruleId: rule.sigmaId, title: rule.title, description: rule.description, category: "sigma", siemSeverity: level,
            severity: wazuhLevelToSeverity(level), occurredAt: e.timestamp ? new Date(e.timestamp) : new Date(), assetExternalId: e.agent?.id ?? null, hostname: e.agent?.name ?? null,
            userName: null, attackTechniques: rule.attackTechniques, routingKeys: [], raw: ev,
          },
        });
        if (r.created) await evaluateTriggers(d.tenantId, "alert.created", { alertId: r.alertId });
      }
      await systemDb().update(detectionDeployments).set({ lastRunAt: new Date(), lastHitCount: res.total }).where(eq(detectionDeployments.id, d.id));
    } catch (e) {
      logger.warn("detection run failed", { tenantId: d.tenantId, deploymentId: d.id, ruleId: rule.id, err: e });
    }
  }
}

/** Health probe for every enabled integration (not just SIEMs). */
export async function probeHealth() {
  const rows = await systemDb().select().from(integrations).where(eq(integrations.enabled, true));
  const { instantiate } = await import("@/lib/connectors/instances");
  for (const row of rows) {
    try {
      const inst = instantiate(row);
      if (inst.kind === "notify") continue;
      const h = await inst.provider.health();
      integrationPolls().inc({ integration: row.id, provider: row.provider, kind: "health", outcome: h.ok ? "ok" : "error" });
      if (!h.ok) logger.warn("integration health check failed", { integrationId: row.id, provider: row.provider, error: h.error });
      await systemDb()
        .update(integrations)
        .set({ health: h as never, status: h.ok ? "healthy" : "error", ...(h.ok ? { lastSuccessAt: new Date() } : { lastError: h.error ?? "health check failed", lastErrorAt: new Date() }) })
        .where(eq(integrations.id, row.id));
    } catch (e) {
      await markHealth(row, "health", false, (e as Error).message);
    }
  }
}

export async function tenantsWithAssets() {
  return (await systemDb().selectDistinct({ id: assets.tenantId }).from(assets)).map((r) => r.id);
}
