import { and, asc, eq, gt, inArray } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { alertObservables, alerts, assetSources, assets, integrations, intelMatches, observables } from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { recordAlertGraph, recordAssetGraph } from "./store";

/**
 * Rebuilds one tenant's graph from stored assets and alerts. Safe to re-run: entity and edge
 * upserts are idempotent and edge counts only move on new evidence. Assets go first so alert
 * user names can be matched to identities. Each batch is its own transaction.
 */
export async function backfillGraph(tenantId: string, opts: { batchSize?: number } = {}): Promise<{ assets: number; alerts: number }> {
  const batchSize = opts.batchSize ?? 200;
  // Shared integrations are platform rows the tenant scope cannot read; their provider names are not tenant data.
  const providers = new Map((await systemDb().select({ id: integrations.id, provider: integrations.provider }).from(integrations)).map((r) => [r.id, r.provider]));
  const scope = systemScope(tenantId);
  let assetCount = 0;
  let alertCount = 0;

  for (let after: string | null = null; ;) {
    const done: boolean = await withScope(scope, async (tx) => {
      const rows = await tx.select().from(assets).where(and(eq(assets.tenantId, tenantId), after ? gt(assets.id, after) : undefined)).orderBy(asc(assets.id)).limit(batchSize);
      if (!rows.length) return true;
      const sources = await tx.select({ assetId: assetSources.assetId, integrationId: assetSources.integrationId }).from(assetSources).where(inArray(assetSources.assetId, rows.map((r) => r.id)));
      for (const a of rows) {
        const names = [...new Set(sources.filter((s) => s.assetId === a.id).map((s) => providers.get(s.integrationId) ?? "inventory"))];
        await recordAssetGraph(tx, tenantId, a, names.length ? names : ["inventory"]);
      }
      assetCount += rows.length;
      after = rows.at(-1)!.id;
      return rows.length < batchSize;
    });
    if (done) break;
  }

  for (let after: string | null = null; ;) {
    const done: boolean = await withScope(scope, async (tx) => {
      const rows = await tx
        .select({ alert: alerts, asset: { id: assets.id, kind: assets.kind, name: assets.name, hostname: assets.hostname } })
        .from(alerts)
        .leftJoin(assets, eq(assets.id, alerts.assetId))
        .where(and(eq(alerts.tenantId, tenantId), after ? gt(alerts.id, after) : undefined))
        .orderBy(asc(alerts.id))
        .limit(batchSize);
      if (!rows.length) return true;
      const ids = rows.map((r) => r.alert.id);
      const [obs, matches] = await Promise.all([
        tx.select({ alertId: alertObservables.alertId, type: observables.type, value: observables.value }).from(alertObservables).innerJoin(observables, eq(observables.id, alertObservables.observableId)).where(inArray(alertObservables.alertId, ids)),
        tx.select({ id: intelMatches.id, alertId: intelMatches.alertId, summary: intelMatches.summary }).from(intelMatches).where(inArray(intelMatches.alertId, ids)),
      ]);
      for (const { alert: a, asset } of rows) {
        await recordAlertGraph(tx, tenantId, {
          alert: a,
          asset: asset?.id ? asset : null,
          hostname: a.ocsf?.evidences?.[0]?.device?.hostname ?? obs.find((o) => o.alertId === a.id && o.type === "hostname")?.value ?? null,
          observables: obs.filter((o) => o.alertId === a.id),
          intel: matches.filter((m) => m.alertId === a.id).map((m) => ({ id: m.id, match: m.summary })),
        });
      }
      alertCount += rows.length;
      after = rows.at(-1)!.alert.id;
      return rows.length < batchSize;
    });
    if (done) break;
  }
  return { assets: assetCount, alerts: alertCount };
}

/** Every tenant that has alerts or assets. */
export async function backfillAllTenants(log: (m: string) => void = console.log) {
  const tenantIds = [...new Set([
    ...(await systemDb().selectDistinct({ id: assets.tenantId }).from(assets)).map((r) => r.id),
    ...(await systemDb().selectDistinct({ id: alerts.tenantId }).from(alerts)).map((r) => r.id),
  ])];
  for (const id of tenantIds) {
    const r = await backfillGraph(id);
    log(`graph ${id.slice(0, 8)}: ${r.assets} assets, ${r.alerts} alerts`);
  }
}
