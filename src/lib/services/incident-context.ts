import { and, asc, eq, inArray } from "drizzle-orm";
import type { DbOrTx } from "@/db/client";
import { alerts, assets, incidentAlerts, integrations } from "@/db/schema";
import { env } from "@/lib/env";
import { wazuhAlertUrl } from "@/lib/providers/wazuh-link";
import { contributingIds } from "@/lib/correlation/events";
import type { DetectionAlert } from "@/lib/incidents/explanation";

export function sourceAlertUrl(a: { source: string; externalId: string; occurredAt: Date }, config: Record<string, unknown> | null) {
  if (a.source !== "wazuh") return null;
  return wazuhAlertUrl(
    typeof config?.dashboardUrl === "string" ? config.dashboardUrl : env().WAZUH_DASHBOARD_URL,
    a.externalId, a.occurredAt,
    typeof config?.dashboardIndexPatternId === "string" ? config.dashboardIndexPatternId : undefined,
  );
}

const columns = {
    id: alerts.id, title: alerts.title, source: alerts.source, ruleId: alerts.ruleId,
    severity: alerts.severity, siemSeverity: alerts.siemSeverity, occurredAt: alerts.occurredAt,
    assetName: assets.name, userName: alerts.userName, description: alerts.description,
    raw: alerts.raw, externalId: alerts.externalId, config: integrations.config,
};

export async function contributingDetections(tx: DbOrTx, tenantId: string, raw: unknown): Promise<DetectionAlert[]> {
  const ids = contributingIds(raw).filter((id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)).slice(0, 200);
  if (!ids.length) return [];
  const rows = await tx.select(columns).from(alerts)
    .leftJoin(assets, eq(assets.id, alerts.assetId))
    .leftJoin(integrations, eq(integrations.id, alerts.integrationId))
    .where(and(eq(alerts.tenantId, tenantId), inArray(alerts.id, ids)))
    .orderBy(asc(alerts.occurredAt), asc(alerts.id));
  return rows.map(({ config, ...a }) => ({ ...a, wazuhUrl: sourceAlertUrl(a, config) }));
}

/** Call only inside an authorised incident scope; raw event context is for SOC analysts and Kelpie. */
export async function incidentDetections(tx: DbOrTx, incidentId: string): Promise<DetectionAlert[]> {
  const rows = await tx.select({ ...columns, tenantId: alerts.tenantId, groupReason: incidentAlerts.reason }).from(incidentAlerts)
    .innerJoin(alerts, eq(alerts.id, incidentAlerts.alertId))
    .leftJoin(assets, eq(assets.id, alerts.assetId))
    .leftJoin(integrations, eq(integrations.id, alerts.integrationId))
    .where(eq(incidentAlerts.incidentId, incidentId))
    .orderBy(asc(alerts.occurredAt), asc(alerts.id));
  return Promise.all(rows.map(async ({ config, ...a }) => ({
    ...a, wazuhUrl: sourceAlertUrl(a, config),
    contributing: a.source === "blaksoc-correlation" ? await contributingDetections(tx, a.tenantId, a.raw) : [],
  })));
}
