import { and, eq, inArray, isNull, lt } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { alerts, entities, entityRelationshipEvidence } from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import type { Severity } from "@/lib/providers/types";

const DAY = 86_400_000;

/**
 * Days an alert is kept after it occurred, by severity. Informational events (session opened, sudo) are most
 * of the volume and least of the value. Alerts linked to an incident are never purged here: they are the case
 * record, kept with the incident.
 */
export const ALERT_RETENTION_DAYS: Record<Severity, number> = {
  informational: 30,
  low: 180,
  medium: 180,
  high: 365,
  critical: 365,
};

/** Alerts deleted per transaction, so a large purge never holds locks for long. */
export const PURGE_BATCH = 1000;

export type PurgeCounts = Partial<Record<Severity, number>>;

/**
 * Delete one tenant's alerts past retention, with the graph nodes and evidence that point at them (other rows
 * cascade or are nulled by foreign keys). Writes one audit row with the counts when anything was removed.
 */
export async function purgeTenantAlerts(tenantId: string, now = new Date()): Promise<PurgeCounts> {
  const counts: PurgeCounts = {};
  for (const [severity, days] of Object.entries(ALERT_RETENTION_DAYS) as [Severity, number][]) {
    const cutoff = new Date(now.getTime() - days * DAY);
    for (;;) {
      const removed = await withScope(systemScope(tenantId), async (tx) => {
        const batch = await tx
          .select({ id: alerts.id })
          .from(alerts)
          .where(and(eq(alerts.tenantId, tenantId), eq(alerts.severity, severity), lt(alerts.occurredAt, cutoff), isNull(alerts.incidentId)))
          .limit(PURGE_BATCH);
        if (!batch.length) return 0;
        const ids = batch.map((b) => b.id);
        await tx.delete(entityRelationshipEvidence).where(and(eq(entityRelationshipEvidence.tenantId, tenantId), eq(entityRelationshipEvidence.evidenceType, "alert"), inArray(entityRelationshipEvidence.evidenceId, ids)));
        // An alert's own graph node; its edges cascade.
        await tx.delete(entities).where(and(eq(entities.tenantId, tenantId), eq(entities.type, "alert"), inArray(entities.key, ids)));
        await tx.delete(alerts).where(inArray(alerts.id, ids));
        return ids.length;
      });
      if (!removed) break;
      counts[severity] = (counts[severity] ?? 0) + removed;
      if (removed < PURGE_BATCH) break;
    }
  }
  const total = Object.values(counts).reduce((s, n) => s + (n ?? 0), 0);
  if (total) {
    await withScope(systemScope(tenantId), (tx) =>
      audit(tx, { actorId: null, actorKind: "system", tenantId, action: "retention.purge_alerts", targetType: "tenant", targetId: tenantId, detail: { deleted: counts, retentionDays: ALERT_RETENTION_DAYS, before: now.toISOString() } }),
    );
  }
  return counts;
}

/** Scheduled entry point: every tenant holding alerts. One tenant failing never stops the rest. */
export async function runAlertRetention(log: (m: string) => void, now = new Date()) {
  const oldest = Math.min(...Object.values(ALERT_RETENTION_DAYS));
  const tenants = await systemDb()
    .selectDistinct({ tenantId: alerts.tenantId })
    .from(alerts)
    .where(and(lt(alerts.occurredAt, new Date(now.getTime() - oldest * DAY)), isNull(alerts.incidentId)));
  for (const { tenantId } of tenants) {
    try {
      const counts = await purgeTenantAlerts(tenantId, now);
      const total = Object.values(counts).reduce((s, n) => s + (n ?? 0), 0);
      if (total) log(`tenant ${tenantId.slice(0, 8)}: purged ${total} alerts past retention ${JSON.stringify(counts)}`);
    } catch (err) {
      log(`tenant ${tenantId.slice(0, 8)}: alert retention failed: ${(err as Error).message}`);
    }
  }
}
