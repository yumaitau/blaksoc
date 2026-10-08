import { and, eq, inArray, isNull, lt, sql } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { alerts, entities, entityRelationshipEvidence } from "@/db/schema";
import type { Tx } from "@/db/client";
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
 * Delete one tenant's alerts past retention, with the graph data that points at them (other rows cascade or are
 * nulled by foreign keys). Each batch is one transaction that also writes its own audit row, so a failed run
 * leaves an accurate record of what it did delete.
 */
export async function purgeTenantAlerts(tenantId: string, now = new Date(), retention: Partial<Record<Severity, number>> = ALERT_RETENTION_DAYS): Promise<PurgeCounts> {
  const counts: PurgeCounts = {};
  for (const [severity, days] of Object.entries(retention) as [Severity, number][]) {
    const cutoff = new Date(now.getTime() - days * DAY);
    for (;;) {
      const removed = await withScope(systemScope(tenantId), async (tx) => {
        // Locked so a concurrent link to an incident waits for this batch, or is skipped when it holds the row.
        const batch = await tx
          .select({ id: alerts.id })
          .from(alerts)
          .where(and(eq(alerts.tenantId, tenantId), eq(alerts.severity, severity), lt(alerts.occurredAt, cutoff), isNull(alerts.incidentId)))
          .limit(PURGE_BATCH)
          .for("update", { skipLocked: true });
        if (!batch.length) return 0;
        const deleted = (
          await tx
            .delete(alerts)
            .where(and(inArray(alerts.id, batch.map((b) => b.id)), isNull(alerts.incidentId)))
            .returning({ id: alerts.id })
        ).map((r) => r.id);
        if (!deleted.length) return 0;
        await removeAlertGraph(tx, tenantId, deleted);
        await audit(tx, {
          actorId: null, actorKind: "system", tenantId, action: "retention.purge_alerts", targetType: "tenant", targetId: tenantId,
          detail: { severity, deleted: deleted.length, retentionDays: days, before: cutoff.toISOString() },
        });
        return deleted.length;
      });
      if (!removed) break;
      counts[severity] = (counts[severity] ?? 0) + removed;
      if (removed < PURGE_BATCH) break;
    }
  }
  return counts;
}

/**
 * Graph data for deleted alerts: their own nodes (edges cascade), and the evidence they gave other edges
 * (user → device). An edge left without evidence goes; one with evidence left points at its latest record.
 */
export async function removeAlertGraph(tx: Tx, tenantId: string, alertIds: string[]) {
  const touched = (
    await tx
      .delete(entityRelationshipEvidence)
      .where(and(eq(entityRelationshipEvidence.tenantId, tenantId), eq(entityRelationshipEvidence.evidenceType, "alert"), inArray(entityRelationshipEvidence.evidenceId, alertIds)))
      .returning({ id: entityRelationshipEvidence.relationshipId })
  ).map((r) => r.id);
  await tx.delete(entities).where(and(eq(entities.tenantId, tenantId), eq(entities.type, "alert"), inArray(entities.key, alertIds)));
  const ids = [...new Set(touched)];
  if (!ids.length) return;
  await tx.execute(sql`
    delete from entity_relationships r
    where r.tenant_id = ${tenantId} and r.id in ${ids}
      and not exists (select 1 from entity_relationship_evidence e where e.relationship_id = r.id)`);
  await tx.execute(sql`
    update entity_relationships r
    set count = latest.n, evidence_type = latest.evidence_type, evidence_id = latest.evidence_id
    from (
      select distinct on (e.relationship_id) e.relationship_id, e.evidence_type, e.evidence_id,
        count(*) over (partition by e.relationship_id) as n
      from entity_relationship_evidence e
      where e.tenant_id = ${tenantId} and e.relationship_id in ${ids}
      order by e.relationship_id, e.observed_at desc
    ) latest
    where r.id = latest.relationship_id`);
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
