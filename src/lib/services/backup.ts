import { and, eq, notInArray } from "drizzle-orm";
import { alerts, backupStatus, integrations } from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { isStaleBackup, LIVE_VEEAM, parseBackupInstant, veeamConfig } from "@/lib/backup/status";
import { syncAssets } from "@/lib/pipeline/assets";
import { ingestAlert } from "@/lib/pipeline/ingest";

/** Read the tenant Veeam row and store last success, failures, restore tests, and copy flags. */
export async function syncVeeamBackups(tenantId: string, now = new Date()): Promise<{ protectedSystems: number; staleAlerts: number }> {
  const [row] = await withScope(systemScope(tenantId), (tx) =>
    tx.select().from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "veeam"))),
  );
  if (!row) return { protectedSystems: 0, staleAlerts: 0 };

  const parsed = veeamConfig.safeParse(row.config);
  if (!parsed.success) {
    if (parsed.error.issues.some((issue) => issue.message === LIVE_VEEAM)) throw new Error(LIVE_VEEAM);
    throw new Error(parsed.error.issues[0]?.message ?? "backup config");
  }
  const config = parsed.data;
  const systems = config.systems.map((system) => {
    const externalId = `veeam:${system.name}`;
    const lastSuccessAt = parseBackupInstant(system.lastSuccessAt);
    const restoreTestedAt = parseBackupInstant(system.restoreTestedAt);
    return { system, externalId, lastSuccessAt, restoreTestedAt, stale: isStaleBackup(lastSuccessAt, config.staleHours, now) };
  });

  const ids = systems.length
    ? await withScope(systemScope(tenantId), (tx) => syncAssets(tx, tenantId, row.id, systems.map((item) => ({
        externalId: item.externalId,
        kind: "server" as const,
        name: item.system.name,
        hostname: item.system.hostname ?? item.system.name,
        ips: [],
        os: null,
        macs: [],
        agentStatus: null,
        lastSeen: item.lastSuccessAt,
        routingKeys: [],
        raw: { failedJobs: item.system.failedJobs, immutable: item.system.immutable, offlineCopy: item.system.offlineCopy },
      }))))
    : new Map<string, string>();

  await withScope(systemScope(tenantId), async (tx) => {
    for (const item of systems) {
      const assetId = ids.get(item.externalId);
      if (!assetId) continue;
      await tx.insert(backupStatus).values({
        tenantId,
        assetId,
        integrationId: row.id,
        lastSuccessAt: item.lastSuccessAt,
        failedJobs: item.system.failedJobs,
        restoreTestedAt: item.restoreTestedAt,
        immutable: item.system.immutable,
        offlineCopy: item.system.offlineCopy,
        stale: item.stale,
        updatedAt: now,
      }).onConflictDoUpdate({
        target: backupStatus.assetId,
        set: {
          integrationId: row.id,
          lastSuccessAt: item.lastSuccessAt,
          failedJobs: item.system.failedJobs,
          restoreTestedAt: item.restoreTestedAt,
          immutable: item.system.immutable,
          offlineCopy: item.system.offlineCopy,
          stale: item.stale,
          updatedAt: now,
        },
      });
    }
  });

  let staleAlerts = 0;
  for (const item of systems) {
    const externalId = `stale:${item.externalId}`;
    if (item.stale) {
      const result = await ingestAlert({
        tenantId,
        integrationId: row.id,
        source: "veeam",
        intel: null,
        alert: {
          externalId,
          ruleId: "backup-stale",
          title: `Stale backup on ${item.system.name}`,
          description: `No successful backup inside ${config.staleHours} hours.`,
          category: "backup",
          siemSeverity: null,
          severity: "high",
          occurredAt: now,
          assetExternalId: item.externalId,
          hostname: item.system.hostname ?? item.system.name,
          userName: null,
          attackTechniques: [],
          routingKeys: [],
          raw: { staleHours: config.staleHours, lastSuccessAt: item.lastSuccessAt?.toISOString() ?? null, failedJobs: item.system.failedJobs },
        },
      });
      if (result.created) staleAlerts += 1;
    } else {
      await withScope(systemScope(tenantId), (tx) =>
        tx.update(alerts).set({ status: "RESOLVED", updatedAt: now }).where(and(
          eq(alerts.tenantId, tenantId),
          eq(alerts.source, "veeam"),
          eq(alerts.externalId, externalId),
          notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"]),
        )),
      );
    }
  }

  return { protectedSystems: systems.length, staleAlerts };
}
