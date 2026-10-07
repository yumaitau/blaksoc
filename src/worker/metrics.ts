import { eq } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { integrations } from "@/db/schema";
import { registerHeartbeatMetrics } from "@/lib/obs/heartbeat";
import { collectedGauge } from "@/lib/obs/metrics";
import { queue, QUEUES, type QueueName } from "@/lib/queue";

const STATES = ["waiting", "active", "delayed", "prioritized", "waiting-children", "failed"] as const;

/** Oldest job in `wait` (BullMQ keeps that list newest-first, so ask for it ascending). */
async function oldestWaitingAge(name: QueueName, now: number): Promise<number> {
  const [oldest] = await queue(name).getJobs(["wait"], 0, 0, true);
  // A scheduled job becomes runnable at timestamp + delay, not when it was created.
  return oldest ? Math.max(0, now - oldest.timestamp - (oldest.delay ?? 0)) / 1000 : 0;
}

// One query per scrape feeds the three integration gauges.
let cached: { at: number; rows: Promise<(typeof integrations.$inferSelect)[]> } | undefined;
function enabledIntegrations() {
  if (!cached || Date.now() - cached.at > 5_000) cached = { at: Date.now(), rows: systemDb().select().from(integrations).where(eq(integrations.enabled, true)) };
  return cached.rows;
}

/**
 * Worker-side collectors, read at scrape time: BullMQ queue depth per state and oldest waiting
 * job age (Redis, shared by every replica), integration health (Postgres), and the scheduler
 * heartbeat. Queue and integration series are global, so alert rules aggregate with max by.
 */
export function registerWorkerMetrics() {
  registerHeartbeatMetrics();
  collectedGauge("blaksoc_queue_jobs", "BullMQ jobs per queue and state.", ["queue", "state"] as const, async (set) => {
    for (const name of Object.values(QUEUES)) {
      const counts = await queue(name).getJobCounts(...STATES);
      for (const state of STATES) set({ queue: name, state }, counts[state] ?? 0);
    }
  });
  collectedGauge("blaksoc_queue_oldest_waiting_age_seconds", "Age of the oldest runnable job waiting in each queue.", ["queue"] as const, async (set) => {
    const now = Date.now();
    for (const name of Object.values(QUEUES)) set({ queue: name }, await oldestWaitingAge(name, now));
  });
  collectedGauge("blaksoc_integration_up", "1 when an enabled integration's last poll or probe succeeded, 0 when it failed.", ["integration", "provider"] as const, async (set) => {
    for (const r of await enabledIntegrations()) if (r.status === "healthy" || r.status === "error") set({ integration: r.id, provider: r.provider }, r.status === "healthy" ? 1 : 0);
  });
  collectedGauge("blaksoc_integration_last_success_timestamp_seconds", "Unix time of an integration's last successful poll or probe.", ["integration", "provider"] as const, async (set) => {
    for (const r of await enabledIntegrations()) if (r.lastSuccessAt) set({ integration: r.id, provider: r.provider }, r.lastSuccessAt.getTime() / 1000);
  });
  collectedGauge("blaksoc_integration_info", "Integration names for joining onto integration ids.", ["integration", "provider", "category", "name"] as const, async (set) => {
    for (const r of await enabledIntegrations()) set({ integration: r.id, provider: r.provider, category: r.category, name: r.name }, 1);
  });
}
