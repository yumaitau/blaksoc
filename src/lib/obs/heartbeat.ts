import { redis } from "@/lib/redis";
import { collectedGauge } from "./metrics";

/**
 * Scheduler heartbeat in Redis. The worker stamps it whenever a scheduled job starts; web and
 * worker both export it, so a stopped worker still shows as a stale timestamp on the web pods
 * instead of silently disappearing with its own scrape target.
 */
const HEARTBEAT = "blaksoc:worker:heartbeat";
const LAST_RUN = "blaksoc:scheduler:last-run";
const INTERVAL = "blaksoc:scheduler:interval";

export async function recordScheduleRun(queue: string, schedule: string, now = Date.now()) {
  await redis().multi().set(HEARTBEAT, String(now)).hset(LAST_RUN, `${queue}:${schedule}`, String(now)).exec();
}

/** Called on worker boot with the configured schedules, so alerts can compare last run to interval. */
export async function recordSchedules(schedules: { queue: string; name: string; every: number }[], now = Date.now()) {
  const intervals = Object.fromEntries(schedules.map((s) => [`${s.queue}:${s.name}`, String(s.every)]));
  await redis().multi().del(INTERVAL).hset(INTERVAL, intervals).set(HEARTBEAT, String(now)).exec();
}

export async function lastHeartbeat(): Promise<number | null> {
  const v = await redis().get(HEARTBEAT);
  return v ? Number(v) : null;
}

function split(field: string) {
  const i = field.indexOf(":");
  return { queue: field.slice(0, i), schedule: field.slice(i + 1) };
}

export function registerHeartbeatMetrics() {
  collectedGauge("blaksoc_worker_heartbeat_timestamp_seconds", "Unix time a worker last started a scheduled job.", [], async (set) => {
    const at = await lastHeartbeat();
    if (at) set({}, at / 1000);
  });
  collectedGauge("blaksoc_scheduler_last_run_timestamp_seconds", "Unix time each job schedule last started.", ["queue", "schedule"] as const, async (set) => {
    for (const [field, at] of Object.entries(await redis().hgetall(LAST_RUN))) set(split(field), Number(at) / 1000);
  });
  collectedGauge("blaksoc_scheduler_interval_seconds", "Configured interval of each job schedule.", ["queue", "schedule"] as const, async (set) => {
    for (const [field, every] of Object.entries(await redis().hgetall(INTERVAL))) set(split(field), Number(every) / 1000);
  });
}
