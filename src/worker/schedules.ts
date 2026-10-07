import { queue, QUEUES, type QueueName } from "@/lib/queue";

/** Repeatable schedules. Upserted on boot so config changes apply on redeploy. */
export const SCHEDULES: { queue: QueueName; name: string; every: number }[] = [
  { queue: QUEUES.ingest, name: "poll", every: 30_000 },
  { queue: QUEUES.ingest, name: "syslog-retain", every: 60 * 60_000 },
  { queue: QUEUES.response, name: "poll-pending", every: 30_000 },
  { queue: QUEUES.response, name: "expire-approvals", every: 5 * 60_000 },
  { queue: QUEUES.sync, name: "assets", every: 15 * 60_000 },
  { queue: QUEUES.sync, name: "vulns", every: 60 * 60_000 },
  { queue: QUEUES.sync, name: "health", every: 5 * 60_000 },
  { queue: QUEUES.sync, name: "dfir-release", every: 15 * 60_000 },
  { queue: QUEUES.sync, name: "kelpie", every: 60_000 },
  { queue: QUEUES.detection, name: "run", every: 5 * 60_000 },
  { queue: QUEUES.detection, name: "correlate", every: 60_000 },
  { queue: QUEUES.intel, name: "cve", every: 6 * 60 * 60_000 },
  { queue: QUEUES.intel, name: "advisories", every: 60 * 60_000 },
  { queue: QUEUES.notify, name: "escalate", every: 60_000 },
  { queue: QUEUES.surface, name: "scan", every: 15 * 60_000 },
  { queue: QUEUES.report, name: "board", every: 60 * 60_000 },
];

/** How often a running worker checks that its schedulers still exist in Redis. */
export const SCHEDULE_CHECK_MS = 60_000;

/**
 * Schedulers live only in Redis. `force` upserts all (boot); otherwise only missing ones are
 * recreated, so a flushed or replaced Redis gets its schedules back without resetting the rest.
 * Returns the ids written.
 */
export async function ensureSchedules(force = false): Promise<string[]> {
  const written: string[] = [];
  for (const s of SCHEDULES) {
    const id = `${s.queue}:${s.name}`;
    const q = queue(s.queue);
    if (!force && (await q.getJobScheduler(id))) continue;
    await q.upsertJobScheduler(id, { every: s.every }, { name: s.name });
    written.push(id);
  }
  return written;
}
