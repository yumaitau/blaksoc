import { Worker, type Job } from "bullmq";
import { queue, QUEUES, type QueueName } from "@/lib/queue";
import { redisConnectionOptions } from "@/lib/redis";
import { runDueEscalations } from "@/lib/services/escalation";
import { runDueClockReminders, runDueObligationReminders } from "@/lib/services/obligations";
import { advanceRun, resumeRun } from "@/lib/soar/engine";
import { executeResponseAction, expireDueApprovals, pollPendingResponseActions } from "@/lib/soar/response";
import { createSighting, ingestAdvisories, refreshCveIntel, rescoreVulnerabilities } from "./jobs/intel";
import { pollAlerts, probeHealth, runDetections, syncAllAssets, syncAllVulnerabilities, tenantsWithAssets } from "./jobs/ingest";
import { runDueBoardSummaries } from "@/lib/services/board";
import { releaseDueCollections } from "@/lib/services/dfir";
import { archiveDueSyslog } from "@/lib/services/syslog";
import { runDueHealth } from "@/lib/services/health";
import { syncKelpie } from "@/lib/services/kelpie";
import { runDueSurface } from "@/lib/services/surface";
import { runCorrelationAll } from "@/lib/services/correlation";
import { assertHostingEnv } from "@/lib/hosting/profile";
import { deliverToIntegration, eventJobPayload, fanOutEvent } from "@/lib/connectors/subscriptions";
import type { Notification } from "@/lib/connectors/notify";
import { recordSchedules } from "@/lib/obs/heartbeat";
import { logger, setLogService } from "@/lib/obs/log";
import { serveMetrics } from "@/lib/obs/metrics";
import { startTracing, stopTracing } from "@/lib/obs/tracing";
import { instrumented, onFailed } from "./instrument";
import { registerWorkerMetrics } from "./metrics";

setLogService("worker");

/** Progress lines from job code; correlation fields come from the job's log context. */
const log = (scope: string) => (m: string) => logger.info(m, { scope });

type Handler = (job: Job) => Promise<unknown>;

const handlers: Record<QueueName, Handler> = {
  [QUEUES.ingest]: async (job) => {
    if (job.name === "syslog-retain") return archiveDueSyslog();
    return pollAlerts(log("ingest"));
  },
  [QUEUES.sync]: async (job) => {
    if (job.name === "assets") return syncAllAssets(log("sync"));
    if (job.name === "vulns") return syncAllVulnerabilities(log("sync"));
    if (job.name === "health") {
      await probeHealth();
      return runDueHealth();
    }
    if (job.name === "dfir-release") return releaseDueCollections();
    if (job.name === "kelpie") return syncKelpie();
  },
  [QUEUES.playbook]: async (job) => {
    const { tenantId, runId } = job.data as { tenantId: string; runId: string };
    if (job.name === "resume") {
      const { approvalId, decision, reason } = job.data as { approvalId: string; decision: "APPROVED" | "REJECTED"; reason?: string };
      return resumeRun(tenantId, runId, approvalId, decision, reason);
    }
    return advanceRun(tenantId, runId);
  },
  [QUEUES.response]: async (job) => {
    if (job.name === "poll-pending") return pollPendingResponseActions(new Date(), log("response"));
    if (job.name === "expire-approvals") return expireDueApprovals(new Date());
    const { tenantId, actionId } = job.data as { tenantId: string; actionId: string };
    return executeResponseAction(tenantId, actionId);
  },
  [QUEUES.intel]: async (job) => {
    if (job.name === "cve") {
      await refreshCveIntel(log("intel"));
      for (const t of await tenantsWithAssets()) await rescoreVulnerabilities(t);
      return;
    }
    if (job.name === "rescore") return rescoreVulnerabilities((job.data as { tenantId: string }).tenantId);
    if (job.name === "advisories") return ingestAdvisories(log("advisories"));
    if (job.name === "sighting") {
      const { tenantId, matchId } = job.data as { tenantId: string; matchId: string };
      return createSighting(tenantId, matchId);
    }
  },
  [QUEUES.detection]: async (job) => {
    if (job.name === "correlate") return runCorrelationAll(log("correlation"));
    return runDetections();
  },
  [QUEUES.report]: async (job) => {
    if (job.name === "board") return runDueBoardSummaries();
  },
  [QUEUES.notify]: async (job) => {
    if (job.name === "event") {
      const { event, eventId } = eventJobPayload(job.data as Record<string, unknown>, String(job.id));
      return fanOutEvent(event, eventId);
    }
    if (job.name === "deliver") {
      const { integrationId, notification } = job.data as { integrationId: string; notification: Notification };
      return deliverToIntegration(integrationId, notification);
    }
    const escalations = await runDueEscalations();
    const obligations = await runDueObligationReminders();
    const clocks = await runDueClockReminders();
    return { escalations, obligations, clocks };
  },
  [QUEUES.surface]: async () => runDueSurface(),
};

/** Repeatable schedules. Upserted on boot so config changes apply on redeploy. */
const SCHEDULES: { queue: QueueName; name: string; every: number }[] = [
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

async function main() {
  assertHostingEnv(process.env);
  startTracing("blaksoc-worker");
  for (const s of SCHEDULES) {
    await queue(s.queue).upsertJobScheduler(`${s.queue}:${s.name}`, { every: s.every }, { name: s.name });
  }
  await recordSchedules(SCHEDULES);
  // Own port, never behind the ingress; see the chart's PodMonitor and NetworkPolicy.
  if (process.env.METRICS_PORT) {
    registerWorkerMetrics();
    serveMetrics(Number(process.env.METRICS_PORT));
  }
  const concurrency: Partial<Record<QueueName, number>> = { [QUEUES.ingest]: 1, [QUEUES.playbook]: 4, [QUEUES.response]: 2, [QUEUES.intel]: 1, [QUEUES.sync]: 1, [QUEUES.surface]: 1 };
  const workers = (Object.values(QUEUES) as QueueName[]).map(
    (name) =>
      new Worker(name, instrumented(name, handlers[name]), { connection: redisConnectionOptions(), concurrency: concurrency[name] ?? 1 })
        .on("failed", onFailed(name))
        .on("error", (err) => logger.error("worker error", { queue: name, err })),
  );
  logger.info("worker started", { queues: workers.length, schedules: SCHEDULES.length });

  const shutdown = async () => {
    logger.info("worker shutting down");
    await Promise.all(workers.map((w) => w.close()));
    await stopTracing();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  logger.error("worker failed to start", { err });
  process.exit(1);
});
