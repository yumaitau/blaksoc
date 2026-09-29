import { Worker, type Job } from "bullmq";
import { queue, QUEUES, type QueueName } from "@/lib/queue";
import { redisConnectionOptions } from "@/lib/redis";
import { runDueEscalations } from "@/lib/services/escalation";
import { runDueObligationReminders } from "@/lib/services/obligations";
import { advanceRun, resumeRun } from "@/lib/soar/engine";
import { executeResponseAction } from "@/lib/soar/response";
import { createSighting, ingestAdvisories, refreshCveIntel, rescoreVulnerabilities } from "./jobs/intel";
import { pollAlerts, probeHealth, runDetections, syncAllAssets, syncAllVulnerabilities, tenantsWithAssets } from "./jobs/ingest";
import { runDueBoardSummaries } from "@/lib/services/board";
import { releaseDueCollections } from "@/lib/services/dfir";
import { archiveDueSyslog } from "@/lib/services/syslog";
import { runDueHealth } from "@/lib/services/health";
import { runDueSurface } from "@/lib/services/surface";

const log = (scope: string) => (m: string) => console.log(`[${new Date().toISOString()}] [${scope}] ${m}`);

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
      await probeHealth(log("health"));
      return runDueHealth();
    }
    if (job.name === "dfir-release") return releaseDueCollections();
  },
  [QUEUES.playbook]: async (job) => {
    const { tenantId, runId } = job.data as { tenantId: string; runId: string };
    if (job.name === "resume") {
      const { approvalId, decision } = job.data as { approvalId: string; decision: "APPROVED" | "REJECTED" };
      return resumeRun(tenantId, runId, approvalId, decision);
    }
    return advanceRun(tenantId, runId);
  },
  [QUEUES.response]: async (job) => {
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
  [QUEUES.detection]: async () => runDetections(log("detection")),
  [QUEUES.report]: async (job) => {
    if (job.name === "board") return runDueBoardSummaries();
  },
  [QUEUES.notify]: async () => {
    const escalations = await runDueEscalations();
    const obligations = await runDueObligationReminders();
    return { escalations, obligations };
  },
  [QUEUES.surface]: async () => runDueSurface(),
};

/** Repeatable schedules. Upserted on boot so config changes apply on redeploy. */
const SCHEDULES: { queue: QueueName; name: string; every: number }[] = [
  { queue: QUEUES.ingest, name: "poll", every: 30_000 },
  { queue: QUEUES.ingest, name: "syslog-retain", every: 60 * 60_000 },
  { queue: QUEUES.sync, name: "assets", every: 15 * 60_000 },
  { queue: QUEUES.sync, name: "vulns", every: 60 * 60_000 },
  { queue: QUEUES.sync, name: "health", every: 5 * 60_000 },
  { queue: QUEUES.sync, name: "dfir-release", every: 15 * 60_000 },
  { queue: QUEUES.detection, name: "run", every: 5 * 60_000 },
  { queue: QUEUES.intel, name: "cve", every: 6 * 60 * 60_000 },
  { queue: QUEUES.intel, name: "advisories", every: 60 * 60_000 },
  { queue: QUEUES.notify, name: "escalate", every: 60_000 },
  { queue: QUEUES.surface, name: "scan", every: 15 * 60_000 },
  { queue: QUEUES.report, name: "board", every: 60 * 60_000 },
];

async function main() {
  for (const s of SCHEDULES) {
    await queue(s.queue).upsertJobScheduler(`${s.queue}:${s.name}`, { every: s.every }, { name: s.name });
  }
  const concurrency: Partial<Record<QueueName, number>> = { [QUEUES.ingest]: 1, [QUEUES.playbook]: 4, [QUEUES.response]: 2, [QUEUES.intel]: 1, [QUEUES.sync]: 1, [QUEUES.surface]: 1 };
  const workers = (Object.values(QUEUES) as QueueName[]).map(
    (name) =>
      new Worker(name, handlers[name], { connection: redisConnectionOptions(), concurrency: concurrency[name] ?? 1 }).on("failed", (job, err) =>
        log(name)(`job ${job?.name} failed: ${err.message}`),
      ),
  );
  log("worker")(`started ${workers.length} queues`);

  const shutdown = async () => {
    log("worker")("shutting down");
    await Promise.all(workers.map((w) => w.close()));
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
