import { SpanKind, SpanStatusCode } from "@opentelemetry/api";
import type { Job } from "bullmq";
import { takeJobMeta, withObsContext } from "@/lib/obs/context";
import { recordScheduleRun } from "@/lib/obs/heartbeat";
import { logger } from "@/lib/obs/log";
import { jobDuration, jobFailures } from "@/lib/obs/metrics";
import { tracer } from "@/lib/obs/tracing";

type Handler = (job: Job) => Promise<unknown>;

// The failed event fires outside the job's async context; keep its request id for that log line.
const requestIds = new WeakMap<Job, string>();

function tenantOf(data: unknown): string | undefined {
  const t = (data as { tenantId?: unknown } | null)?.tenantId;
  return typeof t === "string" ? t : undefined;
}

/**
 * Wrap a queue handler: strip correlation meta from the job data, run inside a log context and a
 * consumer span (child of the enqueuing request's trace), stamp the scheduler heartbeat for
 * scheduled jobs, and time the run.
 */
export function instrumented(queue: string, handler: Handler): Handler {
  return async (job) => {
    const { requestId, parent } = takeJobMeta(job);
    if (requestId) requestIds.set(job, requestId);
    const ctx = { requestId, jobId: job.id, queue, job: job.name, tenantId: tenantOf(job.data) };
    return withObsContext(ctx, () =>
      tracer().startActiveSpan(`${queue} ${job.name}`, { kind: SpanKind.CONSUMER, attributes: { "messaging.system": "bullmq", "messaging.destination.name": queue, "messaging.operation.name": job.name, "messaging.message.id": job.id ?? "", "blaksoc.attempt": job.attemptsMade + 1 } }, parent, async (span) => {
        const started = performance.now();
        if (job.repeatJobKey) await recordScheduleRun(queue, job.name).catch((err: unknown) => logger.warn("heartbeat write failed", { err }));
        let outcome = "ok";
        try {
          return await handler(job);
        } catch (err) {
          outcome = "error";
          span.recordException(err as Error);
          span.setStatus({ code: SpanStatusCode.ERROR });
          throw err;
        } finally {
          const seconds = (performance.now() - started) / 1000;
          jobDuration().observe({ queue, job: job.name, outcome }, seconds);
          logger.debug("job finished", { outcome, durationMs: Math.round(seconds * 1000) });
          span.end();
        }
      }),
    );
  };
}

/** Worker `failed` hook: count the failure and log it with enough context to find the job. Covers stalled jobs too. */
export function onFailed(queue: string) {
  return (job: Job | undefined, err: Error) => {
    const attempts = job?.opts.attempts ?? 1;
    const final = !job || job.attemptsMade >= attempts;
    jobFailures().inc({ queue, job: job?.name ?? "unknown", final: String(final) });
    const fields = { queue, job: job?.name, jobId: job?.id, attemptsMade: job?.attemptsMade, attempts, final, err };
    withObsContext({ requestId: job ? requestIds.get(job) : undefined, tenantId: tenantOf(job?.data) }, () => (final ? logger.error("job failed", fields) : logger.warn("job attempt failed", fields)));
  };
}
