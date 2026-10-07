import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ added: [] as { name: string; data: unknown }[], stamped: [] as string[][] }));

vi.mock("bullmq", () => ({
  Queue: class {
    constructor(readonly name: string) {}
    async add(name: string, data: unknown) {
      state.added.push({ name, data });
      return { id: String(state.added.length), name, data };
    }
  },
}));
vi.mock("@/lib/obs/heartbeat", () => ({ recordScheduleRun: async (queue: string, name: string) => void state.stamped.push([queue, name]) }));

const { withObsContext, JOB_META_KEY } = await import("@/lib/obs/context");
const { setLogSink } = await import("@/lib/obs/log");
const { queue, QUEUES } = await import("@/lib/queue");
const { instrumented, onFailed } = await import("@/worker/instrument");
const { registry } = await import("@/lib/obs/metrics");

function capture() {
  const lines: Record<string, unknown>[] = [];
  setLogSink((line) => void lines.push(JSON.parse(line)));
  return lines;
}

afterEach(() => {
  setLogSink(undefined);
  state.added = [];
  state.stamped = [];
  delete process.env.LOG_LEVEL;
});

type FakeJob = { id: string; name: string; data: unknown; attemptsMade: number; opts: { attempts?: number }; repeatJobKey?: string };
const asJob = (j: FakeJob) => j as never;

describe("request id from web to worker", () => {
  it("attaches the current request id to job data on enqueue, and nothing outside a request", async () => {
    await withObsContext({ requestId: "req-web-0001" }, () => queue(QUEUES.playbook).add("advance", { tenantId: "t", runId: "r" }));
    await queue(QUEUES.playbook).add("advance", { tenantId: "t", runId: "r2" });
    expect(state.added[0]!.data).toEqual({ tenantId: "t", runId: "r", [JOB_META_KEY]: { requestId: "req-web-0001" } });
    expect(state.added[1]!.data).toEqual({ tenantId: "t", runId: "r2" });
  });

  it("follows one id from the enqueuing request into the worker's log lines", async () => {
    await withObsContext({ requestId: "req-web-0002" }, () => queue(QUEUES.playbook).add("advance", { tenantId: "t-9", runId: "r" }));
    const lines = capture();
    process.env.LOG_LEVEL = "info";
    let seen: unknown;
    const { logger } = await import("@/lib/obs/log");
    const handler = instrumented("playbook", async (job) => {
      seen = job.data;
      logger.info("advancing run");
    });
    await handler(asJob({ id: "77", name: "advance", data: state.added[0]!.data, attemptsMade: 0, opts: { attempts: 3 } }));
    // Handlers never see the reserved key (an outbound webhook payload must not carry it).
    expect(seen).toEqual({ tenantId: "t-9", runId: "r" });
    expect(lines).toEqual([expect.objectContaining({ msg: "advancing run", requestId: "req-web-0002", jobId: "77", queue: "playbook", job: "advance", tenantId: "t-9", service: "web" })]);
  });

  it("keeps the request id on the failure log and counts the failure", async () => {
    const lines = capture();
    const job: FakeJob = { id: "88", name: "execute", data: { tenantId: "t", actionId: "a", [JOB_META_KEY]: { requestId: "req-web-0003" } }, attemptsMade: 0, opts: { attempts: 3 } };
    const handler = instrumented("response", async () => {
      throw new Error("provider returned 500 for Bearer abc.def");
    });
    await expect(handler(asJob(job))).rejects.toThrow();
    job.attemptsMade = 3;
    onFailed("response")(asJob(job), new Error("provider returned 500 for Bearer abc.def"));
    expect(lines).toEqual([expect.objectContaining({ level: "error", msg: "job failed", requestId: "req-web-0003", final: true, jobId: "88" })]);
    expect(JSON.stringify(lines)).not.toContain("abc.def");
    const text = await registry().metrics();
    expect(text).toContain('blaksoc_job_failures_total{queue="response",job="execute",final="true"} 1');
    expect(text).toMatch(/blaksoc_job_duration_seconds_count\{queue="response",job="execute",outcome="error"\} 1/);
  });

  it("stamps the scheduler heartbeat only for scheduled jobs", async () => {
    const handler = instrumented("ingest", async () => undefined);
    await handler(asJob({ id: "repeat:1", name: "poll", data: {}, attemptsMade: 0, opts: {}, repeatJobKey: "ingest:poll" }));
    await handler(asJob({ id: "2", name: "poll", data: {}, attemptsMade: 0, opts: {} }));
    expect(state.stamped).toEqual([["ingest", "poll"]]);
  });
});
