import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  job: null as null | { data: Record<string, unknown>; failed: boolean; retried: unknown[][]; updated: Record<string, unknown>[] },
  added: [] as unknown[][],
  scoped: 0,
}));

vi.mock("@/lib/queue", () => ({
  QUEUES: { response: "response", playbook: "playbook" },
  queue: () => ({
    getJob: async () =>
      state.job && {
        data: state.job.data,
        isFailed: async () => state.job!.failed,
        updateData: async (d: Record<string, unknown>) => void state.job!.updated.push(d),
        retry: async (...args: unknown[]) => void state.job!.retried.push(args),
      },
    add: async (...args: unknown[]) => void state.added.push(args),
  }),
}));

vi.mock("@/db/scope", () => ({
  withScope: async () => {
    state.scoped++;
  },
}));

const failedJob = (recoveries: number) => ({ data: { tenantId: "t", actionId: "a", recoveries }, failed: true, retried: [], updated: [] });

describe("recovery of failed jobs", () => {
  it("retries a failed job with a fresh set of attempts and counts the recovery", async () => {
    const { queueExecute } = await import("@/lib/soar/response");
    state.job = failedJob(0);
    await queueExecute("t", "a");
    expect(state.job.retried).toEqual([["failed", { resetAttemptsMade: true, resetAttemptsStarted: true }]]);
    expect(state.job.updated).toEqual([{ tenantId: "t", actionId: "a", recoveries: 1 }]);
  });

  it("gives up after the cap and settles the action instead of retrying", async () => {
    const { queueExecute, MAX_RECOVERIES } = await import("@/lib/soar/response");
    state.job = failedJob(MAX_RECOVERIES);
    state.scoped = 0;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await queueExecute("t", "a");
    expect(state.job.retried).toEqual([]);
    expect(state.scoped).toBe(1);
    warn.mockRestore();
  });

  it("adds a job once when none exists", async () => {
    const { queueExecute } = await import("@/lib/soar/response");
    state.job = null;
    state.added = [];
    await queueExecute("t", "a");
    expect(state.added).toEqual([["execute", { tenantId: "t", actionId: "a" }, { jobId: "execute-a" }]]);
  });
});
