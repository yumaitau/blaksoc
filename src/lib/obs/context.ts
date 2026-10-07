import { AsyncLocalStorage } from "node:async_hooks";
import { context, propagation, ROOT_CONTEXT, type Context } from "@opentelemetry/api";

/** Correlation fields every log line in the current request or job carries. */
export type ObsContext = { requestId?: string; jobId?: string; queue?: string; job?: string; tenantId?: string };

/** Reserved job-data key. Stripped by the worker before a handler sees the data. */
export const JOB_META_KEY = "_obs";
type JobMeta = { requestId?: string; trace?: Record<string, string> };

// Next bundles route code and instrumentation separately; one store per process keeps them in step.
const g = globalThis as unknown as { __blaksocObs?: AsyncLocalStorage<ObsContext> };
const store = (g.__blaksocObs ??= new AsyncLocalStorage<ObsContext>());

export function obsContext(): ObsContext {
  return store.getStore() ?? {};
}

/** Run `fn` with extra correlation fields; inner values win over outer ones. */
export function withObsContext<T>(ctx: ObsContext, fn: () => T): T {
  const merged: ObsContext = { ...obsContext() };
  for (const [k, v] of Object.entries(ctx)) if (v != null && v !== "") merged[k as keyof ObsContext] = v;
  return store.run(merged, fn);
}

/** Job data with the current request id and trace context attached, so the worker continues the same story. */
export function withJobMeta<T>(data: T): T {
  if (!data || typeof data !== "object" || Array.isArray(data)) return data;
  const meta: JobMeta = {};
  const { requestId } = obsContext();
  if (requestId) meta.requestId = requestId;
  const trace: Record<string, string> = {};
  propagation.inject(context.active(), trace);
  if (Object.keys(trace).length) meta.trace = trace;
  if (!meta.requestId && !meta.trace) return data;
  return { ...data, [JOB_META_KEY]: meta };
}

/** Worker side: remove the meta from job data and return it with the parent trace context. */
export function takeJobMeta(job: { data: unknown }): { requestId?: string; parent: Context } {
  const data = job.data as Record<string, unknown> | null;
  if (!data || typeof data !== "object" || !(JOB_META_KEY in data)) return { parent: ROOT_CONTEXT };
  const { [JOB_META_KEY]: raw, ...rest } = data;
  job.data = rest;
  const meta = (raw ?? {}) as JobMeta;
  const parent = meta.trace ? propagation.extract(ROOT_CONTEXT, meta.trace) : ROOT_CONTEXT;
  return { requestId: typeof meta.requestId === "string" ? meta.requestId : undefined, parent };
}
