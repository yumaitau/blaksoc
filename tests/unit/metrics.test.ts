import { describe, expect, it, vi } from "vitest";

const NOW = Date.now();

vi.mock("@/lib/queue", () => ({
  QUEUES: { ingest: "ingest", notify: "notify" },
  queue: (name: string) => ({
    getJobCounts: async (...types: string[]) => Object.fromEntries(types.map((t) => [t, name === "ingest" && t === "waiting" ? 3 : 0])),
    // A scheduled job created 10 minutes ago with a 5 minute delay has waited 5 minutes.
    getJobs: async () => (name === "ingest" ? [{ timestamp: NOW - 600_000, delay: 300_000 }] : []),
  }),
}));
vi.mock("@/db/client", () => ({
  systemDb: () => ({
    select: () => ({
      from: () => ({
        where: async () => [
          { id: "int-1", name: "Shared Wazuh", provider: "wazuh", category: "siem", status: "error", lastSuccessAt: new Date(NOW - 3_600_000) },
          { id: "int-2", name: "Teams", provider: "teams", category: "notify", status: "unknown", lastSuccessAt: null },
        ],
      }),
    }),
  }),
}));
vi.mock("@/lib/redis", () => ({
  redis: () => ({
    get: async () => String(NOW - 20_000),
    hgetall: async (key: string) => (key.endsWith("last-run") ? { "ingest:poll": String(NOW - 20_000) } : { "ingest:poll": "30000" }),
  }),
}));

const metrics = await import("@/lib/obs/metrics");
const { RequestMetricsProcessor } = await import("@/lib/obs/tracing");
const { registerWorkerMetrics } = await import("@/worker/metrics");

function span(attributes: Record<string, unknown>, parent?: { isRemote: boolean }) {
  return { attributes, parentSpanContext: parent, duration: [0, 250_000_000] } as never;
}

describe("metrics registry", () => {
  it("exposes the worker queue, scheduler and integration series", async () => {
    registerWorkerMetrics();
    const text = await metrics.registry().metrics();
    expect(text).toContain('blaksoc_queue_jobs{queue="ingest",state="waiting"} 3');
    expect(text).toContain('blaksoc_queue_jobs{queue="notify",state="failed"} 0');
    expect(text).toMatch(/blaksoc_queue_oldest_waiting_age_seconds\{queue="ingest"\} 30\d(\.\d+)?\n/);
    expect(text).toContain('blaksoc_queue_oldest_waiting_age_seconds{queue="notify"} 0');
    expect(text).toContain(`blaksoc_worker_heartbeat_timestamp_seconds ${(NOW - 20_000) / 1000}`);
    expect(text).toContain(`blaksoc_scheduler_last_run_timestamp_seconds{queue="ingest",schedule="poll"} ${(NOW - 20_000) / 1000}`);
    expect(text).toContain('blaksoc_scheduler_interval_seconds{queue="ingest",schedule="poll"} 30');
    expect(text).toContain('blaksoc_integration_up{integration="int-1",provider="wazuh"} 0');
    // Never probed: no up/down sample rather than a false "down".
    expect(text).not.toContain('blaksoc_integration_up{integration="int-2"');
    expect(text).toContain('blaksoc_integration_info{integration="int-1",provider="wazuh",category="siem",name="Shared Wazuh"} 1');
    // Default process metrics come along for free.
    expect(text).toContain("process_cpu_user_seconds_total");
  });

  it("records ingest, AI and SSE series with bounded labels", async () => {
    metrics.ingestAlerts().inc({ integration: "int-1", provider: "wazuh", outcome: "created" }, 2);
    metrics.ingestLag().observe({ integration: "int-1", provider: "wazuh" }, 42);
    metrics.aiCalls().inc({ provider: "bedrock", purpose: "assistant", outcome: "completed" });
    metrics.sseConnections().inc();
    metrics.sseConnections().inc();
    metrics.sseConnections().dec();
    const text = await metrics.registry().metrics();
    expect(text).toContain('blaksoc_ingest_alerts_total{integration="int-1",provider="wazuh",outcome="created"} 2');
    expect(text).toContain('blaksoc_ingest_lag_seconds_bucket{le="60",integration="int-1",provider="wazuh"} 1');
    expect(text).toContain('blaksoc_ai_calls_total{provider="bedrock",purpose="assistant",outcome="completed"} 1');
    expect(text).toContain("blaksoc_sse_connections 1");
  });

  it("counts each Next.js request once by route pattern and status", async () => {
    const p = new RequestMetricsProcessor();
    p.onEnd(span({ "next.span_type": "BaseServer.handleRequest", "http.method": "GET", "next.route": "/alerts/[id]", "http.status_code": 200 }));
    p.onEnd(span({ "next.span_type": "BaseServer.handleRequest", "http.method": "GET", "next.route": "/alerts/[id]", "http.status_code": 200 }, { isRemote: true }));
    // Nested root span (minimal mode) and child spans are not separate requests.
    p.onEnd(span({ "next.span_type": "BaseServer.handleRequest", "http.method": "GET", "next.route": "/alerts/[id]", "http.status_code": 200 }, { isRemote: false }));
    p.onEnd(span({ "next.span_type": "AppRender.getBodyResult", "next.route": "/alerts/[id]" }));
    const text = await metrics.registry().metrics();
    expect(text).toContain('blaksoc_http_requests_total{method="GET",route="/alerts/[id]",status="200"} 2');
    expect(text).toContain('blaksoc_http_request_duration_seconds_count{method="GET",route="/alerts/[id]"} 2');
  });

  it("serves the registry on its own port", async () => {
    const server = metrics.serveMetrics(0, "127.0.0.1");
    await new Promise((resolve) => (server.listening ? resolve(null) : server.once("listening", resolve)));
    const { port } = server.address() as { port: number };
    const ok = await fetch(`http://127.0.0.1:${port}/metrics`);
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain("blaksoc_sse_connections");
    expect((await fetch(`http://127.0.0.1:${port}/other`)).status).toBe(404);
    server.close();
  });
});
