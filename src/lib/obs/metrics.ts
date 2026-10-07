import { createServer, type Server } from "node:http";
import { collectDefaultMetrics, Counter, Gauge, Histogram, Registry } from "@prometheus-io/client";
import { logger } from "./log";

/**
 * Prometheus metrics. Families are created on first use, so each process (web or worker) exposes
 * only what it records: a worker-only gauge never shows up as a stale zero on a web pod.
 */
type Store = { registry: Registry; families: Map<string, unknown>; server?: Server };
// Shared across Next bundles (instrumentation and route code) in one process.
const g = globalThis as unknown as { __blaksocMetrics?: Store };

function store(): Store {
  if (!g.__blaksocMetrics) {
    const registry = new Registry();
    collectDefaultMetrics({ register: registry });
    g.__blaksocMetrics = { registry, families: new Map() };
  }
  return g.__blaksocMetrics;
}

export const registry = () => store().registry;

function family<T>(name: string, make: (registers: Registry[]) => T): () => T {
  return () => {
    const s = store();
    let m = s.families.get(name) as T | undefined;
    if (!m) {
      m = make([s.registry]);
      s.families.set(name, m);
    }
    return m;
  };
}

// Worker jobs.
export const jobDuration = family("job_duration", (registers) => new Histogram({ name: "blaksoc_job_duration_seconds", help: "Worker job run time by queue, job name and outcome.", labelNames: ["queue", "job", "outcome"] as const, buckets: [0.05, 0.25, 1, 5, 15, 60, 300, 900], registers }));
export const jobFailures = family("job_failures", (registers) => new Counter({ name: "blaksoc_job_failures_total", help: "Failed worker job attempts. final=true when no attempts remain.", labelNames: ["queue", "job", "final"] as const, registers }));

// Ingest. `integration` is the integration id; join blaksoc_integration_info for its name.
export const ingestAlerts = family("ingest_alerts", (registers) => new Counter({ name: "blaksoc_ingest_alerts_total", help: "Alerts read from providers, by outcome (created, duplicate, unrouted).", labelNames: ["integration", "provider", "outcome"] as const, registers }));
export const ingestLag = family("ingest_lag", (registers) => new Histogram({ name: "blaksoc_ingest_lag_seconds", help: "Delay from an alert occurring at the provider to blakSOC creating it.", labelNames: ["integration", "provider"] as const, buckets: [10, 30, 60, 300, 900, 1800, 3600, 6 * 3600, 24 * 3600], registers }));
export const integrationPolls = family("integration_polls", (registers) => new Counter({ name: "blaksoc_integration_polls_total", help: "Provider polls (alerts, assets, health) by outcome.", labelNames: ["integration", "provider", "kind", "outcome"] as const, registers }));
export const syslogLines = family("syslog_lines", (registers) => new Counter({ name: "blaksoc_syslog_lines_total", help: "Syslog lines received on /api/ingest/syslog by outcome.", labelNames: ["outcome"] as const, registers }));

// AI. Provider is the provider type, never a key or endpoint.
export const aiCalls = family("ai_calls", (registers) => new Counter({ name: "blaksoc_ai_calls_total", help: "AI provider invocations by provider, purpose and outcome (completed, denied, error).", labelNames: ["provider", "purpose", "outcome"] as const, registers }));

// Web.
export const sseConnections = family("sse_connections", (registers) => new Gauge({ name: "blaksoc_sse_connections", help: "Open live-update (SSE) streams on this web pod.", registers }));
export const httpRequests = family("http_requests", (registers) => new Counter({ name: "blaksoc_http_requests_total", help: "Requests served by Next.js, by method, route pattern and status.", labelNames: ["method", "route", "status"] as const, registers }));
export const httpDuration = family("http_duration", (registers) => new Histogram({ name: "blaksoc_http_request_duration_seconds", help: "Next.js request time by method and route pattern.", labelNames: ["method", "route"] as const, buckets: [0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10], registers }));

/** Register a gauge whose value is read at scrape time. Collection errors are logged, never fail the scrape. */
export function collectedGauge<L extends string>(name: string, help: string, labelNames: readonly L[], collect: (set: (labels: Record<L, string>, value: number) => void) => Promise<void>) {
  return family(name, (registers) => {
    const gauge: Gauge<L> = new Gauge({
      name,
      help,
      labelNames,
      registers,
      async collect() {
        gauge.reset();
        try {
          await collect((labels, value) => gauge.set(labels as never, value));
        } catch (err) {
          logger.warn("metrics collection failed", { metric: name, err });
        }
      },
    });
    return gauge;
  })();
}

/**
 * Serve /metrics on its own port. The port is never behind the ingress, so the endpoint needs no
 * token: only the monitoring namespace may reach it (see the chart's NetworkPolicy).
 */
export function serveMetrics(port: number, host = process.env.METRICS_HOST ?? "0.0.0.0"): Server {
  const s = store();
  if (s.server) return s.server;
  const server = createServer((req, res) => {
    if (req.method !== "GET" || (req.url !== "/metrics" && !req.url?.startsWith("/metrics?"))) {
      res.writeHead(404).end();
      return;
    }
    s.registry
      .metrics()
      .then((body) => res.writeHead(200, { "content-type": s.registry.contentType }).end(body))
      .catch((err: unknown) => {
        logger.error("metrics render failed", { err });
        res.writeHead(500).end();
      });
  });
  server.on("error", (err) => logger.warn("metrics server error", { port, err }));
  server.listen(port, host, () => logger.info("metrics listening", { port }));
  // Never keeps the process alive on its own (worker shutdown, tests).
  server.unref();
  s.server = server;
  return server;
}
