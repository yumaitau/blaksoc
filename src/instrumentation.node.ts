import { registerHeartbeatMetrics } from "@/lib/obs/heartbeat";
import { logger } from "@/lib/obs/log";
import { serveMetrics } from "@/lib/obs/metrics";
import { RequestMetricsProcessor, startTracing } from "@/lib/obs/tracing";

// Request counts come from the root span Next.js already emits, so a local processor is always
// registered; spans are exported only when OTEL_EXPORTER_OTLP_ENDPOINT is set.
startTracing("blaksoc-web", [new RequestMetricsProcessor()]);

// Metrics live on their own port, not behind the ingress: the Service and NetworkPolicy expose it
// to the monitoring namespace only, so no token is needed and nothing is public. Skipped at build.
const port = Number(process.env.METRICS_PORT);
if (port && process.env.NEXT_PHASE !== "phase-production-build") {
  // Web pods report the worker heartbeat too, so a stopped worker shows as stale, not absent.
  registerHeartbeatMetrics();
  serveMetrics(port);
  logger.debug("web instrumentation registered", { metricsPort: port });
}
