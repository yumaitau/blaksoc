import { trace, type Tracer } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BatchSpanProcessor, type ReadableSpan, type SpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { httpDuration, httpRequests } from "./metrics";

const g = globalThis as unknown as { __blaksocTracing?: NodeTracerProvider };

/** Spans are exported only when an OTLP endpoint is configured (standard OTEL_* variables). */
export function otlpConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.OTEL_EXPORTER_OTLP_ENDPOINT || env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT);
}

/**
 * Register a tracer provider. Without an OTLP endpoint and without local processors this is a
 * no-op and the OpenTelemetry API stays on its zero-cost default.
 */
export function startTracing(service: string, local: SpanProcessor[] = []): NodeTracerProvider | null {
  if (g.__blaksocTracing) return g.__blaksocTracing;
  const spanProcessors = [...local];
  if (otlpConfigured()) spanProcessors.push(new BatchSpanProcessor(new OTLPTraceExporter()));
  if (!spanProcessors.length) return null;
  const provider = new NodeTracerProvider({ resource: resourceFromAttributes({ "service.name": process.env.OTEL_SERVICE_NAME || service }), spanProcessors });
  provider.register();
  g.__blaksocTracing = provider;
  return provider;
}

/** Flush buffered spans on shutdown. */
export async function stopTracing() {
  await g.__blaksocTracing?.shutdown().catch(() => {});
}

export const tracer = (): Tracer => trace.getTracer("blaksoc");

const ROOT_SPAN = "BaseServer.handleRequest";

/**
 * Request metrics from the root span Next.js already creates per request. `next.route` is the
 * route pattern (/alerts/[id]), so label cardinality stays bounded by the app's routes.
 */
export class RequestMetricsProcessor implements SpanProcessor {
  onStart() {}
  onEnd(span: ReadableSpan) {
    const a = span.attributes;
    if (a["next.span_type"] !== ROOT_SPAN) return;
    // A nested handleRequest (minimal mode) has a local parent; count each request once.
    if (span.parentSpanContext && !span.parentSpanContext.isRemote) return;
    const method = String(a["http.method"] ?? "GET");
    const route = String(a["next.route"] ?? "unmatched");
    httpRequests().inc({ method, route, status: String(a["http.status_code"] ?? 0) });
    httpDuration().observe({ method, route }, span.duration[0] + span.duration[1] / 1e9);
  }
  async forceFlush() {}
  async shutdown() {}
}
