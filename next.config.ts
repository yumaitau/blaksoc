import type { NextConfig } from "next";

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
];

const config: NextConfig = {
  output: "standalone",
  turbopack: { root: import.meta.dirname },
  poweredByHeader: false,
  // Telemetry packages stay external so instrumentation and route code share one copy (one registry, one tracer provider).
  serverExternalPackages: ["bullmq", "ioredis", "postgres", "undici", "@prometheus-io/client", "@opentelemetry/api", "@opentelemetry/sdk-trace-node", "@opentelemetry/sdk-trace-base", "@opentelemetry/exporter-trace-otlp-http", "@opentelemetry/resources"],
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default config;
