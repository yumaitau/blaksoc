# Observability

Platform telemetry for operators: structured logs, a request id that follows work from the web app
into the worker, OpenTelemetry traces, Prometheus metrics, alert rules and a platform dashboard.
None of it carries tenant event data. The per-tenant Grafana dashboard
(`deploy/grafana/dashboards/tenant-ops.json`) is separate and reads Postgres.

| Piece | Where |
| --- | --- |
| Logger and redaction | `src/lib/obs/log.ts` |
| Request id and job correlation | `src/lib/obs/request-id.ts`, `src/lib/obs/context.ts`, `src/proxy.ts`, `src/lib/queue.ts` |
| Metrics registry and `/metrics` server | `src/lib/obs/metrics.ts`, `src/worker/metrics.ts` |
| Scheduler heartbeat | `src/lib/obs/heartbeat.ts` |
| Tracing | `src/lib/obs/tracing.ts`, `src/instrumentation.ts`, `src/instrumentation.node.ts`, `src/worker/instrument.ts` |
| Alert rules, PodMonitor | `deploy/helm/blaksoc/templates/prometheusrule.yaml`, `podmonitor.yaml` |
| Platform dashboard | `deploy/grafana/dashboards/platform-ops.json` |

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `LOG_LEVEL` | `info` (`warn` under tests) | `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT` | JSON | `pretty` prints one readable line per entry for local work. |
| `METRICS_PORT` | unset | Serves `/metrics` on this port. Unset: no metrics server. |
| `METRICS_HOST` | `0.0.0.0` | Bind address for the metrics server. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/HTTP collector, e.g. `http://otel-collector:4318`. Unset: no spans are exported. Other standard `OTEL_*` variables (headers, `OTEL_SERVICE_NAME`) apply. |

The Helm chart sets these from `observability.*` in `values.yaml`. Locally, web and worker both read
`.env.local`, so give each its own `METRICS_PORT` on the command line rather than in the file.

## Logs

Every line is one JSON object on stdout:

```json
{"time":"2026-10-07T07:17:05.839Z","level":"warn","msg":"job attempt failed","service":"worker",
 "requestId":"54335cc6-…","jobId":"execute-8ae4…","queue":"response","job":"execute",
 "tenantId":"aaca59e1-…","attemptsMade":1,"attempts":3,"final":false,"err":{"type":"Error","message":"…"}}
```

- `service` is `web` or `worker`. `requestId`, `jobId`, `queue`, `job` and `tenantId` come from the
  current request or job context and appear only when known. Tenant ids are UUIDs, not names.
- Use `logger.info(msg, fields)` from `@/lib/obs/log`. Keep `msg` constant and put variables in fields,
  so lines can be grouped and searched.

### Redaction

`redact()` runs on every field before it is written; `scrub()` runs on every string, including `msg`
and error messages and stacks.

- Keys naming credentials are replaced with `[redacted]`: anything containing `password`, `secret`,
  `authorization`, `cookie`, `apikey`, `privatekey`, `encryptionkey`, `credential`, `signature`, any key
  ending in `token`, and `key`, `dsn`, `otp`. `inputTokens`/`outputTokens` are kept (usage, not secrets).
- Keys holding tenant telemetry are replaced with `[omitted]`: `raw`, `rawEvent`, `payload`, `body`,
  `line(s)`, `alert(s)`, `finding`, `sourceEvent`, `notification`.
- Strings are scrubbed of `Bearer`/`Basic` credentials, JWTs, URL passwords (`scheme://user:pass@`),
  `token=`/`password=`/`client_secret=`/`sig=` query values, OAuth `?code=`, quoted JSON secrets, and the
  bound parameters Drizzle appends to query errors (`params: …`).
- `Headers` and `Map` values are walked like objects, so a logged request's `authorization` and
  `cookie` headers are redacted.

`tests/unit/log.test.ts` asserts that none of a set of secrets or raw payload fragments reach a log line.
Never log a provider response or an alert object directly; log its id.

Remaining `console.*` calls are in CLI scripts (`src/db/*.ts`), where output goes to a terminal.

## Request id: web to worker

1. `src/proxy.ts` gives every app request an `x-request-id`: a well-formed inbound id (from the ingress)
   is kept, anything else is replaced with a UUID. The id goes on the forwarded request and on the
   response, so a user can quote it.
2. Routes the proxy does not cover assign their own (`/api/ingest/syslog`). Server actions run inside
   `withAccess`, which reads the header into the log context.
3. `queue().add()` attaches `{ _obs: { requestId, trace } }` to the job data from the current context.
4. The worker strips `_obs` before the handler sees the data (it must not leak into outbound webhook
   payloads) and runs the job in a log context with that `requestId`.

To follow a request: take the `x-request-id` from the browser or ingress log and search both services'
logs for `requestId`. Jobs enqueued by other jobs inherit the id. Scheduled jobs have none.

## Traces

`startTracing()` registers a tracer provider. With `OTEL_EXPORTER_OTLP_ENDPOINT` set, spans are batched
to the collector over OTLP/HTTP; without it nothing is exported.

- Web: Next.js creates spans for requests, route handlers, server actions and renders itself
  (`node_modules/next/dist/docs/01-app/02-guides/open-telemetry.md`). The web always registers a provider
  so `RequestMetricsProcessor` can count requests from the root span; spans are still only exported when
  the endpoint is set. `NEXT_OTEL_VERBOSE=1` adds more Next.js spans.
- Worker: each job runs in a `CONSUMER` span named `<queue> <job>`, a child of the enqueuing request's
  trace when the job carried trace context.

## Metrics

Both processes serve `/metrics` on `METRICS_PORT`, a port that is not on the web Service, so the ingress
never routes to it. The NetworkPolicy admits only `observability.metrics.scrapeNamespace` to it. This
avoids a scrape token and keeps the endpoint off the public hostname. Default Node.js process metrics
(`process_*`, `nodejs_*`) are included.

| Metric | Source | Labels |
| --- | --- | --- |
| `blaksoc_worker_heartbeat_timestamp_seconds` | Redis, web and worker | |
| `blaksoc_scheduler_last_run_timestamp_seconds` | Redis, web and worker | `queue`, `schedule` |
| `blaksoc_scheduler_interval_seconds` | Redis, web and worker | `queue`, `schedule` |
| `blaksoc_queue_jobs` | BullMQ, worker | `queue`, `state` (waiting, active, delayed, prioritized, waiting-children, failed) |
| `blaksoc_queue_oldest_waiting_age_seconds` | BullMQ, worker | `queue` |
| `blaksoc_job_duration_seconds` | worker | `queue`, `job`, `outcome` |
| `blaksoc_job_failures_total` | worker | `queue`, `job`, `final` |
| `blaksoc_ingest_alerts_total` | worker | `integration`, `provider`, `outcome` (created, duplicate, unrouted) |
| `blaksoc_ingest_lag_seconds` | worker | `integration`, `provider` |
| `blaksoc_integration_polls_total` | worker | `integration`, `provider`, `kind` (alerts, assets, health), `outcome` |
| `blaksoc_integration_up`, `blaksoc_integration_last_success_timestamp_seconds` | Postgres, worker | `integration`, `provider` |
| `blaksoc_integration_info` | Postgres, worker | `integration`, `provider`, `category`, `name` |
| `blaksoc_syslog_lines_total` | web | `outcome` |
| `blaksoc_ai_calls_total` | web | `provider` (type), `purpose`, `outcome` (completed, denied, error) |
| `blaksoc_sse_connections` | web | |
| `blaksoc_http_requests_total`, `blaksoc_http_request_duration_seconds` | web | `method`, `route` (pattern), `status` |

`integration` is the integration id. Join names with
`* on (integration) group_left(name) blaksoc_integration_info`. HTTP `route` is the Next.js route
pattern (`/soc/alerts/[id]`); responses the proxy ends itself (sign-in redirects) appear as `unmatched`.

Queue, scheduler and integration series are read at scrape time from Redis or Postgres, so every replica
reports the same values. Aggregate with `max by`, not `sum`.

### Heartbeat

The worker writes `blaksoc:worker:heartbeat` (epoch ms) and a field in `blaksoc:scheduler:last-run`
whenever a scheduled job starts, and the schedule intervals to `blaksoc:scheduler:interval` on boot.
The fastest schedules tick every 30 seconds. Web pods export the same keys, so when every worker is
stopped the heartbeat goes stale on the web pods rather than disappearing with the worker's scrape target.

### Failed jobs

The worker's `failed` hook (including stalled jobs) increments `blaksoc_job_failures_total` and logs
`job attempt failed` (warn) or `job failed` (error, no attempts left) with the job id and request id.
A failed integration poll or probe also sets `integrations.status`; the tenant health sweep
(`src/lib/services/health.ts`, every 5 minutes) raises an `Integration failing: <name>` health alert
for an owned or linked integration that is still failing with no success inside the tenant's poll-lag
limit (60 minutes by default), and resolves it on the next success. Identity polls (M365, Entra,
Google Workspace) keep their existing `Polling lag` alert.

## Alerts

Enable with `observability.prometheusRule.enabled` (Prometheus Operator). Thresholds are in values.

| Alert | Fires when | First check |
| --- | --- | --- |
| `BlaksocWorkerHeartbeatStale` (critical) | No scheduled job started for `heartbeatStaleSeconds` (120s) for 1m | Worker pods, Redis reachability, worker logs for `worker failed to start`. |
| `BlaksocHeartbeatMissing` (critical) | No pod reports the heartbeat for 3m | Pods running? PodMonitor selecting them? NetworkPolicy scrape namespace? |
| `BlaksocSchedulerStalled` | A schedule is more than three intervals plus 5m late | `blaksoc_queue_jobs` for that queue; a long-running job on a concurrency-1 queue blocks its schedules. |
| `BlaksocQueueBacklogGrowing` | Waiting jobs above `queueBacklog` and rising for 15m | Job duration and failures for the queue; add worker replicas. |
| `BlaksocOldestJobAgeHigh` | A runnable job has waited over `oldestJobAgeSeconds` | Stuck or saturated worker. |
| `BlaksocJobFailureRate` | Over `jobFailureRatio` of job attempts fail for 15m | Worker logs, `msg="job failed"`, filter by `queue`. |
| `BlaksocIntegrationFailing` | An integration is down with no success in `integrationFailingSeconds` (or never) | Integration page, `lastError`; logs `msg="integration poll failed"`. |
| `BlaksocWebErrorRate` | Over 5% of web requests return 5xx for 10m | Web logs, `msg="request failed"`. |

A stopped worker: the last heartbeat is at most 30 seconds old when it stops, the expression is true
90–120 seconds later, and with a 1-minute evaluation interval plus `for: 1m` the alert fires within about
4 minutes, inside the 5-minute target.

## Dashboard

Import `deploy/grafana/dashboards/platform-ops.json` into Grafana. It asks for a Prometheus data source
and a namespace, and shows the heartbeat, schedule lag, queue depth and age, job failures and duration,
ingest throughput and lag per integration, integration status, syslog and AI call rates, and web
request rates, latency and SSE streams.

## Not yet done

- No log shipping config (Vector/Fluent Bit); any collector that reads container stdout works.
- No OpenTelemetry metrics or logs export; metrics are Prometheus only.
- No liveness probe on the worker; the metrics port could serve one.
- No per-tenant ingest lag or SLO burn-rate alerts.
