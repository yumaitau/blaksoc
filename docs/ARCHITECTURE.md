# blakSOC architecture

## Data flow: alert to analyst

```
Wazuh indexer (wazuh-alerts-*) ──poll 30s, search_after cursor──► WazuhProvider.getAlerts()
      │  NormalisedAlert { externalId, severity, agent, user, ATT&CK, raw }
      ▼
route to tenant: agent id → asset_sources → tenant   (shared cluster: agent groups per tenant link)
      ▼
extractObservables(raw)   ipv4/ipv6/domain/url/md5/sha1/sha256/email/hostname/cve/user
      ▼
lookupWithCache()  Redis 1h (hit) / 15m (miss)  →  OpenCTI GraphQL (observables, then indicators)
      ▼
filterByEntitlement()  drop commercial-feed intel the tenant isn't licensed for
      ▼
scoreAlert()  SIEM severity + asset criticality + exposure + identity privilege + intel
              + KEV/EPSS + high-impact ATT&CK + repetition + active incident  → 0–100 + factors
      ▼
ocsfForAlert() + validateOcsf()  Detection Finding (+ Network Activity / Authentication source record)
      ▼
alerts / observables / intel_matches rows (RLS scope = that tenant)  →  Redis pub/sub → SSE
      ▼
evaluateTriggers("alert.created")  →  playbook runs  →  approval gates  →  response actions
```

Scheduled jobs (`src/worker/index.ts`, `SCHEDULES`): alert poll 30s, in-flight response action status 30s,
Kelpie sync and escalations 1m, integration health and tenant health 5m, Sigma deployments 5m, approval expiry 5m,
asset sync, DFIR release and attested surface scans 15m, vulnerability sync, syslog archive, ACSC/CISA advisories and
board summaries 1h, CISA KEV + FIRST EPSS + OpenCTI CVE context 6h.

Notifications: webhook, Teams and Slack integrations list the bus events they want (`events` in their config).
`publish()` queues a `notify` job for subscribed event types; the worker sends one delivery job per integration,
which BullMQ retries with backoff and keeps on failure.

## Provider abstraction

`SecurityEventProvider` (`src/lib/providers/types.ts`): `getAlerts`, `getAlert`, `searchEvents`,
`getAssets`, `getAsset`, `getVulnerabilities?`, `supportedActions`, `executeResponseAction`, `health`.
Nothing outside an adapter touches vendor shapes. New SIEM = one class + one connector definition.

### Query-in-place search

`SecurityDataProvider` (`src/lib/providers/data.ts`) reads events where they live and returns OCSF events
with provenance; nothing is copied into Postgres. `capabilities()` declares search, event lookup, entity
activity, OCSF classes, the longest range, paging, free-text syntax, typed filters (`severity`, `host`,
`user`, `ip`, `ruleId`) and tiers. `search()` takes time bounds, typed filters, free text, page size and an
opaque cursor; `getEvent(id)`, `getEntityActivity(entity, range)` and `health()` complete it.

An event provider opts in with `dataProvider(scope)`, which binds it to one tenant's slice of the source
(`TenantDataScope`). Existing providers keep working unchanged; connectors without an adapter declare
`NO_DATA_CAPABILITIES` through the registry (`data` on the connector definition, `dataCapabilitiesOf()`).

| Source | Reads | Tenant filter | Paging | OCSF |
| --- | --- | --- | --- | --- |
| Wazuh | `wazuh-alerts-*`, plus `archivesIndex` when configured, through the SSRF-guarded fetch | `terms` on the tenant's agent ids (asset_sources + link selector) on a shared cluster; no query at all when the tenant has no agents | `search_after` on `timestamp`, `_id` | Detection Finding; Base Event for records with no rule |
| Syslog | Hot lines in `syslog_events`; cold lines from the AU archive object store (`scanArchive`, capped per page) | The integration's stamped owner, under that tenant's RLS scope | Keyset on receive time per tier | Network Activity; Base Event when no IPs |
| Demo | Deterministic synthetic events for the seeded cluster | Tenant's agents | Slot cursor | Detection Finding |

`src/lib/services/search.ts` federates a tenant's sources: it resolves every enabled event integration
serving the tenant (tenant-owned, or platform-owned with a tenant link), runs them in parallel with a
per-source timeout, and reports each as `ok`, `partial`, `error` or `unsupported` (no adapter, a typed
filter it cannot apply, or not in the tenant's plan). One failing source never fails the search. Searching
needs `alert:triage` in the tenant and the first page of each search is audited (`event.search`).
`listTenantDataSources()` and `connectorDataCapabilities()` expose capability discovery.

The alert queue's free text uses a generated `tsvector` with a GIN index (`alerts.search_vector`,
migration 0033) alongside the substring match on title, user and asset.

`IntelProvider` (`src/lib/intel/types.ts`) plays the same role for CTI; OpenCTI is the implementation,
and blakSOC stores only what it needs locally (CVE scoring context, advisories, sector tags, per-tenant matches).

## Canonical event schema

Alerts are stored with an OCSF Detection Finding and, where blakSOC maps the source record, that record in its
OCSF activity class. Provenance (source, source event id, tenant, ingestion time, normaliser version) is in OCSF
`metadata`; the vendor payload stays in `alerts.raw`. See [ocsf.md](ocsf.md).

## Risk scores are explainable by construction

Both engines (`src/lib/risk/engine.ts`) are pure functions that return `{ score, factors[] }`, where each
factor has points, a label, evidence text and, where possible, a reference to the record behind it. The
score is the capped sum of factor points. The UI always renders the factors; no model output feeds scores.

## Detections

Sigma YAML is the source of truth. Each save creates an immutable version (sha256). Tests evaluate a
version against sample events with blakSOC's Sigma evaluator. Deploying converts the current version to an
OpenSearch `query_string` with Wazuh field mappings and records a per-tenant deployment; the worker runs it
every 5 minutes against that tenant's agents and feeds hits back through the normal ingest pipeline
(`source = blaksoc-sigma`). A customer with no shared-SIEM link that owns a provider able to run Sigma itself
(`deployDetection`, e.g. Tawny) gets the raw YAML pushed there instead; that provider's own alerts carry the hits. ATT&CK coverage compares enabled rules and active deployments against observed
alerts and incidents per technique.

## SOAR

Playbook = trigger (event + conditions) + ordered steps (`when` guards, `requireApproval`,
`continueOnError`). Non-destructive steps: OpenCTI enrichment, asset/endpoint context, incident creation,
notification, record note, explicit approval gate. Response steps (isolate, disable identity, block IOC…)
always go through `requestResponseAction()`, which creates an approval unless the tenant has
admin-enabled auto-containment and the requester is a playbook. Anything an AI proposes waits for a human,
destructive or not. Runs pause at gates and resume when a human decides; a gate nobody decides expires after 24h
and cancels the run. Each run stores the steps it started with, so editing a playbook never changes a run in flight.

Most providers finish a response action in the call. Endpoint agents that act on their next check-in
(Tawny) return `pending` with a provider reference; the action stays `EXECUTING`, the worker asks
`getResponseActionStatus` every 30s, and settles it `SUCCEEDED`/`FAILED` from the agent's answer, or
`FAILED` after 15 minutes. The blakSOC action id goes to the provider as its idempotency key.

## UI routes

| Route | Purpose |
|---|---|
| `/soc` | SOC dashboard: what is happening, what matters, who is affected, what next, what was done |
| `/soc/mssp` | Per-customer roll-up; enter a customer workspace |
| `/soc/alerts`, `/soc/alerts/[id]` | Unified queue (saved views, bulk actions) and alert detail with risk factors + intel |
| `/soc/hunt` | Event search across a customer's sources in place (Wazuh, syslog, cold syslog archive) with per-source status |
| `/soc/incidents`, `/soc/incidents/[id]` | Case management with visual timeline, evidence, tasks, containment |
| `/soc/approvals` | Human approval gates |
| `/assets`, `/assets/[id]` | Deduplicated asset inventory |
| `/vulnerabilities` | "What should this customer patch first?" with evidence |
| `/intel` | Australian threat intelligence, OpenCTI search/tagging, sightings, feeds & licences |
| `/detections`, `/detections/rules/[id]`, `/detections/attack` | Sigma repository, tests, deployment, ATT&CK coverage |
| `/soar/playbooks`, `/soar/runs` | Playbook builder and run history |
| `/integrations` | Connector catalogue, health, secrets (write-only), audit |
| `/reports` | Daily/weekly/monthly/incident/vuln/intel/Essential Eight/coverage/SLA — PDF, CSV, JSON |
| `/assistant` | AI SOC analyst with verified citations |
| `/portal` | Customer portal |
| `/admin`, `/admin/audit` | Tenants & policies, users & roles, IdPs, audit trail + integrity check |

Server components read through `src/lib/services/*`; mutations are server actions wrapped in
`withAccess()`. Live updates arrive over `/api/stream` (SSE) and trigger a throttled `router.refresh()`.

## Tables (abridged)

Platform: `tenants`, `sites`, `roles`, `role_assignments`, `saved_views`, auth tables.
Security: `alerts`, `observables`, `alert_observables`, `intel_matches`, `assets`, `asset_sources`,
`vulnerabilities`, `incidents`, `incident_alerts`, `incident_links`, `incident_timeline`, `incident_notes`,
`incident_tasks`, `evidence`. Detection: `sigma_rules`, `sigma_rule_versions`, `sigma_rule_tests`,
`detection_deployments`. SOAR: `playbooks`, `playbook_runs`, `playbook_run_steps`, `approvals`,
`response_actions`. AI: `ai_conversations`, `ai_messages`, `ai_invocations`. Reports: `reports`.
Global reference (no tenant data): `cve_intel`, `attack_techniques`, `intel_feeds`, `advisories`, `intel_tags`.
Audit: `audit_log` (append-only, hash-chained).
