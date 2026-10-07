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
      +  entity graph: alert, device, user, observable, indicator entities and edges (same transaction)
      ▼
evaluateTriggers("alert.created")  →  playbook runs  →  approval gates  →  response actions
```

Scheduled jobs (`src/worker/schedules.ts`, `SCHEDULES`; recreated within a minute if Redis loses them): alert poll 30s, in-flight response action status 30s,
Kelpie sync, escalations, and correlation + incident grouping 1m, integration health and tenant health 5m, Sigma deployments 5m, approval expiry 5m,
asset sync, DFIR release and attested surface scans 15m, vulnerability sync, syslog archive, ACSC/CISA advisories and
board summaries 1h, CISA KEV + FIRST EPSS + OpenCTI CVE context 6h.

Notifications: webhook, Teams and Slack integrations list the bus events they want (`events` in their config).
`publish()` queues a `notify` job for subscribed event types; the worker sends one delivery job per integration,
which BullMQ retries with backoff and keeps on failure.

## Provider abstraction

`SecurityEventProvider` (`src/lib/providers/types.ts`): `getAlerts`, `getAlert`, `searchEvents`,
`getAssets`, `getAsset`, `getVulnerabilities?`, `supportedActions`, `executeResponseAction`, `health`.
Nothing outside an adapter touches vendor shapes. New SIEM = one class + one connector definition.

`IntelProvider` (`src/lib/intel/types.ts`) plays the same role for CTI; OpenCTI is the implementation,
and blakSOC stores only what it needs locally (CVE scoring context, advisories, sector tags, per-tenant matches).

## Canonical event schema

Alerts are stored with an OCSF Detection Finding and, where blakSOC maps the source record, that record in its
OCSF activity class. Provenance (source, source event id, tenant, ingestion time, normaliser version) is in OCSF
`metadata`; the vendor payload stays in `alerts.raw`. See [ocsf.md](ocsf.md).

## Entity graph

Postgres tables under the same forced RLS as everything else (`src/db/schema/graph.ts`, `src/lib/graph`).
No graph database: revisit only with a measured need.

- `entities`: one row per (tenant, type, canonical key). Types: user, identity, device, ip, domain, url, file,
  process, cloud_resource, indicator, threat_actor, campaign, email, alert. Keys are normalised per type
  (`canonicalKey`): devices on short hostname (the asset dedup key), users lowercased, files as `sha256:<hex>`.
  Identifiers (jsonb), source systems and first/last seen merge on upsert.
- `entity_aliases`: alternate identifiers (asset id, MAC, FQDN, provider source id, account name) → entity.
  First claim wins.
- `entity_relationships`: directed, typed edges, unique on (tenant, from, to, type), with first/last seen,
  count, provenance and the record that created the edge. `observed` means a record states the relationship;
  `inferred` means blakSOC derived it (a user name matched to an identity, a user acting on a device without
  a sign-in record). Once any record states an edge it stays `observed`.
- `entity_relationship_evidence`: every record (alert, asset, intel match) that asserted an edge. An edge's
  count only moves when a new evidence row lands, so re-ingest and backfill are idempotent.

Aliases and edges reference entities by (id, tenant_id), so the database rejects a row joining two tenants.

| Edge | From → to | Written by | Provenance |
|---|---|---|---|
| `alerted_on` | alert → device, user, ip, domain, url, file, email | ingest | observed |
| `logged_into` | user → device | ingest | observed on a successful sign-in; inferred when the user merely acted on the device; none for a failed sign-in |
| `communicated_with` | ip → ip | ingest (OCSF Network Activity) | observed |
| `matched` | alert → indicator | ingest (intel match) | observed |
| `indicates` | indicator → ip, domain, url, file, email | ingest (intel match) | observed |
| `attributed_to` | indicator → threat actor, campaign | ingest (intel match) | observed |
| `has_ip` | device → ip | asset sync | observed |
| `same_as` | user → identity | ingest and asset sync (account-name match) | inferred |

Writers: `ingestAlert` and `syncAssets` record facts inside their own transaction behind a savepoint, so a
failed graph write is logged and never costs the alert or asset. `pnpm db:graph-backfill [tenantId]`
(`src/lib/graph/backfill.ts`) rebuilds a tenant from stored assets and alerts; the demo seed runs it.

Traversal (`traverse`, `src/lib/graph/traverse.ts`): breadth-first from one entity, one indexed query per hop,
edges followed in both directions, depth capped at 3, optional entity-type and relationship-type filters, and a
row limit (default 200, max 1000) that keeps entities on the most recent edges first. Returns the entities
reached with their hop count and the edges among them, with provenance. Per-hop queries rather than one
recursive CTE: a CTE cannot share a visited set across branches, so a hub is re-expanded on every path. It runs
in the caller's RLS scope and filters by tenant, so another tenant's entity id returns nothing.

Measured traversal latency (depth 3, Postgres 16, Apple M4, warm cache):

| Data | Graph size | Limit | p50 | p95 |
|---|---|---|---|---|
| Demo seed (one `pnpm db:seed`), every user and identity as start, 22 × 10 runs | 159 entities, 205 edges | 200 | 1.8 ms | 2.9 ms |
| Synthetic busy user: 2,000 alerts, 50 devices, 10,350 edges (`tests/integration/graph.test.ts`) | 10,350 edges | 200 | 17.0 ms | 23.6 ms |
| Same | 10,350 edges | 1000 | 29.4 ms | 37.0 ms |

The integration test fails if p50 at limit 200 exceeds 500 ms.

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

## Correlation and incident grouping

Correlation rules (`src/lib/correlation/rules.ts`) are typed definitions: entity keys to group by, a time window,
and one clause: an ordered **sequence** (steps with alternatives, per-step counts, "new value" and "differs from
step" conditions), a **count** threshold (optionally of distinct values), an **absence** (A not followed by B,
decided once the window closes) or **risk accumulation** (summed alert risk), plus optional corroborating
`require` clauses. The evaluator (`src/lib/correlation/engine.ts`) is pure like the risk engine: each finding
lists exactly which events met which clause, and its dedupe key (rule, entity, anchor event) is stable across runs.

`source` rules run inside a provider over raw records (Entra impossible travel and MFA fatigue run in the M365
provider). `alerts` rules (account takeover, user/host risk accumulation, source-IP fan-out) run every minute
per tenant over stored alerts, from a cursor minus each rule's look-back. New findings go through the normal
ingest path (`source = blaksoc-correlation`, so scoring, OCSF, SSE and playbooks apply) and a
`correlation_findings` row records rule id, version and clause matches. Tenants can switch rules off.

Grouping (`src/lib/correlation/grouping.ts`) then links open alerts that share a user or asset inside 6 hours and
share an ATT&CK technique or tactic, or that a correlated alert was built from. A group joins the open incident
one of its alerts is in, or opens a new one (`incidents.grouping_key`). Links carry `origin = auto`, the reason and
the alert's prior status. An analyst can ungroup: links go, statuses come back, an emptied auto incident closes,
the timeline records it, and grouping leaves those alerts alone afterwards.

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
| `/soc/incidents`, `/soc/incidents/[id]` | Case management with visual timeline, evidence, tasks, containment |
| `/soc/approvals` | Human approval gates |
| `/soc/entities/[id]` | Entity: identifiers, aliases, neighbours by relationship with provenance and evidence, reach within 3 hops |
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
`incident_tasks`, `evidence`. Graph: `entities`, `entity_aliases`, `entity_relationships`,
`entity_relationship_evidence`. Detection: `sigma_rules`, `sigma_rule_versions`, `sigma_rule_tests`,
`detection_deployments`, `correlation_findings`, `correlation_rule_settings`, `correlation_cursors`,
`incident_group_exclusions`. SOAR: `playbooks`, `playbook_runs`, `playbook_run_steps`, `approvals`,
`response_actions`. AI: `ai_conversations`, `ai_messages`, `ai_invocations`. Reports: `reports`.
Global reference (no tenant data): `cve_intel`, `attack_techniques`, `intel_feeds`, `advisories`, `intel_tags`.
Audit: `audit_log` (append-only, hash-chained).
