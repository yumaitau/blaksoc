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
alerts / observables / intel_matches rows (RLS scope = that tenant)  →  Redis pub/sub → SSE
      ▼
evaluateTriggers("alert.created")  →  playbook runs  →  approval gates  →  response actions
```

Scheduled jobs (`src/worker/index.ts`): alert poll 30s, asset sync 15m, vulnerability sync 1h,
integration health 5m, Sigma deployments 5m, CISA KEV + FIRST EPSS + OpenCTI CVE context 6h,
ACSC/CISA advisories 1h.

## Provider abstraction

`SecurityEventProvider` (`src/lib/providers/types.ts`): `getAlerts`, `getAlert`, `searchEvents`,
`getAssets`, `getAsset`, `getVulnerabilities?`, `supportedActions`, `executeResponseAction`, `health`.
Nothing outside an adapter touches vendor shapes. New SIEM = one class + one connector definition.

`IntelProvider` (`src/lib/intel/types.ts`) plays the same role for CTI; OpenCTI is the implementation,
and blakSOC stores only what it needs locally (CVE scoring context, advisories, sector tags, per-tenant matches).

## Risk scores are explainable by construction

Both engines (`src/lib/risk/engine.ts`) are pure functions that return `{ score, factors[] }`, where each
factor has points, a label, evidence text and, where possible, a reference to the record behind it. The
score is the capped sum of factor points. The UI always renders the factors; no model output feeds scores.

## Detections

Sigma YAML is the source of truth. Each save creates an immutable version (sha256). Tests evaluate a
version against sample events with blakSOC's Sigma evaluator. Deploying converts the current version to an
OpenSearch `query_string` with Wazuh field mappings and records a per-tenant deployment; the worker runs it
every 5 minutes against that tenant's agents and feeds hits back through the normal ingest pipeline
(`source = blaksoc-sigma`). ATT&CK coverage compares enabled rules and active deployments against observed
alerts and incidents per technique.

## SOAR

Playbook = trigger (event + conditions) + ordered steps (`when` guards, `requireApproval`,
`continueOnError`). Non-destructive steps: OpenCTI enrichment, asset/endpoint context, incident creation,
notification, record note, explicit approval gate. Response steps (isolate, disable identity, block IOC…)
always go through `requestResponseAction()`, which creates an approval unless the tenant has
admin-enabled auto-containment and the requester is a playbook (never AI). Runs pause at gates and resume
when a human decides.

## UI routes

| Route | Purpose |
|---|---|
| `/soc` | SOC dashboard: what is happening, what matters, who is affected, what next, what was done |
| `/soc/mssp` | Per-customer roll-up; enter a customer workspace |
| `/soc/alerts`, `/soc/alerts/[id]` | Unified queue (saved views, bulk actions) and alert detail with risk factors + intel |
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
