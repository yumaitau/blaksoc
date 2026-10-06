# blakSOC enterprise gap analysis

## Purpose and method

This document compares the blakSOC repository with the enterprise SOC target set out in the
Enterprise SOC Gap-Closure & Differentiation Program. The target is an open, sovereign,
vendor-neutral, agent-first security operations control plane. Every rating below comes from reading
the implementation: schema, services, worker jobs, UI routes, deploy files, tests and docs. File
references point at the evidence.

- **Baseline:** `main` at `66224d5` (2026-10-06).
- **Not yet merged:** PR #68 (`deploy/yumait-prod`) adds AWS/EKS deployment, External Secrets and
  hardened EC2 host scripts. It is noted where it changes a rating.
- **Not measured:** no load, penetration or accessibility audit was run for this analysis. Ratings
  on those topics come from code and docs only.

### Ratings

Ratings are against the enterprise target, not against blakSOC's original V1 scope. A V1 feature
that works as designed can still be PARTIAL here.

| Rating | Meaning |
| --- | --- |
| COMPLETE | Meets the target for this phase. Further work is optional polish. |
| PARTIAL | A real implementation exists, but significant parts of the target are absent. |
| MISSING | Nothing usable exists. Isolated fragments may be noted. |
| NEEDS HARDENING | The design is right and largely built, but correctness, safety or operational gaps block enterprise use. |
| DEFER | Deliberately out of scope for now, with a reason. |

## Executive summary

blakSOC is further along than its README suggests. It already holds several properties that the
large vendor platforms do not offer and that the target market cares about:

- **Tenant isolation by construction.** Every tenant table has forced Postgres RLS
  (`src/db/sql/005_rls.sql`), the app connects as a `NOBYPASSRLS` role, and scope is set per
  transaction (`src/db/scope.ts:17-27`).
- **Explainable, deterministic risk.** Alert and vulnerability scores are pure functions that
  return the factors behind every point (`src/lib/risk/engine.ts`). No model output feeds a score.
- **Tamper-evident audit.** `audit_log` is append-only and hash-chained, with an integrity check
  (`src/db/sql/010_audit.sql`).
- **Human-gated response.** Destructive actions always go through `requestResponseAction()`
  (`src/lib/soar/response.ts:36`). AI requests are never auto-approved.
- **Sovereignty as policy.** AU residency checks for AI and intel, a data-steward governance profile
  with a two-person rule, AU-pinned archives, and consented, anonymised OpenCTI sightings.
- **Australian obligations.** NDB 30-day assessment clocks, OAIC draft notices, Essential Eight
  scoring, ACSC advisories, board reports and an Indigenous co-design track (in draft).

The headline gaps against the enterprise target are architectural, not cosmetic:

1. **No security data fabric.** Every alert is copied into Postgres. Provider event search exists
   only for scheduled Sigma runs, with no federated query and no hunting UI.
2. **No entity graph.** Assets and observables are deduplicated well, but there is no generic
   entity or relationship model, no entity pages beyond assets, and no traversal API.
3. **No correlation engine.** Two hard-coded M365 correlators exist. There are no sequences, windows,
   thresholds or automatic incident grouping.
4. **No programmable surface.** There is no external API, no service identities, no MCP server, no
   durable event bus and no webhook subscriptions.
5. **No agent runtime.** The AI is one assistant with good guardrails. There are no typed agents,
   handoffs, stored reasoning summaries, cost limits or caching.
6. **Operational maturity.** There are no metrics, tracing or structured logs, no platform backup
   or DR, no data retention, no security scanning in CI, and the Helm chart on `main` does not start.

### Ratings by area

| Rating | Count | Capabilities |
| --- | --- | --- |
| COMPLETE | 4 | Threat intelligence, OpenCTI, MITRE ATT&CK, training and awareness |
| PARTIAL | 27 | Architecture, authentication, SIEM abstraction, normalisation, detection engineering, Sigma, detection testing, risk-based alerting, investigations, cases, timeline, entity modelling, AI, AI gateway, integration coverage, search, dashboards, reporting, MSSP, SLA, webhooks and events, exposure context, AU obligations, deployment and CI, testing, UX and accessibility, documentation |
| NEEDS HARDENING | 13 | Tenancy, authorisation, audit, ingestion, evidence, SOAR, approval workflows, connector framework, data residency, HA, Kubernetes, secrets, Indigenous data governance |
| MISSING | 15 | Correlation, graph relationships, agent architecture, agent handoffs, MCP, external agent API, public APIs, investigation memory, knowledge base, AI cost governance, attack paths, data retention, observability, DR, security testing |
| DEFER | 1 | STIX/TAXII server |

The detailed matrix below has one row per capability.

## Defects found during the analysis

These are bugs or contradictions with documented behaviour, not missing features. They should be
fixed before feature work, because several weaken controls the new program depends on.

**Update:** all 19 were fixed on branch `docs/enterprise-gap-analysis`, with unit tests and database
tests in `tests/integration/hardening.test.ts`. The table records what was found; the status column
records how each claim was confirmed before it was fixed. **Verified**
means the claim was checked directly against the code while writing this document. **Reported**
means it came from the evidence sweep and should be confirmed when it is fixed.

| # | Severity | Status | Where | Defect |
| --- | --- | --- | --- | --- |
| D1 | High | Verified | `src/lib/services/admin.ts:77-95` | `assignRole` has no grant ceiling. Anyone with `user:manage` on a tenant can assign any tenant-scope role there. A `customer_admin` can grant `partner_admin` on its own tenant, which adds `tenant:manage`, `settings:manage` and `mssp:read` (`src/lib/auth/permissions.ts:88-124`). A customer admin can also create data stewards, which weakens the two-person governance rule. |
| D2 | High | Verified | `src/proxy.ts:18` | The proxy matcher exempts `api/auth` and `api/health` but not `api/ingest`. A syslog POST from Vector carries a bearer token and no session cookie, so it is redirected to `/login`. The integration test calls the handler directly and cannot catch this (`tests/integration/syslog.test.ts`). |
| D3 | High | Verified | `Dockerfile:27,38`, `deploy/helm/blaksoc/values.yaml:67` | The images run as the named user `blaksoc`, and the chart sets `runAsNonRoot: true` with no `runAsUser`. Kubernetes cannot verify a non-numeric user and refuses to start the container. PR #68 works around this only in `values-yumait-prod.yaml`. |
| D4 | Medium | Verified | `src/db/client.ts:21-23`, `src/lib/services/onboarding.ts` (23 uses) | The web tier holds the owner database credentials (`DATABASE_ADMIN_URL` arrives through the shared Secret) and uses `adminDb()` in request paths. RLS is bypassed on those paths, and a web-tier compromise gets owner access. |
| D5 | Medium | Verified | `src/lib/ai/tools.ts:139`, `src/lib/soar/response.ts:40-41,97` | `propose_response_action` says actions are "always queued for human approval". Non-destructive actions (`release_endpoint`, `scan_endpoint`, `unblock_ioc`) execute immediately. `docs/SECURITY.md` states that AI-originated actions are always approval-gated. Unblocking an IOC or releasing an isolated endpoint on a model's suggestion contradicts that. |
| D6 | Medium | Reported | `src/lib/services/admin.ts:33`, `005_rls.sql:192` | `updateTenantSettings` runs with `platform: true` for tenant-scope callers, which enables the `platform_write` policy for every tenant. Only the `WHERE` clause limits the write. |
| D7 | Medium | Reported | `src/lib/soar/response.ts:129-131` | Approvals are marked `EXPIRED` only when someone tries to decide them. No job expires them, so a playbook run waiting on an approval stays `WAITING_APPROVAL` forever. |
| D8 | Medium | Reported | `src/lib/services/playbooks.ts:114`, `src/lib/soar/engine.ts:188-192` | Saving a playbook overwrites its steps. A paused run resumes against the new steps, not the version it started with. `playbookVersion` on the run is a counter, not a snapshot. |
| D9 | Medium | Reported | `src/lib/providers/http.ts:24`, `src/lib/connectors/notify.ts:56` | Admin-supplied integration and webhook URLs are fetched with no private-address or metadata-endpoint guard (SSRF). |
| D10 | Medium | Reported | `deploy/helm/blaksoc/templates/networkpolicy.yaml:22-38` | The worker NetworkPolicy allows cluster-internal egress only, but the worker must reach Microsoft Graph, CISA, FIRST, Kelpie and ABR. PR #68 disables the policy as a result. The web pod, which runs the AI assistant, has no egress policy at all. |
| D11 | Low | Verified | `src/lib/ai/assistant.ts:71-73,78` | PII redaction applies to the current message and tool output only. Earlier turns are stored unredacted and sent back to the model on every later turn. |
| D12 | Low | Verified | `Dockerfile:28-29` | The standalone web image never copies `public/`, so `sw.js` and the PWA icons return 404. |
| D13 | Low | Reported | `deploy/helm/blaksoc/templates/web.yaml:30-31` | `/api/health` checks Postgres and Redis and is used for both readiness and liveness. A database outage restarts every web pod. |
| D14 | Low | Reported | `src/lib/auth/auth.ts:54` | Login rate limiting uses in-memory storage, so each of the 2–8 web replicas has its own limit. |
| D15 | Low | Reported | `src/app/api/stream/route.ts:14-37` | SSE permissions are captured when the stream opens. A user whose role is revoked keeps receiving live events until they disconnect. |
| D16 | Low | Reported | `src/lib/connectors/registry.ts:169,181,193`, `src/lib/soar/engine.ts:84-94` | Webhook, Teams and Slack configs declare an `events` filter that nothing reads. The SOAR `notify` step discards send errors. |
| D17 | Low | Reported | `src/db/sql/010_audit.sql:11-15` | The audit `ip` column is not included in the hash chain. |
| D18 | Low | Reported | `src/lib/detections/sigma.ts:148` | Sigma keyword matching runs against `JSON.stringify(event)`, so a keyword can match a field name rather than a value. |
| D19 | Low | Reported | `registry.ts:110-120` | Velociraptor is listed as `available` but has no `create()`, so instantiating it throws. |

Documentation drift: `docs/ARCHITECTURE.md:25-26` lists a subset of the worker schedules
(`src/worker/index.ts:76-91` has 17), and the README lists connectors as available that are
fixture-only (see Integrations).

## Capability matrix

### Platform foundations

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| Architecture | PARTIAL | Clear layering: UI → `src/lib/services/*` (the only data path, RBAC and scope enforced) → Postgres with RLS; BullMQ worker with 9 queues and 17 schedules (`src/lib/queue.ts:4-14`, `src/worker/index.ts:76-91`); provider and intel abstractions (`src/lib/providers/types.ts`, `src/lib/intel/types.ts`); connector registry. | Every alert is copied into Postgres; there is no data, intelligence and action plane separation; no event store or outbox; no external API surface. The services layer is a good foundation for all three planes and should be kept. |
| Tenancy | NEEDS HARDENING | `tenants` with `kind` (mssp/partner/customer), `parentId`, `deploymentMode`, `settings` (`src/db/schema/platform.ts:46-78`). Partner → customer hierarchy with consent records (`drizzle/0014_partner_tenancy.sql`, `src/lib/services/partner.ts`). 51 tables with forced RLS plus shared-read and special-case policies (`005_rls.sql:74-241`). Cross-tenant integration tests (`tests/integration/tenancy.test.ts`). | One level of hierarchy only; no tenant groups; no tenant offboarding or deletion; `role_assignments` and `sso_provider` have no RLS (by design, but undocumented); no automated test that every tenant table has RLS. D4 and D6. |
| Authentication | PARTIAL | Entra OIDC for staff, per-customer OIDC/SAML registered by platform admins, password only for break-glass with forced TOTP, lockout, 12-hour sessions, disabled-user checks on every request (`src/lib/auth/auth.ts`, `src/lib/auth/session.ts`). | No SSO role mapping, just-in-time provisioning or SCIM: new SSO users wait at `/access-pending`. SSO domain verification is never enforced. No idle timeout, concurrent-session limit or admin session revocation. `ENTRA_TENANT_ID` falls back to any Entra tenant (`auth.ts:21`). D14. |
| Authorisation | NEEDS HARDENING | 33 permissions, 11 built-in roles, platform-only custom roles, per-tenant permission checks, parent-to-child grant inheritance (`src/lib/auth/permissions.ts`, `src/lib/auth/access.ts:47-169`). | D1 (no grant ceiling). `can()` without a tenant returns true if any grant matches (`access.ts:146-149`). No per-resource or attribute-based control. No service identities, API keys or scoped machine credentials, apart from syslog tokens, agent enrolment tokens and per-tenant Grafana database logins. |
| Audit | NEEDS HARDENING | Append-only, hash-chained `audit_log` with a verify function and UI (`010_audit.sql`, `src/app/(app)/admin/audit`). About 97 call sites covering RBAC, tenants, SSO, integrations, response actions, approvals, governance, incidents, DFIR and reports. | No authentication events (login, failure, MFA, SSO). AI invocations go to `ai_invocations`, not the chain. Report exports are not audited. No audit export or streaming to a SIEM. Audit reads are not audited. The UI is capped at 200 rows over 30 days. D17. |
| Secrets | NEEDS HARDENING | AES-256-GCM with the row id as associated data; write-only in UI and API (`src/lib/crypto.ts`, `src/lib/services/integrations.ts`). Production refuses to start without the auth and encryption keys (`src/lib/env.ts:40-44`). PR #68 adds External Secrets from AWS Secrets Manager. | One key with no key id or rotation path; no KMS or Vault envelope encryption; database URLs fall back to development defaults in production (`env.ts:7-14`). |
| Data residency and sovereignty | NEEDS HARDENING | `AI_DATA_RESIDENCY=AU` enforced in `checkAiPolicy` (`src/lib/ai/policy.ts:11-20`); steward-controlled governance profile, most protective by default, two-person rule (`src/lib/governance/policy.ts`); residency lock covers AI, intel lookups and EPSS; AU-pinned archives and a worker boot-time region check (`src/lib/hosting/profile.ts:32-40`). | AI provider region and country are declared by the admin and default to "AU" (`registry.ts:384-388`); nothing checks the endpoint against the declared region. No integration egress policy as a product feature. D10. |
| Indigenous data governance | NEEDS HARDENING | Data steward role, consent-gated sightings, cultural protocol in IR plans, co-design terms of reference and session materials (`docs/codesign/*`). | The co-design work is an explicit draft: no advisory group, no decisions logged (`docs/codesign/README.md:3-5`, `decision-log.md:40`). `docs/SECURITY.md` marks the governance defaults as interim until that review. |
| Data retention | MISSING | 30-day syslog hot window and an hourly archive job (`src/lib/syslog/retain.ts`). | Archived syslog rows stay in Postgres and `retainUntil` is never enforced; the archive store is a local directory on an `emptyDir` volume. No retention policy for alerts, incidents, evidence or AI messages; no purge jobs; no legal hold. |

### Data plane

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| SIEM abstraction | PARTIAL | `SecurityEventProvider` with alerts, events, assets, vulnerabilities, response actions, async action status and detection deployment (`src/lib/providers/types.ts:84-105`). Implemented by Wazuh (live), Tawny (live), Entra/M365 (live Graph), syslog, Google (fixture), demo. | No `capabilities()` method (capabilities are static in the registry); `searchEvents` returns untyped records with no paging and is called only by the Sigma scheduler (`src/worker/jobs/ingest.ts:181`); no federated or query-in-place search. This contract is the natural seed for `SecurityDataProvider`. |
| Telemetry ingestion | NEEDS HARDENING | 30-second pull with per-integration cursors in Redis, at-least-once delivery, dedup on (tenant, source, external id) (`src/worker/jobs/ingest.ts:115-160`, `src/lib/pipeline/ingest.ts`). Push syslog over TLS with per-tenant tokens, IP allowlist and parsers for five vendors (`src/app/api/ingest/syslog`, `src/lib/syslog/parse.ts`). Raw payload kept in `alerts.raw`. | Single-threaded poll with per-alert transactions and no backpressure; cursors only in Redis; every syslog allow line becomes an informational alert in the analyst queue; no ingest metrics or dead-letter. D2. |
| Schema normalisation | PARTIAL | `NormalisedAlert`, `NormalisedAsset`, `NormalisedVulnerability`, 11 observable types; ATT&CK technique ids on alerts; Sigma for detections. | No OCSF or ECS alignment; no `normalization_version`; network, process and file fields exist only inside `raw`; `category` is free text. Event-level schema (as opposed to alert-level) does not exist. |
| Search | PARTIAL | Structured alert filters, saved views, asset and OpenCTI search, AI search tools (`src/lib/services/alerts.ts:12-91`). | `ilike` only, no full-text index, no query language, no event or log search UI, no archive search UI. |
| Connector framework | NEEDS HARDENING | One definition per connector: category, capabilities, remote permissions, zod config and secrets, `create()` (`src/lib/connectors/registry.ts:38-50`); encrypted instances; health probes every 5 minutes; secret fields never read back. | No connector versioning or packaging; capabilities are not tied to executable actions; no per-connector rate limits or egress declaration; no KMS. D19. |
| Integration coverage | PARTIAL | Live: Wazuh, Tawny, Entra/M365 (sign-ins, audits, risk detections, identity actions), OpenCTI, Kelpie cases, webhook (HMAC), Teams, Slack. Live-or-fixture: SMS, voice, email. Five AI provider types. | Fixture only: Google Workspace, Defender, Sophos, Cloudflare, Fortinet, Veeam, Velociraptor. Planned only: Sentinel, Elastic, Splunk, CrowdStrike, SentinelOne, AWS, Azure, GCP, Jira, ServiceNow and others. No GuardDuty, Security Hub, CloudTrail or Security Lake. |

### Detection and intelligence

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| Detection engineering | PARTIAL | Immutable versions with sha256, change notes and authors; per-tenant deployments; audit on every save; deploy to OpenSearch or push YAML to Tawny; stale-deployment health checks (`src/db/schema/detections.ts`, `src/lib/services/detections.ts`). | No enforced lifecycle (`status` is whatever the YAML says); no review or approval of rule changes; no owner; no rollback; no Git sync; effectiveness is only `lastHitCount`; analyst `FALSE_POSITIVE` decisions do not feed back to rules. |
| Sigma | PARTIAL | Parser and evaluator with common modifiers, wildcards, `1 of`/`all of`, keyword search; one backend (OpenSearch `query_string`) with a 23-field Wazuh map (`src/lib/detections/sigma.ts`). Built-in content: 42-rule SME pack with false-positive gate, BEC rules. | No aggregation or `timeframe`; no Sigma correlation rules; many modifiers missing (`cidr`, `base64*`, `windash`, numeric comparisons); logsource is not used for routing; no other backends. D18. |
| Detection testing | PARTIAL | Sample-event tests stored per version; the deploy gate blocks a version whose latest test failed (`detections.ts:146`). | No historical backtest; untested and `experimental` rules deploy freely; test cases are pasted per run, not kept as fixtures; the in-memory evaluator and the generated query are never checked against each other. |
| Correlation | MISSING | Two hard-coded M365 correlators: impossible travel and MFA fatigue (`src/lib/detections/bec.ts:248-293`). Exact-duplicate suppression. | No correlation engine (sequences, windows, thresholds, absence, cross-source joins); no automatic incident grouping. |
| Risk-based alerting | PARTIAL | Deterministic, additive alert scoring with evidence per factor; vulnerability priority scoring; asset risk rolled up every 6 hours as the worst open alert or vulnerability (`src/lib/risk/engine.ts`, `src/worker/jobs/intel.ts:134-138`); factors shown in the UI. | No accumulation per user or host; no decay; no identity risk score; weights are constants; health alerts bypass the scorer. The "never hide the calculation" principle is already in place and should carry over to entity risk. |
| Threat intelligence | COMPLETE | Observable extraction with private-IP filtering; Redis-cached OpenCTI lookups before the write transaction; per-tenant commercial-feed entitlement filter; KEV, EPSS (with a bulk path for residency-locked tenants), ACSC and CISA advisories (`src/lib/intel/*`, `src/worker/jobs/intel.ts`). | Retro-hunting IOCs over history and pushing IOCs to the SIEM are worthwhile additions, not blockers. |
| OpenCTI | COMPLETE | GraphQL lookups, CVE context, search, consented anonymised sightings, advisory reports, sector labels (`src/lib/intel/opencti.ts`). | None blocking. |
| STIX/TAXII | DEFER | STIX handled through OpenCTI and for the ATT&CK import only. | No STIX object model or TAXII client or server. OpenCTI already provides TAXII, so blakSOC should consume it through OpenCTI until a customer needs a direct feed. |
| MITRE ATT&CK | COMPLETE | Full Enterprise import; techniques on alerts from Sigma, correlators and OpenCTI; coverage against observed alerts and incidents (`src/lib/services/detections.ts:193-215`). | No scheduled refresh, data-source coverage or Navigator export. |
| Exposure and posture context | PARTIAL | Vulnerability prioritisation; attack surface classifier with attestation; credential exposure with sanitisation and entitlement; SPF/DMARC/DKIM posture; Essential Eight scoring; health rules. | Scan, Shodan and breach sources are fixtures; DNS is pasted by hand; email posture findings are not scored; posture does not feed entity risk. |
| Attack paths | MISSING | None. | No asset relationship model, so no path modelling. Depends on the entity graph. |

### Investigation and cases

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| Investigations | PARTIAL | Alert detail with intel, observables, related alerts (same asset or user, 72 hours), risk breakdown and response; asset detail with sources, alerts, vulnerabilities, incidents and identities. | No identity, IP, domain, file, process or cloud-resource pages; no event search or pivoting; no graph view. |
| Entity modelling | PARTIAL | Assets with nine kinds (including `identity`), criticality, exposure, privilege, first and last seen, cross-source dedup keys (`src/lib/pipeline/assets.ts`); observables with first and last seen and sighting counts; incident links to assets, identities, observables and intel. | No generic entity model, aliases or source-system lineage across entity types; identities are assets matched by name. |
| Graph relationships | MISSING | `incident_links` and `alert_observables` only. | No relationship table, relationship types, provenance (observed vs inferred) or traversal API. |
| Universal timeline | PARTIAL | `incident_timeline` with origin (machine, analyst, ai, customer), category, actor and record reference, written by most case activity (`src/db/schema/security.ts:271-288`). | A case activity log, not a multi-source investigation timeline: no telemetry events, no filters, no provenance beyond the record reference. |
| Cases | PARTIAL | Severity, status workflow, owner, collaborators, techniques, risk, containment and remediation fields, SLA due date, notes (internal or customer), tasks, linked alerts, approvals and response actions; Kelpie as an external case system. | No priority, tags, team, closure reason, parent/child or merge; no status transition rules; AI conversations link to a case only through a loose JSON subject. |
| Evidence | NEEDS HARDENING | `evidence` table with sha256 and storage URI; DFIR collections behind approval with artefact sets and low-bandwidth deferral; custody export (`src/db/schema/dfir.ts`, `src/lib/dfir/*`). | Hashes and URIs are typed in by the analyst; no upload or server-side hashing; no custody log; `collectedBy` is free text; Velociraptor is a fixture. |
| AU obligations | PARTIAL | NDB assessment clock with reminders, decisions with rationale, referrals, draft OAIC and individual notices, evidence pack; versioned IR plans with cultural protocol; tabletop exercises (`src/lib/obligations/*`, `src/lib/ir/*`). | No SOCI 12-hour and 72-hour reporting clocks; no ransomware payment reporting clock (Cyber Security Act 2024). |
| SLA | PARTIAL | Per-severity minutes per tenant; one `slaDueAt` per incident; breach badges; SLA report against containment; MTTA and MTTR in trends. | No separate acknowledge, triage, investigate, contain and resolve clocks; no alert-level acknowledgement; no recalculation on severity change; no pause or business hours; no pre-breach warning job. |

### Response and automation

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| SOAR | NEEDS HARDENING | Triggers with conditions; steps with guards, approval gates and `continueOnError`; eight non-destructive step types; 17 response actions with a destructive flag; async provider actions with a 15-minute timeout; run and step records (`src/lib/soar/*`). | No dry-run; no playbook version snapshots (D8); response providers other than Wazuh, Tawny and M365 are fixtures. |
| Approval workflows | NEEDS HARDENING | Approvals for response actions and DFIR collections, 24-hour expiry, `response:approve` permission, auto-containment only by platform admins and only for playbook requests (`src/lib/soar/response.ts`). | Actions carry only a destructive flag: no risk level, required role, reversibility or blast radius; no observe, recommend, approval-required or autonomous modes; no policy engine. D5, D7. |
| Webhooks and event bus | PARTIAL | Typed `SocEvent` union of six events over Redis pub/sub; SSE with per-viewer filtering; HMAC-signed outbound webhook; notification delivery records (`src/lib/events.ts`, `src/lib/connectors/notify.ts`). | Pub/sub is lossy (no outbox or persistence); no subscription model, retries or dead-letter; no generic inbound webhooks. D16. |

### AI and agents

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| AI | PARTIAL | One assistant with a policy check, residency and governance, a six-turn tool loop, 12 read tools, a note writer and a response proposer behind an opt-in, PII redaction, raw-event stripping and citation verification (`src/lib/ai/*`). | One purpose (`assistant`) only. D5, D11. |
| AI gateway | PARTIAL | All model calls go through `aiProviderFor` and `checkAiPolicy`; `ai_invocations` records provider, model, region, purpose, policy decision and tokens. | No classification-aware decisions, cost or latency, or per-operation policy. |
| AI cost governance | MISSING | Token counts only. | No cost, budgets (per investigation, tenant, agent or model) or caching. |
| Agent architecture | MISSING | None. `src/lib/agents` and `src/db/schema/agents.ts` are about endpoint agents (Wazuh and Tawny enrolment), not AI. | No typed agents, agent identity or execution records. |
| Agent handoffs and reasoning summaries | MISSING | None. | No handoffs or stored reasoning summaries. Citations exist per message and can be the start of evidence references. |
| MCP | MISSING | No MCP code or SDK. | — |
| External agent API | MISSING | None. | Depends on public APIs and service identities. |
| Investigation memory | MISSING | `FALSE_POSITIVE` alert status and Sigma `falsepositives` text only. | No suppression, allowlist, exception or known-benign records with owner, expiry and confidence. |
| Knowledge base | MISSING | IR plans and scenarios act as static runbooks. | No runbook, procedure or environment documentation store. |

### Operations and delivery

| Capability | Rating | What exists (evidence) | Gap against the target |
| --- | --- | --- | --- |
| MSSP operation | PARTIAL | `/soc/mssp` roll-up, workspace switcher re-checked every request, partner and customer admin roles, co-branding, per-tenant settings and AI provider preference, plans and usage metering, partner revenue share. | No analyst-to-tenant assignment (every platform role sees every tenant); no tenant groups; usage is metered only when a page is viewed; no cross-tenant workload or SLA attainment view. |
| Public APIs | MISSING | Six route handlers: auth, health, SSE, syslog ingest, billing quote and report export. Everything else is server actions. | No REST or GraphQL resource API, OpenAPI spec, API keys, rate limiting or versioning. |
| Dashboards | PARTIAL | SOC dashboard, MSSP overview, trends with MTTA and MTTR, one per-tenant Grafana dashboard reading Postgres through RLS-bound logins. | No MTTD, analyst workload, automation or AI usage metrics, or platform operations dashboard. |
| Reporting | PARTIAL | Ten report kinds with observed and interpretation sections; PDF, CSV and slides; scheduled board reports (`src/lib/reports/*`). | Only board reports are scheduled; no SLA attainment report for MSSP customers. |
| Observability | MISSING | `/api/health` checks Postgres and Redis; tenant health rules raise alerts for silent sensors and stale feeds. | `console.log` only; no structured logs, correlation ids, metrics or tracing; failed jobs are only logged; Wazuh poll failures raise no alert. D13. |
| High availability | NEEDS HARDENING | Web 2–8 replicas with HPA and PDB; worker 2 replicas; fixed-id job schedulers; SSE fan-out through Redis. | No worker PDB, probes or HPA; `affinity` value unused; no explicit job locking; Postgres and Redis HA left to the operator (PR #68 uses single-AZ RDS and Redis); one Redis connection per SSE viewer. |
| Disaster recovery | MISSING | `src/lib/backup` monitors customers' Veeam backups (fixture), not the platform. PR #68 enables 7-day RDS backups. | No platform backup, restore runbook, drill, RPO or RTO. |
| Kubernetes | NEEDS HARDENING | Helm chart with web, worker, migration hook, SSE-tuned ingress, NetworkPolicies and a restricted security context; k3s overlay. | D3, D10, D13. |
| Deployment and CI | PARTIAL | Multi-stage Dockerfile; Compose with OpenCTI and AI profiles; CI runs lint, typecheck, unit and integration tests against Postgres 17 and Redis 7 (`.github/workflows/ci.yml`). | CI does not run `next build`, build images, lint the chart, generate an SBOM or measure coverage; no release workflow; PR #68 pushes images by hand and runs Postgres 16 while CI uses 17. D12. |
| Testing | PARTIAL | 30 unit files (186 cases), 27 integration files (76 cases), tenancy isolation tests. | No end-to-end or UI tests, coverage thresholds, authorisation matrix, RLS coverage check or SSRF tests. |
| Security testing | MISSING | Security headers except CSP (`next.config.ts:3-9`). | No SAST, dependency or secret scanning, threat model, disclosure policy or CSP. |
| UX and accessibility | PARTIAL | Radix-based components, 83 `aria-*` attributes across 37 files, dark theme, offline portal pages. | No skip link, keyboard shortcuts, theme toggle, automated accessibility tests or i18n. |
| Documentation | PARTIAL | Architecture, security model, hosting profile with measured data-plane numbers, one ADR, connector guides, co-design drafts. | No API reference, operator, upgrade, backup or on-call runbooks, threat model, user guide or changelog. |
| Training and awareness | COMPLETE | Isolated training tenants with ten scenarios, scoring and mentor co-sign; consented phishing awareness campaigns. | Outside the program brief; keep as is. |

## What to preserve

The program should extend these rather than replace them:

- **`src/lib/services/*` as the only data path.** New APIs, MCP tools and agent tools should call
  services, not the database, so RBAC and RLS stay in one place.
- **`withScope()` and forced RLS.** Every new table (entities, edges, memory, agent runs, webhook
  subscriptions) gets `tenant_id` and a policy in `005_rls.sql` from the start.
- **`requestResponseAction()` as the single response gate.** Policy-based approvals should be a
  richer decision inside this function, not a second path around it.
- **Deterministic, explained scoring.** Entity risk, correlation and attack path scores should
  return factors the same way `src/lib/risk/engine.ts` does.
- **`SecurityEventProvider` and the connector registry.** Evolve them into `SecurityDataProvider`
  and a capability-declaring connector model rather than starting again.
- **Governance profile and residency checks.** These become the policy inputs for the AI gateway and
  the egress policy.
- **Australian differentiators.** NDB clocks, Essential Eight, ACSC advisories, board reports,
  low-bandwidth agent profiles, consented sightings and the co-design track. None of the large vendor
  platforms offers these together.

## Recommended sequencing

Each phase is shippable on its own and builds on the one before it. The detailed design belongs in
`docs/architecture/TARGET-ARCHITECTURE.md`.

| Phase | Theme | Contents | Why this order |
| --- | --- | --- | --- |
| 0 | Fix defects | D1–D12 first, then the rest. Add an RLS coverage test and an authorisation matrix test. | Several defects weaken controls the later phases rely on (role grants, approval gating, egress). |
| 1 | Programmable foundations | Service identities with scopes and short-lived tokens; a versioned REST API over existing services with OpenAPI; a transactional event outbox replacing lossy pub/sub; webhook subscriptions with signing, retries and dead-letter; structured logs, metrics and tracing. | The API, events and identities are prerequisites for MCP, external agents and integrations. Observability is needed before scale. |
| 2 | Data fabric and schema | Evolve `SecurityEventProvider` into `SecurityDataProvider` with `capabilities()`, typed and paged search, and query-in-place for Wazuh/OpenSearch and syslog first; an OCSF-aligned canonical event schema with provenance fields and `normalization_version`; an event search UI. | Correlation, backtesting, timelines and agents all need typed event access. |
| 3 | Entities and investigation | Generic entity and relationship tables in Postgres (observed vs inferred provenance), traversal API, entity pages, entity risk with decay and explanation, and a unified timeline merging case activity with provider events. | Builds on phase 2 events. Postgres with recursive queries is enough to start; revisit a graph store only with measured need. |
| 4 | Detection and correlation | Enforced rule lifecycle with review and approval, owners, rollback, Git sync, reusable fixtures, historical backtest through the data fabric, an explainable correlation engine, and automatic incident grouping. | Needs phase 2 search and phase 3 entities. |
| 5 | Response, cases and SLA | Action policy metadata (risk, required role, reversibility, blast radius) and the four automation modes; playbook version snapshots and dry-run; approval expiry job; case priority, tags, closure reasons, parent/child and merge; evidence upload with custody log; multi-clock SLA engine with warnings; SOCI timers. | Extends existing gates rather than replacing them. |
| 6 | AI gateway and agents | Gateway with classification-aware policy, cost and latency recording, budgets and caching; typed agents with execution records, handoffs and reasoning summaries; evidence-referenced conclusions; MCP server and external agent API over phase 1 identities; investigation memory and knowledge base with expiry and classification. | Safest once APIs, policies and evidence models exist. |
| 7 | Scale and coverage | Analyst-to-tenant assignment and tenant groups; per-tenant retention and legal hold; platform backup and DR drills; integrations (Defender XDR, Sentinel, GuardDuty, Security Hub, CloudTrail, Jira, ServiceNow); exposure-driven attack paths. | Breadth once the frameworks are stable. |

## Decisions needed before building

1. **Canonical schema basis.** OCSF is recommended: it is vendor-neutral, event-class based, and
   maps well to Security Lake and many vendors. ECS field names can be kept as aliases for
   Elastic and Wazuh.
2. **Graph storage.** Postgres tables with RLS are recommended to start, so tenant isolation stays
   in one mechanism. A dedicated graph database would need its own isolation design.
3. **Event bus.** A Postgres outbox drained by the worker is recommended over adding Kafka or NATS.
   It keeps one durable store and fits the current scale.
4. **Query-in-place vs copy.** Keep copying alerts (they drive workflow) but query raw events in
   place through providers. This needs a decision on which providers must support search in phase 2.
5. **Ownership of D1 fix semantics.** Whether customer admins may create data stewards at all is a
   governance question for the co-design process, not only an engineering fix.
