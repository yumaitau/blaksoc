# blakSOC

**One SOC. One interface. Open components underneath.**

blakSOC is Yuma IT's Australian-focused, sovereign-capable, multi-tenant Security Operations
Centre platform. It is a unified control plane over best-of-breed open-source security tools, not
a re-implementation of them:

| Capability | Component | blakSOC's role |
|---|---|---|
| SIEM / XDR / endpoint telemetry | **Wazuh** (first provider behind `SecurityEventProvider`) | Ingest, route to tenant, enrich, score, respond |
| Endpoint detection and response | **Tawny EDR** (Yuma IT's agent, via its `twny_` API) | Alerts with ATT&CK, agent inventory, kill process with the agent's result tracked to completion, Sigma rules deployed as Tawny alert rules |
| Cyber threat intelligence | **OpenCTI** (system of record, STIX 2.1) | Enrichment, sightings feedback, AU advisory reports, sector tags |
| Detection content | **Sigma** | Repository, versioning, testing, deployment as scheduled SIEM queries, ATT&CK coverage |
| Orchestration | Native lightweight SOAR | Trigger → conditions → actions → **human approval** → execution |
| Case management | Native | Alerts → incidents, timeline, evidence, tasks, immutable audit |
| AI | Pluggable (Bedrock, Azure OpenAI, OpenAI-compatible, Ollama, vLLM) | Evidence-cited analyst accelerator, never an autonomous authority |

It runs as Yuma IT's MSSP/MDR platform (many customers, one control plane) or as a dedicated
single-tenant SOC for customers who need isolated infrastructure.

## Quick start (development)

Requirements: Node 22+, pnpm 10, Docker.

```bash
pnpm install
docker compose up -d                 # Postgres 17 + Redis 7 (see docker-compose.yml)
cp .env.example .env.local           # set secrets; DEMO_MODE=true for demo tenants
pnpm db:migrate                      # schema + RLS policies + audit hash chain
pnpm db:seed                         # roles, ATT&CK subset, feeds, Sigma rules, playbook (+ demo data)
pnpm db:attack                       # optional: full MITRE ATT&CK Enterprise matrix
pnpm dev                             # http://localhost:3107
pnpm worker:dev                      # ingest, enrichment, sync, playbooks, response, intel refresh
```

The seed prints a one-time **break-glass administrator** password. With `DEMO_MODE=true` it also
creates three demo customers (synthetic Wazuh telemetry + an OpenCTI fixture) and personas for
every role (password `blaksoc-demo-2026`):

| Persona | Role |
|---|---|
| `manager@demo.blaksoc.local` | SOC Manager (approves containment) |
| `l2@demo.blaksoc.local` / `l1@demo.blaksoc.local` | SOC Analyst L2/L3 / L1 |
| `auditor@demo.blaksoc.local` | Auditor |
| `wattle.admin@demo.blaksoc.local` | Customer Administrator (Wattle Health Services) |
| `murray.security@demo.blaksoc.local` | Customer Security User (Murray Regional Water) |

Tests: `pnpm test` (unit) and `pnpm test:integration` (against a migrated, demo-seeded DB).

## Architecture

```
Wazuh ──┐                     ┌── OpenCTI (GraphQL, STIX 2.1, sightings, reports)
Future  ├─ SecurityEventProvider ─┐   │
SIEMs ──┘                         ▼   ▼
                     worker: ingest → observables → enrichment (Redis-cached) → risk engine
                                        │                         │
                                        ▼                         ▼
                   Postgres (tenant_id everywhere + RLS)   playbooks → approvals → response
                                        │
                     Next.js 16 control plane (RSC + server actions + SSE live updates)
                                        │
            Alert queue · Incidents · Assets · Vulnerabilities · Intel · Detections · Portal · AI analyst
```

- `src/lib/providers` — `SecurityEventProvider` contract, Wazuh implementation (API + indexer), Tawny EDR, demo provider.
- `src/lib/intel` — observable extraction, OpenCTI GraphQL provider, enrichment cache, entitlement filter.
- `src/lib/risk/engine.ts` — deterministic, additive 0–100 scores for alerts and vulnerabilities; every point carries evidence.
- `src/lib/pipeline` — alert ingest and asset deduplication.
- `src/lib/soar` — playbook engine, response actions, approval gates.
- `src/lib/detections/sigma.ts` — Sigma parser, evaluator (rule tests) and OpenSearch converter.
- `src/lib/ai` — provider interface, residency policy, PII redaction, read/write tool separation, citation verification.
- `src/lib/connectors` — connector SDK (zod config + write-only secrets + capabilities).
- `src/lib/services` — the only path from UI to data; RBAC + tenant scope enforced here.
- `src/worker` — BullMQ workers and schedules.
- `deploy/` — Docker targets, full-stack Compose (with OpenCTI + feeds + Ollama), Wazuh active-response scripts, Helm chart.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY.md](docs/SECURITY.md). Connector setup guides:
[Microsoft 365](docs/connectors/entra-setup.md), [Tawny EDR](docs/connectors/tawny.md).

## Multi-tenancy in one paragraph

Every security object has `tenant_id`. Services filter by tenant explicitly **and** every query runs
in a transaction whose Postgres RLS scope (`app.tenant_ids`) is limited to the tenants the caller
holds the needed permission on. The app connects as `blaksoc_app`, a non-owner role, and tables use
`FORCE ROW LEVEL SECURITY`, so a missed filter fails closed. Customer users only ever resolve to
their own tenant; Yuma IT staff reach all customers through platform-scope roles, and the workspace
switcher narrows the RLS scope further.

## Deployment

- **Compose (single host / dedicated tenant):** `deploy/compose/docker-compose.yml` with profiles
  `opencti` (platform + MITRE, CISA KEV, NVD CVE, URLhaus, MalwareBazaar, EPSS connectors) and `ai` (Ollama).
- **Kubernetes:** `deploy/helm/blaksoc` — web (HPA, PDB), worker, pre-upgrade migration job, ingress
  tuned for SSE, NetworkPolicies, non-root read-only containers. Secrets come from an existing Secret.
- **Backup and DR:** AU S3 syslog archive, Postgres dumps (`deploy/backup`), RPO/RTO per profile, restore
  runbook and the quarterly drill (`pnpm drill:restore`) are in `docs/disaster-recovery.md`.
- **Wazuh:** run the official wazuh-docker/Helm stack; see `deploy/wazuh/README.md` for accounts,
  multi-tenant agent-group routing and the isolation scripts blakSOC uses for containment.

For AU sovereignty: host in an Australian region, keep `AI_DATA_RESIDENCY=AU` (the policy engine
refuses any model provider that does not declare Australian processing), and prefer Ollama/vLLM or
Bedrock `ap-southeast-2`/`ap-southeast-4` without cross-region inference profiles.

## Status

Implemented in V1: everything above plus the UI routes listed in docs/ARCHITECTURE.md. Declared but not
yet implemented connectors (Sentinel, Elastic, Splunk, Defender, CrowdStrike, SentinelOne, Entra ID
identity response, firewalls, cloud, Jira, ServiceNow) appear in the integration catalogue as
"planned"; each needs one connector definition in `src/lib/connectors/registry.ts`.
