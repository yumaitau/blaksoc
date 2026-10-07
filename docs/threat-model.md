# blakSOC threat model

STRIDE review of the blakSOC control plane as built in this repository. It complements
[`SECURITY.md`](SECURITY.md) (the security model) and the disclosure policy in [`/SECURITY.md`](../SECURITY.md).
Review it when a trust boundary, identity path, connector type or deployment target changes, and at
least once per release cycle.

## Scope and assets

In scope: the Next.js web app (SOC console under `src/app/(app)`, customer portal under
`src/app/(portal)`), API route handlers (`src/app/api`, portal form routes), the BullMQ worker
(`src/worker`), outbound connectors, the AI assistant, Postgres and Redis, the container images and the
Helm chart. Wazuh, OpenCTI, identity providers and cloud services are external dependencies.

| Asset | Why it matters |
| --- | --- |
| Customer security telemetry (alerts, events, assets, vulnerabilities, incidents, evidence) | Confidential per tenant; cross-tenant exposure is the worst-case failure. |
| Identities and sessions (SSO links, passkeys, break-glass passwords and TOTP) | Control every other asset. |
| Integration secrets (EDR, M365, webhook and SaaS credentials) | Allow actions inside customer environments. |
| Response actions and approvals (isolate host, disable identity, block IOC) | Can disrupt a customer's business if forged. |
| Audit log | Evidence for customers, regulators and incident review. |
| Data governance profile and AI controls | Indigenous data sovereignty and AU residency commitments. |
| Build and release pipeline, images | A compromised image compromises every deployment. |

## Actors

- **Yuma IT SOC staff** (platform roles), **customer users** (tenant roles, portal), **data stewards**,
  **break-glass administrators**.
- **Machines**: log shippers posting syslog with bearer tokens, Wazuh agents enrolling with tokens,
  identity providers posting SAML or returning OIDC codes, Microsoft 365 consent callbacks.
- **Adversaries**: an unauthenticated internet attacker; a malicious or compromised customer user trying to
  reach another tenant; an attacker controlling content that flows into the SOC (log lines, alert fields,
  threat intel, email) to attack analysts or the AI; a compromised dependency or CI workflow; an insider
  with cluster access.

## Trust boundaries

```
 Browser (staff / customer)          IdPs (Entra, Google, customer OIDC/SAML)
        |  TLS, session cookie, CSP          |  OIDC code / SAML POST to ACS
        v                                    v
 [B1] Ingress ---------------------> Web pods (Next.js: pages, portal, /api/*, proxy.ts)
        ^                                    |  role-scoped SQL (blaksoc_app, RLS)
 Log shippers / agents (bearer token)        v
                                     [B3] Postgres <---- Worker pods (blaksoc_system, system_access)
                                      Redis (queues, rate limits, live events)   |
                                                                                 | [B4] egress guard
                                                                                 v
                                    Wazuh, OpenCTI, EDR/M365/SaaS APIs, AI providers, intel feeds
 [B5] GitHub Actions -> GHCR images (signed) -> cluster (Helm)
```

- **B1 internet to web**: everything from the browser or a machine client is untrusted until the session,
  bearer token or IdP assertion is verified.
- **B2 tenant to tenant** (logical, inside web, worker and database): every query is scoped to the caller's
  tenants; Postgres RLS is the backstop.
- **B3 app to data plane**: serving pods hold the least-privileged database roles; only the migration job
  holds owner credentials.
- **B4 platform to external systems**: connector, intel and AI calls leave the cluster; responses are
  untrusted input.
- **B5 source to running image**: CI and release pipeline, registry, chart values.

## STRIDE by component

Each row lists the threat, the mitigation in place (with file references) and the residual risk.

### Web app and customer portal

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Session cookie theft or fixation | better-auth `HttpOnly`, `Secure`, `SameSite=Lax` session cookie; 12 h lifetime, 1 h rolling update (`src/lib/auth/auth.ts`); HSTS (`next.config.ts`). | A stolen cookie works until expiry or revocation. |
| T | XSS injecting script through alert, log or intel content rendered in the console | React escaping; per-request nonce CSP with `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'` (`src/proxy.ts`); only one inline script, nonce-stamped (`src/app/(portal)/layout.tsx`). | `style-src 'unsafe-inline'` permits CSS injection (no script execution). |
| T | Clickjacking of approval or containment buttons | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | None known. |
| T | CSRF against portal form routes (`src/app/(portal)/**/save/route.ts`, `/portal/leave`) | `SameSite=Lax` session cookie (not sent on cross-site POST); CSP `form-action 'self'`. Server actions carry Next.js origin checks. | Route handlers do not check `Origin`; a same-site origin (sibling subdomain) could post. See open risks. |
| R | User denies an action taken in the UI | Hash-chained append-only `audit_log` (`src/db/sql/010_audit.sql`, `src/lib/audit.ts`). | None known. |
| I | Offline portal cache on a shared phone | Service worker caches only `/portal` and incident pages (`public/sw.js`), same-origin, `basic` responses. | Cached status remains on the device after sign-out. |
| D | Many open SSE streams | Ping and per-minute session recheck close dead or revoked streams (`src/app/api/stream/route.ts`); ingress timeouts. | No per-user stream cap. |
| E | Optimistic gate bypass in `src/proxy.ts` | The proxy only redirects; every page, action and route re-checks the session and permissions (`src/lib/auth/session.ts`, `src/lib/auth/access.ts`). | None known. |

### Authentication (SSO, passkeys, break-glass)

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Credential stuffing on password sign-in | Password sign-in refused for anyone not break-glass; TOTP forced (`BREAK_GLASS_REQUIRE_MFA`); Redis-backed rate limits shared across replicas (`src/lib/auth/rate-limit.ts`). | Falls back to per-replica limits during a Redis outage. |
| S | Account takeover through an IdP for another domain, or a personal Google account | SSO `resolveUser` checks the email domain and Google `hd` claim against the provider's domains (`src/lib/auth/sso-policy.ts`); only platform admins register providers. | A compromised customer IdP can sign in as its own users. |
| S | Stolen session used to register an attacker passkey | Passkey registration needs a session younger than 15 minutes (`freshAge`), audited (`auth.passkey.add`). | Passkeys survive IdP deprovisioning until SCIM exists (#102). |
| S | Open redirect after sign-in | `next` accepted only as a same-origin path (`src/app/login/page.tsx`); better-auth `trustedOrigins` (`src/lib/auth/auth.ts`). | None known. |
| R | Break-glass use goes unnoticed | Break-glass sign-ins are alerted and the session shows a banner (`docs/SECURITY.md`). | Depends on the SOC Manager acting on the alert. |
| E | New SSO user gains access automatically | SSO users arrive with no role (`/access-pending`). | None known. |

### API (route handlers)

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Forged syslog from the internet | Per-tenant bearer token, optional source allowlist using the trusted-proxy-aware client IP (`src/app/api/ingest/syslog/route.ts`, `src/lib/net/client-ip.ts`); plain HTTP refused. | Token in the shipper's config is a long-lived secret. |
| T | Spoofed `X-Forwarded-For` to bypass allowlists or rate limits | Client IP read right-to-left past `TRUSTED_PROXY_CIDRS` only. | Misconfigured CIDRs weaken it. |
| I | Report or export download of another tenant's data | Session plus per-tenant permission checks in services; RLS. | None known. |
| D | Oversized ingest bodies | 800 kB body cap on syslog ingest. | No global request rate limit outside auth. |

### Worker

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| T | Forged job payloads via Redis | Redis is cluster-internal behind NetworkPolicies (`deploy/helm/blaksoc/templates/networkpolicy.yaml`) with credentials in `REDIS_URL` where the deployment sets them. | Anyone with Redis access can enqueue jobs; jobs re-read state from Postgres. |
| E | Worker database role abused to escape tenancy | `blaksoc_system` owns nothing and has no `BYPASSRLS`; it reaches rows through `system_access` policies (`src/db/sql/020_system_access.sql`). | Broader read than a tenant user by design. |
| R | Auto-expired approvals or automated actions without a trail | Expiry, decisions and executions audited and put on the incident timeline (`src/lib/soar/response.ts`). | None known. |

### Connectors and egress

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S/I | SSRF through an integration URL to cloud metadata or internal services | `src/lib/net/egress.ts` refuses link-local and metadata addresses for every connector and private ranges for SaaS endpoints, checked on every connection (DNS rebinding); NetworkPolicy egress excludes private, CGNAT and metadata ranges. | Internal-reach connectors (Wazuh, OpenCTI) can address cluster-internal hosts by design. |
| I | Integration secret disclosure | AES-256-GCM with row id as AAD (`src/lib/crypto.ts`); secrets never returned to clients. | `BLAKSOC_ENCRYPTION_KEY` compromise exposes all secrets; no key rotation tooling. |
| T | Malicious content from a connector (alert fields, intel) | Treated as data, rendered escaped under CSP. | See AI prompt injection. |
| T | MITM to on-prem Wazuh or OpenCTI | TLS verification with optional pinned CA per integration (`caPem`). | Operators can disable verification. |

### AI assistant

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| I | Tenant data sent to a non-AU or disallowed provider | `checkAiPolicy` (tenant enablement, provider allow-list, AU residency) and the data governance profile (`src/lib/ai/policy.ts`, `src/lib/ai/assistant.ts`); PII redaction (`redactPii`). | Relies on providers' declared processing region. |
| T/E | Prompt injection in alert or log content steering tools | Tools run with the analyst's permissions pinned to one tenant; write tools off by default; every AI-proposed action needs approval (`src/lib/ai/tools.ts`, `responseNeedsApproval` in `src/lib/soar/response.ts`). | Injected text can still mislead an analyst's reading of a summary. |
| R | Unattributed model output | Every call recorded in `ai_invocations`; uncited claims flagged. | None known. |

### Data plane (Postgres, Redis, backups)

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| I | Cross-tenant read through an application bug | Explicit tenant filters plus forced RLS on every tenant table (`src/db/sql/005_rls.sql`) evaluated against transaction-local scope; cross-tenant integration tests (`tests/integration/tenancy.test.ts`). | Paths that run as `blaksoc_system` before a scope exists. |
| T | Audit tampering | No UPDATE/DELETE grants, statement trigger, SHA-256 hash chain, `audit_log_verify()` (`src/db/sql/010_audit.sql`). | An owner-role attacker can rewrite the chain; detection depends on an external anchor. |
| E | Serving pod obtains owner credentials | Chart passes only `runtimeSecretKeys` to web and worker; owner URL only in the migration job (`deploy/helm/blaksoc/values.yaml`). | None known. |
| I | Data leaving the AU boundary | Hosting profile pins storage, backups and archives to `ap-southeast-2`/`ap-southeast-4` (`src/lib/hosting`). | Operator-managed backups outside the chart. |

### Supply chain and deployment

| | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| T | Malicious or vulnerable dependency | Frozen lockfile; `pnpm audit --prod` gate at high (`.github/workflows/security.yml`); Dependabot (`.github/dependabot.yml`); CodeQL (`.github/workflows/codeql.yml`). | Zero-day or malicious releases inside the lockfile window. |
| T | Compromised GitHub Action | Actions pinned to commit SHAs; least-privilege `permissions:` per job; `persist-credentials: false`. | Pinned actions still run with the permissions granted. |
| T | Tampered or replaced image | Immutable version and commit tags, never `latest`; cosign keyless signatures and SBOM attestations; Trivy gate on fixable critical CVEs (`.github/workflows/release.yml`). | Clusters do not yet verify signatures at admission. |
| I | Secrets committed to the repository | gitleaks over full history on every PR (`.gitleaks.toml`). | Enable GitHub secret scanning and push protection as well. |
| E | Container breakout or privilege escalation | Numeric non-root user (100:101), read-only root filesystem, no privilege escalation and all capabilities dropped (`deploy/helm/blaksoc/values.yaml`); minimal Alpine base pinned by digest (`Dockerfile`). | None known. |

## Open risks

1. **CSRF defence for portal form routes is SameSite-only.** Add an `Origin`/`Sec-Fetch-Site` check to the
   POST route handlers under `src/app/(portal)` (and `/onboarding/save`) so a compromised sibling subdomain
   cannot post as a signed-in user.
2. **`style-src 'unsafe-inline'`.** Needed for React style attributes and Radix runtime styles. CSS
   injection can restyle pages (for example to disguise an approval) but cannot run script.
3. **No CSP violation reporting.** Add `report-to` with a collector to detect injection attempts and
   regressions.
4. **Image signatures are not enforced at deploy time.** Add an admission policy (Kyverno or Sigstore
   policy-controller) that requires the release workflow's identity.
5. **Passkeys outlive IdP deprovisioning** until SCIM lands (#102).
6. **Encryption key rotation.** There is no tooling to re-encrypt integration secrets under a new
   `BLAKSOC_ENCRYPTION_KEY`.
7. **Audit chain anchoring.** The hash chain detects tampering only by someone without owner rights;
   periodically anchoring the head hash outside the database would close this.
8. **Data governance defaults** have not been validated by the Indigenous advisory group (#1).
9. **Per-user SSE and API rate limits** do not exist outside the auth endpoints.
