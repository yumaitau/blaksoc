# blakSOC security model

## Identity

| Path | Who | Notes |
|---|---|---|
| Microsoft Entra ID (OIDC) | Yuma IT staff | `ENTRA_*` env; single-tenant app registration. MFA enforced by Entra Conditional Access. |
| Google Workspace (OIDC) | Yuma IT staff | `GOOGLE_*` env. `GOOGLE_HOSTED_DOMAIN` is required with the client id; it is sent as the `hd` hint and checked against the verified ID token, so personal Google accounts are refused. |
| Organisation SSO (OIDC, SAML or Google Workspace) | Customer users, government/enterprise IdPs | Registered per customer by platform admins only (`providersLimit` is 0 for everyone else). The SSO `resolveUser` hook refuses an identity whose email is outside the provider's domains, and a Google identity whose `hd` claim is not one of them (`src/lib/auth/sso-policy.ts`). Users arrive with **no role** until one is assigned. |
| Passkey (WebAuthn) | Any user with access | Added at `/account/security` from a session no older than 15 minutes (`session.freshAge`), so a stolen cookie cannot mint a lasting credential. Adds and deletions are audited (`auth.passkey.add`, `auth.passkey.delete`). A passkey does not go back to the IdP: disable the blakSOC user to stop it working until SCIM deprovisioning exists (#102). |
| Password | Break-glass administrators only | Sign-in hook rejects password auth for any non-break-glass user. TOTP enrolment is forced before any page loads (`BREAK_GLASS_REQUIRE_MFA`). Sessions show a red banner. |
| Demo personas | `DEMO_MODE=true` only | Never enable in production. |

## Authorisation

- Permissions (`src/lib/auth/permissions.ts`) are grouped into built-in roles; custom roles are rows in `roles`.
- Platform-scope roles (Yuma IT) span tenants; tenant-scope roles are bound to one tenant. A tenant role assigned without a tenant is ignored, never widened.
- Every service call checks the permission **per tenant** and builds the DB scope from only the tenants where the permission holds.

## Tenant isolation (defence in depth)

1. Explicit `tenant_id` filters in every service query.
2. Postgres RLS on every tenant table (`src/db/sql/005_rls.sql`), `FORCE`d, evaluated against transaction-local `app.tenant_ids` set by `withScope()`.
3. App connects as `blaksoc_app` (no ownership, `NOBYPASSRLS`). Worker jobs and the few web paths that run before a tenant scope exists (onboarding, provider lookups) use `blaksoc_system`, which also owns nothing and has no `BYPASSRLS`: it reaches rows through `system_access` policies (`src/db/sql/020_system_access.sql`), so it cannot change schema, policies or triggers, or update or delete audit rows. Only the migration job holds the owner credentials; the Helm chart gives web and worker an explicit list of secret keys (`runtimeSecretKeys`) that excludes them.
4. Integration tests (`tests/integration/tenancy.test.ts`) assert cross-tenant reads return nothing, cross-tenant filters fail closed, and customers cannot triage.
5. SSE live events are filtered server-side per viewer.

## Secrets

Integration secrets are AES-256-GCM encrypted with `BLAKSOC_ENCRYPTION_KEY`, with the integration id as
additional authenticated data (a ciphertext cannot be moved to another row). Secrets are write-only in
the UI and API: they are never selected into client payloads, and updates keep existing values when blank.

## Audit

`audit_log` is append-only: the app and system roles have no UPDATE/DELETE grant, a statement trigger rejects
UPDATE/DELETE/TRUNCATE, and each row is hash-chained (SHA-256 of the previous hash + row content) by a
`SECURITY DEFINER` trigger. Rows written since migration 0022 (`hash_version` 2) also cover the source IP. `audit_log_verify()` (Admin → Audit → Verify integrity) detects tampering by
anyone who bypasses the triggers.

## Containment safety

- Destructive actions (isolate, disable identity, block IOC, kill process) always create an approval
  unless a **platform administrator** enabled auto-containment for that customer — and then only for
  playbook-initiated actions.
- Every AI-proposed action is approval-gated, destructive or not (releasing an endpoint or unblocking an IOC
  included), regardless of tenant settings (`responseNeedsApproval` in `src/lib/soar/response.ts`).
- Approvals expire after 24h. A worker job expires them every 5 minutes, rejects the waiting response action
  or DFIR collection, and cancels the waiting playbook run. Decisions, expiries and executions are audited and
  placed on the incident timeline.
- Integration URLs go through an egress guard (`src/lib/net/egress.ts`) that refuses cloud metadata and
  link-local addresses for every connector, and private addresses for SaaS endpoints (webhooks, Teams, Slack,
  Azure OpenAI). The check runs on each connection, so DNS answers that change after a check are covered.

## AI

- Tenant data reaches a model only after `checkAiPolicy`: AI enabled for the tenant, provider on the
  tenant allow-list (if set), and — under `AI_DATA_RESIDENCY=AU` — provider declares Australian processing.
  The tenant's data governance profile must also allow the capability (see below).
- Raw event payloads are stripped unless the tenant allows them; PII (emails, AU phone, TFN, Medicare) is redacted by default.
- Tools run with the analyst's own permissions pinned to one tenant. Write tools are off by default.
- Citations the model makes that no tool returned are flagged as unverified; every call is recorded in `ai_invocations`.

## Data governance profile

Each customer tenant has a data governance profile (`data_governance`). It narrows tenant settings and
never widens them. A tenant with no row is governed by the most protective profile, and onboarding writes
that profile explicitly.

| Rule | Most protective (default) | Enforced in |
| --- | --- | --- |
| Residency lock | On | `checkGovernedAi` (assistant), `intelProviderFor` (intel lookups), EPSS refresh |
| Sightings | None, no consent | `requestSighting` (service) and `createSighting` (worker) |
| AI, per capability | Assistant off, alert summaries off | `runAssistant`, assistant page |

- Storage, backups and log archives are pinned to `ap-southeast-2`/`ap-southeast-4` for every tenant by the
  hosting profile, so the lock adds AI inference and intel lookups to that boundary.
- Under the lock, an intel connector whose config declares a non-AU region is not used. EPSS scores for CVEs
  held only by locked tenants come from the public bulk file, so their CVE list is never sent abroad.
- A sighting needs both the tenant sharing setting and steward consent. The narrower attribution and the
  lower TLP ceiling apply. Consent records which stewards approved it and when.
- Only **data stewards** (`data_steward`, a tenant-scope role matched by key on a direct grant) can change
  the profile. Platform staff cannot hold it, and a steward cannot be given a platform role.
- With two or more stewards, a change needs two different stewards. The proposer cannot approve their own
  change. Applying a change supersedes other open proposals.
- Proposals, approvals, rejections, applied changes and steward list changes are audited, and every steward
  is emailed. A missing email connector is recorded as a failed delivery, never skipped silently.

**Status:** the requirements above follow issue #13. They have not yet been validated by the Indigenous
advisory group (#1), and no decision-log entry exists to trace them to. Treat the defaults as interim until
that review.

## Threat-intel sharing

Sightings are created in OpenCTI only when the tenant's sharing policy and data stewards allow it, attributed by default to
an anonymised sector identity (e.g. "blakSOC AU healthcare sector"), never the customer's name unless the
policy is explicitly `named`. Commercial feed intel is filtered per tenant entitlement before it is shown
or scored.

## External scanning

The `surface` worker job is the only scanner. It allows one active scan per tenant and six hosts per minute. The worker NetworkPolicy (`deploy/helm/blaksoc/templates/networkpolicy.yaml`) is the egress for DNS, certificate transparency, WHOIS, Have I Been Pwned, and an entitled Shodan or Censys lookup. Web pods do not scan. Active scanning starts only after an `asm.attest` audit row for that domain. The shipped scanner uses fixture observations and does not open sockets to customer hosts.

## Credential exposure

A domain must pass TXT verification before a breach check runs. Each stored row has the email address, breach name, source (`hibp` or the commercial feed name), observation date, and data classes. Permitted classes are `email`, `username`, and `password-hash`. Plaintext passwords are removed before insert and are not a permitted class. The same email, breach, and source are stored once. Commercial infostealer rows use `filterByEntitlement()` and are dropped when the tenant is not licensed for that feed.

## Browser hardening

`src/proxy.ts` sets a per-request Content-Security-Policy on every page and API response (except
better-auth's own `/api/auth/*` protocol endpoints): scripts only
with the request's nonce (`'strict-dynamic'`, no `'unsafe-inline'` or `'unsafe-eval'` in production),
same-origin `connect-src` (SSE) and `worker-src` (portal service worker), `frame-ancestors 'none'`,
`form-action 'self'`, `base-uri 'none'`, `object-src 'none'`. Every page renders per request so Next.js can
stamp the nonce on its scripts (`src/app/layout.tsx`); an inline script must read `x-nonce` from the request
headers (see `src/app/(portal)/layout.tsx`). Other headers (HSTS, `X-Frame-Options`, `nosniff`,
`Referrer-Policy`, `Permissions-Policy`) are in `next.config.ts`.

## Supply chain

CI builds the app and both images and validates the chart on every PR (`.github/workflows/ci.yml`), runs
CodeQL, gitleaks over full history and `pnpm audit --prod` at high severity. Release images are scanned with
Trivy, signed with cosign keyless, and published with SPDX and CycloneDX SBOMs and the scan report
(`.github/workflows/release.yml`). Verify an image before deploying it:

```sh
cosign verify ghcr.io/yumaitau/blaksoc-web@<digest> \
  --certificate-identity-regexp '^https://github.com/yumaitau/blaksoc/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Threats, trust boundaries and open risks: [`threat-model.md`](threat-model.md). Disclosure policy:
[`/SECURITY.md`](../SECURITY.md).

## Hardening checklist

- Set strong `BETTER_AUTH_SECRET`, `BLAKSOC_ENCRYPTION_KEY`, DB/Redis passwords; rotate via your secret manager.
- TLS everywhere; Wazuh/OpenCTI CAs can be pinned per integration (`caPem`) instead of disabling verification.
- Keep `DEMO_MODE=false`. Store break-glass credentials + TOTP backup codes sealed and test them quarterly.
- The shipped NetworkPolicies give web and worker cluster-internal egress plus public TCP 443 (`networkPolicy.publicHttps`), with private, link-local (cloud metadata), CGNAT and loopback ranges excluded. Set `publicHttps: false` for an air-gapped install. Add the VPC CIDR of a managed Postgres or Redis to `networkPolicy.egressCidrs`. Do not set `egressCidrs` to `0.0.0.0/0` or `::/0`.
