# blakSOC security model

## Identity

| Path | Who | Notes |
|---|---|---|
| Microsoft Entra ID (OIDC) | Yuma IT staff | `ENTRA_*` env; single-tenant app registration. MFA enforced by Entra Conditional Access. |
| Organisation SSO (OIDC or SAML) | Customer users, government/enterprise IdPs | Registered per customer by platform admins only (`providersLimit` is 0 for everyone else). Users arrive with **no role** until one is assigned. |
| Password | Break-glass administrators only | Sign-in hook rejects password auth for any non-break-glass user. TOTP enrolment is forced before any page loads (`BREAK_GLASS_REQUIRE_MFA`). Sessions show a red banner. |
| Demo personas | `DEMO_MODE=true` only | Never enable in production. |

## Authorisation

- Permissions (`src/lib/auth/permissions.ts`) are grouped into built-in roles; custom roles are rows in `roles`.
- Platform-scope roles (Yuma IT) span tenants; tenant-scope roles are bound to one tenant. A tenant role assigned without a tenant is ignored, never widened.
- Every service call checks the permission **per tenant** and builds the DB scope from only the tenants where the permission holds.

## Tenant isolation (defence in depth)

1. Explicit `tenant_id` filters in every service query.
2. Postgres RLS on every tenant table (`src/db/sql/005_rls.sql`), `FORCE`d, evaluated against transaction-local `app.tenant_ids` set by `withScope()`.
3. App connects as `blaksoc_app` (no ownership, `NOBYPASSRLS`). Migrations/seed use the owner role, which the running web tier never needs.
4. Integration tests (`tests/integration/tenancy.test.ts`) assert cross-tenant reads return nothing, cross-tenant filters fail closed, and customers cannot triage.
5. SSE live events are filtered server-side per viewer.

## Secrets

Integration secrets are AES-256-GCM encrypted with `BLAKSOC_ENCRYPTION_KEY`, with the integration id as
additional authenticated data (a ciphertext cannot be moved to another row). Secrets are write-only in
the UI and API: they are never selected into client payloads, and updates keep existing values when blank.

## Audit

`audit_log` is append-only: the app role has no UPDATE/DELETE grant, a statement trigger rejects
UPDATE/DELETE/TRUNCATE, and each row is hash-chained (SHA-256 of the previous hash + row content) by a
`SECURITY DEFINER` trigger. `audit_log_verify()` (Admin → Audit → Verify integrity) detects tampering by
anyone who bypasses the triggers.

## Containment safety

- Destructive actions (isolate, disable identity, block IOC, kill process) always create an approval
  unless a **platform administrator** enabled auto-containment for that customer — and then only for
  playbook-initiated actions.
- AI-originated actions are always approval-gated, regardless of tenant settings.
- Approvals expire after 24h; decisions and executions are audited and placed on the incident timeline.

## AI

- Tenant data reaches a model only after `checkAiPolicy`: AI enabled for the tenant, provider on the
  tenant allow-list (if set), and — under `AI_DATA_RESIDENCY=AU` — provider declares Australian processing.
- Raw event payloads are stripped unless the tenant allows them; PII (emails, AU phone, TFN, Medicare) is redacted by default.
- Tools run with the analyst's own permissions pinned to one tenant. Write tools are off by default.
- Citations the model makes that no tool returned are flagged as unverified; every call is recorded in `ai_invocations`.

## Threat-intel sharing

Sightings are created in OpenCTI only when the tenant's sharing policy allows it, attributed by default to
an anonymised sector identity (e.g. "blakSOC AU healthcare sector"), never the customer's name unless the
policy is explicitly `named`. Commercial feed intel is filtered per tenant entitlement before it is shown
or scored.

## Hardening checklist

- Set strong `BETTER_AUTH_SECRET`, `BLAKSOC_ENCRYPTION_KEY`, DB/Redis passwords; rotate via your secret manager.
- TLS everywhere; Wazuh/OpenCTI CAs can be pinned per integration (`caPem`) instead of disabling verification.
- Keep `DEMO_MODE=false`. Store break-glass credentials + TOTP backup codes sealed and test them quarterly.
- Restrict worker egress to Wazuh, OpenCTI, AI endpoints and the public feed hosts (Helm `networkPolicy.egressCidrs`).
