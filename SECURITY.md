# Security policy

blakSOC is a security operations platform that holds customer security telemetry, so we treat
vulnerability reports as a priority. Thank you for helping keep blakSOC and its users safe.

## Reporting a vulnerability

Please **do not** open a public issue, pull request or discussion for a security problem.

Report privately through either channel:

- GitHub private vulnerability reporting:
  <https://github.com/yumaitau/blaksoc/security/advisories/new>
- Email: <security@yumait.com.au>

Include what you can of:

- the affected component (web app, customer portal, API, worker, Helm chart, container image) and version or commit;
- steps to reproduce, a proof of concept, or the request and response involved;
- the impact you believe it has (for example cross-tenant data access, authentication bypass, code execution);
- whether you want to be credited, and under what name.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledge your report | 3 business days |
| Initial assessment and severity (CVSS) | 10 business days |
| Fix or mitigation for critical and high issues | 30 days, sooner where exploitation is likely |
| Coordinated public disclosure | When a fix is released, or 90 days after the report, whichever is first, unless we agree otherwise |

We will keep you updated while we work on it, and credit you in the advisory unless you ask us not to.

## Scope

In scope:

- this repository: the Next.js web app and customer portal, API routes, the worker, database migrations
  and row-level security, the Dockerfile and published images (`ghcr.io/yumaitau/blaksoc-web`,
  `ghcr.io/yumaitau/blaksoc-worker`), and the Helm chart under `deploy/helm`;
- tenant isolation, authentication (SSO, passkeys, break-glass), authorisation, audit integrity, secret
  handling and the AI data controls described in [`docs/SECURITY.md`](docs/SECURITY.md).

Out of scope:

- third-party components blakSOC integrates with (Wazuh, OpenCTI, identity providers, cloud services).
  Report those to their maintainers; tell us too if blakSOC's use of them makes the issue worse;
- findings that need a compromised administrator account, physical access, or a deployment that ignores the
  hardening checklist in `docs/SECURITY.md` (for example `DEMO_MODE=true` in production);
- volumetric denial of service, social engineering, and reports from automated scanners without a demonstrated impact.

## Safe harbour

We will not pursue legal action against good-faith research that follows this policy: test only against
your own deployment or accounts you own, do not access, change or keep other people's data, stop and report
as soon as you reach data that is not yours, and give us reasonable time to fix the issue before disclosure.

Do not test against Yuma IT's production service (`soc.yumait.au`) or any customer deployment without
written permission.

## Supported versions

Security fixes go to the latest release. Images are published per release with immutable version tags, a
signed SBOM and a vulnerability scan report (see `.github/workflows/release.yml`).

## Further reading

- [`docs/SECURITY.md`](docs/SECURITY.md): the security model and hardening checklist.
- [`docs/threat-model.md`](docs/threat-model.md): STRIDE threat model, trust boundaries and open risks.
