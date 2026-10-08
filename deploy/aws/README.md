# Yuma IT production on AWS

blakSOC runs on the `yumait-prod` EKS Auto Mode cluster in `ap-southeast-2`. Wazuh runs on its own EC2 host
in the same VPC. OpenCTI is shared with ThreatSieve (Cloudflare Workers), which feeds it through its own
connector. blakSOC-owned resources carry the tags `Project=yumait-eks` and `App=blaksoc`.

```
ThreatSieve (Cloudflare) ──STIX──► OpenCTI (EC2 threatsieve-opencti-production)
                                        ▲ GraphQL :8080 (EKS cluster SG only)
EC2 hosts ──agents──► Wazuh (EC2 blaksoc-wazuh) ◄──API :55000 / indexer :9200── blakSOC (EKS)
outside AWS ──agents──► NLB agents.soc.yumait.au ┘
```

## Resources

| Resource | Name | Notes |
| --- | --- | --- |
| EKS release | `blaksoc` in namespace `blaksoc` | Chart `deploy/helm/blaksoc`, values `values-yumait-prod.yaml` |
| Images | ECR `blaksoc-web`, `blaksoc-worker`, `blaksoc-hermes` | Immutable tags = 12-character main commit, the same tag for all three. amd64. |
| Database | RDS `blaksoc-eks-postgres` | PostgreSQL 16, `db.t4g.small`, encrypted, 7-day backups, deletion protection |
| Queue and events | ElastiCache `blaksoc-eks-cache` | Redis 7, TLS, `maxmemory-policy noeviction` for BullMQ |
| Runtime env | Secrets Manager `blaksoc-eks-runtime` | Synced to `blaksoc/blaksoc-runtime` by External Secrets |
| Generated credentials | Secrets Manager `blaksoc-eks-bootstrap` | Source of the runtime values, including break-glass |
| TLS | ACM `soc.yumait.au` | On the ALB created by the Ingress |
| Wazuh host | EC2 `blaksoc-wazuh` | `r7g.large` until the vCPU quota rises, then `m7g.xlarge` (stop, change type, start; IP and disk stay). Fixed private IP, 200 GiB gp3 kept on termination, private subnet, SSM only, termination protection |
| Agent entry | NLB `blaksoc-wazuh-agents` | Public TCP 1514 and 1515 to the Wazuh host only, for agents outside AWS |
| OpenCTI | EC2 `threatsieve-opencti-production` (ThreatSieve) | OpenCTI 7. Published on its private address, port 8080; its security group admits port 8080 from the EKS cluster SG only |
| Host credentials | `blaksoc-wazuh-credentials` | Indexer, API, dashboard and enrolment passwords, plus blakSOC's own API and indexer users. Read by the Wazuh host's role |
| OpenCTI token | `blaksoc-opencti-service-token` | blakSOC service account in OpenCTI's Connectors group (not admin). Expires after 365 days |
| Hermes model access | IAM role `blaksoc-eks-hermes` (to create) | Bedrock invoke on the AU Sonnet 4.5 inference profile only, through EKS Pod Identity on service account `blaksoc/blaksoc-hermes`. See [Hermes](#hermes-in-cluster-agent) |
| Backups | S3 `coolify-yumabackups` (shared, ap-southeast-2) | blakSOC writes only under `blaksoc/`: nightly `pg_dump` to `blaksoc/postgres/`, cold syslog to `blaksoc/archive/`. IAM role `blaksoc-eks-storage` (inline policy `blaksoc-backups-prefix`) through EKS Pod Identity on service account `blaksoc/blaksoc` |
| Wazuh dashboard | `https://wazuh.yumait.au` | Cloudflare Tunnel `blaksoc-wazuh` (cloudflared on the Wazuh host, outbound only) behind Cloudflare Access: `yumait.com.au` Google identities, 12-hour session |
| Dashboard users | `blaksoc-wazuh-dashboard-users` | Personal Wazuh dashboard logins. `admin` (`INDEXER_PASSWORD` in `blaksoc-wazuh-credentials`) is the fallback |
| Staff sign-in | Cloudflare Access SaaS app `blakSOC` (OIDC) | blakSOC SSO provider `yumait-staff` for `yumait.com.au`. Client ID and secret backed up in `blaksoc-eks-bootstrap` (`STAFF_SSO_*`) |
| EKS audit | CloudWatch `/aws/eks/yumait-prod/cluster` | `audit` and `authenticator` control plane logs, 30 days. Read by the Wazuh host's role (`read-eks-control-plane-logs`) |
| Enrolment password | SSM parameter `/blaksoc/wazuh/enrollment` | Passed to SSM commands as the reference `{{ssm:/blaksoc/wazuh/enrollment}}`, which Systems Manager resolves on the instance; CloudTrail and command history keep only the reference. Mirrors `ENROLLMENT_PASSWORD` in `blaksoc-wazuh-credentials` |

## Staff sign-in

Yuma IT staff sign in with organisation SSO: on `https://soc.yumait.au/login`, enter the `yumait.com.au` address
and choose **Continue with organisation SSO**. blakSOC sends them to Cloudflare Access (the same Google
Workspace and one-time PIN login as the Wazuh dashboard), which returns an OIDC identity. Password sign-in is
reserved for the break-glass administrator (`BREAK_GLASS_*` in `blaksoc-eks-bootstrap`; behind the
**Emergency break-glass access** link, with TOTP enforced).

- Access app `blakSOC` (type SaaS, OIDC, PKCE): redirect URI
  `https://soc.yumait.au/api/auth/sso/callback/yumait-staff`, policy "Yuma IT staff" (email domain
  `yumait.com.au`), 12-hour session.
- blakSOC provider `yumait-staff`: issuer is the Access app's OIDC issuer, domain `yumait.com.au`, no tenant
  (platform staff). Its domain is marked verified so a sign-in links to an account created in advance.
- Anyone in the domain can pass Access, but a new account holds no role until a platform admin grants one
  (`/admin`). `justin@yumait.com.au` and `josh@yumait.com.au` hold `platform_admin`.
- To rotate the client secret: regenerate it on the Access app, update `STAFF_SSO_CLIENT_SECRET` in
  `blaksoc-eks-bootstrap`, then replace `clientSecret` in the `oidc_config` JSON of the `yumait-staff` row in
  `sso_provider` (or call the SSO plugin's `updateSSOProvider` with a platform admin session). Registering
  again under the same provider ID fails: `providerId` is unique.

## Deploy a new version

1. Merge to main. Build the three images for `linux/amd64` and push with the main commit as the tag:

   ```bash
   sha=$(git rev-parse --short=12 HEAD)
   ecr=959038055523.dkr.ecr.ap-southeast-2.amazonaws.com
   for target in web worker; do
     docker --context homelab buildx build --builder homelab --platform linux/amd64 --target "$target" \
       -t "$ecr/blaksoc-$target:$sha" --push .
   done
   docker --context homelab buildx build --builder homelab --platform linux/amd64 -f hermes/Dockerfile \
     -t "$ecr/blaksoc-hermes:$sha" --push .
   ```

2. Install or upgrade:

   ```bash
   helm upgrade --install blaksoc deploy/helm/blaksoc -n blaksoc --create-namespace \
     --kube-context arn:aws:eks:ap-southeast-2:959038055523:cluster/yumait-prod \
     -f deploy/helm/blaksoc/values.yaml -f deploy/helm/blaksoc/values-yumait-prod.yaml \
     --set image.tag=<commit>
   ```

   The pre-upgrade hooks sync the secret, then run migrations and the reference-data seed.

### Client addresses

Set `config.TRUSTED_PROXY_CIDRS` in `values-yumait-prod.yaml` to the VPC CIDR. The ALB appends the client
address to `X-Forwarded-For`; without the VPC listed as a trusted proxy, sign-in rate limits fall back to one
shared bucket for multi-hop requests and syslog source allowlists reject them.

### Required runtime keys

`blaksoc-eks-runtime` must hold `DATABASE_URL`, `DATABASE_SYSTEM_URL`, `DATABASE_ADMIN_URL`,
`BLAKSOC_APP_DB_PASSWORD`, `BLAKSOC_SYSTEM_DB_PASSWORD`, `REDIS_URL`, `BETTER_AUTH_SECRET` and
`BLAKSOC_ENCRYPTION_KEY`. Only the migration job receives the whole secret; web and worker get the keys in
`runtimeSecretKeys`, so they never hold `DATABASE_ADMIN_URL`.

`DATABASE_SYSTEM_URL` and `BLAKSOC_SYSTEM_DB_PASSWORD` were added with the `blaksoc_system` role. Before the
first upgrade that includes them, generate a password, store it in `blaksoc-eks-bootstrap`, and add both keys
to `blaksoc-eks-runtime`. The URL is `postgres://blaksoc_system:<password>@<rds-endpoint>:5432/blaksoc` with the
password percent-encoded (`encodeURIComponent`); `BLAKSOC_SYSTEM_DB_PASSWORD` holds it unencoded. The migration
job checks that the two match and stops if they do not.
The migration job sets the role's password from `BLAKSOC_SYSTEM_DB_PASSWORD`. Web and worker refuse to start
in production without `DATABASE_SYSTEM_URL`.

Backups connect as `blaksoc_backup`, a read-only role that bypasses RLS so the dump holds every tenant (the RDS
master cannot bypass FORCE RLS). It logs in only when the migration job has `BLAKSOC_BACKUP_DB_PASSWORD`; the
CronJob reads `DATABASE_BACKUP_URL` (`backup.databaseUrlKey`), built the same way as `DATABASE_SYSTEM_URL`. Both
keys are in `blaksoc-eks-bootstrap` and `blaksoc-eks-runtime`.

## Hermes (in-cluster agent)

Hermes is blakSOC's alert-noise analyst. A CronJob (`blaksoc-blaksoc-hermes`, Mondays 09:30 Sydney time) runs
one container from ECR `blaksoc-hermes`: the official Hermes Agent image (v0.20.5, pinned by digest in
`hermes/Dockerfile`) plus a deterministic controller and the blakSOC tuning toolset (`hermes/warden`). It ships
**off** in `values.yaml` and **on, in dry-run**, in `values-yumait-prod.yaml`.

### What it reads

Only blakSOC's tuning API, inside the cluster (`http://blaksoc-blaksoc-web.blaksoc.svc:80`): anonymised alert
patterns for the last 7 days (counts, rule ids and groups, MITRE ids, severity and disposition distributions,
fleet co-firing), its own past actions with their outcomes, its memory notes and earlier reports. Never alert
titles, raw events, hostnames, usernames, IP or email addresses or customer names. blakSOC enforces that
server-side; the controller also:

- aborts the run, before any model call, if a response contains a key such as `title`, `hostname`, `username`,
  `ip`, `email` or `description` (any spelling, any depth), or an email or IP address in a kept value. The log
  line names the keys, never the values;
- keeps only allowlisted fields (`hermes/warden/api.py`) and logs dropped field names;
- drops analysts' annotation text and redacts identifier-shaped text everywhere else (blakSOC refusal
  messages, memory notes, the report), and rejects any action reason or report that contains one.

### Tools and guardrails

Hermes runs with every default toolset off (no terminal, browser, web, file, code execution, delegation or
cron) and Hermes' tool-search bridge, plugins and lazy installs disabled. It has exactly two toolsets, and the
controller refuses to start the run if the agent reports any other tool:

- its built-in `memory` tool;
- `blaksoc_tuning`, registered in-process into Hermes' tool registry: `get_patterns`, `get_past_actions`,
  `annotate_pattern`, `close_pattern_alerts`, `create_noise_rule`, `purge_pattern_noise`,
  `submit_weekly_report`. Reads return the controller's sanitised snapshot; Hermes cannot choose what is
  fetched.

Every write passes local guardrails first, whatever the model says (`hermes/warden/policy.py`): the pattern
must be in this run's data; no pattern with any high or critical alert; no pattern with analyst overrides;
no close on a pattern escalated or with an incident in the last 30 days; no close, noise rule or purge on a
pattern whose earlier Hermes action analysts undid or reopened; a reason of 10–500 characters (annotations
1,000) with no identifiers; noise rules 1–30 days; one action of each kind per pattern per run; and per-run caps of at most
10 closes, 5 noise rules, 10 purges and 50 annotations (`hermes.caps`, which can only be lowered). Every
attempt is recorded as executed, dry-run, refused by blakSOC, held back by a guardrail, or failed (outcome
unknown; writes are never retried after an ambiguous failure). The run is bounded by `hermes.model.maxTurns`
model calls, `maxTokens` tokens, `runSeconds` of wall clock and the Job's `activeDeadlineSeconds`, and is
never retried (`backoffLimit: 0`) so actions cannot repeat.

### Dry-run and the blakSOC switch

Two independent locks must both be open before Hermes changes anything:

1. `hermes.dryRun` (default `true`): Hermes records what it would do and calls no write endpoint
   (annotations included). Memory and the weekly report are still saved.
2. blakSOC's **Allow Hermes to act** switch: while it is off every write answers 409. Hermes then treats the
   rest of the run as dry-run and says so at the top of the report.

To start acting, review a few dry-run reports on the Hermes page, set `hermes.dryRun: false` in
`values-yumait-prod.yaml`, upgrade, and turn the switch on in blakSOC. Turning the switch off stops writes
immediately, without a deploy.

### Memory and the weekly report

Memory lives in blakSOC's database (`GET`/`PUT /api/v1/tuning/memory`, versioned), not on a volume. At the
start of a run the controller writes the notes into Hermes' memory file (an `emptyDir`); at the end it reads
them back, redacts identifiers, de-duplicates, caps them (40 notes, 6,000 characters) and saves them with the
version it read (a concurrent edit in blakSOC is merged and retried once). Actions analysts undid or reopened
become `[outcome]` lessons written by the controller, not the model; Hermes cannot remove them, they block
further closes on that pattern, and they expire after 180 days.

The report (`POST /api/v1/tuning/reports`) contains Hermes' sections (what was noisy, what it did, what it
held back, analyst feedback, Wazuh rule tuning recommendations by rule id) and the controller's own table
of every attempted action with counts of executed, dry-run, refused, held back and failed. A report is
submitted even when the model fails, and the Job then exits non-zero with one `run_failed` log line. Exit
codes: 2 configuration, 3 prohibited fields in a blakSOC response, 4 blakSOC API, 5 model run.

### Model and residency

Amazon Bedrock in `ap-southeast-2` through the Australian cross-region inference profile
`au.anthropic.claude-sonnet-4-5-20250929-v1:0`, which keeps inference in Sydney and Melbourne
(`hermes.model.id`, `hermes.model.region`). Rendering fails for a non-AU profile (`us.`, `eu.`, `apac.`,
`global.` …) or a region outside `ap-southeast-2`/`ap-southeast-4`; the controller checks the same at start.
Credentials come only from EKS Pod Identity: no AWS keys exist in the Secret or the pod.

To switch to `au.anthropic.claude-opus-5-5` once AWS enables it for this account (it currently answers
AccessDenied): add its inference-profile ARN and the matching `anthropic.claude-opus-5-5…` foundation-model
ARNs in both regions to the policy below, then set `hermes.model.id` in `values-yumait-prod.yaml` and upgrade.

### IAM role and Pod Identity

Create role `blaksoc-eks-hermes` with the Pod Identity trust policy (principal `pods.eks.amazonaws.com`,
actions `sts:AssumeRole` and `sts:TagSession`) and this inline policy, `blaksoc-hermes-bedrock`. Converse and
ConverseStream are authorised by `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`; there are
no separate IAM actions for them.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeAuSonnetProfile",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": "arn:aws:bedrock:ap-southeast-2:959038055523:inference-profile/au.anthropic.claude-sonnet-4-5-20250929-v1:0"
    },
    {
      "Sid": "InvokeSonnetOnlyThroughTheAuProfile",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": [
        "arn:aws:bedrock:ap-southeast-2::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
        "arn:aws:bedrock:ap-southeast-4::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"
      ],
      "Condition": {
        "StringEquals": {
          "bedrock:InferenceProfileArn": "arn:aws:bedrock:ap-southeast-2:959038055523:inference-profile/au.anthropic.claude-sonnet-4-5-20250929-v1:0"
        }
      }
    }
  ]
}
```

Then associate it with the service account the chart creates:

```bash
aws eks create-pod-identity-association --cluster-name yumait-prod --region ap-southeast-2 \
  --namespace blaksoc --service-account blaksoc-hermes \
  --role-arn arn:aws:iam::959038055523:role/blaksoc-eks-hermes
```

The pod's network policy (rendered when `networkPolicy.enabled`) allows only DNS, the web pods on 3000, the
Pod Identity agent (`169.254.170.23:80`) and public HTTPS for Bedrock. With a `bedrock-runtime` VPC interface
endpoint, set `hermes.networkPolicy.bedrockPublicHttps: false` and list its subnets' CIDRs in
`hermes.networkPolicy.bedrockCidrs`.

### blakSOC credential

1. In blakSOC, **Admin → API clients** (Service identities), create a platform identity (no tenant) named
   `hermes` with scopes `tuning:read`, `tuning:annotate`, `tuning:act`, `tuning:report` and `tuning:memory`,
   and copy the client ID and secret (shown once).
2. Add `HERMES_BLAKSOC_TOKEN` to Secrets Manager `blaksoc-eks-runtime` as `<client id>:<client secret>`. The
   controller exchanges it at `/api/v1/oauth/token` (client credentials) at the start of each run, because
   access tokens last 15 minutes. A bearer access token (`bsa_…`) also works, for a manual run inside its
   lifetime. External Secrets syncs the key into `blaksoc-runtime`; only the Hermes pod mounts it (web and
   worker do not list it in `runtimeSecretKeys`).
3. Rotate by rotating the identity's secret in blakSOC and updating the key; revoke the identity to stop
   Hermes at once.

### Build, check and run manually

Build and push with the other images (see [Deploy a new version](#deploy-a-new-version)). Tests:
`python3 -m unittest discover -s hermes/tests -t hermes` (standard library only; CI job `hermes`) and
`pnpm test` for the chart. After bumping the Hermes base digest, confirm the tool surface offline: build the
image and check that an agent constructed with the `memory` and `blaksoc_tuning` toolsets lists exactly
`memory` and the seven tuning tools (the controller refuses to run otherwise).

```bash
ctx=arn:aws:eks:ap-southeast-2:959038055523:cluster/yumait-prod
kubectl --context $ctx -n blaksoc create job hermes-manual-$(date +%Y%m%d%H%M) --from=cronjob/blaksoc-blaksoc-hermes
kubectl --context $ctx -n blaksoc logs -f job/hermes-manual-<suffix>
kubectl --context $ctx -n blaksoc get cronjob blaksoc-blaksoc-hermes   # last schedule and active jobs
```

A manual run takes the same guards, caps and dry-run setting as the scheduled one; with the Monday run still
active it is not blocked by `concurrencyPolicy`, so avoid overlapping them. Suspend the schedule with
`kubectl patch cronjob blaksoc-blaksoc-hermes -p '{"spec":{"suspend":true}}'` (the next upgrade resets it), or
set `hermes.enabled: false`.

## Data plane hosts

The scripts run as root through SSM Run Command and can be re-run:

- `wazuh-host.sh`: wazuh-docker single-node `v4.14.8`. Replaces the published default passwords before
  first start, turns on enrolment passwords, and sets the indexer `node.attr.region`. Reissues the indexer and
  API certificates from the stack's root CA with `wazuh-internal.soc.yumait.au` and the private address in the
  SAN, runs cloudflared for the dashboard, reads the EKS control plane logs, and installs the local rules.
- `wazuh-agent-ssm.py`: creates the `BlakSOC-WazuhAgent` SSM document and the State Manager association
  `blaksoc-wazuh-agent`, which runs `wazuh-agent.sh` on every SSM-managed Linux instance when it registers
  and daily after that. New EC2 hosts are enrolled without any action, provided they run the SSM agent with
  an instance profile that allows it. Re-run the script after changing `wazuh-agent.sh`.
- `wazuh-agent.sh`: installs and enrols the pinned agent on an EC2 host (Ubuntu or Amazon Linux) into group
  `yumait-aws`. It normally runs through the `BlakSOC-WazuhAgent` document; for a one-off Run Command,
  prefix it with `export WAZUH_REGISTRATION_PASSWORD='{{ssm:/blaksoc/wazuh/enrollment}}'` (a reference, never the
  value) and optionally `WAZUH_AGENT_NAME`. EC2 hosts point at `wazuh-internal.soc.yumait.au`, a public
  record holding the manager's private address: hosts on Tailscale resolve through MagicDNS, so a Route 53
  private zone would never be consulted. Every EC2 host in the VPC runs an agent; EKS Auto Mode nodes cannot.
- `opencti-host.sh`: a blakSOC-owned OpenCTI. Not used in production, which shares ThreatSieve's OpenCTI.

blakSOC's Wazuh API user (`blaksoc`) holds `agents_readonly`, `cluster_readonly` and a policy for
`active-response:command`; its indexer user (`blaksoc`) can only read `wazuh-alerts-*`, `wazuh-archives-*` and
`wazuh-states-vulnerabilities-*` plus node info for the region check. The integrations are `Wazuh (AWS)`,
linked to the `Yuma IT Internal` tenant by agent group `yumait-aws` and connecting to
`wazuh-internal.soc.yumait.au` with TLS verified against the stack's root CA (`caPem`), and `OpenCTI (ThreatSieve)` at platform
level.

Cases go to Kelpie (`kelpie` namespace, `https://kelpie-app.yumait.au`): the `Yuma IT Internal` tenant has a
Kelpie integration whose token (`blaksoc-kelpie-token`, Yuma IT organisation, `cases:*`, `comments:write`,
`observables:write`, 365 days) belongs to an organisation admin. Every open incident in that tenant becomes a
Kelpie case. Incidents open automatically only for high and critical alerts and correlation findings
(`AUTO_INCIDENT_SEVERITIES` in `src/lib/services/correlation.ts`); lower severities stay in the alert queue.
Wazuh local rule 100100 (installed by `wazuh-host.sh`) silences promiscuous-mode alerts from Docker `veth`
interfaces.

The SOC dashboard shows a card for Wazuh, ThreatSieve and Kelpie with a link and a status. Wazuh and Kelpie
come from their integrations' health checks (every 5 minutes); ThreatSieve from its public API `/health`
(checked at most once a minute). In `values-yumait-prod.yaml`, the "Open" links are `WAZUH_DASHBOARD_URL`,
`THREATSIEVE_URL` (the web app) and `KELPIE_URL`; `THREATSIEVE_API_URL` is the ThreatSieve API origin whose
`/health` gives that card its status, not a link.

Noise controls:

- blakSOC stores Wazuh alerts from `low` up. Change it under Integrations → the Wazuh integration → **Alert
  floor** (for example "high and critical only"); lower alerts then stay in Wazuh only. Informational events (sessions,
  sudo, login success) stay in Wazuh for 90 days (ISM policy `blaksoc-alerts-90d`).
- The `yumait-aws` agent group's shared configuration (`deploy/wazuh/agent-yumait-aws.conf`, applied by
  `wazuh-host.sh`) skips inode checks on `/boot/efi`: it is FAT, and Linux renumbers its inodes.

Intel: OpenCTI on `threatsieve-opencti-production` runs public feed connectors next to ThreatSieve's (MITRE ATT&CK,
CISA KEV, abuse.ch ThreatFox, URLhaus and SSL blacklist, OpenCTI datasets). They are defined in ThreatSieve's
`infra/opencti/compose.yaml` and use the non-admin connector token; none needs an API key.

Kubernetes visibility: Wazuh reads the EKS audit and authenticator logs every 5 minutes (aws-s3 wodle,
`cloudwatchlogs`). Rules in `blaksoc_eks_rules.xml` (installed by `wazuh-host.sh`) watch people and unknown
identities; Kubernetes controllers (`system:`), EKS components (`eks:`) and AWS service-linked roles
(`AWSServiceRoleFor*`) are ignored.

| Rule | Level | Fires on |
| --- | --- | --- |
| 100202 | 8 | `kubectl exec` or `attach` into a pod |
| 100203 | 7 | Reading secrets (`get`, `list`, `watch`) |
| 100204 | 10 | Creating, changing or deleting roles and role bindings |
| 100205 | 10 | A pod or workload with `privileged`, `hostPID` or `hostNetwork` |
| 100206 | 12 | An anonymous request allowed, other than health and version |
| 100207, 100208 | 5, 10 | A request refused (403); ten from one identity in two minutes |
| 100210, 100211 | 5, 10 | An IAM identity refused by the authenticator; ten in two minutes |

Wazuh dashboard: `https://wazuh.yumait.au`. Cloudflare Access asks for a `yumait.com.au` Google sign-in, then
Wazuh asks for its own login (`blaksoc-wazuh-dashboard-users`). Wazuh logins are indexer internal users with
backend role `admin`, plus a Wazuh API security rule mapping the user name to the `administrator` role (the
dashboard runs API calls as the signed-in user).

Reach OpenCTI with SSM port forwarding, for example:

```bash
aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSession \
  --parameters portNumber=8080,localPortNumber=8080
```

## DNS (Cloudflare, `yumait.au`)

| Name | Type | Target | Proxy |
| --- | --- | --- | --- |
| `soc.yumait.au` | CNAME | ALB hostname from `kubectl -n blaksoc get ingress` | DNS only |
| `agents.soc.yumait.au` | CNAME | NLB hostname | DNS only (raw TCP) |
| `wazuh-internal.soc.yumait.au` | A | the manager's fixed private address | DNS only |
| `wazuh.yumait.au` | CNAME | Cloudflare Tunnel `blaksoc-wazuh` | Proxied (one level, so Universal SSL covers it) |
| ACM validation | CNAME | from the certificate | DNS only |

## Known gaps

- The `r7g.large` Wazuh host stays below `m7g.xlarge` until the account's vCPU quota increase is granted.
- Helm upgrades need cluster-admin on `yumait-prod` (the hooks manage External Secrets objects). The Agent Vault
  IAM user has `AmazonEKSClusterAdminPolicy`.
- Network policies are disabled here because the cluster does not enforce them. The chart now allows public
  HTTPS egress with private and metadata ranges excluded (`networkPolicy.publicHttps`). Before turning
  enforcement on, set `networkPolicy.dataStoresInCluster: false`, add the VPC range to
  `networkPolicy.egressCidrs` for RDS, ElastiCache, Wazuh and OpenCTI, and replace the ingress-nginx namespace
  rule with one that admits the ALB.
- Hermes needs, before its first run: ECR repository `blaksoc-hermes` (immutable tags), IAM role
  `blaksoc-eks-hermes` with its Pod Identity association, the `hermes` service identity in blakSOC and
  `HERMES_BLAKSOC_TOKEN` in `blaksoc-eks-runtime`. None of these exist yet.
- One RDS instance, single AZ, and one Redis node, the same as the other apps on this cluster.
