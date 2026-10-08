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
| Images | ECR `blaksoc-web`, `blaksoc-worker` | Immutable tags = 12-character main commit. amd64. |
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
| Backups | S3 `coolify-yumabackups` (shared, ap-southeast-2) | blakSOC writes only under `blaksoc/`: nightly `pg_dump` to `blaksoc/postgres/`, cold syslog to `blaksoc/archive/`. IAM role `blaksoc-eks-storage` (inline policy `blaksoc-backups-prefix`) through EKS Pod Identity on service account `blaksoc/blaksoc` |
| Wazuh dashboard | `https://wazuh.yumait.au` | Cloudflare Tunnel `blaksoc-wazuh` (cloudflared on the Wazuh host, outbound only) behind Cloudflare Access: `yumait.com.au` Google identities, 12-hour session |
| Dashboard users | `blaksoc-wazuh-dashboard-users` | Personal Wazuh dashboard logins. `admin` (`INDEXER_PASSWORD` in `blaksoc-wazuh-credentials`) is the fallback |
| EKS audit | CloudWatch `/aws/eks/yumait-prod/cluster` | `audit` and `authenticator` control plane logs, 30 days. Read by the Wazuh host's role (`read-eks-control-plane-logs`) |
| Enrolment password | SSM parameter `/blaksoc/wazuh/enrollment` | Passed to SSM commands as the reference `{{ssm:/blaksoc/wazuh/enrollment}}`, which Systems Manager resolves on the instance; CloudTrail and command history keep only the reference. Mirrors `ENROLLMENT_PASSWORD` in `blaksoc-wazuh-credentials` |

## Deploy a new version

1. Merge to main. Build both targets for `linux/amd64` and push with the main commit as the tag.
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

Noise controls:

- blakSOC stores Wazuh alerts from `low` up (`minSeverity` on the integration). Informational events (sessions,
  sudo, login success) stay in Wazuh for 90 days (ISM policy `blaksoc-alerts-90d`).
- The `yumait-aws` agent group's shared configuration (`deploy/wazuh/agent-yumait-aws.conf`, applied by
  `wazuh-host.sh`) skips inode checks on `/boot/efi`: it is FAT, and Linux renumbers its inodes.

Intel: OpenCTI on `threatsieve-opencti-production` runs public feed connectors next to ThreatSieve's (MITRE ATT&CK,
CISA KEV, abuse.ch ThreatFox, URLhaus and SSL blacklist, OpenCTI datasets). They are defined in ThreatSieve's
`infra/opencti/compose.yaml` and use the non-admin connector token; none needs an API key.

Kubernetes visibility: Wazuh reads the EKS audit and authenticator logs every 5 minutes (aws-s3 wodle,
`cloudwatchlogs`). Rules in `blaksoc_eks_rules.xml` (installed by `wazuh-host.sh`) watch people and unknown
identities; Kubernetes controllers (`system:`) and EKS components (`eks:`) are ignored.

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
- One RDS instance, single AZ, and one Redis node, the same as the other apps on this cluster.
