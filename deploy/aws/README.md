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
| Wazuh host | EC2 `blaksoc-wazuh` (`i-081ab4c4f4199e054`) | `r7g.large` until the vCPU quota rises, then `m7g.xlarge` (stop, change type, start; IP and disk stay). Fixed IP `172.31.49.40`, 200 GiB gp3 kept on termination, private subnet, SSM only, termination protection |
| Agent entry | NLB `blaksoc-wazuh-agents` | Public TCP 1514 and 1515 to the Wazuh host only, for agents outside AWS |
| OpenCTI | EC2 `threatsieve-opencti-production` (ThreatSieve) | OpenCTI 7. Published on `172.31.49.31:8080`; its security group admits port 8080 from the EKS cluster SG only |
| Host credentials | `blaksoc-wazuh-credentials` | Indexer, API, dashboard and enrolment passwords, plus blakSOC's own API and indexer users. Read by the Wazuh host's role |
| OpenCTI token | `blaksoc-opencti-service-token` | blakSOC service account in OpenCTI's Connectors group (not admin). Expires after 365 days |
| Enrolment password | SSM `/blaksoc/wazuh/enrollment-password` | SecureString mirror; Run Command does not resolve `ssm-secure` references, so the rollout reads the secret instead |

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

## Data plane hosts

The scripts run as root through SSM Run Command and can be re-run:

- `wazuh-host.sh`: wazuh-docker single-node `v4.14.8`. Replaces the published default passwords before
  first start, turns on enrolment passwords, and sets the indexer `node.attr.region`.
- `wazuh-agent.sh`: installs and enrols the pinned agent on an EC2 host (Ubuntu or Amazon Linux) into group
  `yumait-aws`. Prefix it with exports of `WAZUH_REGISTRATION_PASSWORD` and `WAZUH_AGENT_NAME` (the Name tag)
  when sending it with `AWS-RunShellScript`. EC2 hosts point at `wazuh-internal.soc.yumait.au`, a public
  record holding the manager's private address: hosts on Tailscale resolve through MagicDNS, so a Route 53
  private zone would never be consulted. Every EC2 host in the VPC runs an agent; EKS Auto Mode nodes cannot.
- `opencti-host.sh`: a blakSOC-owned OpenCTI. Not used in production, which shares ThreatSieve's OpenCTI.

blakSOC's Wazuh API user (`blaksoc`) holds `agents_readonly`, `cluster_readonly` and a policy for
`active-response:command`; its indexer user (`blaksoc`) can only read `wazuh-alerts-*`, `wazuh-archives-*` and
`wazuh-states-vulnerabilities-*` plus node info for the region check. The integrations are `Wazuh (AWS)`,
linked to the `Yuma IT Internal` tenant by agent group `yumait-aws`, and `OpenCTI (ThreatSieve)` at platform
level.

Reach the Wazuh dashboard or OpenCTI with SSM port forwarding, for example:

```bash
aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSession \
  --parameters portNumber=8080,localPortNumber=8080
```

## DNS (Cloudflare, `yumait.au`)

| Name | Type | Target | Proxy |
| --- | --- | --- | --- |
| `soc.yumait.au` | CNAME | ALB hostname from `kubectl -n blaksoc get ingress` | DNS only |
| `agents.soc.yumait.au` | CNAME | NLB hostname | DNS only (raw TCP) |
| `wazuh-internal.soc.yumait.au` | A | `172.31.49.40` (manager private address) | DNS only |
| ACM validation | CNAME | from the certificate | DNS only |

## Known gaps

- The Wazuh indexer and API certificates name `wazuh.indexer` and `localhost`, so the Wazuh integration
  connects to `172.31.49.40` with `tlsVerify: false`. Traffic stays in the VPC and the ports admit only the VPC
  range. Reissue the certificates with the IP (or a private name) in the SAN, then set `caPem` and turn
  verification back on.
- `BLAKSOC_ARCHIVE_S3_BUCKETS` is unset, so cold syslog lives on the worker's emptyDir. Create the AU buckets and
  an IAM role for the service account, then set `archive.s3` and `backup` in `values-yumait-prod.yaml`.

- Network policies are disabled here because the cluster does not enforce them. The chart now allows public
  HTTPS egress with private and metadata ranges excluded (`networkPolicy.publicHttps`). Before turning
  enforcement on, set `networkPolicy.dataStoresInCluster: false`, add the VPC range to
  `networkPolicy.egressCidrs` for RDS, ElastiCache, Wazuh and OpenCTI, and replace the ingress-nginx namespace
  rule with one that admits the ALB.
- One RDS instance, single AZ, and one Redis node, the same as the other apps on this cluster.
