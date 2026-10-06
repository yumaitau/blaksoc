# Yuma IT production on AWS

blakSOC runs on the `yumait-prod` EKS Auto Mode cluster in `ap-southeast-2`. Wazuh and OpenCTI run on
separate EC2 hosts in the same VPC. Everything carries the tags `Project=yumait-eks` and `App=blaksoc`.

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
| Wazuh host | EC2 `blaksoc-wazuh` | `m7g.xlarge`, 200 GiB gp3, private subnet, SSM only |
| OpenCTI host | EC2 `blaksoc-opencti` | `m7g.xlarge`, 150 GiB gp3, private subnet, SSM only |
| Agent entry | NLB `blaksoc-wazuh-agents` | Public TCP 1514 and 1515 to the Wazuh host only |
| Host credentials | `blaksoc-wazuh-credentials`, `blaksoc-opencti-credentials` | Read by the hosts' instance role |

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

## Data plane hosts

The scripts run as root through SSM Run Command and can be re-run:

- `wazuh-host.sh`: wazuh-docker single-node `v4.14.8`. Replaces the published default passwords before
  first start, turns on enrolment passwords, and sets the indexer `node.attr.region`.
- `opencti-host.sh`: OpenCTI from `deploy/compose/docker-compose.yml` (profile `opencti`). Copy the compose
  file to `/opt/blaksoc-opencti/docker-compose.yml` first.

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
| ACM validation | CNAME | from the certificate | DNS only |

## Known gaps

- The worker needs internet egress (Microsoft Graph, Kelpie, CISA KEV, FIRST EPSS, ABR). The chart's
  network policies assume cluster-only egress and are disabled here because the cluster does not enforce
  them. Add an egress proxy or allow-list before turning enforcement on.
- One RDS instance, single AZ, and one Redis node, the same as the other apps on this cluster.
