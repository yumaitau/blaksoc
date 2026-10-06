# Hosting profile

Shared control plane and a single-node k3s install. The archive table is the output of `pnpm exec tsx scripts/hosting-load.ts docs/hosting-load.json`. That command runs k6 against the file object store in `src/lib/hosting/store.ts`. OpenSearch, the Wazuh indexer, and OpenCTI numbers are in the data-plane section. Public list prices are not a bill and are not a sized cluster for 10, 50, or 200 tenants.

## Measured archive load

k6 v2.3.0 on Darwin arm64, Node v22.23.1, Apple M4, 10 CPUs, 17179869184 bytes of RAM. Each tenant is 20 objects. Each iteration does one PUT and one GET. Byte counts are what the store wrote during that run. RSS and CPU are the Node process that served the store, sampled after the run.

| Tenants | Objects | Bytes | Wall ms | HTTP avg ms | HTTP p95 ms | Server RSS bytes | CPU user µs | CPU system µs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 200 | 40400 | 306.49 | 0.37 | 0.58 | 89571328 | 40441 | 46578 |
| 50 | 1000 | 202000 | 440.36 | 0.28 | 0.54 | 90275840 | 135526 | 219121 |
| 200 | 4000 | 808000 | 813.22 | 0.23 | 0.43 | 91553792 | 370923 | 850405 |

The same run rejected a `us-east-1` put. Raw rows are in `docs/hosting-load.json`.

## Measured data plane

Measured 2026-09-29 on OrbStack 29.4.0 with 47.03 GiB RAM. The egress country of that host was AU. This run was not in an AWS account. Each tenant is 20 documents. OpenSearch and the Wazuh indexer report the bulk API `took` time. Client wall includes the SSH hop to the Docker host. OpenCTI wall is the time inside the platform container for that many `indicatorAdd` calls. Raw rows are in `docs/hosting-plane.json`.

The OpenSearch node API returned region `ap-southeast-2` (OpenSearch 2.19.6). One stored document read back with that region. The Wazuh indexer image `wazuh/wazuh-indexer:4.14.8` returned the same region after `deploy/wazuh/indexer-region.yml` wrote `node.attr.region` into `opensearch.yml`. One stored document read back with that region. OpenCTI `opencti/platform:6.8.0` had `BLAKSOC_REGION` set to `ap-southeast-2` and wrote into that OpenSearch. One indicator read back was named `blaksoc-load-ap-southeast-2-0`.

The OpenSearch data disk on that host was 95 percent full, with 12.4 GB free. The first OpenCTI `indicatorAdd` hit a flood-stage read-only block. The throwaway cluster's disk watermark was raised and the block was cleared. The calls below then succeeded. MinIO does not advertise a storage region. The platform, search, MinIO, RabbitMQ, and Redis processes were on this same host.

### OpenSearch bulk

| Tenants | Objects | Server took ms | Client wall ms | Errors | Count | Container memory |
| --- | --- | --- | --- | --- | --- | --- |
| 10 | 200 | 146 | 665.12 | false | 200 | 2.653GiB |
| 50 | 1000 | 176 | 760.7 | false | 1000 | 2.677GiB |
| 200 | 4000 | 160 | 703.65 | false | 4000 | 2.689GiB |

### Wazuh indexer bulk

| Tenants | Objects | Server took ms | Client wall ms | Errors | Count | Container memory |
| --- | --- | --- | --- | --- | --- | --- |
| 10 | 200 | 180 | 851.7 | false | 200 | 1.44GiB |
| 50 | 1000 | 166 | 927.09 | false | 1000 | 1.474GiB |
| 200 | 4000 | 194 | 884.06 | false | 4000 | 1.532GiB |

### OpenCTI indicatorAdd

| Tenants | Calls | Wall ms | Read back | Container memory |
| --- | --- | --- | --- | --- |
| 10 | 200 | 5196 | true | 357MiB |
| 50 | 1000 | 20825 | true | 335.6MiB |
| 200 | 4000 | 73931 | true | 349.7MiB |

After the 200-tenant run the containers were using 256.8MiB (platform), 2.896GiB (OpenSearch), 86.1MiB (MinIO), 116.2MiB (RabbitMQ), and 11.54MiB (Redis).

## Public list prices

Fetched 2026-09-29. Raw rows are in `docs/hosting-prices.json`. These rates are what the publishers listed. They are not an invoice and not a recommendation of how many nodes 10, 50, or 200 tenants need.

### AWS OpenSearch

Public offer `AmazonES`, publication `2026-09-27T12:24:24Z`. On-demand USD per hour. The offer attributes for `t3.small.search` are 2 vCPU, 2 GiB memory, EBS only.

| Instance | vCPU | Memory GiB | ap-southeast-2 USD/hr | ap-southeast-4 USD/hr |
| --- | --- | --- | --- | --- |
| t3.small.search | 2 | 2 | 0.056 | 0.056 |

gp3 storage, USD per GB-month: `0.1464` in ap-southeast-2 (`APS2-ES:GP3-Storage`), `0.146` in ap-southeast-4 (`APS6-ES:GP3-Storage`).

Source prefix: `https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonES/20260927122424/`

### Australian-owned IaaS

Binary Lane sizes API `https://api.binarylane.com.au/v2/sizes`, also shown on `https://www.binarylane.com.au/vps-hosting/linux-vps`. AUD, exclusive of GST. The page marks these CPU plans as a starting price ("From"). The API row is that starting disk. Both SKUs list Sydney, Melbourne, Brisbane, and Perth only.

| Slug | vCPU | Memory MB | Disk GB | AUD / month | AUD / hour | Regions |
| --- | --- | --- | --- | --- | --- | --- |
| cpu-6thr | 6 | 12288 | 200 | 108 | 0.15 | syd, mel, bne, per |
| cpu-8thr | 8 | 16384 | 300 | 144 | 0.2 | syd, mel, bne, per |

Binary Lane is an Australian-owned VPS host. This table is not an IRAP sovereign-cloud rate card. Fetches of `https://www.vaultcloud.com.au/` and `https://macquariecloudservices.com/` on the same day returned no readable VM price, so no figure from those providers is listed.

## Chart requests

These requests are the Helm budget, not the measurement above.

Shared chart `deploy/helm/blaksoc/values.yaml`: web and worker replicas 2, request 250m CPU and 512Mi memory, memory limit 1Gi. Web autoscaling runs from 2 to 8 replicas at 70% CPU.

Single-node k3s overlay `deploy/helm/blaksoc/values-k3s.yaml`: web and worker replicas 1, request 100m CPU and 256Mi memory, memory limit 512Mi, web autoscaling off. Install it on top of the base file:

```
helm upgrade --install blaksoc deploy/helm/blaksoc -f deploy/helm/blaksoc/values.yaml -f deploy/helm/blaksoc/values-k3s.yaml
```

The web pod disruption budget stays at `minAvailable: 1`, so the single web pod is not voluntarily evicted.

## Archive and restore

Hot syslog stays in Postgres for 30 days (`SYSLOG_HOT_MS`). The worker schedule `syslog-retain` in `src/worker/index.ts` runs every 1 hour and calls `archiveDueSyslog`. That calls `archiveColdForTenant` per tenant. The function writes the line into `ap-southeast-2` or `ap-southeast-4` and marks the event cold. `syslog_archive.body` is the copy taken at that moment. `searchArchive` and `restoreArchive` read the object.

`BLAKSOC_ARCHIVE_DIR` is the file-store root. The chart sets it to `/tmp/blaksoc-archive`. The worker root filesystem is read-only aside from that emptyDir, and the emptyDir dies with the pod. Mount a volume on that path when the object has to outlive the pod. The driver still rejects a region outside Australia.

### RPO and RTO

RPO for the cold object is one `syslog-retain` interval: 1 hour after the line is older than 30 days. Until that upload succeeds, the hot Postgres row is the copy.

RTO for one line is the time `restoreArchive` takes to read the object and mark the event hot. `tests/integration/hosting.test.ts` is the restore drill. A cluster failover time was not measured.

Web and worker egress is cluster-internal plus public TCP 443 (`networkPolicy.publicHttps`, on by default), with private, link-local (cloud metadata), CGNAT and loopback ranges excluded. Entra sign-in, Microsoft Graph, CISA KEV, FIRST EPSS, ACSC advisories, Kelpie, ABR and hosted AI providers need it. That egress is not region-pinned: which tenant data may reach those services is enforced in the app by the data governance profile, and `egressReachesPublicInternet` reports it. `networkPolicy.egressCidrs` is empty, so no any-port world CIDR is allowed. Anything private or on another port (self-hosted Ollama or vLLM, the Wazuh API on 55000, SMTP relays, managed Postgres and Redis) needs its CIDR in `networkPolicy.egressCidrs`. Set `publicHttps: false` for an air-gapped install.

## Regions

`AI_DATA_RESIDENCY` is `AU` in the base values and in the k3s overlay. Archive buckets are `ap-southeast-2` and `ap-southeast-4`. `assertAuRegion` rejects any other region.

`hostingComponents` names OpenSearch, the Wazuh indexer, and OpenCTI. The base values and the k3s overlay set `OPENSEARCH_REGION`, `WAZUH_INDEXER_REGION`, and `OPENCTI_REGION` to `ap-southeast-2`. The worker calls `assertHostingEnv` before it schedules jobs. A partial set throws. A region outside `ap-southeast-2` and `ap-southeast-4` throws. Leaving all three unset is local dev.

The OpenCTI compose profile sets OpenSearch `node.attr.region` from `OPENSEARCH_REGION`. `assertSearchNodeInAustralia` reads that attribute back from the node API and rejects a missing or non-Australian value. The same check covers a Wazuh indexer. `deploy/wazuh/indexer-region.yml` is the drop-in for the official indexer service. Wazuh and OpenCTI connector config accepts only those two regions.

`minio/minio` is not publicly pullable. The compose file uses `chainguard/minio:latest`, which still runs `minio server`. MinIO does not advertise a storage region. The OpenCTI service carries `BLAKSOC_REGION` from `OPENCTI_REGION`.

A world-open egress CIDR fails `egressOpensTheWorld`; public HTTPS is reported separately by `egressReachesPublicInternet`. The data-plane section records the region read back from the live OpenSearch and Wazuh indexer APIs, and the OpenCTI indicator stored on that host.
