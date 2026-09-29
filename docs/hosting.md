# Hosting profile

Shared control plane and a single-node k3s install. The load table is the output of `pnpm exec tsx scripts/hosting-load.ts docs/hosting-load.json`. That command runs k6 against the file object store in `src/lib/hosting/store.ts`. OpenSearch, the Wazuh indexer, OpenCTI, Australian IaaS prices, and AWS prices were not measured. Do not read this page as a bill.

## Measured archive load

k6 v2.3.0 on Darwin arm64, Node v22.23.1, Apple M4, 10 CPUs, 17179869184 bytes of RAM. Each tenant is 20 objects. Each iteration does one PUT and one GET. Byte counts are what the store wrote during that run. RSS and CPU are the Node process that served the store, sampled after the run.

| Tenants | Objects | Bytes | Wall ms | HTTP avg ms | HTTP p95 ms | Server RSS bytes | CPU user µs | CPU system µs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 200 | 40400 | 306.49 | 0.37 | 0.58 | 89571328 | 40441 | 46578 |
| 50 | 1000 | 202000 | 440.36 | 0.28 | 0.54 | 90275840 | 135526 | 219121 |
| 200 | 4000 | 808000 | 813.22 | 0.23 | 0.43 | 91553792 | 370923 | 850405 |

The same run rejected a `us-east-1` put. Raw rows are in `docs/hosting-load.json`.

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

Worker network policy egress is cluster-internal. The shipped chart sets `networkPolicy.egressCidrs` to an empty list, so the worker does not allow `0.0.0.0/0` or `::/0`.

## Regions

`AI_DATA_RESIDENCY` is `AU` in the base values and in the k3s overlay. Archive buckets are `ap-southeast-2` and `ap-southeast-4`. `assertAuRegion` rejects any other region.

`hostingComponents` also checks OpenSearch, the Wazuh indexer, and OpenCTI. The base values pin each of those to `ap-southeast-2`. Wazuh and OpenCTI connector config accepts only `ap-southeast-2` and `ap-southeast-4`. A world-open egress CIDR fails `egressOpensTheWorld`. Load numbers and prices for OpenSearch, the Wazuh indexer, and OpenCTI were not measured.
