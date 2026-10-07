# Disaster recovery

This covers the blakSOC platform itself: Postgres, Redis, the syslog archive and the app. Customer backups that blakSOC monitors (`src/lib/backup`, Veeam) are a separate feature.

All backup and archive storage is in `ap-southeast-2` or `ap-southeast-4`. The archive driver, the backup script and the chart refuse any other region.

## What holds state

| Store | Holds | Loss means | Recovery |
| --- | --- | --- | --- |
| Postgres | Tenants, users, alerts, incidents, evidence, audit chain, integration config and alert poll cursors | Platform down | Restore (below) |
| Syslog archive (S3) | Syslog lines older than 30 days, `syslog/<tenant>/<event>.log` | Archived lines cannot be searched or restored | Object store durability; versioning and cross-region replication on the bucket |
| Redis | BullMQ queues and schedulers, enrichment cache, sign-in rate-limit counters, live-update pub/sub | Queued jobs that had not run | Rebuilt by the worker (see Redis loss) |
| Worker `/tmp` emptyDir | File-store archive when no bucket is set | Every archived object | None. Development only |

## RPO and RTO by deployment profile

RPO is the most data that can be lost. RTO is the time from declaring the outage to a working platform. The targets below are design targets. Only the local data-tier drill at the end of this file has been measured; no production restore has been timed yet.

| Profile | What it is | Postgres backup | RPO | RTO target |
| --- | --- | --- | --- | --- |
| Shared | Multi-tenant chart on EKS with RDS and ElastiCache (`values.yaml`, `values-yumait-prod.yaml`) | RDS automated backups with point-in-time recovery (7 days on `blaksoc-eks-postgres`), plus the chart's 6-hourly `pg_dump` to S3 | 5 minutes (RDS transaction-log upload interval); 6 hours if only the logical dump survives | 4 hours |
| Dedicated | One customer on one host with Compose (`deploy/compose`) | `--profile backup` dump to S3 from host cron, every 6 hours | 6 hours | 4 hours |
| k3s | One customer on a single-node cluster (`values-k3s.yaml`) | Chart `backup` CronJob, every 6 hours; WAL archiving optional (below) | 6 hours; 5 minutes with WAL archiving | 4 hours |

Syslog archive RPO in every profile is one `syslog-retain` interval (1 hour) after a line passes 30 days. Until the upload succeeds the hot Postgres row is the copy, so the archive's RPO is covered by the Postgres RPO.

## Postgres backup

### Logical dumps (all profiles)

`deploy/backup/pg-backup.sh` runs in two steps so each uses a stock image:

1. `dump` (postgres image): `pg_dump --format=custom` of the blakSOC database with the owner URL, checked with `pg_restore --list` before it is kept.
2. `upload` (aws-cli image): copies the newest dump to `s3://<bucket>/<prefix>blaksoc-<UTC time>.dump` with server-side encryption (`AES256` or `aws:kms`), compares the uploaded size, then deletes all but the newest `BACKUP_KEEP` dumps (28 by default, 7 days at 6-hourly).

The owner role must bypass RLS. Tables use `FORCE ROW LEVEL SECURITY`; `pg_dump` turns row security off and stops with an error rather than writing a partial dump when the role cannot bypass it. The Compose owner (`POSTGRES_USER`) and a k3s Postgres superuser can. On RDS the master user is not a superuser, so the logical dump there needs a role with `BYPASSRLS`, and RDS snapshots remain the primary copy.

Kubernetes (shared and k3s):

```yaml
backup:
  enabled: true
  bucket: blaksoc-backup-syd
  region: ap-southeast-2
  # endpoint: https://s3.example.com.au   # S3-compatible store
serviceAccount:
  create: true
  annotations: { eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/blaksoc-backup }
```

The CronJob reads `DATABASE_ADMIN_URL` from `existingSecret`. Without IRSA or Pod Identity, put `BACKUP_AWS_ACCESS_KEY_ID` and `BACKUP_AWS_SECRET_ACCESS_KEY` in the same Secret. Keep `backup.pgImage` at the server's major version or newer.

Compose (dedicated): set `BACKUP_BUCKET` (and `BACKUP_REGION`, `BACKUP_ENDPOINT`, `BACKUP_AWS_ACCESS_KEY_ID`, `BACKUP_AWS_SECRET_ACCESS_KEY` as needed) in `.env`, then from host cron:

```
15 */6 * * * cd /opt/blaksoc/deploy/compose && docker compose --env-file .env --profile backup run --rm backup
```

Bucket settings for every backup and archive bucket: block public access, default encryption on, versioning on, a bucket policy that denies non-TLS requests, and a lifecycle rule that expires `postgres/` objects after 35 days as a backstop to `BACKUP_KEEP`. For region loss, replicate `ap-southeast-2` buckets to `ap-southeast-4`.

### Point-in-time recovery

Shared profile (RDS, `ap-southeast-2`). RDS uploads transaction logs about every 5 minutes, so `LatestRestorableTime` is usually within 5 minutes of now. A restore creates a new instance in the same region:

```bash
# --restore-time <UTC time before the incident>, or --use-latest-restorable-time
aws rds restore-db-instance-to-point-in-time --region ap-southeast-2 \
  --source-db-instance-identifier blaksoc-eks-postgres \
  --target-db-instance-identifier blaksoc-eks-postgres-pitr-<yyyymmddhhmm> \
  --restore-time <UTC time> \
  --db-subnet-group-name <same group> --vpc-security-group-ids <same groups> \
  --deletion-protection
aws rds wait db-instance-available --region ap-southeast-2 --db-instance-identifier blaksoc-eks-postgres-pitr-<yyyymmddhhmm>
```

For loss of `ap-southeast-2`, enable RDS cross-region automated backup replication to `ap-southeast-4`; it is not enabled on `blaksoc-eks-postgres` today.

k3s. The CronJob gives a 6-hour RPO. For a 5-minute RPO, run Postgres with continuous WAL archiving to an AU bucket. Two supported ways, documented here and not shipped in the chart:

- CloudNativePG: a `Cluster` with `backup.barmanObjectStore` pointing at `s3://<bucket>/cnpg/` (`endpointURL` for an S3-compatible store, `s3Credentials` from a Secret, `wal.compression: gzip`), `postgresql.parameters.archive_timeout: "5min"`, and a daily `ScheduledBackup`. Recover into a new `Cluster` with `bootstrap.recovery.source` and `recoveryTarget.targetTime`.
- pgBackRest on a plain Postgres pod: `repo1-type=s3`, `repo1-s3-region=ap-southeast-2`, `repo1-s3-bucket`, `repo1-cipher-type=aes-256-cbc`, `archive_command = 'pgbackrest --stanza=blaksoc archive-push %p'`, `archive_timeout = 300`, a weekly full and daily differential. Restore with `pgbackrest --stanza=blaksoc --type=time --target="<UTC time>" restore`.

Either way, keep the chart's logical dump on as an independent copy.

## Restore runbook

1. Declare the incident and record the start time. Stop writes: `kubectl -n blaksoc scale deploy/blaksoc-blaksoc-web deploy/blaksoc-blaksoc-worker --replicas=0` (Compose: `docker compose stop web worker`).
2. Get a database back.
   - RDS: point-in-time restore as above.
   - Logical dump: create an empty database on the target server. The roles are cluster-wide and not in the dump, so create them first (`CREATE ROLE blaksoc_app LOGIN; CREATE ROLE blaksoc_system LOGIN;`), then `pg_restore --exit-on-error --dbname=<url> blaksoc-<time>.dump`. On a server where the restoring role is not a superuser, drop the extension comment from the list first: `pg_restore -l dump | grep -v 'COMMENT - EXTENSION' > list && pg_restore -L list --dbname=<url> dump`.
   - Compose: `docker compose stop web worker`, then `docker compose exec -T postgres sh -c 'dropdb -U blaksoc --force blaksoc && createdb -U blaksoc blaksoc'` and `docker compose exec -T postgres pg_restore -U blaksoc -d blaksoc --exit-on-error < blaksoc-<time>.dump`.
3. Point the platform at it: update `DATABASE_URL`, `DATABASE_SYSTEM_URL` and `DATABASE_ADMIN_URL` (shared: Secrets Manager `blaksoc-eks-runtime`, synced by External Secrets).
4. Run the migration job: `helm upgrade` (pre-upgrade hook) or `docker compose up migrate`. It applies anything pending, reapplies RLS and grants, and sets the role passwords from the environment.
5. Verify before opening up: run `pnpm drill:restore --dump <file> --target <scratch>` against a scratch copy, or on the restored database check `select * from audit_log_verify()` (`ok = true`) and row counts of `tenants`, `alerts`, `incidents`, `audit_log`.
6. Scale web and worker back up. The worker recreates its schedulers, verifies the archive buckets' regions, and resumes alert polling from the cursors stored in `integrations.poll_cursor`.
7. Record the end time and the restore point in the incident. Alerts raised by providers between the restore point and now are fetched again by the poll when the provider still holds them (the cursor rolls back with the database; duplicates are dropped by the `(tenant, source, external id)` unique index).

## Redis loss

Redis is a cache and a queue, not a system of record. When it is flushed or replaced by an empty node:

- Alert poll cursors are in Postgres (`integrations.poll_cursor`). The worker writes the cursor to Postgres after every alert of the page is stored, then to Redis as a cache for older worker images. A flush neither replays alerts nor skips them (`tests/integration/redis-loss.test.ts`). With both copies gone the provider replays its window and the unique index drops duplicates.
- Job schedulers live only in Redis. The worker checks every 60 seconds (`SCHEDULE_CHECK_MS`) and recreates any that are missing, without resetting the others.
- Approved response actions and playbook runs whose follow-up job was lost are re-queued by `recoverStalledRuns` on the next 5-minute `expire-approvals` run; anything decided more than 24 hours earlier is closed with an audit row instead.
- Lost for good: notification and webhook deliveries queued but not yet sent, and live-update events published during the outage. Browsers reconnect for new events.
- Sign-in rate limits fall back to per-process counters while Redis is unreachable and restart from zero after a flush. The enrichment cache refills on demand.

## Archive durability

Set at least one bucket in production; the emptyDir fallback loses every archived line when the worker pod is replaced.

| Variable | Chart value | Meaning |
| --- | --- | --- |
| `BLAKSOC_ARCHIVE_S3_BUCKETS` | `archive.s3.buckets` | `ap-southeast-2=<bucket>,ap-southeast-4=<bucket>`; other regions are rejected at start and at render |
| `BLAKSOC_ARCHIVE_S3_ENDPOINT` | `archive.s3.endpoint` | S3-compatible endpoint; empty means AWS S3. Metadata and link-local addresses are refused |
| `BLAKSOC_ARCHIVE_S3_FORCE_PATH_STYLE` | `archive.s3.forcePathStyle` | Defaults to path style when an endpoint is set |
| `BLAKSOC_ARCHIVE_S3_SSE` | `archive.s3.sse` | `AES256` (default) or `aws:kms`; sent on every put |
| `BLAKSOC_ARCHIVE_S3_KMS_KEY_ID` | `archive.s3.kmsKeyId` | KMS key for `aws:kms` |
| `BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID`, `BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY` | `existingSecret` keys | Optional; otherwise the AWS default chain (IRSA, EKS Pod Identity, instance role) |

At start the worker calls `HeadBucket` on each bucket and stops if a bucket reports a region other than the one it is configured for. A store that reports no region (some S3-compatible servers) is accepted; set the server's region (for MinIO, `MINIO_REGION`) so it does. An unreachable store is logged and the worker keeps polling alerts.

Archived objects survive pod replacement because they are not on the pod: `tests/integration/hosting.test.ts` archives through one store instance, closes it, and searches and restores the same objects through a new instance. The IAM policy for the worker needs `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` and `s3:GetBucketLocation` on the archive buckets (plus `kms:GenerateDataKey` and `kms:Decrypt` for `aws:kms`). The backup role needs `s3:PutObject`, `s3:ListBucket` and `s3:DeleteObject` on the backup prefix.

## Quarterly restore drill

Run in the first week of each quarter, and after any change to the backup path. The owner is the platform on-call lead.

1. Take the newest dump from the bucket, not from the host that made it: `BACKUP_BUCKET=<bucket> BACKUP_REGION=ap-southeast-2 pnpm drill:restore --s3 /tmp/drill --target blaksoc_drill_restore --label "<quarter> production drill" --out drill.json`, with `DATABASE_ADMIN_URL` pointing at a non-production server in the same region (and `DATABASE_SYSTEM_URL` with the same host, to check the worker role's access).
2. The script creates the scratch database, restores with `pg_restore --exit-on-error`, checks that no migration in `drizzle/meta/_journal.json` is pending, runs `audit_log_verify()`, checks that `blaksoc_system` sees every tenant, counts key tables, drops the scratch database and writes the timings. It exits 1 on any failure.
3. Restore one archived object: `searchArchive` for a known tenant against the production bucket from a scratch worker, or `aws s3api head-object` on a key from `syslog_archive`.
4. For the shared profile, also run an RDS point-in-time restore to a throwaway instance and time it to `available`; delete it afterwards.
5. Add a row below with the measured times and compare against the RTO target. A miss is an incident action.

`rtoMs` in the result is the data tier only: create, restore and verify. A platform RTO adds provisioning, the secret change, the migration job and pod start.

### Results

| Date | Kind | Dump | Dump time | Restore | Verify | Data-tier RTO | Checks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-07 | Local dev drill, not production: Homebrew Postgres 16.14 on an Apple M-series Mac (10 cores), seeded demo data, scratch database `blaksoc_dr_restore` on the same server | 493756 bytes | 185 ms | 215 ms | 22 ms | 304 ms (create 67 ms) | 28 of 28 migrations applied, audit chain ok over 934 rows, system role sees 4 of 4 tenants, row counts match the source |

The local drill proves the scripts and the checks, not the RTO: the database was 482 KiB of seed and test data on a laptop. The first production drill has not been run. Raw output: `docs/restore-drill-local.json`.
