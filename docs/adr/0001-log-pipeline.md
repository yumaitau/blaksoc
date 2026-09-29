# ADR 0001: Log pipeline for small-office syslog

## Status

Accepted

## Context

Small offices send firewall and router logs with syslog. The connector list has Graylog marked planned. A shared Graylog node means a JVM, MongoDB, and an OpenSearch heap. That is a poor fit for many small tenants on one host. Graylog's SSPL is also a poor fit for shipping inside this product.

## Decision

Use Vector as the edge forwarder and parse inside blakSOC.

- Vector is one static binary, uses tens of megabytes, and is MPL-2.0.
- Fluent Bit is smaller but weaker at per-event transforms.
- Graylog stays planned. We do not run it.

Vector listens for syslog and POSTs each line to `/api/ingest/syslog` over TLS with a per-tenant bearer token. An optional source-IP allowlist can bind a token to the office firewall. A template lives in `deploy/vector/syslog.toml`. The product does not ship a Vector binary.

Parsers cover UniFi, Sophos, FortiGate, MikroTik, and DrayTek. Each line becomes a `NormalisedAlert` through the `syslog` security-event provider, then the existing ingest path. Bytes land in the daily usage meter.

Hot retention is 30 days. Older lines are copied to `syslog_archive` with an object key and an Australian region (`ap-southeast-2` or `ap-southeast-4`). Any other region is refused. Searchable restore from object storage stays with issue 29. This change does not call a cloud API.

## Consequences

- Tenant routing is the token, checked again by row level security.
- Allow-lines are still stored so the meter counts them.
- Response actions stay on the firewall connectors, not on this ingest path.
