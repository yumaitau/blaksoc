# Wedgetail

Wedgetail runs in the customer's AWS account. Its signed inbound webhook puts AWS detections
in blakSOC's existing alert queue, with OCSF Detection Findings, observable extraction,
threat-intel enrichment, risk scoring and alert-created playbooks.

## Setup

1. In blakSOC, open **Integrations → Add integration → Wedgetail**. Select the customer that
   owns this install and save. Each integration serves exactly one tenant; multiple installs
   may have separate integrations. Platform/shared ownership is refused.
2. Copy the **ingest URL** and generated **HMAC secret** from the creation confirmation.
   The secret is shown once, encrypted at rest with integration-bound AES-256-GCM, and never
   returned by integration reads. Keep it in the install's secret store. It is never a URL parameter.
3. In Wedgetail, open **Settings → Notifications → blakSOC**, then paste the URL and secret.
   For versions that only offer **Generic webhook**, use that channel instead: it sends the
   same signature scheme. The parameters are `/wedgetail/integrations/webhook-url` and
   `/wedgetail/integrations/webhook-secret`. Enable notifications and choose a severity threshold.
4. Send a test alert and check the integration's **Connection** panel for **Last received**
   and the `created`, `duplicate`, `unrouted` and `rejected` counts.

Use HTTPS. The ingest URL is `/api/ingest/wedgetail/<integrationId>` on the blakSOC origin.
Disabling the integration stops deliveries with 404. To rotate, enter a new signingSecret in
its settings and update Wedgetail's secret store. Secrets are write-only after creation.

## Signed delivery contract

The signature matches Wedgetail's `engine/src/notify/payloads.ts` `signedWebhook`:

| Header | Value |
| --- | --- |
| Content-Type | application/json |
| X-Wedgetail-Timestamp | Canonical decimal Unix seconds (10–12 digits) |
| X-Wedgetail-Signature | `v1=<lowercase hex HMAC-SHA256(secret, timestamp + "." + raw body bytes)>` |
| X-Wedgetail-Event-Id | Sender delivery ID (optional to the receiver) |

The timestamp must be within ±5 minutes. Comparison is constant time. Bodies are capped at
256 KB while streaming, including when Content-Length is absent or dishonest. Requests are
limited to 300 per integration per minute in Redis, with the existing per-process fallback
when Redis is unavailable. Every response carries `x-request-id` and `Cache-Control: no-store`.
Raw payloads and credentials are never logged.

The receiver accepts both upstream shapes:

- Generic webhook: `{ "type": "wedgetail.alert.created", "alert": { ... }, "url": "..." }`.
  Alert fields include `id`, `ruleId`, `ruleTitle`, `severity`, `firstSeen`, `entities` (type/value
  pairs), `mitre`, `ism` and `essentialEight`. Other upstream fields are optional.
- Summary: `{ "schema": "wedgetail.alert.v1", "alert": { ... }, "entities": { ... } }` as documented
  in Wedgetail's `docs/integrations/kelpie.md`. Title, description, severity, ruleId and detectedAt
  map directly. Classification carries the first ATT&CK technique; optional `mitre` arrays
  preserve additional techniques. Compliance references remain in description/raw; optional
  `ism` and `essentialEight` arrays are also retained. Summary deliveries must use the **Wedgetail
  signature headers**, rather than Kelpie's intake token.

Entities map host to hostname, principal to userName/principalArn, IP to sourceIp and resource
to assetExternalId/resourceArn. IPs are extracted for enrichment; ARNs and compliance references
remain in raw evidence. Account IDs and payload tenant IDs never influence tenant routing.
Raw event samples and unrecognised fields are discarded.

Deduplication is `(tenant, source="wedgetail", alert.id)`, using the signed alert ID rather than
an unsigned event-id header. Replays refresh detection fields, scoring and OCSF without changing
analyst status, doubling sightings, or rerunning alert-created notifications/playbooks. A finding
already bound to another install in the same tenant is refused as unrouted; use distinct alert IDs
across installs. Concurrent deliveries serialise on that deduplication key.

202 means created; 200 means refreshed or status applied/ignored; 400 means invalid payload;
401 means invalid/stale signature; 404 means unknown/disabled integration; 409 means unrouted;
413 means oversized; 429 includes Retry-After; 503 means retry later. Retry a status event returning
409 after its creation event has arrived. Unknown installs only contribute to the metric's fixed
`integration="unknown"` rejected bucket. For known installs, rejected deliveries increment health
counts but do not advance Last received. Valid status events count as duplicate (existing finding).
Prometheus uses `blaksoc_ingest_alerts_total{provider="wedgetail",outcome="..."}`.

## Inbound status sync

Post a signed event with the same headers:

```json
{
  "type": "wedgetail.alert.updated",
  "alert": {
    "id": "wt-fictional-root-activity",
    "status": "acknowledged",
    "updatedAt": "2026-10-13T00:00:01.000Z"
  }
}
```

`acknowledged` maps to TRIAGING, `in_progress` to INVESTIGATING, `closed_true_positive`,
`closed_benign` and `closed` to RESOLVED, `closed_false_positive` to FALSE_POSITIVE, and `new`
or `reopened` to NEW. `updatedAt` is required: old/equal timestamps are ignored, including after
creation retries. Each actual status change is audited in its write transaction with actor
`wedgetail:<integrationId>`. Matching also requires the tenant and integration ID. Inbound
updates never publish outbound notifications or run alert-created playbooks, so they cannot loop.

The locally inspected upstream version emits creation webhooks but does not yet emit
`wedgetail.alert.updated`. This receiver contract is ready for that upstream sender; enable
status deliveries once the installed Wedgetail version supports them.

## Follow-up: outbound status sync

Outbound analyst closures are phase 2. Kelpie's existing case API sync is incident-specific and
cannot be reused for Wedgetail alerts. A follow-up needs an authenticated Wedgetail alert-update
API, installation URL/credentials, retry/idempotency handling and origin markers to prevent loops.
The receiver does not call a customer install or request AWS permissions.

The generated [OpenAPI document](../openapi.json) documents this endpoint under its own root
server, alongside the service-identity API.
