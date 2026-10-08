# Kelpie case management

Yuma IT Kelpie is the case management system for blakSOC. When a customer tenant has a Kelpie integration,
every open blakSOC incident becomes a case in that customer's own Kelpie organisation, and analysts run the
case there.

## What lives where

| Kelpie (system of record for case work) | blakSOC (detection and customer side) |
| --- | --- |
| Status, severity, title, assignee | Alerts, detections, intel matches |
| Tasks, internal notes, comments | Customer-visible notes and the portal |
| Playbook task follow-up (forwarded as comments) | Paging, acknowledgement, breach clocks |
| Observables (copied once from blakSOC) | Response actions and approvals, DFIR evidence |

blakSOC refuses its own status, field, task, timeline and internal-note edits for a Kelpie tenant and links
the analyst to the case. Customer notes, acknowledgement, evidence, response actions and breach obligations
stay in blakSOC.

## Set it up for one customer

1. In Kelpie, use (or create) the customer's own organisation. Do not put several customers in one
   organisation.
2. Under **Settings → API tokens**, create a token with `cases:write`, `cases:read`, `comments:write` and
   `observables:write`. Grant nothing else. The token is shown once.
3. In blakSOC, add an integration for the customer tenant: provider **Kelpie**, base URL of the Kelpie
   deployment, and the AU region where it stores data. Paste the token as the secret. Use **Test** to check
   the token can read cases.

blakSOC never uses a platform-wide Kelpie token: a tenant without its own integration keeps blakSOC's built-in
case management.

## How sync works

The worker runs every minute, and again a few seconds after a new incident:

1. Open incidents without a case are queued. Closed incidents stay in blakSOC as history.
2. Each is created with `sourceSystem: "blaksoc"` and the incident id as `sourceReference`, so a retry
   converges on the same case. A failed push backs off (2, 4, 8 … up to 60 minutes) and shows on the incident.
3. Observables are added once. Playbook tasks are posted as comments, once each.
4. Kelpie's status, severity and title are copied back when the case version changes, with a timeline entry
   and an audit record. `in_progress` maps to INVESTIGATING; the other statuses map by name.

Cases include a **Why this needs attention** section with the matched rules, source severity, affected
host, selected event details and investigation checks. Correlation findings identify blakSOC as their
source and include contributing alerts, with an **Open Wazuh alert** link for each Wazuh event.
The worker also adds this section to existing open cases. It refreshes only the marked blakSOC section
of the summary, preserves analyst text, and uses Kelpie's case version to avoid overwriting concurrent edits.
The overview renders the source links as buttons when the companion Kelpie UI change is deployed.

Wazuh links use the integration's optional `dashboardUrl`, falling back to `WAZUH_DASHBOARD_URL`.
Set `dashboardIndexPatternId` if the dashboard's saved index pattern id differs from `wazuh-alerts-*`.
Links search the exact indexer document id with a time window around the event, including older alerts.
The linked dashboard still requires the analyst's normal Wazuh login.

Under a tenant's data governance residency lock, a Kelpie integration outside an Australian region is not used.
