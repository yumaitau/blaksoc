# Connect Tawny EDR

Tawny is Yuma IT's endpoint agent. Its API sends blakSOC alerts and the agent inventory, and blakSOC can ask an agent to kill a process. This guide is for the person who runs Tawny for the customer.

## What blakSOC does with Tawny

| Capability | Tawny API | Notes |
|---|---|---|
| Alerts | `GET /api/alerts?after_id=…` | Polled every 30 seconds, oldest first. blakSOC keeps the last alert id as its cursor, so no alert is read twice. Severity, ATT&CK techniques, host, and the triggering telemetry come across. Observables (IPs, domains, hashes, users) are pulled from the telemetry payload. |
| Assets | `GET /api/agents` | Synced every 15 minutes as endpoint assets. Revoked agents are skipped. The agent's `public_ip` becomes the asset IP. Each Tawny tag becomes a `group:<tag>` routing key (see Tenancy). Assets merge with other sources by hostname. |
| Kill process | `POST /api/agents/{id}/actions` | Needs a numeric PID. A process name is refused. A playbook step uses the PID of the process that raised the alert. |
| Isolate / release | `POST /api/agents/{id}/actions` | Sent to Tawny, but current agents do not implement isolation and report it as failed. blakSOC shows that failure. Do not rely on Tawny for containment until the agent build supports isolation. |
| Action status | `GET /api/agents/{id}/actions/{actionId}` | Polled every 30 seconds while an action is in flight. |
| Sigma detections | `GET /api/alert-rules`, `POST /api/alert-rules/sigma`, `PUT`/`DELETE /api/alert-rules/{id}` | Deploying a blakSOC Sigma rule to a customer with a Tawny integration sends the raw YAML to Tawny, which maps Sigma fields to its telemetry and runs the rule itself. Hits come back through the alert poll. Tawny's reason is shown if it rejects the rule. |
| Health | `GET /api/health` + `GET /api/agents` | Checks the API is up and the token works. |

Response actions are asynchronous. Tawny delivers each action on the agent's next heartbeat (60 seconds or less). blakSOC keeps the action in **Executing**, checks Tawny every 30 seconds, and records the agent's result as **Succeeded** or **Failed** on the incident timeline and in the audit log. If the agent has not answered after 15 minutes, blakSOC marks the action **Failed** ("timed out waiting for endpoint"). Tawny itself expires an undelivered action after 15 minutes.

blakSOC sends its own response action id as Tawny's `idempotency_key`, so a retried job never creates a second action on the agent.

## 1. Create an API token in Tawny

1. Sign in to the Tawny console for **this customer's tenant**.
2. Open **Tokens** (`/api-tokens`) and create an API token named `blakSOC`.
3. Pick the role:
   - **Viewer** if blakSOC should only read alerts, agents, and action status. Kill process, isolate, release, and Sigma deployment fail with a 403.
   - **Admin** if analysts will run response actions or deploy Sigma rules from blakSOC.
4. Copy the token. It starts with `twny_` and is shown once.

## 2. Add the integration in blakSOC

**Integrations > Add > Tawny EDR**, on the customer's workspace.

| Field | Value |
|---|---|
| `apiUrl` | The Tawny API base URL, e.g. `https://tawny.example.com` |
| `region` | `ap-southeast-2` or `ap-southeast-4`. Where the Tawny API stores this customer's telemetry. |
| `mode` | `live`. Use `fixture` only for demos and tests. It returns canned alerts and one agent and never calls Tawny. |
| `tlsVerify` / `caPem` | Keep `tlsVerify` on. Paste the CA certificate in `caPem` for a private CA. |
| `apiToken` (secret) | The `twny_` token. Write-only: blakSOC never shows it again. |

## Tenancy

A Tawny API token belongs to one Tawny tenant and sees only that tenant's agents and alerts.

- **Recommended:** one Tawny tenant per customer, and **one Tawny integration per blakSOC customer**, owned by that customer, with a token from the matching Tawny tenant.
- **Shared Tawny tenant:** if one Tawny tenant holds several customers' agents, tag each agent in Tawny with the customer's group name and add a platform-owned Tawny integration with a tenant link per customer whose `agentGroups` lists those tags. blakSOC maps each Tawny tag to `group:<tag>`, which is what `agentGroups` matches, so assets and their alerts route to the right customer. An agent with no matching tag is not synced, and its alerts are dropped unless the integration has exactly one tenant link. Sigma deployment only targets tenant-owned Tawny integrations.

Tawny collection is plan-gated like the Wazuh endpoint service (Standard plan and up).

## Current limits

- Isolation and release are not implemented by the Tawny agent yet. They finish as Failed.
- Kill process needs a PID. Tawny does not kill by process name.
- Sigma rule lifecycle on Tawny:
  - Redeploying the same YAML reuses the existing Tawny rule, and re-enables it if a pause disabled it.
  - Deploying a new version imports it, then disables the Tawny rule it replaces. If that disable fails, the deploy still succeeds and the result says the superseded rule is still enabled.
  - Pausing a rule in blakSOC disables its Tawny rules first. If Tawny refuses, the pause is aborted with Tawny's reason, so blakSOC never shows a rule as paused while Tawny still runs it.
  - blakSOC disables rather than deletes, because Tawny refuses to delete a rule that has alerts. It deletes only when Tawny will not accept the disable (see below).
- Tawny currently rejects a metadata update on a Sigma rule compiled from more than one selection ("match_value is required unless the operator is exists"). blakSOC then deletes the rule instead, which works until the rule has alerts. After that, disable it in the Tawny console.
- A customer linked to a shared Wazuh cluster keeps getting the scheduled Wazuh query; Sigma goes to Tawny only when the customer has no shared-SIEM link and owns an enabled Tawny integration.
