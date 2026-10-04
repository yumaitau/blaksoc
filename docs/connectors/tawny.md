# Connect Tawny EDR

Tawny is Yuma IT's endpoint agent. Its API sends blakSOC alerts and the agent inventory, and blakSOC can ask an agent to kill a process. This guide is for the person who runs Tawny for the customer.

## What blakSOC does with Tawny

| Capability | Tawny API | Notes |
|---|---|---|
| Alerts | `GET /api/alerts?after_id=…` | Polled every 30 seconds, oldest first. blakSOC keeps the last alert id as its cursor, so no alert is read twice. Severity, ATT&CK techniques, host, and the triggering telemetry come across. Observables (IPs, domains, hashes, users) are pulled from the telemetry payload. |
| Assets | `GET /api/agents` | Synced every 15 minutes as endpoint assets. Revoked agents are skipped. Tawny does not report agent IP addresses yet, so assets merge with other sources by hostname. |
| Kill process | `POST /api/agents/{id}/actions` | Needs a numeric PID. A process name is refused. A playbook step uses the PID of the process that raised the alert. |
| Isolate / release | `POST /api/agents/{id}/actions` | Sent to Tawny, but current agents do not implement isolation and report it as failed. blakSOC shows that failure. Do not rely on Tawny for containment until the agent build supports isolation. |
| Health | `GET /api/health` + `GET /api/agents` | Checks the API is up and the token works. |

Response actions are asynchronous. Tawny delivers each action on the agent's next heartbeat (60 seconds or less). blakSOC keeps the action in **Executing**, checks Tawny every 30 seconds, and records the agent's result as **Succeeded** or **Failed** on the incident timeline and in the audit log. If the agent has not answered after 15 minutes, blakSOC marks the action **Failed** ("timed out waiting for endpoint"). Tawny itself expires an undelivered action after 15 minutes.

blakSOC sends its own response action id as Tawny's `idempotency_key`, so a retried job never creates a second action on the agent.

## 1. Create an API token in Tawny

1. Sign in to the Tawny console for **this customer's tenant**.
2. Open **Tokens** (`/api-tokens`) and create an API token named `blakSOC`.
3. Pick the role:
   - **Viewer** if blakSOC should only read alerts and agents. Kill process, isolate, and release will fail with a 403.
   - **Admin** if analysts will run response actions from blakSOC. Tawny also needs Admin to report the outcome of an action, so a Viewer token cannot track one.
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

A Tawny API token belongs to one Tawny tenant and sees only that tenant's agents and alerts. Create **one Tawny integration per blakSOC customer**, owned by that customer, with a token from the matching Tawny tenant. Do not share one Tawny integration across customers. Every alert would be routed to whichever customer owns it.

Tawny collection is plan-gated like the Wazuh endpoint service (Standard plan and up).

## Current limits

- Isolation and release are not implemented by the Tawny agent yet. They finish as Failed.
- Kill process needs a PID. Tawny does not kill by process name.
- Tawny API tokens cannot import Sigma rules (`/api/alert-rules` accepts console users only), so blakSOC detection deployments do not target Tawny. Write the detection as a Tawny alert rule.
- Tawny has no single-alert or single-action route. blakSOC looks up one alert with `after_id`, and one action by listing the agent's 100 newest actions.
