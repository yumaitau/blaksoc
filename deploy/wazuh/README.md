# Wazuh for blakSOC

blakSOC uses Wazuh as its first SIEM/XDR provider. Run Wazuh from the official
[wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node or multi-node stack (or
the Wazuh Helm/Kubernetes deployment), then register the cluster in blakSOC under
**Integrations → Wazuh**.

## 1. Accounts blakSOC needs

| Where | Account | Minimum rights |
|---|---|---|
| Wazuh server API (`:55000`) | `blaksoc` | `agents:read`, `active-response:command`, `cluster:read`, `manager:read` |
| Wazuh indexer (`:9200`) | `blaksoc_reader` | `read` on `wazuh-alerts-*`, `wazuh-states-vulnerabilities-*` |

Credentials are entered once in blakSOC, encrypted with AES-256-GCM and never shown again.

## 2. Multi-tenant routing (shared cluster)

Put each customer's agents in their own agent group (e.g. `wattle`, `murray`). In blakSOC,
link the cluster to each customer with that group as the selector. Alerts are routed to a
tenant by agent → asset → tenant; agents in no linked group are never ingested.

For customers needing isolated infrastructure, deploy a dedicated cluster and register it as a
tenant-owned integration instead.

## 3. Containment (active response)

Wazuh has no built-in host isolation, so blakSOC ships scripts in `active-response/`:

| Script | Platform | Purpose |
|---|---|---|
| `blaksoc-isolate.sh` / `blaksoc-release.sh` | Linux (nftables) | Drop all traffic except Wazuh manager(s) |
| `blaksoc-isolate-win.cmd` / `blaksoc-release-win.cmd` (+ `.ps1`) | Windows | Firewall block-all except manager(s) |

Install on agents (e.g. via your RMM or a Wazuh shared-file push):

- Linux: copy `*.sh` to `/var/ossec/active-response/bin/`, `chown root:wazuh`, `chmod 750`;
  write manager IPs to `/var/ossec/etc/blaksoc-allow`.
- Windows: copy the `.cmd` and `.ps1` to `C:\Program Files (x86)\ossec-agent\active-response\bin\`;
  write manager IPs to `C:\Program Files (x86)\ossec-agent\blaksoc-allow.txt`.

Declare the commands on the manager (`ossec.conf`):

```xml
<command><name>blaksoc-isolate</name><executable>blaksoc-isolate.sh</executable><timeout_allowed>no</timeout_allowed></command>
<command><name>blaksoc-release</name><executable>blaksoc-release.sh</executable><timeout_allowed>no</timeout_allowed></command>
<command><name>blaksoc-isolate-win</name><executable>blaksoc-isolate-win.cmd</executable><timeout_allowed>no</timeout_allowed></command>
<command><name>blaksoc-release-win</name><executable>blaksoc-release-win.cmd</executable><timeout_allowed>no</timeout_allowed></command>
```

No `<active-response>` blocks are needed: blakSOC triggers these commands through the API,
and only after a human approval (or a platform administrator's explicit auto-containment
opt-in for that customer). The command names can be overridden per cluster in the
integration's `activeResponse` config.

**Test in a lab first.** Isolation cuts RDP/SSH; recovery is via the Wazuh manager (release
action in blakSOC) or console access.
