# Wazuh for blakSOC

blakSOC uses Wazuh as its first SIEM/XDR provider. Run Wazuh from the official
[wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node or multi-node stack (or
the Wazuh Helm/Kubernetes deployment), then register the cluster in blakSOC under
**Integrations → Wazuh**.

`indexer-region.yml` sets `node.attr.region` to `ap-southeast-2` on the official
single-node service `wazuh.indexer`. Merge that file when you start the stack.
The Wazuh indexer image does not import that variable on its own, so the file's
entrypoint writes it into `opensearch.yml` and then runs the official entrypoint.
The worker refuses to boot unless `WAZUH_INDEXER_REGION` is `ap-southeast-2` or
`ap-southeast-4`. A node that omits the attribute, or names another region, fails
`assertSearchNodeInAustralia`.

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

## 4. Enrolment kits

Customer administrators download pre-configured installers from **Portal → Agents**.
Each file carries the tenant agent group, a revocable enrolment token, and either the
standard or low-bandwidth profile selected for that site. Links expire after 15 minutes.
See `docs/agents.md`. The official Wazuh MSI, pkg, deb, or rpm is still the agent package.
These scripts only pin the manager, group, and profile.

## 5. SME endpoint profile

`sme-sysmon.xml` is a low-noise Sysmon filter: process creation, LSASS process access,
network connections from remote-access tools, and ransomware file extensions. Image-load
logging is left out.

`sme-agent.conf` is the matching Wazuh agent config. It tails the Sysmon channel and watches
the common startup folder. It is not an agent installer. Use the official Wazuh package.
