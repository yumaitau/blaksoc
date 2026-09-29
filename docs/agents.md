# Endpoint agent kits

blakSOC does not ship a private copy of the Wazuh agent. Each place gets an enrolment token and a short-lived signed download. The file is a script that installs the official Windows MSI, macOS pkg, Debian package, or RPM, and writes the agent group plus the bandwidth profile into `ossec.conf`.

## Tokens and links

- The token is stored as a hash and as AES-GCM ciphertext bound to the enrolment row. The plaintext is shown once, then only used to build a download.
- Revoke clears the ciphertext. `claimEnrolment` then refuses the token, and download links return gone.
- A download link is an HMAC over enrolment id, platform, and expiry. It lasts 15 minutes. The signing key is `BLAKSOC_ENCRYPTION_KEY`.
- Set `WAZUH_MANAGER` to the manager address written into the installer. The default is `wazuh.blaksoc.local`.

## Slow links

Onboarding and the Agents page store `sites.bandwidth_profile` as `standard` or `low`.

`dailyUploadBytes` counts one idle day:

- keepalive size times how often `notify_time` fires
- one file-integrity sample per `syscheck` interval, plus an hourly sample when realtime is on
- one policy sample per SCA interval
- one inventory buffer per syscollector interval
- a short auth log when the log level is quiet, a longer one when it is not

The inventory buffer is `INVENTORY_ROWS` (32,000) copies of one package line. That is the upper end of a full software list, and the byte count is `Buffer.byteLength` of that buffer. The slow profile sends it once a day, turns realtime file checks off, checks in once a minute, and caps `events_per_second` at 5. The unit test fails if that idle day is 20 MB or more. The Agents page prints the same figure.

## Coverage tasks

Opening the Agents page compares endpoint assets from Microsoft 365, Entra, and Google Workspace with Wazuh agents. Match is the hostname's first label. An inventory computer with no matching agent becomes an open task. A later match marks the task done.

## What your IT helper runs

The office-manager steps are on `/portal/agents`. The same files are what Intune (Windows script), Google endpoint management (Mac or Windows push), and an RMM (script) should run. They join the tenant slug as the Wazuh agent group.
