#!/usr/bin/env bash
# Installs and enrols the Wazuh agent on an EC2 host (Ubuntu/Debian or Amazon Linux). Safe to re-run.
# Runs as root over SSM: the BlakSOC-WazuhAgent document (State Manager enrols every managed instance,
# including new ones) or Run Command. Needs WAZUH_REGISTRATION_PASSWORD from blaksoc-wazuh-credentials;
# WAZUH_AGENT_NAME defaults to the Name tag or instance id.
# EC2 hosts use wazuh-internal.soc.yumait.au, a public record holding the manager's private address,
# because hosts on Tailscale resolve through MagicDNS and never see a Route 53 private zone.
# Hosts outside AWS use agents.soc.yumait.au (the NLB). The agent version is pinned to the manager's.
set -euo pipefail
VERSION=4.14.8
MANAGER=${WAZUH_MANAGER:-wazuh-internal.soc.yumait.au}
GROUP=${WAZUH_AGENT_GROUP:-yumait-aws}
: "${WAZUH_REGISTRATION_PASSWORD:?}"
if [ -z "${WAZUH_AGENT_NAME:-}" ]; then
  # From State Manager there is no per-host argument: use the Name tag when instance tags are exposed in
  # metadata, else the instance id (unique and stable), else the hostname.
  imds_token=$(curl -sf -m 2 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)
  imds() { curl -sf -m 2 -H "X-aws-ec2-metadata-token: $imds_token" "http://169.254.169.254/latest/meta-data/$1" || true; }
  WAZUH_AGENT_NAME=$(imds tags/instance/Name)
  [ -n "$WAZUH_AGENT_NAME" ] || WAZUH_AGENT_NAME=$(imds instance-id)
  [ -n "$WAZUH_AGENT_NAME" ] || WAZUH_AGENT_NAME=$(hostname)
fi

if [ -s /var/ossec/etc/client.keys ] && systemctl is-active -q wazuh-agent && grep -q "<address>$MANAGER</address>" /var/ossec/etc/ossec.conf; then
  echo "wazuh-agent already enrolled and running"
  exit 0
fi

getent hosts "$MANAGER" || { echo "cannot resolve $MANAGER" >&2; exit 1; }

export WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -q -o Dir::Etc::sourcelist=sources.list.d/wazuh.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  apt-get install -y -q "wazuh-agent=${VERSION}-1"
  # Never upgrade past the manager with the host's routine updates.
  apt-mark hold wazuh-agent >/dev/null
else
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
  dnf install -y -q "wazuh-agent-${VERSION}-1"
  dnf -q versionlock add wazuh-agent 2>/dev/null || true
fi

# The package only configures a fresh install, so set the manager and enrol explicitly.
sed -i -E "0,/<address>[^<]*<\/address>/s//<address>$MANAGER<\/address>/" /var/ossec/etc/ossec.conf
rm -f /var/ossec/etc/authd.pass
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null
systemctl stop wazuh-agent || true
if [ ! -s /var/ossec/etc/client.keys ]; then
  /var/ossec/bin/agent-auth -m "$MANAGER" -P "$WAZUH_REGISTRATION_PASSWORD" -G "$GROUP" -A "$WAZUH_AGENT_NAME" >/dev/null
fi
systemctl start wazuh-agent
for _ in $(seq 1 30); do
  grep -q "^status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && break
  sleep 2
done
if grep -q "^status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null; then
  echo "enrolled as $(cut -d' ' -f2 /var/ossec/etc/client.keys) in group $GROUP, connected to $MANAGER"
else
  echo "agent not connected; see /var/ossec/logs/ossec.log" >&2
  grep -iE "error|warn" /var/ossec/logs/ossec.log | tail -5 >&2
  exit 1
fi
