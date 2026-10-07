#!/usr/bin/env bash
# Installs the Wazuh single-node stack (manager, indexer, dashboard) on the blaksoc-wazuh EC2 host.
# Runs as root over SSM Run Command on Ubuntu 24.04 (arm64). Safe to re-run.
# Credentials come from Secrets Manager (blaksoc-wazuh-credentials) and never reach the command output.
set -euo pipefail
VERSION=4.14.8
REGION=ap-southeast-2
SECRET=blaksoc-wazuh-credentials
DIR=/opt/wazuh-docker/single-node

export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q docker.io docker-compose-v2 git jq python3 curl unzip
command -v aws >/dev/null || snap install aws-cli --classic
systemctl enable --now docker
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-wazuh.conf

creds=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" --query SecretString --output text)
INDEXER_PASSWORD=$(jq -r .INDEXER_PASSWORD <<<"$creds")
API_PASSWORD=$(jq -r .API_PASSWORD <<<"$creds")
DASHBOARD_PASSWORD=$(jq -r .DASHBOARD_PASSWORD <<<"$creds")
ENROLLMENT_PASSWORD=$(jq -r .ENROLLMENT_PASSWORD <<<"$creds")

if [ ! -d /opt/wazuh-docker ]; then
  git clone -q --depth 1 -b "v$VERSION" https://github.com/wazuh/wazuh-docker.git /opt/wazuh-docker
fi
cd "$DIR"

if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator >/dev/null
fi

# Replace the published default passwords before the first start, so the indexer
# security index is initialised with ours.
if [ ! -f .blaksoc-passwords-set ]; then
  # The password goes in through the environment, never into the command string.
  hash() {
    local h
    h=$(PW="$1" docker run --rm -e PW "wazuh/wazuh-indexer:$VERSION" \
      bash -c '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' 2>/dev/null | tail -1)
    [[ $h == '$2'* ]] || { echo "hash.sh did not return a bcrypt hash" >&2; return 1; }
    printf '%s' "$h"
  }
  ADMIN_HASH=$(hash "$INDEXER_PASSWORD")
  KIBANA_HASH=$(hash "$DASHBOARD_PASSWORD")
  ADMIN_HASH="$ADMIN_HASH" KIBANA_HASH="$KIBANA_HASH" INDEXER_PASSWORD="$INDEXER_PASSWORD" API_PASSWORD="$API_PASSWORD" DASHBOARD_PASSWORD="$DASHBOARD_PASSWORD" python3 - <<'PY'
import os, re, pathlib
users = pathlib.Path("config/wazuh_indexer/internal_users.yml")
text = users.read_text()
for user, key in (("admin", "ADMIN_HASH"), ("kibanaserver", "KIBANA_HASH")):
    text, n = re.subn(rf'(^{user}:\n\s+hash: )"[^"]*"', lambda m: f'{m.group(1)}"{os.environ[key]}"', text, flags=re.M)
    assert n == 1, user
def yaml_sq(v):
    return "'" + v.replace("'", "''") + "'"

# docker-compose.yml: quote each entry and escape $ so Compose passes the password through unchanged.
compose = pathlib.Path("docker-compose.yml")
t = compose.read_text()
for key, default in (("INDEXER_PASSWORD", "SecretPassword"), ("DASHBOARD_PASSWORD", "kibanaserver"), ("API_PASSWORD", "MyS3cr37P450r.*-")):
    value = os.environ[key].replace("$", "$$")
    t, n = re.subn(rf"^(\s*- ){key}={re.escape(default)}$", lambda m: m.group(1) + yaml_sq(f"{key}={value}"), t, flags=re.M)
    assert n >= 1, key
dashboard = pathlib.Path("config/wazuh_dashboard/wazuh.yml")
d, n = re.subn(r'^(\s*password: )"MyS3cr37P450r\.\*-"$', lambda m: m.group(1) + yaml_sq(os.environ["API_PASSWORD"]), dashboard.read_text(), flags=re.M)
assert n == 1, "wazuh.yml password"
# Write only after every default was found, so a failed run leaves the files untouched.
users.write_text(text)
compose.write_text(t)
dashboard.write_text(d)
PY
  touch .blaksoc-passwords-set
fi

# Agent enrolment needs the password; agent traffic itself uses per-agent keys.
install -m 0640 /dev/null config/authd.pass
printf '%s\n' "$ENROLLMENT_PASSWORD" > config/authd.pass
python3 - <<'PY'
import pathlib, re
p = pathlib.Path("config/wazuh_cluster/wazuh_manager.conf")
t = p.read_text()
t = re.sub(r"<use_password>no</use_password>", "<use_password>yes</use_password>", t)
p.write_text(t)
PY

# Region attribute that blakSOC checks before trusting the indexer (assertSearchNodeInAustralia).
# opensearch.yml is a read-only bind mount of this file inside the container, so it is written here.
python3 - <<'PY'
import pathlib, re
p = pathlib.Path("config/wazuh_indexer/wazuh.indexer.yml")
t = p.read_text()
line = "node.attr.region: ap-southeast-2"
t, n = re.subn(r"^node\.attr\.region:.*$", line, t, flags=re.M)
if not n:
    t = t.rstrip("\n") + "\n" + line + "\n"
p.write_text(t)
PY

cat > blaksoc-overlay.yml <<'YML'
services:
  wazuh.manager:
    volumes:
      - ./config/authd.pass:/var/ossec/etc/authd.pass:ro
YML

docker compose -f docker-compose.yml -f blaksoc-overlay.yml up -d
echo "wazuh stack started"

# Retention: alert indices are deleted after 90 days; vulnerability and inventory state indices hold current
# state only and are not touched. Raw-log archiving (logall) stays off. See docs/disaster-recovery.md.
for _ in $(seq 1 60); do curl -sk -o /dev/null -u "admin:$INDEXER_PASSWORD" https://localhost:9200 && break; sleep 5; done
curl -sk -u "admin:$INDEXER_PASSWORD" -X PUT "https://localhost:9200/_plugins/_ism/policies/blaksoc-alerts-90d" -H 'Content-Type: application/json' -d '{
  "policy": {
    "description": "blakSOC: delete Wazuh alert and monitoring indices 90 days after creation",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [], "transitions": [{ "state_name": "delete", "conditions": { "min_index_age": "90d" } }] },
      { "name": "delete", "actions": [{ "delete": {} }], "transitions": [] }
    ],
    "ism_template": [{ "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"], "priority": 100 }]
  }
}' | jq -c '{ism_policy: (._id // .error.type)}'
# The template only covers indices created from now on; attach existing ones that have no policy yet.
curl -sk -u "admin:$INDEXER_PASSWORD" -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*,wazuh-monitoring-*,wazuh-statistics-*" -H 'Content-Type: application/json' -d '{"policy_id":"blaksoc-alerts-90d"}' | jq -c '{attached: .updated_indices, failed: .failures}'

# Local rules (blakSOC tuning), applied through the API once the manager answers.
API_URL=https://localhost:55000
for _ in $(seq 1 60); do curl -sk -o /dev/null "$API_URL" && break; sleep 5; done
T=$(curl -sk -u "wazuh-wui:$API_PASSWORD" -X POST "$API_URL/security/user/authenticate?raw=true")
current=$(curl -sk -H "Authorization: Bearer $T" "$API_URL/rules/files/local_rules.xml?raw=true")
if ! grep -q 'id="100100"' <<<"$current"; then
  # Docker attaching a container's veth to a bridge puts it in promiscuous mode (rule 80710) on every
  # container start; a real interface entering promiscuous mode still alerts.
  printf '%s\n%s\n' "$current" '<group name="local,audit,blaksoc,">
  <rule id="100100" level="0">
    <if_sid>80710</if_sid>
    <field name="audit.dev">^veth</field>
    <description>Docker container interface entered promiscuous mode (bridge attach); not a sniffer.</description>
  </rule>
</group>' | curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/octet-stream" -X PUT "$API_URL/rules/files/local_rules.xml?overwrite=true" --data-binary @- | jq -c '{rules: .message}'
  curl -sk -H "Authorization: Bearer $T" -X PUT "$API_URL/manager/restart" | jq -c '{restart: .message}'
fi

# Shared agent configuration for EC2 hosts (deploy/wazuh/agent-yumait-aws.conf, inlined so this script stays
# self-contained over SSM). Agents pick it up on their next sync.
curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/json" -X POST "$API_URL/groups" -d '{"group_id":"yumait-aws"}' >/dev/null
cat <<'XML' | curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/xml" -X PUT "$API_URL/groups/yumait-aws/configuration" --data-binary @- | jq -c '{agent_conf: .message}'
<agent_config>
  <!-- blakSOC: /boot/efi is FAT; Linux assigns its inode numbers dynamically, so inode changes there are noise.
       Content, size, owner and permissions are still checked. -->
  <syscheck>
    <directories check_all="yes" check_inode="no">/boot/efi</directories>
  </syscheck>
</agent_config>
XML
docker compose -f docker-compose.yml -f blaksoc-overlay.yml ps --format '{{.Service}} {{.State}}'
