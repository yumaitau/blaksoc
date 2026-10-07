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
docker compose -f docker-compose.yml -f blaksoc-overlay.yml ps --format '{{.Service}} {{.State}}'
