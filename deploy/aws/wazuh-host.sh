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
  hash() { docker run --rm "wazuh/wazuh-indexer:$VERSION" bash -c "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$1'" 2>/dev/null | tail -1; }
  ADMIN_HASH=$(hash "$INDEXER_PASSWORD")
  KIBANA_HASH=$(hash "$DASHBOARD_PASSWORD")
  ADMIN_HASH="$ADMIN_HASH" KIBANA_HASH="$KIBANA_HASH" INDEXER_PASSWORD="$INDEXER_PASSWORD" API_PASSWORD="$API_PASSWORD" DASHBOARD_PASSWORD="$DASHBOARD_PASSWORD" python3 - <<'PY'
import os, re, pathlib
users = pathlib.Path("config/wazuh_indexer/internal_users.yml")
text = users.read_text()
for user, key in (("admin", "ADMIN_HASH"), ("kibanaserver", "KIBANA_HASH")):
    text, n = re.subn(rf'(^{user}:\n\s+hash: )"[^"]*"', lambda m: f'{m.group(1)}"{os.environ[key]}"', text, flags=re.M)
    assert n == 1, user
users.write_text(text)
swaps = {"SecretPassword": os.environ["INDEXER_PASSWORD"], "kibanaserver": os.environ["DASHBOARD_PASSWORD"], "MyS3cr37P450r.*-": os.environ["API_PASSWORD"]}
for path in ("docker-compose.yml", "config/wazuh_dashboard/wazuh.yml"):
    p = pathlib.Path(path)
    t = p.read_text()
    t = t.replace("INDEXER_PASSWORD=SecretPassword", "INDEXER_PASSWORD=" + swaps["SecretPassword"])
    t = t.replace("DASHBOARD_PASSWORD=kibanaserver", "DASHBOARD_PASSWORD=" + swaps["kibanaserver"])
    t = t.replace("MyS3cr37P450r.*-", swaps["MyS3cr37P450r.*-"])
    p.write_text(t)
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

# Region attribute that blakSOC checks before trusting the indexer (deploy/wazuh/indexer-region.yml).
cat > blaksoc-overlay.yml <<'YML'
services:
  wazuh.manager:
    volumes:
      - ./config/authd.pass:/var/ossec/etc/authd.pass:ro
  wazuh.indexer:
    environment:
      node.attr.region: ap-southeast-2
    entrypoint:
      - /bin/bash
      - -c
      - |
        set -eu
        region=$$(printenv 'node.attr.region')
        conf=/usr/share/wazuh-indexer/config/opensearch.yml
        case "$$region" in
          ap-southeast-2|ap-southeast-4) ;;
          *) echo "indexer region must be in Australia, got $${region}" >&2; exit 2 ;;
        esac
        grep -q '^node.attr.region:' "$$conf" || printf '\nnode.attr.region: %s\n' "$$region" >> "$$conf"
        exec /entrypoint.sh opensearchwrapper
YML

docker compose -f docker-compose.yml -f blaksoc-overlay.yml up -d
echo "wazuh stack started"
docker compose -f docker-compose.yml -f blaksoc-overlay.yml ps --format '{{.Service}} {{.State}}'
