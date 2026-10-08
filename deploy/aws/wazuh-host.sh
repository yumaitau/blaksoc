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
TUNNEL_TOKEN=$(jq -r '.CLOUDFLARE_TUNNEL_TOKEN // empty' <<<"$creds")
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
# Overwritten in place: the manager bind-mounts this single file, and a replaced file (new inode) would leave
# the running container on the old password.
[ -f config/authd.pass ] || install -m 0640 /dev/null config/authd.pass
printf '%s\n' "$ENROLLMENT_PASSWORD" > config/authd.pass
# EKS control plane audit and authenticator logs (CloudWatch /aws/eks/yumait-prod/cluster, 30-day retention), read
# with the host role. Rules blaksoc_eks_rules.xml below decide what alerts; everything else stays level 0 and is not
# stored.
MANAGER_CONF_CHANGED=$(python3 - <<'PY'
import pathlib, re
p = pathlib.Path("config/wazuh_cluster/wazuh_manager.conf")
before = p.read_text()
t = re.sub(r"<use_password>no</use_password>", "<use_password>yes</use_password>", before)
if '<wodle name="aws-s3">' not in t:
    wodle = """
<ossec_config>
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <service type="cloudwatchlogs">
      <aws_log_groups>/aws/eks/yumait-prod/cluster</aws_log_groups>
      <regions>ap-southeast-2</regions>
      <only_logs_after>2026-OCT-07</only_logs_after>
    </service>
  </wodle>
</ossec_config>
"""
    t = t.rstrip("\n") + "\n" + wodle
if t != before:
    p.write_text(t)
    print("yes")
PY
)

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
# The manager copies the mounted ossec.conf in only when a new container initialises (a restarted one skips it),
# so a change recreates the container. Its state is in named volumes.
if [ -n "$MANAGER_CONF_CHANGED" ]; then
  docker compose -f docker-compose.yml -f blaksoc-overlay.yml up -d --force-recreate wazuh.manager >/dev/null
  echo "manager recreated for ossec.conf"
fi

# TLS for clients outside the compose network (blakSOC): the generated certificates name only wazuh.indexer and
# the API's is self-signed for localhost. Reissue both from the stack's root CA with the internal DNS name and
# private address. Same subject as before, which the indexer's nodes_dn checks. Files are overwritten in place
# (the containers bind-mount them), then the services restart. Skipped when the private address is already named.
imds_token=$(curl -sf -m 2 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
PRIVATE_IP=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/local-ipv4)
INTERNAL_NAME=wazuh-internal.soc.yumait.au
CERTS=config/wazuh_indexer_ssl_certs
issue_cert() { # subject cert-out key-out
  local tmp; tmp=$(mktemp -d)
  openssl req -new -newkey rsa:2048 -nodes -keyout "$tmp/key" -subj "$1" -out "$tmp/csr" 2>/dev/null
  printf 'subjectAltName=DNS:wazuh.indexer,DNS:wazuh.manager,DNS:%s,DNS:localhost,IP:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$INTERNAL_NAME" "$PRIVATE_IP" > "$tmp/ext"
  openssl x509 -req -in "$tmp/csr" -CA "$CERTS/root-ca.pem" -CAkey "$CERTS/root-ca.key" -CAcreateserial -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/crt" 2>/dev/null
  cat "$tmp/crt" > "$2"; cat "$tmp/key" > "$3"; rm -rf "$tmp"
}
if [ -n "$PRIVATE_IP" ] && ! openssl x509 -in "$CERTS/wazuh.indexer.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$PRIVATE_IP"; then
  issue_cert "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=wazuh.indexer" "$CERTS/wazuh.indexer.pem" "$CERTS/wazuh.indexer-key.pem"
  docker compose -f docker-compose.yml -f blaksoc-overlay.yml restart wazuh.indexer >/dev/null
  echo "indexer certificate reissued"
fi
api_san=$(docker compose -f docker-compose.yml -f blaksoc-overlay.yml exec -T wazuh.manager cat /var/ossec/api/configuration/ssl/server.crt | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
if [ -n "$PRIVATE_IP" ] && ! grep -q "IP Address:$PRIVATE_IP" <<<"$api_san"; then
  tmpd=$(mktemp -d)
  issue_cert "/C=AU/O=Yuma IT/OU=blakSOC/CN=$INTERNAL_NAME" "$tmpd/server.crt" "$tmpd/server.key"
  for f in server.crt server.key; do
    docker compose -f docker-compose.yml -f blaksoc-overlay.yml exec -T wazuh.manager sh -c "cat > /var/ossec/api/configuration/ssl/$f" < "$tmpd/$f"
  done
  rm -rf "$tmpd"
  docker compose -f docker-compose.yml -f blaksoc-overlay.yml exec -T wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null
  echo "API certificate reissued"
fi

# Retention: alert indices are deleted after 90 days; vulnerability and inventory state indices hold current
# state only and are not touched. Raw-log archiving (logall) stays off. See docs/disaster-recovery.md.
# Ready means the security plugin answers 200, not merely that the port accepts connections.
for _ in $(seq 1 60); do curl -fsk -o /dev/null -u "admin:$INDEXER_PASSWORD" https://localhost:9200/_cluster/health && break; sleep 5; done
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

# Dashboard access: Cloudflare Tunnel blaksoc-wazuh publishes https://localhost:443 as wazuh.yumait.au,
# behind a Cloudflare Access application (yumait.com.au identities only). Outbound only; no inbound port opens.
if [ -n "$TUNNEL_TOKEN" ]; then
  CLOUDFLARED_IMAGE=cloudflare/cloudflared:2026.10.0
  if [ "$(docker inspect -f '{{.Config.Image}}' blaksoc-cloudflared 2>/dev/null)" != "$CLOUDFLARED_IMAGE" ]; then
    docker rm -f blaksoc-cloudflared >/dev/null 2>&1 || true
    # The token goes in through the environment of this command only, never into its arguments.
    TUNNEL_TOKEN="$TUNNEL_TOKEN" docker run -d --name blaksoc-cloudflared --restart unless-stopped --network host \
      --security-opt no-new-privileges:true --log-driver local -e TUNNEL_TOKEN "$CLOUDFLARED_IMAGE" tunnel --no-autoupdate run >/dev/null
    echo "cloudflared started"
  fi
fi

# Local rules (blakSOC tuning), applied through the API once the manager answers.
API_URL=https://localhost:55000
for _ in $(seq 1 60); do curl -fsk -o /dev/null -u "wazuh-wui:$API_PASSWORD" -X POST "$API_URL/security/user/authenticate?raw=true" && break; sleep 5; done
T=$(curl -fsk -u "wazuh-wui:$API_PASSWORD" -X POST "$API_URL/security/user/authenticate?raw=true") || T=""
# A JWT, not an error body: without it every call below would fail quietly and the run would look applied.
[ "${#T}" -gt 100 ] || { echo "Wazuh API authentication failed; rules, group configuration and retention not applied" >&2; exit 1; }
RESTART_MANAGER=
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
  RESTART_MANAGER=yes
fi
cat > /tmp/blaksoc_eks_rules.xml <<'XML'
<!-- blakSOC: EKS control plane (yumait-prod) audit and authenticator logs, read from CloudWatch by the aws-s3 wodle.
     People and unknown identities are watched; Kubernetes controllers (system:) and EKS components (eks:) are not.
     Levels map to blakSOC severities: 10+ is high and opens a Kelpie case, 7-9 medium, 4-6 low. -->
<group name="blaksoc,eks,kubernetes,">
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="kind">^Event$</field>
    <field name="apiVersion">^audit.k8s.io/</field>
    <description>EKS audit event.</description>
  </rule>

  <rule id="100201" level="0">
    <if_sid>100200</if_sid>
    <field name="user.username" negate="yes">^system:|^eks:</field>
    <description>EKS audit event by a person or unknown identity.</description>
  </rule>

  <rule id="100202" level="8">
    <if_sid>100201</if_sid>
    <field name="objectRef.subresource">^exec$|^attach$</field>
    <field name="stage">^ResponseStarted$</field>
    <description>EKS: $(user.username) opened a shell (kubectl $(objectRef.subresource)) in pod $(objectRef.namespace)/$(objectRef.name).</description>
    <mitre><id>T1609</id></mitre>
    <group>kubernetes_exec,</group>
  </rule>

  <rule id="100203" level="7">
    <if_sid>100201</if_sid>
    <field name="objectRef.resource">^secrets$</field>
    <field name="verb">^get$|^list$|^watch$</field>
    <field name="stage">^ResponseComplete$</field>
    <field name="responseStatus.code">^2</field>
    <description>EKS: $(user.username) read secrets ($(verb)) in namespace $(objectRef.namespace).</description>
    <mitre><id>T1552.007</id></mitre>
    <group>kubernetes_secrets,</group>
  </rule>

  <rule id="100204" level="10">
    <if_sid>100201</if_sid>
    <field name="objectRef.resource">^clusterrolebindings$|^rolebindings$|^clusterroles$|^roles$</field>
    <field name="verb">^create$|^update$|^patch$|^delete$</field>
    <field name="stage">^ResponseComplete$</field>
    <field name="responseStatus.code">^2</field>
    <description>EKS: $(user.username) changed RBAC: $(verb) $(objectRef.resource) $(objectRef.namespace)/$(objectRef.name).</description>
    <mitre><id>T1098</id></mitre>
    <group>kubernetes_rbac,</group>
  </rule>

  <rule id="100205" level="10">
    <if_sid>100201</if_sid>
    <field name="objectRef.resource">^pods$|^deployments$|^daemonsets$|^statefulsets$|^replicasets$|^jobs$|^cronjobs$</field>
    <field name="verb">^create$|^update$|^patch$</field>
    <field name="stage">^ResponseComplete$</field>
    <field name="responseStatus.code">^2</field>
    <regex type="pcre2">"privileged":\s*true|"hostPID":\s*true|"hostNetwork":\s*true</regex>
    <description>EKS: $(user.username) deployed a privileged or host-namespace workload: $(objectRef.resource) $(objectRef.namespace)/$(objectRef.name).</description>
    <mitre><id>T1610</id><id>T1611</id></mitre>
    <group>kubernetes_privileged,</group>
  </rule>

  <rule id="100206" level="12">
    <if_sid>100200</if_sid>
    <field name="user.username">^system:anonymous$</field>
    <field name="responseStatus.code">^2</field>
    <field name="requestURI" negate="yes">^/healthz|^/livez|^/readyz|^/version</field>
    <description>EKS: anonymous request allowed: $(verb) $(requestURI).</description>
    <mitre><id>T1190</id></mitre>
    <group>kubernetes_anonymous,</group>
  </rule>

  <rule id="100207" level="5">
    <if_sid>100201</if_sid>
    <field name="responseStatus.code">^403$</field>
    <description>EKS: $(user.username) was refused: $(verb) $(objectRef.resource) $(objectRef.namespace)/$(objectRef.name).</description>
    <group>kubernetes_forbidden,</group>
  </rule>

  <rule id="100208" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100207</if_matched_sid>
    <same_field>user.username</same_field>
    <description>EKS: $(user.username) was refused 10 times in 2 minutes (permission probing).</description>
    <mitre><id>T1613</id></mitre>
    <group>kubernetes_forbidden,</group>
  </rule>

  <rule id="100210" level="5">
    <decoded_as>aws-eks-authenticator</decoded_as>
    <field name="msg">^access denied$</field>
    <description>EKS: IAM identity $(arn) refused by the cluster authenticator.</description>
    <group>kubernetes_authentication_failed,authentication_failed,</group>
  </rule>

  <rule id="100211" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100210</if_matched_sid>
    <same_field>arn</same_field>
    <description>EKS: IAM identity $(arn) refused by the cluster authenticator 10 times in 2 minutes.</description>
    <mitre><id>T1110</id></mitre>
    <group>kubernetes_authentication_failed,authentication_failures,</group>
  </rule>
</group>
XML
if ! curl -sk -H "Authorization: Bearer $T" "$API_URL/rules/files/blaksoc_eks_rules.xml?raw=true" | cmp -s - /tmp/blaksoc_eks_rules.xml; then
  curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/octet-stream" -X PUT "$API_URL/rules/files/blaksoc_eks_rules.xml?overwrite=true" --data-binary @/tmp/blaksoc_eks_rules.xml | jq -c '{eks_rules: .message}'
  RESTART_MANAGER=yes
fi
rm -f /tmp/blaksoc_eks_rules.xml
if [ -n "$RESTART_MANAGER" ]; then
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
