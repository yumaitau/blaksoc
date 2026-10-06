#!/usr/bin/env bash
# Runs OpenCTI and its public feed connectors on the blaksoc-opencti EC2 host from
# deploy/compose/docker-compose.yml (profile opencti). Runs as root over SSM Run Command on
# Ubuntu 24.04 (arm64). Safe to re-run. The compose file must already be at $DIR/docker-compose.yml.
# Credentials come from Secrets Manager (blaksoc-opencti-credentials) and never reach the command output.
set -euo pipefail
REGION=ap-southeast-2
SECRET=blaksoc-opencti-credentials
DIR=/opt/blaksoc-opencti

export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q docker.io docker-compose-v2 jq curl
command -v aws >/dev/null || snap install aws-cli --classic
systemctl enable --now docker
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-opensearch.conf

cd "$DIR"
test -f docker-compose.yml

# Private IP is the base URL blakSOC uses inside the VPC.
token=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
ip=$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/local-ipv4)

umask 077
aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" --query SecretString --output text \
  | jq -r 'to_entries[] | "\(.key)=\(.value)"' > .env
cat >> .env <<EOF
OPENCTI_BASE_URL=http://$ip:8080
OPENSEARCH_REGION=ap-southeast-2
OPENCTI_REGION=ap-southeast-2
# The shared compose file also declares the blakSOC core services. They are not started here,
# but compose still interpolates their required variables.
APP_URL=http://unused.invalid
BETTER_AUTH_SECRET=unused-on-this-host-unused-on-this-host
BLAKSOC_APP_DB_PASSWORD=unused
BLAKSOC_ENCRYPTION_KEY=unused
POSTGRES_PASSWORD=unused
REDIS_PASSWORD=unused
EOF

SERVICES="opencti-redis opencti-search opencti-minio opencti-rabbitmq opencti opencti-worker connector-mitre connector-cisa-kev connector-cve connector-urlhaus connector-malwarebazaar connector-epss"
docker compose --env-file .env --profile opencti up -d $SERVICES
echo "opencti stack started"
docker compose --env-file .env --profile opencti ps --format '{{.Service}} {{.State}}'
