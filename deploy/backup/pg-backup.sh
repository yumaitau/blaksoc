#!/bin/sh
# blakSOC Postgres backup. Two steps so each runs in a stock image:
#   pg-backup.sh dump     postgres image: pg_dump -Fc of the blakSOC database into $BACKUP_DIR
#   pg-backup.sh upload   aws-cli image: copy the newest dump to the AU bucket, verify, prune
#   pg-backup.sh          both, when one image has pg_dump and aws
#
# dump:   BACKUP_DATABASE_URL (owner URL; the owner must bypass RLS or pg_dump stops with an error
#         instead of writing a partial dump), BACKUP_DIR (default /backup)
# upload: BACKUP_BUCKET, BACKUP_REGION (ap-southeast-2 or ap-southeast-4), BACKUP_PREFIX
#         (default postgres/), BACKUP_KEEP (dumps kept, default 28), BACKUP_SSE (AES256 or aws:kms),
#         BACKUP_KMS_KEY_ID, BACKUP_ENDPOINT (S3-compatible endpoint; empty = AWS S3).
#         Credentials: the AWS default chain (IRSA, Pod Identity, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY).
#
# This file is copied byte for byte to deploy/helm/blaksoc/files/pg-backup.sh (tests/unit/platform-backup.test.ts).
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backup}"

dump() {
  : "${BACKUP_DATABASE_URL:?set BACKUP_DATABASE_URL}"
  mkdir -p "$BACKUP_DIR"
  file="$BACKUP_DIR/blaksoc-$(date -u +%Y%m%dT%H%M%SZ).dump"
  pg_dump --format=custom --compress=6 --file="$file.partial" --dbname="$BACKUP_DATABASE_URL"
  # A dump pg_restore cannot list is not a backup.
  pg_restore --list "$file.partial" > /dev/null
  mv "$file.partial" "$file"
  # Older local dumps are superseded; the bucket holds the history.
  find "$BACKUP_DIR" -maxdepth 1 -name 'blaksoc-*.dump*' ! -name "$(basename "$file")" -exec rm -f {} +
  echo "dump $(basename "$file") $(wc -c < "$file") bytes"
}

upload() {
  : "${BACKUP_BUCKET:?set BACKUP_BUCKET}"
  : "${BACKUP_REGION:?set BACKUP_REGION}"
  case "$BACKUP_REGION" in
    ap-southeast-2|ap-southeast-4) ;;
    *) echo "backup region must be in Australia, got $BACKUP_REGION" >&2; exit 1 ;;
  esac
  prefix="${BACKUP_PREFIX:-postgres/}"
  keep="${BACKUP_KEEP:-28}"
  sse="${BACKUP_SSE:-AES256}"
  file="$(find "$BACKUP_DIR" -maxdepth 1 -name 'blaksoc-*.dump' | sort | tail -n 1)"
  [ -n "$file" ] || { echo "no dump in $BACKUP_DIR" >&2; exit 1; }
  key="$prefix$(basename "$file")"

  set -- --region "$BACKUP_REGION"
  if [ -n "${BACKUP_ENDPOINT:-}" ]; then
    set -- "$@" --endpoint-url "$BACKUP_ENDPOINT"
    # S3-compatible stores often reject the newer default checksum headers and chunked uploads.
    export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
  fi
  enc="--sse $sse"
  [ -n "${BACKUP_KMS_KEY_ID:-}" ] && enc="$enc --sse-kms-key-id $BACKUP_KMS_KEY_ID"

  # shellcheck disable=SC2086 # $enc is a word list by design
  aws "$@" s3 cp "$file" "s3://$BACKUP_BUCKET/$key" $enc --only-show-errors
  local_size="$(wc -c < "$file" | tr -d ' ')"
  remote_size="$(aws "$@" s3api head-object --bucket "$BACKUP_BUCKET" --key "$key" --query ContentLength --output text)"
  [ "$local_size" = "$remote_size" ] || { echo "uploaded size $remote_size != $local_size" >&2; exit 1; }
  echo "uploaded s3://$BACKUP_BUCKET/$key ($remote_size bytes, $sse)"

  # Keys sort by timestamp; delete all but the newest $keep. A bucket lifecycle rule is the backstop.
  aws "$@" s3api list-objects-v2 --bucket "$BACKUP_BUCKET" --prefix "${prefix}blaksoc-" --query 'Contents[].Key' --output text \
    | tr '\t' '\n' | grep -v '^None$' | sort | awk -v keep="$keep" '{ k[NR] = $0 } END { for (i = 1; i <= NR - keep; i++) print k[i] }' \
    | while read -r old; do
        aws "$@" s3 rm "s3://$BACKUP_BUCKET/$old" --only-show-errors
        echo "pruned $old"
      done
}

case "${1:-all}" in
  dump) dump ;;
  upload) upload ;;
  all) dump && upload ;;
  *) echo "usage: $0 [dump|upload]" >&2; exit 2 ;;
esac
