#!/bin/sh
# blakSOC network isolation for Linux Wazuh agents (nftables).
# Keeps only: loopback, established flows, and the Wazuh manager(s) listed in
# /var/ossec/etc/blaksoc-allow (one IP per line). Everything else is dropped.
# Invoked by Wazuh active response with a JSON message on stdin; "delete" releases.
set -eu
LOG=/var/ossec/logs/active-responses.log
read -r INPUT || true
CMD=$(printf '%s' "$INPUT" | sed -n 's/.*"command":"\([a-z]*\)".*/\1/p')
ALLOW_FILE=/var/ossec/etc/blaksoc-allow

log() { echo "$(date '+%Y/%m/%d %H:%M:%S') blaksoc-isolate: $*" >> "$LOG"; }

isolate() {
  nft list table inet blaksoc >/dev/null 2>&1 && { log "already isolated"; return; }
  nft add table inet blaksoc
  nft add chain inet blaksoc out '{ type filter hook output priority -10; policy drop; }'
  nft add chain inet blaksoc in '{ type filter hook input priority -10; policy drop; }'
  for c in in out; do
    nft add rule inet blaksoc $c ct state established,related accept
    nft add rule inet blaksoc $c iif lo accept 2>/dev/null || nft add rule inet blaksoc $c oif lo accept
  done
  if [ -f "$ALLOW_FILE" ]; then
    while read -r ip; do
      [ -n "$ip" ] || continue
      nft add rule inet blaksoc out ip daddr "$ip" accept
      nft add rule inet blaksoc in ip saddr "$ip" accept
    done < "$ALLOW_FILE"
  fi
  log "isolated (allow: $(tr '\n' ' ' < "$ALLOW_FILE" 2>/dev/null))"
}

release() {
  nft delete table inet blaksoc 2>/dev/null && log "released" || log "not isolated"
}

case "$CMD" in
  add) isolate ;;
  delete) release ;;
  *) log "unknown command '$CMD'"; exit 1 ;;
esac
