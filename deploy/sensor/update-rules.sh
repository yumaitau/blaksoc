#!/bin/sh
# Pull Emerging Threats Open rules and ask Suricata to reload them.
# Does not enable payload capture.
set -eu
suricata-update enable-source et/open
suricata-update
if command -v pidof >/dev/null 2>&1; then
  for pid in $(pidof suricata || true); do
    kill -USR2 "$pid" || true
  done
fi
