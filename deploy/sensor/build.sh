#!/bin/sh
# Write a Suricata reference config. Payloads stay off. Zeek stays off unless --zeek is set.
set -eu

OUT=""
BANDWIDTH="standard"
CAPTURE="span"
ZEEK="no"

while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      OUT="${2:-}"
      shift 2
      ;;
    --bandwidth)
      BANDWIDTH="${2:-}"
      shift 2
      ;;
    --capture)
      CAPTURE="${2:-}"
      shift 2
      ;;
    --zeek)
      ZEEK="yes"
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$OUT" ]; then
  echo "missing --out" >&2
  exit 2
fi

case "$BANDWIDTH" in
  standard | low) ;;
  *)
    echo "bandwidth must be standard or low" >&2
    exit 2
    ;;
esac

case "$CAPTURE" in
  span | tap) ;;
  *)
    echo "capture must be span or tap" >&2
    exit 2
    ;;
esac

IFACE="span0"
CAPTURE_NOTE="SPAN or mirror port. The sensor listens. It does not sit inline."
if [ "$CAPTURE" = "tap" ]; then
  IFACE="tap0"
  CAPTURE_NOTE="Inline tap. The sensor receives a copy and does not rewrite packets."
fi

FORWARDING="alerts-and-metadata"
TYPES="        - alert:
            payload: no
            payload-printable: no
            http-body: no
            http-body-printable: no"
if [ "$BANDWIDTH" = "low" ]; then
  FORWARDING="alerts"
else
  TYPES="$TYPES
        - flow
        - dns
        - tls"
fi

mkdir -p "$OUT"
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

cat > "$OUT/suricata.yaml" <<EOF
%YAML 1.1
---
# ${CAPTURE_NOTE}
# bandwidth: ${BANDWIDTH}
# forwarding: ${FORWARDING}
# Emerging Threats Open. No payload capture by default.
af-packet:
  - interface: ${IFACE}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - et-open.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: unix_dgram
      filename: /var/run/suricata/eve.sock
      types:
${TYPES}
EOF

cp "$HERE/update-rules.sh" "$OUT/update-rules.sh"
chmod 755 "$OUT/update-rules.sh"

if [ "$ZEEK" = "yes" ]; then
  mkdir -p "$OUT/zeek"
  cat > "$OUT/zeek/local.zeek" <<EOF
# Optional metadata only. Packet payloads are not logged.
@load base/protocols/conn
EOF
fi
