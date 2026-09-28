#!/bin/sh
# Release a host isolated by blaksoc-isolate.sh.
set -eu
read -r _ || true
nft delete table inet blaksoc 2>/dev/null || true
echo "$(date '+%Y/%m/%d %H:%M:%S') blaksoc-release: released" >> /var/ossec/logs/active-responses.log
