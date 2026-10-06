#!/usr/bin/env bash
set -euo pipefail
# Selector-only launcher. Native source authentication precedes namespace/FD9.
# Legacy ordinary deployer entrypoints do not pass through this launcher.
issuer_only=false
if [[ $# -eq 3 && "$1" == '--issuer-only' ]]; then
  issuer_only=true
  shift
fi
if [[ $# -ne 2 || "$1" != '--operation-id' || ! "$2" =~ ^[a-f0-9]{32}$ || $EUID -ne 0 ]]; then
  echo 'D101 host operation selector invalid' >&2
  exit 2
fi
readonly host_binary=/etc/opensamguk/d101/native-helper/deployer
# No local stat/hash/service token is interpreted as authority. The native entry
# checks its independently approved source/artifact/card before the first write.
if $issuer_only; then
  exec "$host_binary" --d101-native-keeper --operation-id "$2" --issuer-only
fi
exec "$host_binary" --d101-native-keeper --operation-id "$2"
