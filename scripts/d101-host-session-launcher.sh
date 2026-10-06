#!/usr/bin/env bash
set -euo pipefail

# Two exact reviewed entries. Issuer mode never enters physical operation.
# No operation/card/JWT/key is inferred from env or from filesystem ownership.
issuer_only=false
if [[ $# -eq 3 && "$1" == '--issuer-only' ]]; then
  issuer_only=true
  shift
fi
if [[ $# -ne 2 || "$1" != "--operation-id" || ! "$2" =~ ^[a-f0-9]{32}$ ]]; then
  echo "D101 host operation selector invalid" >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo "D101 installed root launcher required" >&2
  exit 2
fi
operation_id="$2"
readonly host_binary=/etc/opensamguk/d101/native-helper/deployer
readonly host_parent=/etc/opensamguk/d101/native-helper
if [[ ! -d "$host_parent" || -L "$host_parent" || ! -f "$host_binary" || -L "$host_binary" ]]; then
  echo "D101 installed native artifact unavailable" >&2
  exit 2
fi
if [[ "$(stat -c '%u:%a' "$host_parent")" != '0:700' || "$(stat -c '%u:%a:%h' "$host_binary")" != '0:500:1' ]]; then
  echo "D101 native artifact custody unavailable" >&2
  exit 2
fi
# These native facts are not artifact/issuer/keeper authority. The installed
# Root entry must independently verify source/binary/card/all leaves before writes.
read -r keeper_nonce < /proc/sys/kernel/random/uuid
keeper_nonce="${keeper_nonce//-/}"
if [[ ! "$keeper_nonce" =~ ^[a-f0-9]{32}$ ]]; then exit 2; fi
readonly owned_nonce="$keeper_nonce"
readonly keeper_pid="$BASHPID"
readonly lock_path=/tmp/opensamguk-production.lock
if [[ ! -f "$lock_path" || -L "$lock_path" || "$(stat -c '%h' "$lock_path")" != '1' ]]; then
  echo "D101 existing production lock unavailable" >&2
  exit 2
fi
# Initial privilege precedes the one acquisition. Append preserves the existing
# lock inode/content. Child inherits this very OFD; no sudo/closefrom after it.
exec 9>>"$lock_path"
if ! flock -w 30 9; then exit 2; fi
child_pid=''
child_start=''
# Native process identity observation guards against signaling a reused PID;
# it is not issuer/keeper authorization. Root still authenticates every phase.
child_identity() {
  local raw rest
  [[ -n "$child_pid" && -r "/proc/$child_pid/stat" ]] || return 1
  IFS= read -r raw < "/proc/$child_pid/stat" || return 1
  rest="${raw##*) }"
  local -a fields
  read -r -a fields <<< "$rest"
  [[ ${#fields[@]} -ge 20 && "${fields[1]}" == "$keeper_pid" ]] || return 1
  [[ -z "$child_start" || "${fields[19]}" == "$child_start" ]] || return 1
  observed_child_start="${fields[19]}"
}
hold() {
  echo "D101 same operation HOLD; explicit keeper recovery required" >&2
  # Do not unlink socket/owner evidence, unlock FD9, restart or issue another op.
  while true; do sleep 1; done
}
cancel_to_hold() {
  if [[ -n "$child_start" ]] && child_identity; then
    # Cancellation requests no further physical phase; Root preserves its HOLD.
    kill -TERM "$child_pid" 2>/dev/null || true
  fi
  hold
}
trap cancel_to_hold INT TERM HUP
if $issuer_only; then
  # Explicit stdin duplication prevents Bash asynchronous-command /dev/null.
  # stdin/stdout remain the two inherited anonymous pipes. No JWT env/argv/log.
  "$host_binary" --d101-issue-current-receipt --operation-id "$operation_id" <&0 &
else
  "$host_binary" --d101-host-operation --operation-id "$operation_id" </dev/null &
fi
child_pid="$!"
if child_identity; then child_start="$observed_child_start"; fi
status=0
wait "$child_pid" || status="$?"
if [[ "$owned_nonce" != "$keeper_nonce" || "$keeper_pid" != "$BASHPID" ]] || child_identity; then
  hold
fi
if (( status == 2 )); then
  # Reviewed Root contract: definite denial before any admitted operation.
  exit 2
fi
if (( status != 0 )); then hold; fi
# Root's status0 path requires actual terminal worker absence and mandatory
# authenticated full-lifetime release evidence. This script cannot supply it.
# No unconditional trap unlock exists; normal exit closes only our owned FD.
trap - INT TERM HUP
exit 0
