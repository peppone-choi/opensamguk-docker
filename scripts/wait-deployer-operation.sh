#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <deployer-base-url> <deployer-env|env:NAME|file:PATH|dotenv:PATH> <operation-id> <deadline-epoch-seconds> <poll-interval-seconds>" >&2
}

if (($# != 5)); then
  usage
  exit 2
fi

base_url="${1%/}"
token_source="$2"
operation_id="$3"
deadline="$4"
poll_interval="$5"

if [[ ! "$base_url" =~ ^https?://[^[:space:]]+$ ]] || [[ "$base_url" == *$'\n'* || "$base_url" == *$'\r'* ]]; then
  echo "invalid deployer base URL" >&2
  exit 2
fi
if [[ ! "$operation_id" =~ ^[a-f0-9]{32}$ ]]; then
  echo "invalid deployer operation id" >&2
  exit 2
fi
if [[ ! "$deadline" =~ ^[0-9]+$ ]] || [[ ! "$poll_interval" =~ ^[0-9]+$ ]]; then
  echo "deadline and poll interval must be non-negative integer seconds" >&2
  exit 2
fi

token=""
case "$token_source" in
  deployer-env)
    token="${DEPLOYER_TOKEN-}"
    ;;
  env:*)
    token_name="${token_source#env:}"
    if [[ ! "$token_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "invalid bearer token environment source" >&2
      exit 2
    fi
    token="${!token_name-}"
    ;;
  file:*)
    token_file="${token_source#file:}"
    if [[ -z "$token_file" || ! -r "$token_file" ]]; then
      echo "bearer token file is not readable" >&2
      exit 2
    fi
    IFS= read -r token <"$token_file" || true
    ;;
  dotenv:*)
    dotenv_file="${token_source#dotenv:}"
    if [[ -z "$dotenv_file" || ! -r "$dotenv_file" ]]; then
      echo "bearer token dotenv file is not readable" >&2
      exit 2
    fi
    while IFS='=' read -r key value; do
      if [[ "$key" == DEPLOYER_TOKEN ]]; then
        token="$value"
        token="${token%\"}"
        token="${token#\"}"
        token="${token%\'}"
        token="${token#\'}"
        break
      fi
    done <"$dotenv_file"
    ;;
  *)
    echo "unsupported bearer token source" >&2
    exit 2
    ;;
esac

if [[ -z "$token" || "$token" == *$'\n'* || "$token" == *$'\r'* ]]; then
  echo "bearer token source is empty or invalid" >&2
  exit 2
fi

response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
operation_url="$base_url/operations/$operation_id"

while :; do
  now="$(date +%s)"
  remaining=$((deadline - now))
  if ((remaining <= 0)); then
    echo "deployer operation $operation_id did not succeed before the polling deadline" >&2
    exit 124
  fi
  request_timeout=10
  if ((request_timeout > remaining)); then
    request_timeout="$remaining"
  fi

  escaped_token="${token//\\/\\\\}"
  escaped_token="${escaped_token//\"/\\\"}"
  escaped_url="${operation_url//\\/\\\\}"
  escaped_url="${escaped_url//\"/\\\"}"
  : >"$response_file"
  if ! curl --silent --show-error --fail --max-redirs 0 \
    --connect-timeout "$request_timeout" --max-time "$request_timeout" \
    --output "$response_file" --config - <<EOF
url = "$escaped_url"
request = "GET"
header = "Authorization: Bearer $escaped_token"
EOF
  then
    echo "deployer operation $operation_id status request failed" >&2
    exit 1
  fi

  if ! status="$(OPERATION_ID="$operation_id" python3 - "$response_file" <<'PY'
import json
import os
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as response:
        payload = json.load(response)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)

valid_states = {
    "pending", "running", "recovery_required", "succeeded", "failed", "cancelled"
}
if not isinstance(payload, dict):
    raise SystemExit(1)
if payload.get("operationId") != os.environ["OPERATION_ID"]:
    raise SystemExit(1)
status = payload.get("status")
if status not in valid_states:
    raise SystemExit(1)
print(status)
PY
  )"; then
    echo "deployer operation $operation_id returned a malformed status response" >&2
    exit 1
  fi

  case "$status" in
    succeeded)
      echo "deployer operation $operation_id succeeded" >&2
      exit 0
      ;;
    failed|cancelled)
      echo "deployer operation $operation_id reached terminal status $status" >&2
      exit 1
      ;;
    pending|running|recovery_required)
      echo "deployer operation $operation_id is $status" >&2
      ;;
  esac

  if ((poll_interval > 0)); then
    now="$(date +%s)"
    remaining=$((deadline - now))
    if ((remaining <= 0)); then
      echo "deployer operation $operation_id did not succeed before the polling deadline" >&2
      exit 124
    fi
    sleep_for="$poll_interval"
    if ((sleep_for > remaining)); then
      sleep_for="$remaining"
    fi
    sleep "$sleep_for"
  fi
done
