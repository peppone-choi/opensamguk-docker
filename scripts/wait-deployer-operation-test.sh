#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/scripts/wait-deployer-operation.sh"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT

if [[ "$(basename "$0")" == curl ]]; then
  output_file=""
  while (($#)); do
    case "$1" in
      --output)
        output_file="$2"
        shift 2
        ;;
      *) shift ;;
    esac
  done
  [[ -n "$output_file" ]] || exit 91
  curl_config="$(sed -n '1,20p')"
  [[ "$curl_config" == *'Authorization: Bearer contract-token'* ]] || exit 92
  count="$(cat "$FAKE_CURL_COUNT")"
  count=$((count + 1))
  printf '%s\n' "$count" >"$FAKE_CURL_COUNT"
  response="$(sed -n "${count}p" "$FAKE_CURL_RESPONSES")"
  [[ -n "$response" ]] || exit 22
  printf '%s\n' "$response" >"$output_file"
  exit 0
fi

if [[ ! -x "$HELPER" ]]; then
  echo "missing executable helper: $HELPER" >&2
  exit 1
fi

mkdir -p "$TEST_TMP/bin"
ln -s "$ROOT/scripts/wait-deployer-operation-test.sh" "$TEST_TMP/bin/curl"
export PATH="$TEST_TMP/bin:$PATH"
export CONTRACT_TOKEN="contract-token"
export DEPLOYER_TOKEN="contract-token"
export FAKE_CURL_COUNT="$TEST_TMP/curl-count"
export FAKE_CURL_RESPONSES="$TEST_TMP/curl-responses"
operation_id="0123456789abcdef0123456789abcdef"

run_case() {
  local name="$1"
  local responses="$2"
  local expected_exit="$3"
  local expected_calls="$4"
  local output="$TEST_TMP/$name.output"
  printf '0\n' >"$FAKE_CURL_COUNT"
  printf '%s\n' "$responses" >"$FAKE_CURL_RESPONSES"
  local deadline=$(( $(date +%s) + 30 ))
  set +e
  "$HELPER" "http://deployer.invalid:9000" "deployer-env" \
    "$operation_id" "$deadline" 0 >"$output" 2>&1
  local exit_code=$?
  set -e
  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    echo "$name exit=$exit_code, want $expected_exit" >&2
    sed -n '1,80p' "$output" >&2
    exit 1
  fi
  if [[ "$(cat "$FAKE_CURL_COUNT")" -ne "$expected_calls" ]]; then
    echo "$name curl calls=$(cat "$FAKE_CURL_COUNT"), want $expected_calls" >&2
    exit 1
  fi
  if grep -q 'body-secret' "$output"; then
    echo "$name leaked a response body" >&2
    exit 1
  fi
}

run_case success_after_recovery_required \
  "{\"operationId\":\"$operation_id\",\"status\":\"pending\",\"publicMessage\":\"body-secret-1\"}
{\"operationId\":\"$operation_id\",\"status\":\"running\",\"publicMessage\":\"body-secret-running\"}
{\"operationId\":\"$operation_id\",\"status\":\"recovery_required\",\"publicMessage\":\"body-secret-2\"}
{\"operationId\":\"$operation_id\",\"status\":\"succeeded\",\"publicMessage\":\"body-secret-3\"}" \
  0 4
run_case terminal_failed \
  "{\"operationId\":\"$operation_id\",\"status\":\"failed\",\"publicMessage\":\"body-secret-failed\"}" \
  1 1
run_case malformed_response '{"operationId":"wrong","status":"succeeded","publicMessage":"body-secret-malformed"}' 1 1
run_case malformed_json '{not-json' 1 1
run_case missing_response '{}' 1 1

echo "wait-deployer-operation contract tests: PASS"
