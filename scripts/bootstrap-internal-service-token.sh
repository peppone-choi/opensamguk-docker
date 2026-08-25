#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: bootstrap-internal-service-token.sh <shared-env> <servers-dir>" >&2
  exit 2
fi

shared_env="$1"
servers_dir="$2"
readonly token_key="INTERNAL_SERVICE_TOKEN"

if [[ ! -f "$shared_env" || -L "$shared_env" ]]; then
  echo "shared env must be a regular file" >&2
  exit 1
fi
if [[ ! -d "$servers_dir" || -L "$servers_dir" ]]; then
  echo "servers dir must be a regular directory" >&2
  exit 1
fi

shared_token=""
shared_token_count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    "$token_key="*)
      shared_token="${line#*=}"
      shared_token_count=$((shared_token_count + 1))
      ;;
  esac
done < "$shared_env"

if (( shared_token_count > 1 )); then
  echo "shared env contains duplicate internal service token entries" >&2
  exit 1
fi
if (( shared_token_count == 0 )); then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to bootstrap the internal service token" >&2
    exit 1
  fi
  shared_token="$(openssl rand -hex 32)"
fi
if (( ${#shared_token} < 32 || ${#shared_token} > 512 )) ||
  [[ ! "$shared_token" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "shared internal service token is not valid" >&2
  exit 1
fi

targets=("$shared_env")
shopt -s nullglob
for candidate in "$servers_dir"/s*.env; do
  case "$candidate" in
    *.bak*|*.example) continue ;;
  esac
  if [[ ! -f "$candidate" || -L "$candidate" ]]; then
    echo "server env must be a regular file" >&2
    exit 1
  fi
  targets+=("$candidate")
done

umask 077
staged=()
cleanup() {
  if (( ${#staged[@]} > 0 )); then
    rm -f -- "${staged[@]}"
  fi
}
trap cleanup EXIT HUP INT TERM

for target in "${targets[@]}"; do
  temp_file="$(mktemp "${target}.internal-token.XXXXXX")"
  staged+=("$temp_file")
  token_count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "$token_key="*)
        token_count=$((token_count + 1))
        if (( token_count > 1 )); then
          echo "env file contains duplicate internal service token entries" >&2
          exit 1
        fi
        printf '%s=%s\n' "$token_key" "$shared_token" >> "$temp_file"
        ;;
      *) printf '%s\n' "$line" >> "$temp_file" ;;
    esac
  done < "$target"
  if (( token_count == 0 )); then
    printf '%s=%s\n' "$token_key" "$shared_token" >> "$temp_file"
  fi

  if mode="$(stat -f '%Lp' "$target" 2>/dev/null)"; then
    chmod "$mode" "$temp_file"
  else
    chmod --reference="$target" "$temp_file"
  fi
done

for index in "${!targets[@]}"; do
  mv -f -- "${staged[$index]}" "${targets[$index]}"
done
staged=()
trap - EXIT HUP INT TERM

printf 'internal service token is configured for %d env file(s)\n' "${#targets[@]}"
