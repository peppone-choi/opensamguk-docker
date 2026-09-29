#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

python3 - "$ROOT/.github/workflows/deploy-orchestration.yml" > "$TMP_ROOT/workflow.sh" <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
marker = "        run: |"
start = lines.index(marker) + 1
script = []
for line in lines[start:]:
    if not line:
        script.append("")
    elif line.startswith("          "):
        script.append(line[10:])
    else:
        break
print("\n".join(script))
PY

run_case() {
  local scenario="$1"
  local case_root="$TMP_ROOT/$scenario"
  local fake_bin="$case_root/bin"
  local stack="$case_root/home/opensamguk-docker"
  mkdir -p "$fake_bin" "$stack/servers"
  printf 'nonterminal-operation-store\n' > "$stack/servers/.deployer-operations.json"
  cp "$stack/servers/.deployer-operations.json" "$case_root/store.before"

  cat > "$fake_bin/flock" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  cat > "$fake_bin/sudo" <<'SH'
#!/usr/bin/env bash
exec "$@"
SH
  cat > "$fake_bin/timeout" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--foreground" ]]; then shift; fi
if [[ "${1:-}" == "-k" ]]; then shift 2; fi
shift
exec "$@"
SH
  cat > "$fake_bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$BOUNDARY_GIT_LOG"
if [[ "${1:-}" == "fetch" ]]; then
  : > "$BOUNDARY_GIT_REACHED"
  exit 77
fi
exit 0
SH
  cat > "$fake_bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$BOUNDARY_DOCKER_LOG"
if [[ "${1:-}" == "ps" ]]; then
  printf '%s\n' opensamguk-deployer
  exit 0
fi
if [[ "${1:-}" != "exec" ]]; then
  exit 90
fi
if [[ "$*" == *"/usr/local/bin/deployer"* ]]; then
  : > "$BOUNDARY_OLD_BINARY_CALLED"
  printf 'recovered-by-old-binary\n' >> "$BOUNDARY_STORE"
  if [[ "$*" == *"/maintenance/enter"* ]]; then
    printf '{"capability":"maintenance-v1","state":"drained","lease":"0123456789abcdef0123456789abcdef"}\n'
  else
    printf '{"capability":"maintenance-v1","state":"open"}\n'
  fi
  exit 0
fi
if [[ "$*" != *"python3 -c"* || "$*" != *"/maintenance/enter-if-idle"* ]]; then
  exit 91
fi
case "$BOUNDARY_SCENARIO" in
  idle)
    printf '{"capability":"maintenance-v1","state":"drained","lease":"0123456789abcdef0123456789abcdef"}\n'
    exit 0
    ;;
  busy)
    printf '{"error":"maintenance idle admission unavailable"}\n'
    exit 8
    ;;
  transport-error)
    printf '{"capability":"maintenance-v1","state":"drained","lease":"0123456789abcdef0123456789abcdef"}\n'
    exit 8
    ;;
  unavailable)
    printf '{"error":"not found"}\n'
    exit 8
    ;;
esac
exit 92
SH
  chmod +x "$fake_bin"/*

  : > "$case_root/docker.log"
  : > "$case_root/git.log"
  set +e
  HOME="$case_root/home" \
    PATH="$fake_bin:$PATH" \
    BOUNDARY_SCENARIO="$scenario" \
    BOUNDARY_DOCKER_LOG="$case_root/docker.log" \
    BOUNDARY_GIT_LOG="$case_root/git.log" \
    BOUNDARY_GIT_REACHED="$case_root/git.reached" \
    BOUNDARY_OLD_BINARY_CALLED="$case_root/old-binary.called" \
    BOUNDARY_STORE="$stack/servers/.deployer-operations.json" \
    bash "$TMP_ROOT/workflow.sh" > "$case_root/output.log" 2>&1
  local status=$?
  set -e

  if (( status == 0 )); then
    echo "$scenario: workflow unexpectedly completed beyond the admission boundary" >&2
    return 1
  fi
  if [[ -e "$case_root/old-binary.called" ]]; then
    echo "$scenario: pre-admission path invoked the installed deployer binary" >&2
    return 1
  fi
  if ! cmp -s "$case_root/store.before" "$stack/servers/.deployer-operations.json"; then
    echo "$scenario: pre-admission path changed the durable operation store" >&2
    return 1
  fi
  if grep -Eq 'compose .* (build|up).*deployer' "$case_root/docker.log"; then
    echo "$scenario: admission boundary reached deployer replacement" >&2
    return 1
  fi

  if [[ "$scenario" == idle ]]; then
    if [[ ! -e "$case_root/git.reached" ]]; then
      echo "idle: successful idle admission did not proceed to checkout" >&2
      return 1
    fi
  elif [[ -e "$case_root/git.reached" ]]; then
    echo "$scenario: failed idle admission proceeded to checkout" >&2
    return 1
  fi
}

run_case idle
run_case busy
run_case transport-error
run_case unavailable
echo "deploy orchestration idle-admission boundary: PASS"
