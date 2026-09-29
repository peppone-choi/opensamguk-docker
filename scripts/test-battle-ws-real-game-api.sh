#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
product_dir="$tmp_dir/opensamguk"
ci_suffix="${GITHUB_RUN_ID:-local}-$$"
network="battle-ws-real-${ci_suffix}"
nginx="battle-ws-real-nginx-${ci_suffix}"
map_file="$repo_root/infra/nginx/runtime/battle-ws-allowlist.map"

cleanup() {
  docker rm -f "$nginx" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -f "$map_file"
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

# The PR ref is read at run time so CI always exercises the current product PR head.
git init -q "$product_dir"
git -C "$product_dir" fetch -q --depth=1 \
  https://github.com/peppone-choi/opensamguk.git pull/1024/head
git -C "$product_dir" checkout -q FETCH_HEAD
echo "Docker PR #59 checkout: $(git -C "$repo_root" rev-parse HEAD)"
echo "Product PR #1024 head: $(git -C "$product_dir" rev-parse HEAD)"
cp "$repo_root/scripts/real-game-api/BattleWebSocketCrossRepoIT.kt" \
  "$product_dir/app/game-api/src/test/kotlin/opensamguk/battlewebsockettest/"

mkdir -p "$tmp_dir/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$tmp_dir/certs/opensamguk.key" \
  -out "$tmp_dir/certs/opensamguk.crt" >/dev/null 2>&1
docker network create "$network" >/dev/null
gateway="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$network")"
printf 'pep http://%s:8081;\nother http://%s:8081;\n' "$gateway" "$gateway" > "$map_file"
docker run -d --name "$nginx" --network "$network" -p 127.0.0.1:18080:80 \
  --add-host gateway-api:127.0.0.1 --add-host web-gateway:127.0.0.1 \
  -v "$repo_root/infra/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$repo_root/infra/nginx/runtime:/etc/nginx/battle-ws:ro" \
  -v "$tmp_dir/certs:/etc/nginx/certs:ro" \
  nginx:1.27-alpine >/dev/null

for attempt in {1..30}; do
  if curl -fsS --max-time 1 http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 1
done
(
  cd "$product_dir"
  BATTLE_WS_MAP_FILE="$map_file" BATTLE_WS_NGINX_CONTAINER="$nginx" \
    ./gradlew --no-daemon :app:game-api:test \
      --tests 'opensamguk.battlewebsockettest.BattleWebSocketCrossRepoIT' --console=plain
)

python3 - "$product_dir/app/game-api/build/test-results/test/TEST-opensamguk.battlewebsockettest.BattleWebSocketCrossRepoIT.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

result = ET.parse(sys.argv[1]).getroot()
counts = {key: int(result.attrib.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
assert counts == {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}, counts
print("cross-repository test XML: 1 passed, 0 failed, 0 skipped")
PY

if docker logs "$nginx" 2>&1 | grep -q 'BTJ2\.'; then
  echo 'JoinTicket leaked into nginx logs' >&2
  exit 1
fi
echo 'real game-api through nginx cross-repository checks: PASS'
