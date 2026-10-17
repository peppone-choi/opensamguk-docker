#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
ci_suffix="${GITHUB_RUN_ID:-local}-$$"
network="battle-ws-ci-${ci_suffix}"
fixture="battle-ws-fixture-${ci_suffix}"
unregistered="battle-ws-unregistered-${ci_suffix}"
nginx="battle-ws-nginx-${ci_suffix}"
tmp_dir="$(mktemp -d)"
map_file="$repo_root/infra/nginx/runtime/battle-ws-allowlist.map"

cleanup() {
  docker rm -f "$nginx" "$fixture" "$unregistered" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -f "$map_file"
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$tmp_dir/certs/opensamguk.key" \
  -out "$tmp_dir/certs/opensamguk.crt" >/dev/null 2>&1
printf 'pep http://spep-game-api:8081;\n' > "$map_file"
docker network create "$network" >/dev/null
docker run -d --name "$fixture" --network "$network" --network-alias spep-game-api \
  -v "$repo_root/scripts/battle-ws-proxy-fixture.py:/fixture.py:ro" \
  python:3.12-alpine python /fixture.py >/dev/null
# A matching Docker DNS name must not become routable without a registry map entry.
docker run -d --name "$unregistered" --network "$network" --network-alias stest-game-api \
  -v "$repo_root/scripts/battle-ws-proxy-fixture.py:/fixture.py:ro" \
  python:3.12-alpine python /fixture.py >/dev/null
for target in "$fixture" "$unregistered"; do
  ready=0
  for attempt in {1..30}; do
    if docker exec "$target" python -c 'import socket; socket.create_connection(("127.0.0.1", 8081), 1).close()' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if (( ready == 0 )); then
    echo 'battle WS fixture did not become ready' >&2
    exit 1
  fi
done
docker run -d --name "$nginx" --network "$network" -p 127.0.0.1:18080:80 \
  --add-host gateway-api:127.0.0.1 --add-host web-gateway:127.0.0.1 \
  -v "$repo_root/infra/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$repo_root/infra/nginx/runtime:/etc/nginx/battle-ws:ro" \
  -v "$tmp_dir/certs:/etc/nginx/certs:ro" \
  nginx:1.27-alpine >/dev/null

for attempt in {1..30}; do
  if curl -fsS --max-time 1 http://127.0.0.1:18080/health >/dev/null; then break; fi
  sleep 1
done

python3 - <<'PY'
import socket

token = "BTJ2.abc." + "A" * 43

def probe(path, *, origin="https://game.example", ticket=token,
          extra="", expected="101", expects_protocol=False):
    request = (
        f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Protocol: battle.v1, {ticket}\r\n"
        f"Origin: {origin}\r\n{extra}\r\n"
    )
    with socket.create_connection(("127.0.0.1", 18080), timeout=5) as conn:
        conn.sendall(request.encode("ascii"))
        conn.settimeout(5)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
    headers = response.decode("latin1")
    assert headers.startswith("HTTP/1.1 " + expected), (path, headers)
    assert token not in headers, headers
    if expects_protocol:
        assert "Sec-WebSocket-Protocol: battle.v1\r\n" in headers, headers
    return headers

probe("/api/battle-ws/pep/1/battle-1?lastSeenEventSeq=19", expects_protocol=True)
probe("/api/battle-ws/pep/1/battle-1", extra="Authorization: Bearer long\r\nCookie: sam_access=long\r\nProxy-Authorization: Basic long\r\n", expects_protocol=True)
probe("/api/battle-ws/pep/1/battle-1", origin="https://other.example", expected="403")
probe("/api/battle-ws/pep/1/battle-1", ticket="BTJ2.invalid." + "A" * 43, expected="403")
probe("/api/battle-ws/test/1/battle-1", expected="404")
probe("/api/battle-ws/pep/1/../battle-1", expected="404")
print("battle WS proxy Upgrade/negative checks: PASS")
PY

# Simulate deletion: an empty map plus a validated reload must revoke admission.
: > "$map_file"
docker exec "$nginx" nginx -t >/dev/null
docker exec "$nginx" nginx -s reload >/dev/null
python3 - <<'PY'
import socket
import time

request = (
    "GET /api/battle-ws/pep/1/battle-1 HTTP/1.1\r\nHost: localhost\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Protocol: battle.v1, BTJ2.abc." + "A" * 43 + "\r\n"
    "Origin: https://game.example\r\n\r\n"
).encode("ascii")
deadline = time.monotonic() + 5
while True:
    with socket.create_connection(("127.0.0.1", 18080), timeout=5) as conn:
        conn.sendall(request)
        response = conn.recv(1024)
    if response.startswith(b"HTTP/1.1 404"):
        break
    assert response.startswith(b"HTTP/1.1 101"), response
    if time.monotonic() >= deadline:
        raise AssertionError("nginx reload did not revoke the deleted server within 5s")
    time.sleep(0.1)
print("battle WS proxy deletion revoke: PASS")
PY

if docker logs "$nginx" 2>&1 | grep -F 'BTJ2.abc.'; then
  echo 'JoinTicket leaked into nginx logs' >&2
  exit 1
fi
echo 'battle WS proxy log redaction: PASS'
