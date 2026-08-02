#!/usr/bin/env bash
# Deploy opensamguk to a remote host
# Usage: ./scripts/deploy.sh [DEPLOY_HOST] [DEPLOY_USER]

set -euo pipefail

DEPLOY_HOST="${1:-${DEPLOY_HOST:-}}"
DEPLOY_USER="${2:-${DEPLOY_USER:-peppone_choi}}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/id_ed25519}"
COMPOSE_FILE="docker-compose.yml"

if [[ -z "$DEPLOY_HOST" ]]; then
    echo "Usage: $0 <DEPLOY_HOST> [DEPLOY_USER]"
    echo "   or: DEPLOY_HOST=... $0"
    exit 1
fi

echo "=== Deploying opensamguk to ${DEPLOY_USER}@${DEPLOY_HOST} ==="

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "${DEPLOY_USER}@${DEPLOY_HOST}" "mkdir -p ~/opensamguk/infra/nginx"

rsync -avz -e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new" \
    --exclude='.git' \
    "${COMPOSE_FILE}" \
    "${DEPLOY_USER}@${DEPLOY_HOST}:~/opensamguk/docker-compose.yml"
rsync -avz -e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new" \
    --exclude='.git' \
    "infra/nginx/nginx.conf" \
    "${DEPLOY_USER}@${DEPLOY_HOST}:~/opensamguk/infra/nginx/nginx.conf"

# Pull latest images and restart
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "${DEPLOY_USER}@${DEPLOY_HOST}" << 'REMOTE'
    set -euo pipefail
    cd ~/opensamguk

    # Load env if present
    if [[ -f .env ]]; then
        set -a
        source .env
        set +a
    fi

    echo "=== Pulling images ==="
    docker compose -f docker-compose.yml pull

    echo "=== Restarting services ==="
    # Restart non-engine services first
    docker compose -f docker-compose.yml up -d --no-deps \
        gateway-api game-api web-gateway web-game nginx

    # Brief pause for DB/redis readiness
    sleep 5

    # Restart engine last (it owns the in-memory turn state)
    docker compose -f docker-compose.yml up -d --no-deps game-engine

    # Prune old images (keep 7 days)
    docker image prune -af --filter "until=168h" || true

    echo "=== Deploy complete ==="
REMOTE

# --- Health check loop ---
echo "=== Health checks ==="
BASE_URL="http://${DEPLOY_HOST}"

# nginx health
for i in $(seq 1 30); do
    if curl -sf "${BASE_URL}/health" >/dev/null 2>&1; then
        echo "  nginx /health: OK"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "  nginx /health: FAILED after 30 attempts"
        exit 1
    fi
    sleep 5
done

# game-api actuator health
for i in $(seq 1 30); do
    RESP=$(curl -sf "${BASE_URL}/api/game/actuator/health" 2>/dev/null || echo '{"status":"DOWN"}')
    if echo "$RESP" | grep -q '"status":"UP"'; then
        echo "  game-api actuator: OK"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "  game-api actuator: FAILED — $RESP"
        exit 1
    fi
    sleep 5
done

# gateway-api actuator health
for i in $(seq 1 30); do
    RESP=$(curl -sf "${BASE_URL}/api/gateway/actuator/health" 2>/dev/null || echo '{"status":"DOWN"}')
    if echo "$RESP" | grep -q '"status":"UP"'; then
        echo "  gateway-api actuator: OK"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "  gateway-api actuator: FAILED — $RESP"
        exit 1
    fi
    sleep 5
done

# game-engine actuator (internal port, check via docker exec)
for i in $(seq 1 30); do
    RESP=$(ssh -i "$SSH_KEY" "${DEPLOY_USER}@${DEPLOY_HOST}" \
        "docker exec opensamguk-game-engine curl -sf http://localhost:8082/actuator/health 2>/dev/null || echo '{\"status\":\"DOWN\"}'" 2>/dev/null || echo '{"status":"DOWN"}')
    if echo "$RESP" | grep -q '"status":"UP"'; then
        echo "  game-engine actuator: OK"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "  game-engine actuator: FAILED — $RESP"
        exit 1
    fi
    sleep 5
done

# Custom health endpoint
for i in $(seq 1 10); do
    RESP=$(curl -sf "${BASE_URL}/api/game/health" 2>/dev/null || echo '{"status":"DOWN"}')
    if echo "$RESP" | grep -q '"status":"up"'; then
        echo "  /api/game/health: OK — $RESP"
        break
    fi
    if [[ $i -eq 10 ]]; then
        echo "  /api/game/health: FAILED — $RESP"
        exit 1
    fi
    sleep 3
done

echo "=== All health checks passed ==="
