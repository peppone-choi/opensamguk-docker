# opensamguk-docker

**opensamguk** 배포(오케스트레이션) 저장소 — 소스 없이 GHCR에 게시된 이미지로 전체 스택을 띄운다.
(devsam의 [devsam/docker](https://storage.hided.net/gitea/devsam/docker)에 대응하는 위치.)

소스/게임 로직: **[peppone-choi/opensamguk](https://github.com/peppone-choi/opensamguk)** (코프링/Spring + Next.js, 메모리-중심 CQRS).
이미지 자산: **[peppone-choi/opensamguk-images](https://github.com/peppone-choi/opensamguk-images)** (jsDelivr CDN).
원작(grand truth) · 라이선스: HideD님의 **[devsam](https://storage.hided.net/gitea/devsam)** (MIT).

---

## 구성

```
docker-compose.yml      # 8서비스: postgres·redis·game-engine·game-api·gateway-api·web-gateway·web-game·nginx
infra/nginx/nginx.conf  # 리버스 프록시 (게이트웨이/게임 라우팅)
scripts/deploy.sh       # 서버 배포 헬퍼 (pull → up -d → 헬스체크)
.env.example            # 배포 환경변수 예시 (.env로 복사해 사용)
```

앱 이미지는 `ghcr.io/${GHCR_OWNER}/{game-engine,game-api,gateway-api,web-gateway,web-game}:${IMAGE_TAG}`
에서 받아온다. 이미지 빌드·푸시는 소스 저장소(opensamguk)의 CI가 담당한다.

## 빠른 시작

```bash
git clone https://github.com/peppone-choi/opensamguk-docker.git
cd opensamguk-docker
cp .env.example .env          # 값 채우기: JWT_SECRET, POSTGRES_PASSWORD, ADMIN_*, 도메인 등
docker compose pull
docker compose up -d
```

- 브라우저: `http://<호스트>/` (nginx 경유 게이트웨이) · 게임 프론트 `http://<호스트>:3001/game`
- 관리자: 빈 DB 첫 부팅 시 `ADMIN_USERNAME`/`ADMIN_PASSWORD`로 1회 시드(멱등).
- 시나리오 시드: `world_state`가 비어 있으면 game-engine이 부팅 시 1회 시드(`SCENARIO_SEED_ENABLED`).

## HTTPS 배포 주의

- `COOKIE_SECURE=true`는 **HTTPS에서만** — HTTP면 로그인 쿠키가 막힌다(로컬/HTTP는 `false`).
- `NEXT_PUBLIC_GATEWAY_URL` / `NEXT_PUBLIC_GAME_URL`을 실제 도메인으로 교체(빌드타임 인라인).
- `JWT_SECRET`은 gateway-api(발급)·game-api(검증)가 **동일** 값을 써야 한다.

## 대상 환경

AWS EC2 **t3.large**(2 vCPU / 8 GiB) 기준. LLM·외부 API 의존 0개.

---

> 이미지·로직의 단일 출처는 소스 저장소다. 이 저장소는 오케스트레이션(compose/nginx/env)만 둔다.
