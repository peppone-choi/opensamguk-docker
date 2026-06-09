# opensamguk-docker

**opensamguk** 배포(오케스트레이션) 저장소 — 소스 없이 GHCR에 게시된 이미지로 전체 스택을 띄운다.
(devsam의 [devsam/docker](https://storage.hided.net/gitea/devsam/docker)에 대응하는 위치.)

소스/게임 로직: **[peppone-choi/opensamguk](https://github.com/peppone-choi/opensamguk)** (코프링/Spring + Next.js, 메모리-중심 CQRS).
이미지 자산: **[peppone-choi/opensamguk-images](https://github.com/peppone-choi/opensamguk-images)** (jsDelivr CDN).
원작(grand truth) · 라이선스: HideD님의 **[devsam](https://storage.hided.net/gitea/devsam)** (MIT).

---

## 구성

```
docker-compose.shared.yml   # 공유 스택: gateway-postgres·gateway-api·web-gateway·nginx·deployer·socket-proxy
docker-compose.server.yml   # 게임 서버 스택(서버당 1회): game-postgres·game-redis·game-engine·game-api·web-game
docker-compose.yml          # 로컬/단일서버 빠른 시작(8서비스 단일 스택). 멀티서버를 안 쓸 때만.
deployer/                   # 버전 bounce 배포 사이드카(Go stdlib, 외부 의존 0)
infra/nginx/nginx.conf      # 리버스 프록시(게이트웨이 / 진입점)
servers/s1.env.example      # 게임 서버 env 예시(서버마다 복제)
.env.example                # 공유 스택 env 예시(.env로 복사)
scripts/deploy.sh           # (단일서버) 서버 배포 헬퍼
```

앱 이미지는 `ghcr.io/${GHCR_OWNER}/{game-engine,game-api,gateway-api,web-gateway,web-game}:${IMAGE_TAG}`
에서 받아온다. 이미지 빌드·푸시는 소스 저장소(opensamguk)의 CI가 담당한다.

---

## 아키텍처 (멀티서버)

```
                ┌──────────── 공유 스택 (opensamguk-shared) ────────────┐
   브라우저 ──▶ nginx(/) ─▶ web-gateway ─▶ gateway-api ─▶ gateway-postgres(유저/인증)
                                              │  └─▶ deployer ─▶ socket-proxy ─▶ docker
                └────────────────────────────┼───────────────────────────────────┘
                                              │ (레지스트리·로비 절대 URL)
        ┌──────────── 서버 s1 (opensamguk-s1) ─┴─┐   ┌──── 서버 s2 (opensamguk-s2) ────┐
        │ web-game ─▶ game-api ─▶ game-postgres │   │ web-game ─▶ game-api ─▶ game-pg │
        │              game-engine ─▶ game-redis │   │   game-engine ─▶ game-redis     │
        │              (IMAGE_TAG = v1.2.0)      │   │   (IMAGE_TAG = v1.3.0)          │
        └────────────────────────────────────────┘   └─────────────────────────────────┘
                       └────────── 외부 네트워크 opensamguk-net ──────────┘
```

- **서버별 독립 스택**: 게임 서버마다 자기 `game-engine`(그 월드 InMemoryTurnWorld) + `game-api`
  + `game-postgres` + `game-redis` + 자기 `IMAGE_TAG`. 서버끼리 월드/버전이 완전히 격리된다.
- **공유 스택**: `gateway-postgres`(유저/인증) + `gateway-api` + `web-gateway` + `nginx`
  + `deployer` 사이드카 + `socket-proxy`. 전 서버 공통(로그인/로비/어드민/배포).
- **로비 진입**: nginx는 게이트웨이(`/`)만 프록시한다. 게임 진입은 **서버별 절대 URL**
  (로비 `servers.json` / `SERVER_REGISTRY_JSON`)이 담당 — 서버별 web-game/game-api 호스트 포트로 직접.
  (서버별 동적 라우팅을 nginx에 만들지 않는다 — 단순/명료 유지.)

### least-privilege 배포 경로

- 앱(gateway-api)은 `docker.sock`에 **직접 접근하지 않는다.** docker 접근은 `deployer`만,
  그것도 `socket-proxy`를 거쳐 **compose에 필요한 최소 API**(CONTAINERS/SERVICES/IMAGES/POST 등)만.
- `gateway-api → deployer`는 내부망 + Bearer 토큰(`DEPLOYER_TOKEN`). 외부 노출 없음.
- `socket-proxy`는 `docker.sock`을 **read-only**로 마운트하고 위험 섹션(EXEC/BUILD/SWARM/SECRETS/SYSTEM …)을
  거부. (컨테이너 생성/정지/삭제는 compose 재생성에 필수라 `CONTAINERS`+`POST`로 허용 — 엔진 보호는
  socket-proxy가 아니라 deployer 코드의 스테이트리스 화이트리스트가 담당.)

---

## 멀티서버 운영

### 0) 외부 네트워크 1회 생성

공유 스택과 모든 게임 서버가 같은 네트워크에서 통신한다. **최초 1회만:**

```bash
docker network create opensamguk-net
```

### 1) 공유 스택 기동

```bash
cp .env.example .env     # 값 채우기: GATEWAY_POSTGRES_PASSWORD, JWT_SECRET, ADMIN_*, DEPLOYER_TOKEN,
                         #            SERVER_REGISTRY_JSON(서버 표) 등
docker compose -p opensamguk-shared -f docker-compose.shared.yml --env-file .env up -d
```

- 브라우저: `http://<호스트>/` (nginx 경유 게이트웨이/로비/어드민)
- 관리자: 빈 DB 첫 부팅 시 `ADMIN_USERNAME`/`ADMIN_PASSWORD`로 1회 시드(멱등).

### 2) 게임 서버 N회 기동

서버마다 `servers/<id>.env`를 만들고(예시 복제) 포트/비밀번호/`SERVER_ID`가 겹치지 않게 한다.

```bash
cp servers/s1.env.example servers/s1.env    # SERVER_ID=1 (접두 s 없이 — compose가 s${SERVER_ID}로 합성),
                                            # IMAGE_TAG, GAME_API_PORT/WEB_GAME_PORT,
                                            # GAME_POSTGRES_PASSWORD, JWT_SECRET(공유와 동일) 채우기
docker compose -p opensamguk-s1 -f docker-compose.server.yml --env-file servers/s1.env up -d

# 서버 2개째 — s2.env 복제(SERVER_ID=2, 포트 82xx/32xx 등 충돌 없게)
cp servers/s1.env.example servers/s2.env    # 편집 후 (파일명은 s2.env, 내부 SERVER_ID=2)
docker compose -p opensamguk-s2 -f docker-compose.server.yml --env-file servers/s2.env up -d
```

기동 후 공유 스택의 `SERVER_REGISTRY_JSON`에 그 서버를 등록한다(로비/어드민이 인식하도록):

```json
[
  {"id":"s1","name":"통일 서버","gameApiUrl":"http://s1-game-api:8081","gameEngineUrl":"http://s1-game-engine:8082","deployProject":"opensamguk-s1"},
  {"id":"s2","name":"군웅 서버","gameApiUrl":"http://s2-game-api:8081","gameEngineUrl":"http://s2-game-engine:8082","deployProject":"opensamguk-s2"}
]
```

> `gameApiUrl`/`gameEngineUrl` 호스트명은 그 서버 컨테이너 이름(`s<id>-game-api` 등)과 **반드시 일치**.
> `deployProject`는 그 서버 compose 프로젝트명(`opensamguk-s<id>`) — deployer가 이 값으로 bounce 대상을 찾는다.

---

## 서버별 버전 고정 (중요)

각 서버는 **독립적으로 버전을 고정**한다 — 서버마다 `servers/<id>.env`의 `IMAGE_TAG`가 다를 수 있다.

- 서버 A는 `IMAGE_TAG=v1.2.0`, 서버 B는 `IMAGE_TAG=v1.3.0` 식으로 **동시에 서로 다른 버전** 운영 가능.
- 새 릴리스(새 이미지 태그)가 나와도 **진행 중인 서버에 자동 적용되지 않는다.** 운영자가 그 서버의
  버전을 명시적으로 바꿔 bounce 해야만 갱신된다.
- 이는 의도된 설계다: 게임은 턴을 연속 진행하므로(패러티 = byte-단위 일치), **진행 중에 로직/수정치가
  갑자기 바뀌면 RNG·로그가 desync**된다.
- ⚠️ `latest`는 가변 태그다. 진행 중 서버는 반드시 **불변 버전 태그**(`vX.Y.Z` 또는 커밋 SHA)로 고정할 것.

### bounce 업데이트 절차

업데이트 = **bounce**(stop → 이미지 교체 → start). 두 가지 경로가 있다.

**(A) 어드민 UI / deployer (권장)** — gateway-api 어드민 버전 패널이 `deployer`에 위임:

1. 어드민이 서버 + 새 태그 선택 → gateway-api가 `DEPLOYER_TOKEN`으로 `POST deployer/deploy` 호출.
2. deployer가 `servers/<id>.env`의 `IMAGE_TAG`를 치환.
3. deployer가 그 프로젝트의 **스테이트리스만**(`game-api`, `web-game`) `pull` 후 `up -d --no-deps` 으로 교체.
4. **`game-engine`은 건드리지 않는다** — 진행 중 월드 desync 방지. (엔진 버전 변경은 아래 수동 절차.)

```
GET  deployer/status?project=opensamguk-s1   → {"currentTag":"v1.2.0","availableTags":[...]}
POST deployer/deploy  {"project":"opensamguk-s1","tag":"v1.3.0"}
```

환경변수 관리 API도 같은 Bearer 토큰 인증을 사용한다. 임의 raw editor가 아니라 명시 allowlist만 수정한다.
`DEPLOYER_TOKEN`은 서버 내부 권한 토큰이므로 API 수정 대상에서 제외한다. `JWT_SECRET`, `ADMIN_PASSWORD`,
`GHCR_TOKEN` 같은 민감값은 PATCH로만 쓰고 GET/PATCH 응답에는 원문 값을 반환하지 않는다.

```text
GET   deployer/env/shared
PATCH deployer/env/shared {"values":{"NEXT_PUBLIC_GATEWAY_URL":"https://sam.example.com"}}

GET   deployer/env/server?id=s1
PATCH deployer/env/server?id=s1 {"values":{"IMAGE_TAG":"v1.3.0","JWT_SECRET":"base64-secret"}}
```

PATCH 응답의 `restartRequired`와 `affectedServices`는 재기동이 필요한 대상을 알려준다. 서버별 env 변경의
대상은 스테이트리스(`game-api`, `web-game`)뿐이며 `game-engine`은 포함하지 않는다.

**(B) 수동 (시즌 경계 / 엔진 포함 전체 갱신)** — 엔진까지 새 버전으로 올릴 때:

```bash
# 그 서버 env의 IMAGE_TAG 교체
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=v1.3.0/' servers/s1.env
# 전체 pull
docker compose -p opensamguk-s1 -f docker-compose.server.yml --env-file servers/s1.env pull
# 엔진 포함 재기동 — 엔진은 부팅 시 DB→InMemory 재수화로 무손실
docker compose -p opensamguk-s1 -f docker-compose.server.yml --env-file servers/s1.env up -d
```

> **무손실 보장**: game-engine은 부팅 시 `world_state`(DB)에서 `InMemoryTurnWorld`를 재수화한다.
> 따라서 엔진 컨테이너를 새 이미지로 교체해도(같은 버전 로직이면) 진행 상태를 잃지 않는다.
> 단, **로직이 바뀌는 버전 점프는 RNG/로그 desync**를 일으키므로 **시즌 종료/서버 리셋 시점**에만 적용한다.

### Deployer env API 수동 QA

로컬 임시 파일로 C001/C002 성격의 동작을 확인할 수 있다.

```bash
tmp=$(mktemp -d)
mkdir -p "$tmp/servers"
cp .env.example "$tmp/.env"
cp servers/s1.env.example "$tmp/servers/s1.env"

DEPLOYER_TOKEN=test-token \
COMPOSE_DIR="$tmp" \
SERVERS_DIR="$tmp/servers" \
COMPOSE_SERVER_FILE="$PWD/docker-compose.server.yml" \
(cd deployer && go run .)

curl -sS -H 'Authorization: Bearer test-token' \
  'http://localhost:9000/env/server?id=s1'

curl -sS -X PATCH -H 'Authorization: Bearer test-token' -H 'Content-Type: application/json' \
  -d '{"values":{"IMAGE_TAG":"v1.3.0","JWT_SECRET":"new-secret"}}' \
  'http://localhost:9000/env/server?id=s1'

curl -sS -X PATCH -H 'Authorization: Bearer test-token' -H 'Content-Type: application/json' \
  -d '{"values":{"DEPLOYER_TOKEN":"must-not-write"}}' \
  'http://localhost:9000/env/shared'
```

기대값: 첫 두 호출은 200, `JWT_SECRET` 원문은 응답에 없음, `affectedServices`에 `game-engine` 없음,
마지막 호출은 400이며 `DEPLOYER_TOKEN`은 파일에 쓰이지 않음.

### 버전 고정 / 다운그레이드

- **고정**: `IMAGE_TAG`를 불변 태그로 두고 손대지 않으면 그 버전에 머문다(`latest` 금지).
- **다운그레이드**: deployer/수동으로 이전 태그를 지정하면 스테이트리스는 즉시 롤백된다.
  엔진 다운그레이드는 (B) 절차 — 단 이전 로직과 현재 DB 스키마/상태가 호환될 때만 안전.

---

## 단일서버 / 로컬 빠른 시작 (멀티서버 미사용)

멀티서버가 필요 없으면 기존 단일 스택(`docker-compose.yml`)을 그대로 쓴다 — 8서비스 한 프로젝트.

```bash
cp .env.example .env     # (단일 스택은 POSTGRES_PASSWORD 등 기존 키도 필요 — 주석 참고)
docker compose pull
docker compose up -d
```

- 게임 프론트: `http://<호스트>:3001/game`
- `docker-compose.yml`(단일)과 `docker-compose.shared.yml`+`docker-compose.server.yml`(멀티)는
  **상호 배타적**이다 — 같은 호스트에서 동시에 같은 포트로 띄우지 말 것.

---

## HTTPS 배포 주의

- `COOKIE_SECURE=true`는 **HTTPS에서만** — HTTP면 로그인 쿠키가 막힌다(로컬/HTTP는 `false`).
- `NEXT_PUBLIC_GATEWAY_URL` / `NEXT_PUBLIC_GAME_URL`을 실제 도메인으로 교체(빌드타임 인라인).
- `JWT_SECRET`은 gateway-api(발급)·모든 game-api(검증)가 **동일** 값을 써야 한다.
- `DEPLOYER_TOKEN`은 강한 랜덤 값으로 — 이 토큰이 곧 배포 권한이다. 외부 노출 금지(내부망 전용).

## GHCR 이미지 인증 (private 패키지일 때)

이미지 `pull`은 **공개(public) GHCR 패키지면 인증이 필요 없다**(권장 — 비밀 0 배포 유지).
패키지를 **private**로 두면 pull/태그조회 양쪽에 인증이 필요하다:

- **수동/부팅 pull**: 호스트에서 `docker login ghcr.io`(PAT, `read:packages`) — `compose pull`이 그 자격을 쓴다.
- **deployer의 bounce pull**: deployer 컨테이너 안 docker CLI가 pull을 호출하므로, 그 컨테이너에 자격이
  있어야 한다 — `~/.docker/config.json`을 deployer에 마운트하거나(공유 compose에 추가) 패키지를 공개로 둘 것.
- **deployer의 `availableTags` 조회**: `GHCR_TOKEN`(read:packages) env 없으면 private 패키지는 빈 배열을
  돌려준다(상태 조회 자체는 막지 않음 — 현재 태그는 env 파일에서 읽으므로 항상 표시된다).

## 대상 환경

AWS EC2 **t3.large**(2 vCPU / 8 GiB) 기준(단일서버). LLM·외부 API 의존 0개.
멀티서버는 서버 수에 비례해 메모리/CPU가 필요하다(서버당 엔진 ~2G + DB ~1.5G).

---

> 이미지·로직의 단일 출처는 소스 저장소다. 이 저장소는 오케스트레이션(compose/nginx/env)만 둔다.
