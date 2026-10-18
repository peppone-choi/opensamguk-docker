# 환경 변수

`.env`(공유 스택)와 `servers/s<id>.env`(게임 월드)의 변수 이름·용도·읽는 서비스입니다. **값은 적지 않습니다.**
예시 파일 [`.env.example`](../.env.example)·[`servers/s1.env.example`](../servers/s1.env.example)의 `CHANGE_ME`·`example.invalid`는 실행 가능한 값이 아닙니다.
「읽는 서비스」는 `origin/main` b39ebaf의 `docker-compose.shared.yml`·`docker-compose.server.yml` 치환식에서 뽑았습니다.

> **비밀값:** 실제 `.env`·`servers/*.env`는 `chmod 600`, 커밋 금지(`.gitignore`가 막음)입니다. 명령 인자·공개 로그·이슈에 붙이지 않습니다.
> 비밀 표시(🔒)가 붙은 변수는 특히 그렇습니다.

## 빌드 시점 값과 실행 시점 값

`NEXT_PUBLIC_*`와 웹 rewrite 대상(`GATEWAY_WEB_URL`, `ASSET_PREFIX`)은 **웹 이미지 빌드 인수**입니다. 빌드할 때 번들에 박힙니다.
`.env`에 적어도 이미 빌드한 웹 이미지는 바뀌지 않습니다. 현재 shared compose는 `.env`의 `NEXT_PUBLIC_GATEWAY_URL`·`NEXT_PUBLIC_IMAGE_CDN`을 읽지 않습니다.
빌드 명령은 [설치와 배포 §2](installation-and-deployment.md#2-앱-이미지-준비)에 있습니다.

## 공유 스택 `.env`

| 변수 | 용도 | 읽는 서비스 |
|---|---|---|
| `GHCR_REGISTRY`, `GHCR_OWNER`, `IMAGE_TAG` | 앱 이미지 위치와 태그(앱 Git SHA) | gateway-api, board-api, web-gateway (`GHCR_OWNER`는 deployer도) |
| `GHCR_TOKEN` 🔒 | private 패키지의 태그 목록 조회(`read:packages`). 비우면 private 패키지 태그 목록이 빈 배열 | deployer |
| `GATEWAY_POSTGRES_DB`, `GATEWAY_POSTGRES_USER`, `GATEWAY_POSTGRES_PASSWORD` 🔒 | 공유 DB(계정·게시판·서버 레지스트리) | gateway-postgres, gateway-api, board-api |
| `JWT_PRIVATE_KEY` 🔒 | RS256 PKCS#8 개인키. 발급 전용 | gateway-api만 |
| `JWT_PUBLIC_KEY` | 대응 공개키. 모든 게임 월드 env에도 **같은 값** | gateway-api, board-api |
| `JWT_SIGNING_MODE`, `JWT_INCLUDE_PROFILE_CLAIMS` | 서명 방식(RS256), 프로필 claim 포함 여부 | gateway-api |
| `JWT_ACCESS_EXPIRATION`, `JWT_REFRESH_EXPIRATION` | access·refresh 수명(ms) | gateway-api |
| `JWT_LEGACY_SECRET` 🔒, `JWT_LEGACY_ACCESS_ACCEPT_UNTIL`, `JWT_LEGACY_REFRESH_ACCEPT_UNTIL` | 옛 인증 이관 기간. 새 설치는 빈 값 | gateway-api, board-api(일부) |
| `INTERNAL_SERVICE_TOKEN` 🔒 | 서비스 간 내부 호출 토큰. 게임 월드 env와 같은 값 | gateway-api |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` 🔒 | 첫 관리자 계정 | gateway-api |
| `SERVER_REGISTRY_JSON` | **완전히 새 공유 DB**의 첫 부팅 때만 쓰는 서버 레지스트리 seed. 기존 DB에서는 덮어쓰지 않음 | gateway-api, web-gateway |
| `DEPLOYER_URL` | gateway-api가 부르는 deployer 주소 | gateway-api |
| `DEPLOYER_TOKEN` 🔒 | deployer 호출 권한 그 자체. 내부망 전용 | deployer, gateway-api |
| `COMPOSE_HOST_DIR` | **호스트의** 이 checkout 절대 경로(deployer 안의 `/workspace`가 아님). bind mount 기준 | deployer, nginx |
| `NGINX_HTTP_PORT`, `NGINX_HTTPS_PORT` | nginx가 publish할 호스트 포트. compose 기본값은 80·443, 예시 파일은 8080·8443 | nginx |
| `GATEWAY_API_URL`, `BOARD_API_URL` | web-gateway의 서버 측 프록시 대상(내부 DNS) | web-gateway |
| `NEXT_PUBLIC_GATEWAY_URL`, `NEXT_PUBLIC_IMAGE_CDN` | 웹 빌드 인수 메모. compose가 읽지 않음(위 「빌드 시점 값」) | 없음 |
| `COOKIE_SECURE` | 예시 파일에 있으나 현재 shared compose가 서비스로 넘기지 않음 | 없음 |

## 게임 월드 `servers/s<id>.env`

| 변수 | 용도 | 읽는 서비스 |
|---|---|---|
| `SERVER_ID` | 공개 서버 ID(ASCII 영숫자 최대 48자, 소문자 정규화). 컨테이너·볼륨 이름 `s<SERVER_ID>-*`, 프로젝트 `opensamguk-s<SERVER_ID>` | 전부 |
| `SERVER_NAME`, `SERVER_GENERATION` | 표시 이름, 세대(compose 기본 1, 예시 0) | game-api |
| `OPENSAMGUK_WORLD_ID` | 월드 ID. 각 월드가 독립 DB라 보통 1 | game-api, game-engine |
| `TOPDOWN_BAKE_ID` | 지도 bundle 핀. 비우면 웹이 지도 준비 상태 | game-api |
| `GHCR_REGISTRY`, `GHCR_OWNER`, `IMAGE_TAG` | game-api·engine 이미지 태그 | game-api, game-engine, web-game |
| `WEB_GAME_TAG` | web-game만 따로 고정하는 태그. 비우면 `IMAGE_TAG` | web-game |
| `GAME_API_PORT`, `WEB_GAME_PORT` | 호스트 publish 포트. 월드끼리 겹치면 안 됨 | game-api, web-game |
| `GAME_POSTGRES_DB`, `GAME_POSTGRES_USER`, `GAME_POSTGRES_PASSWORD` 🔒 | 월드 DB | game-postgres, game-api, game-engine |
| `GAME_POSTGRES_IMAGE`, `GAME_REDIS_IMAGE` | DB·Redis 이미지 덮어쓰기(예시에 없음, 기본 `postgres:16-alpine`·`redis:7-alpine`) | game-postgres, game-redis |
| `JWT_PUBLIC_KEY` | 공유 `.env`와 같은 공개키 | game-api |
| `JWT_LEGACY_SECRET` 🔒, `JWT_LEGACY_ACCESS_ACCEPT_UNTIL` | 옛 인증 이관. 새 설치는 빈 값 | game-api |
| `INTERNAL_SERVICE_TOKEN` 🔒 | 공유 `.env`와 같은 값 | game-api |
| `BATTLE_JOIN_TICKET_ENABLED`, `BATTLE_JOIN_TICKET_KEY_BASE64` 🔒, `BATTLE_WS_ALLOWED_ORIGINS` | 전투 입장 ticket·WebSocket Origin 허용 목록. 별도 승인 전 비활성(`false`, 빈 값) | game-api |
| `TURN_PROFILE_NAME` | 턴 프로필. 선택한 앱 이미지가 지원하는 값 | game-api, game-engine |
| `SCENARIO_SEED_ENABLED`, `SCENARIO_CODE` | 빈 월드의 시나리오 seed | game-engine |
| `SCENARIO_LOOKUP_DIR`, `SCENARIO_DIR` | 시나리오 조회 위치. `SCENARIO_LOOKUP_DIR=`(빈 값)은 이미지 내장 조회, 키가 없으면 `SCENARIO_DIR`(기본 `/data/scenarios`). **빈 값과 키 없음은 다릅니다** | game-api, game-engine |
| `RESET_TURNTERM`, `RESET_EXTEND`, `RESET_BLOCK_GENERAL_CREATE`, `RESET_NPCMODE`, `RESET_SHOW_IMG_LEVEL` | 초기화 때 월드 설정. `RESET_TURNTERM`은 **분** 단위 | game-engine |
| `RESET_MAXGENERAL`, `RESET_FIRST_TURN`, `RESET_FICTION` | 예시에 없는 초기화 설정(기본 빈 값). 앱 소비 범위는 선택한 앱 이미지로 확인 | game-engine |
| `GAME_API_URL`, `GATEWAY_API_URL` | web-game·game-api의 내부 DNS 대상 | web-game, game-api |

## 같은 값이어야 하는 짝

- `JWT_PUBLIC_KEY`: 공유 `.env`와 모든 월드 env.
- `INTERNAL_SERVICE_TOKEN`: 공유 `.env`와 모든 월드 env.
- `SERVER_ID`: env 파일 이름(`s<id>.env`), 레지스트리 `id`, 프로젝트 `opensamguk-s<id>`, 내부 DNS `s<id>-game-api`.

## localhost 격리 스택

하네스는 `.env`를 읽지 않습니다. 필요한 값은 `prepare`가 새로 만들어 비공개 custody에 둡니다. [localhost 격리 스택](localhost.md#custody와-비밀값)을 봅니다.
