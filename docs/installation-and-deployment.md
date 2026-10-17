# 설치와 배포

이 안내는 Linux 호스트에 공유 스택과 게임 월드 하나를 새로 설치하는 경로입니다.
예시는 `demo`, `CHANGE_ME`, `example.invalid`만 사용합니다. 실제 배포 전에 설치자가
자신의 도메인·키·비밀번호·이미지 핀으로 교체합니다. 코드·자산의 배포 범위는 [NOTICE](../NOTICE)를 확인합니다.

## 요건과 사양

| 항목 | 현재 소스에서 확인되는 요건 / 근거 |
|---|---|
| OS·CPU | Linux x86-64 대상. 배포 workflow는 Linux/X64 runner, Deployer 이미지는 Linux 컨테이너를 사용합니다. macOS·Windows·ARM 설치 합격 근거는 이 안내에 없습니다. |
| Docker | Engine/CLI와 `docker compose` plugin. `docker-compose` v1 대신 plugin 명령을 사용합니다. Deployer Dockerfile은 `docker:27-cli`, Compose plugin 포함 런타임입니다. 호스트 Engine의 정확한 최소 버전은 호환 시험 전 미확정입니다. |
| 저장소·도구 | Git, Bash, OpenSSL, `tar`, SHA-256 도구, 호스트에서 Docker를 관리할 권한. 이미지 자체 빌드 때만 앱 소스와 추가 빌드 공간이 필요합니다. |
| DB·웹 | Compose가 PostgreSQL 16, Redis 7, nginx 1.27, socket-proxy 0.3.0을 선택합니다. DB를 별도 호스트로 옮기는 절차는 여기서 검증하지 않았습니다. |
| 앱 빌드 | 앱 Dockerfile: Gradle 8.12/JDK 21, Node 22/pnpm 10.33.0. Deployer: Go 1.23. 컨테이너 빌드에서는 도구를 Dockerfile이 준비합니다. |
| CPU·RAM 최소 | 부하 시험으로 확정한 최소 사양 없음. 과거 `docker-compose.yml`의 2 vCPU/8 GiB 표기는 단일 스택 설정 메모이며 멀티서버 최소 사양 증거가 아닙니다. |
| RAM 설정 한도 | shared: PostgreSQL 512M, Redis 150M, API 두 개 각512M, web 256M, nginx/deployer 각128M, socket-proxy 64M. 게임 월드당: PostgreSQL 1.5G, Redis 300M, engine 2G, API 1.5G, web 256M. [shared](../docker-compose.shared.yml)·[server](../docker-compose.server.yml)의 한도이며 실제 소비량 측정값이 아닙니다. |
| 권장 사양·디스크 | 확정된 권장 부하 사양 없음. 선택한 월드/동시 사용자로 CPU·RAM·턴 지연·DB 증가량을 측정해 여유를 잡습니다. 디스크에는 현재/원복 이미지, DB·Redis, 검증한 백업 7일분, 빌드 임시 공간을 각각 예산에 넣습니다. 고정 GB 수치를 용량 보증으로 쓰지 않습니다. |

Compose plugin 설치는 [Docker 공식 Linux 안내](https://docs.docker.com/compose/install/linux/)를 따릅니다.
설치 후 `docker version`과 `docker compose version`으로 실제 버전을 기록합니다.

## 1. 저장소와 호환 버전 선택

배포 저장소와 앱의 검증된 릴리스/커밋을 선택합니다. 앱의 API·엔진·웹 이미지에는 같은 앱 SHA를 사용합니다.
이미지 digest와 DB migration/명령·저장 형식 호환성을 릴리스 기록으로 대조합니다.

```bash
set -euo pipefail
git clone https://github.com/peppone-choi/opensamguk-docker.git
cd opensamguk-docker
# 선택한 배포 릴리스/커밋으로 checkout한 뒤 아래 절차를 진행합니다.
cp .env.example .env
cp servers/s1.env.example servers/sdemo.env
chmod 600 .env servers/sdemo.env
mkdir -p data/scenarios infra/nginx/certs
```

`SERVER_ID=demo`는 공개 id이고 내부 Docker key는 `sdemo`, 프로젝트는 `opensamguk-sdemo`입니다.
raw id는 ASCII 영숫자 최대48자이며 제어면에서 소문자로 정규화합니다. 게임 화면의 예약 경로 id는
사용할 수 없습니다. env 파일명·SERVER_ID·레지스트리·프로젝트/DNS를 같은 규칙으로 맞춥니다.
각 게임 월드는 독립 DB이므로 `OPENSAMGUK_WORLD_ID=1`이고 `SERVER_GENERATION=0`도 허용됩니다.

## 2. 앱 이미지 준비

공개 릴리스가 이미지 reference·SHA·digest를 제공하면 그 정확한 값과 공개 접근 가능 여부를 확인해 사용합니다.
예시의 registry owner나 `latest`를 그대로 사용하지 않습니다. 현재 배포 저장소는 앱 이미지를 직접 만들지 않습니다.
공개 이미지가 없거나 자체 도메인/자산 설정이 필요하면 앱 소스에서 같은 SHA로 빌드합니다.

```bash
set -euo pipefail
# 별도 빌드 머신에서 실행합니다. APP_SHA는 검증된 앱의 40자 Git SHA입니다.
git clone https://github.com/peppone-choi/opensamguk.git
cd opensamguk
APP_SHA=CHANGE_ME_40_HEX_APP_SHA
IMAGE_NAMESPACE=CHANGE_ME_IMAGE_NAMESPACE
IMAGE_REPOSITORY="ghcr.io/${IMAGE_NAMESPACE}/opensamguk"
git checkout --detach "$APP_SHA"
for service in gateway-api board-api game-api game-engine; do
  docker build -f "docker/${service}.Dockerfile" --build-arg IMAGE_TAG="$APP_SHA" \
    -t "${IMAGE_REPOSITORY}:${service}-${APP_SHA}" .
done
docker build -f docker/web-gateway.Dockerfile \
  --build-arg NEXT_PUBLIC_GAME_URL=https://game.example.invalid/game/demo \
  -t "${IMAGE_REPOSITORY}:web-gateway-${APP_SHA}" .
docker build -f docker/web-game.Dockerfile \
  --build-arg NEXT_PUBLIC_GATEWAY_URL=https://game.example.invalid \
  --build-arg GATEWAY_WEB_URL=http://web-gateway:3000 --build-arg ASSET_PREFIX=/game \
  -t "${IMAGE_REPOSITORY}:web-game-${APP_SHA}" .
```

위 URL은 가짜이므로 실제 빌드 전에 교체합니다. `NEXT_PUBLIC_*`와 웹 rewrite 설정은 빌드 때 정해지며
서버의 env만 바꿔 이미 빌드한 프런트를 고칠 수 없습니다. 빌드·등록·사용 권한이 있는 자산만 이미지에 포함합니다.
빌드 머신과 설치 머신이 다르면 자신의 registry에 이미지를 push하고 설치 머신에서 인증/pull합니다.
Docker 로그인은 `--password-stdin`을 사용하고 토큰을 명령 인자·Git·공개 로그에 넣지 않습니다.

## 3. 설정과 키

소스의 변수 이름으로 만든 예시에서 모든 `CHANGE_ME`를 교체합니다.

- `.env`: `GHCR_OWNER`, `IMAGE_TAG`, 공유 DB 비밀번호, 관리자 이름/비밀번호,
  `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`, `INTERNAL_SERVICE_TOKEN`, `DEPLOYER_TOKEN`, `COMPOSE_HOST_DIR`.
- `servers/sdemo.env`: 같은 이미지 owner/SHA·JWT 공개키·internal token, 별도 게임 DB 비밀번호,
  충돌 없는 숫자 `GAME_API_PORT`/`WEB_GAME_PORT`, 지원 profile/scenario, 서버 이름·세대.
- `COMPOSE_HOST_DIR`는 **호스트의 절대 checkout 경로**입니다. Deployer 안의 `/workspace`가 아닙니다.
- JWT는 RS256 PKCS#8 개인키와 대응 공개키입니다. 보안 저장 경로에서 `openssl genpkey -algorithm RSA
  -pkeyopt rsa_keygen_bits:2048` 및 `openssl pkey -pubout`으로 생성합니다. PEM의 줄바꿈은 env 단일
  값에서 `\n`으로 표현하고 개인키를 게임 API/board-api에 복사하지 않습니다.
- legacy JWT 키/기한은 새 설치에서 빈 값입니다. 기존 서버 업그레이드 때는 기존 인증 이관 계약을 먼저 확인합니다.

`SCENARIO_CODE`/`TURN_PROFILE_NAME`은 선택한 앱 이미지의 지원 목록에서 고릅니다.
`SCENARIO_LOOKUP_DIR=`는 내장 조회, `/data/scenarios`는 외부 조회입니다. 비어 있는 값과 키 부재는 다릅니다.
외부 조회는 선택된 파일의 바이트 SHA·시나리오/지도 계약까지 확인합니다. 오래된 외부 파일을 자동 재사용하지 않습니다.
외부 파일이 없을 때의 resolver 동작은 앱 소스 기준으로 확인하며, 기대 파일 누락을 성공으로 간주하지 않습니다.

### 새 DB의 레지스트리

수동 Compose는 DB의 서버 membership을 추가하지 않습니다. **공유 DB가 완전히 새것일 때만**
첫 gateway 부팅 전에 `.env`의 `SERVER_REGISTRY_JSON`에 준비한 서버를 등록할 수 있습니다.
예시는 한 줄 JSON으로 넣습니다.

```json
[{"id":"demo","name":"Demo World","generation":0,"gameApiUrl":"http://sdemo-game-api:8081","gameEngineUrl":"http://sdemo-game-engine:8082","deployProject":"opensamguk-sdemo"}]
```

기존 DB에서는 이 seed 값을 덮어 membership을 바꾸지 않습니다. V62 이후 seed 완료 상태가 DB에 기록됩니다.
운영 중 추가/삭제는 어드민→Deployer의 확인된 수명주기와 DB registry 경로를 사용합니다.
새 설치를 공유 스택만으로 시작할 때는 `[]`를 유지한 뒤 그 경로로 게임 서버를 만듭니다.

## 4. TLS·네트워크·기동

nginx는 `infra/nginx/certs/opensamguk.crt`와 `opensamguk.key`를 마운트합니다.
실제 도메인의 인증서/개인키를 준비하고 개인키는 제한된 권한으로 저장합니다. nginx의 `/health`는
nginx 자체 확인이며 전체 앱/시드의 readiness 증명이 아닙니다.

```bash
set -euo pipefail
# 교체를 마친 설정과 인증서가 있을 때만 실행합니다.
docker compose -p opensamguk-shared -f docker-compose.shared.yml --env-file .env config --quiet
docker compose -p opensamguk-sdemo -f docker-compose.server.yml --env-file servers/sdemo.env config --quiet
docker network create opensamguk-net  # 최초 한 번; 기존 network가 있으면 생성하지 않습니다.
docker compose -p opensamguk-shared -f docker-compose.shared.yml --env-file .env up -d --build
docker compose -p opensamguk-sdemo -f docker-compose.server.yml --env-file servers/sdemo.env up -d
```

공유 `up --build`가 Deployer만 이 저장소에서 빌드하고 나머지는 선택한 앱 이미지를 사용합니다.
서비스 이름 `deployer`, `socket-proxy`, `gateway-api` 등은 Compose의 제품 DNS 이름입니다.
Deployer·socket-proxy의 호스트 포트는 공개하지 않습니다. nginx의 선택한 HTTP/HTTPS 포트만
외부에 열고 게임 API/웹의 publish 포트는 설치자의 방화벽에서 접근 범위를 제한합니다.

다음 결과를 저장합니다: 선택한 source/image 핀, 실제 Docker/Compose 버전, 컨테이너 상태,
gateway-api 및 game-api/engine readiness, 게임 DB world/scenario/세대/초기 시각·턴·정원,
로그인·로비·게임 진입·첫 턴. 정상 HTTP만으로 올바른 시드 계약이 확인된 것은 아닙니다.

## 업그레이드와 유지보수

1. 현재 앱/배포 SHA·이미지 digest·env 파일·DB migration 상태·백업과 원복 이미지를 기록합니다.
2. 변경 범위와 시간창·실패 복구 범위를 정하고 자동 배포/수명주기 변경이 겹치지 않게 합니다.
3. Deployer maintenance에 진입하여 기존 제어면 작업이 끝났는지 확인합니다. 게임 writer는 별도로 정지합니다.
4. 아래 백업을 검증합니다. 새 버전의 migration·저장/명령 형식·웹/API 호환을 확인한 뒤 업그레이드합니다.
5. readiness·실제 DB/시드·첫 턴·로그인/화면을 검증하고 미해결 journal/operation이 없는 것을 확인해 maintenance를 종료합니다.

`GET /maintenance`는 `capability:"maintenance-v1"`와 상태를 반환합니다.
`POST /maintenance/enter`는 기존 작업을 배수하고 비공개 단일 사용 lease를 발행합니다.
`enter-if-idle`은 이미 바쁜 제어면을 배수하지 않고 진입을 거절합니다.
`leave`는 안전 조건 충족 때만 open으로 전환하며, `repair`는 보존된 journal의 복구 경로입니다.

```bash
set -euo pipefail
# 읽기만 하는 현재 상태 점검. token은 Deployer 안의 env로 사용합니다.
docker exec opensamguk-deployer /usr/local/bin/deployer --authenticated-http GET /maintenance
```

CLI는 경로 allowlist를 사용하며 `/servers/reset`·`/operations`를 일반 HTTP runner처럼 호출할 수 없습니다.
진입 응답의 lease는 비밀이므로 공개 로그에 남기지 않습니다. maintenance는 game-api intake나 engine을
자동 정지하지 않으며 서버/DB/Redis의 writer quiesce 증거가 별도로 필요합니다.

실패 후 `repair-required`·drained 상태이면 자동 `leave`, 오래된 이미지 재시작, journal 삭제로 풀지 않습니다.
이미 볼륨 삭제 경계를 넘었으면 기존 journal의 목표 상태를 완성하는 forward recovery와
검증한 백업으로 복원하는 절차를 구분합니다. startup 복구 중에도 동일 source·image·요청 식별값을 대조합니다.
공유 registry 재로딩은 새 Deployer 배포 자체와 다른 작업입니다.

GitHub Actions의 클라우드 배포 workflow는 자신이 준비한 runner·대상·secrets에 맞춰 검토해야 합니다.
`scripts/deploy.sh`는 현재 비활성 경로(exit2)입니다. 이 문서의 설치 절차는 해당 workflow의 실행 승인을 대신하지 않습니다.

## 백업과 검증

백업 동안 제어면 변경을 막고 게임 writer를 정지한 뒤, 종료·DB commit 완료를 확인합니다.
아래는 자신의 `demo` 설치에서 수행할 명령 예시입니다. 실패 단계가 있으면 reset/upgrade에 이어 가지 않습니다.

```bash
set -euo pipefail
umask 077
backup_dir="$(pwd)/../demo-backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
cp .env servers/sdemo.env "$backup_dir/"
docker compose -p opensamguk-sdemo -f docker-compose.server.yml --env-file servers/sdemo.env \
  stop game-engine game-api web-game
# writer 종료/정상 flush 및 진행 작업 없음 확인 후 dump합니다.
docker exec sdemo-game-postgres sh -c 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  > "$backup_dir/game.dump"
docker exec -i sdemo-game-postgres pg_restore --list < "$backup_dir/game.dump" > "$backup_dir/game.toc"
docker exec sdemo-game-redis redis-cli SAVE > /dev/null
docker compose -p opensamguk-sdemo -f docker-compose.server.yml --env-file servers/sdemo.env \
  stop game-postgres game-redis
# 두 데이터 컨테이너 정지 확인 후 기존 volume이 존재하는지 확인합니다.
docker volume inspect sdemo-game-pgdata sdemo-game-redisdata > /dev/null
# 존재·정체를 확인한 volume만 읽기 전용으로 보관합니다.
docker run --rm --network none -v sdemo-game-pgdata:/volume:ro postgres:16-alpine \
  tar -czf - -C /volume . > "$backup_dir/postgres-volume.tar.gz"
docker run --rm --network none -v sdemo-game-redisdata:/volume:ro postgres:16-alpine \
  tar -czf - -C /volume . > "$backup_dir/redis-volume.tar.gz"
tar -tzf "$backup_dir/postgres-volume.tar.gz" > /dev/null
tar -tzf "$backup_dir/redis-volume.tar.gz" > /dev/null
(cd "$backup_dir" && sha256sum .env sdemo.env game.dump game.toc postgres-volume.tar.gz redis-volume.tar.gz > SHA256SUMS)
(cd "$backup_dir" && sha256sum --check SHA256SUMS)
```

공유 DB의 계정·board·registry도 바뀌는 업그레이드라면 공유 writer와 DB를 같은 절차로 별도 백업합니다.
게임 월드 백업만으로 공유 DB를 복원할 수 없습니다. 앱/배포 버전·이미지 digest·백업 파일 크기·checksum,
`pg_restore --list` 및 tar 검증 성공을 같은 영수증에 기록합니다. 비밀 env와 백업은 공개 artifact에 업로드하지 않습니다.

현재 검증 요구는 checksum + dump 목록 검사 + volume tar 무결성입니다. 이것은 실제 DB 복원·옛 이미지
부팅 시험의 성공을 뜻하지 않습니다. 복원할 때는 DB 버전과 이미지·저장 계약이 맞는지 먼저 확인합니다.
백업은 7일 보존하며 자동 삭제하지 않습니다. 만료 파일과 원복 이미지는 설치자가 확인하고 삭제합니다.

## 현재 reset 입력과 개장 계약

reset은 세계/게임 DB 볼륨을 초기화합니다. 운영 중인 DB에 새 이미지로 먼저 `up`한 뒤 reset을 잇지 않습니다.
동일 버전 pin·쓰기 정지·검증한 백업·명시 설정을 하나의 변경 절차로 준비합니다.

| 입력 | 현재 제어면 계약 |
|---|---|
| `id`, `confirm` | canonical 공개 id와 정확한 `RESET <id>` 문구. |
| `operationId` | 32자 소문자 hex. 유지보수 lease 경로에서 필수, 일반 경로도 재요청을 같은 ID로 식별하도록 명시합니다. |
| `generation`, `scenarioCode`, `scenarioSeedEnabled`, `turnTerm` | generation은 ASCII 정수 문자열0 이상; 지원 시나리오 코드; seed는 true; turnTerm은 문자열120/60/30/20/10/5/2/1. 현재 main의 일부 생략 호환값을 새 초기화 계획의 자동 선택으로 쓰지 않습니다. |
| `extend`, `blockGeneralCreate`, `npcMode`, `showImgLevel` | 선택한 앱의 실제 소비 범위와 대조해 명시합니다. 일반 생성 차단과 계정 로그인/공개 visibility는 별개의 상태입니다. |
| `imageTag`, `webGameTag`, `maintenanceLease` | 현 유지보수 reset은 제한된 서버·시나리오의 단일 사용 lease 경로입니다. 두 태그는 40자 Git SHA. 일반 reset은 이미지 pin을 바꿀 수 없습니다. 상세 범위는 [현재 접점](pep-maintenance-reset.md)을 확인합니다. |

현재 main은 legacy reset 옵션도 일부 수신합니다. 전달 성공이 그 설정의 앱 효력을 보장하지 않습니다.
시나리오 조회 선택은 현재 env API의 `SCENARIO_LOOKUP_DIR` 경로와 reset 요청 지원을 구분합니다.

**미병합 개장 계약:** 명시 `serverName`, `maxGeneral` 정수1..9999, `firstTurn` immediate|scheduled,
정확한 조회 원천과 생성/공개 gate, 세 서비스의 `imageDigests`와 selected-scenario proof는 별도 제품 PR에서
연결 중입니다. 현재 main의 지원처럼 호출하지 않습니다. 해당 PR이 릴리스에 포함되면 이 표와 접점 문서를
그 릴리스의 실제 strict DTO로 갱신해야 합니다. 공개 전 시드·NPC 첫 턴·0인간 검증은 별도 합격 조건입니다.
