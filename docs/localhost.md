# localhost 격리 스택

개발 기기에서 **정확한 앱 커밋 하나**로 이미지 6개를 소스 빌드하고, 정본 `infra/nginx/nginx.conf` 뒤에서
`https://localhost`로 띄우는 수용 검증 스택입니다. 운영 설치 경로가 아닙니다.

정본 계약은 [하네스 README(영어)](../tools/localhost-acceptance/README.md)와 `tools/localhost-acceptance/harness.py`입니다.
이 문서는 그 길잡이이며, 둘이 다르면 하네스 쪽이 맞습니다.

**검증 상태:** 명령·수치는 `origin/main` b39ebaf의 `harness.py`와 대조했습니다. 문서 작성자가 이 절차를 직접 실행하지는 않았습니다(**검증 안 됨**).

## 운영 compose와 무엇이 다른가

| 항목 | 운영 compose(shared + server) | localhost 격리 스택 |
|---|---|---|
| 이미지 | GHCR의 `<service>-<SHA>` 태그를 pull | 깨끗한 앱 checkout의 Git 추적 파일만 `git archive`로 내보내 6개 Dockerfile을 순서대로 빌드. `up`은 `--no-build --pull never` |
| 컨테이너·볼륨 이름 | 고정(`opensamguk-*`, `s<SERVER_ID>-*`), 외부 network `opensamguk-net` | 프로젝트 `osglha<16자 nonce>`, nonce·세션 label이 붙은 network 1개·볼륨 5개 |
| 포트 | nginx HTTP/HTTPS를 호스트 IP 제한 없이 publish, game-api·web-game 포트도 publish | `127.0.0.1:443:443` 하나만. DB·Redis·API 포트 없음 |
| origin | 설치자 도메인 | 정확히 `https://localhost` |
| TLS | 설치자 인증서(`infra/nginx/certs/`) | `prepare`가 새로 만든 로컬 인증서. 호스트 신뢰 저장소에 설치하지 않습니다 |
| DB | 운영 데이터 | 새 auth DB·새 game DB(world 160, generation 0) |
| JWT·내부 토큰 | 설치자가 만든 비밀값 | `prepare`가 새로 만든 로컬 fixture |
| 서버 ID | 설치자가 정함 | `lha<nonce>`. 레지스트리의 `deployProject`는 `opensamguk-s<serverId>`(compose 프로젝트 이름과 다름) |
| 재시작 | `unless-stopped` | `restart: no` |
| compose 파일 | 그대로 `docker compose -f` | `docker-compose.localhost-acceptance.yml`은 `@PLACEHOLDER@`가 든 JSON 템플릿. `prepare`가 치환해 비공개 custody에 씁니다 |

> **경고:** 운영 compose를 `-p` 이름만 바꿔 로컬에서 띄우면 고정 `container_name` 때문에 다른 스택과 충돌하고,
> nginx가 전체 인터페이스에 열립니다. 로컬 확인은 이 하네스로 합니다.

## 준비물

- macOS 또는 Linux의 **로컬** Docker 데몬(Unix socket). 원격 Docker host·context는 거절됩니다.
- 비어 있는 `127.0.0.1:443`. 점유돼 있으면 시작하지 않습니다.
- 앱 저장소의 깨끗한 checkout: 대상 SHA, 미추적·ignored 파일 없음. `prepare`는 fetch된 `origin/main`이 넘긴 SHA와 같은지도 봅니다(앱·Docker 모두).
- `OPENSAMGUK_TASK_OWNER_SESSION`: 이 스택을 쓰는(쓰기 권한을 가진) 세션 식별자. 변경 명령은 이 값이 맞아야 합니다.
- `--meta <디렉터리>`: 그 아래 `.locks/heavy-run`을 기기 전체 무거운 작업 잠금으로 씁니다. 다른 소유자가 있으면 기다리며 남의 잠금을 지우지 않습니다.

## 자원 관문

각 단계 직전에 다시 검사합니다. 미달이면 거절하고 자원·기록을 그대로 둡니다.

| 단계 | 여유 디스크 | Docker 할당 | Docker 가용 메모리 | 호스트 load5 |
|---|---|---|---|---|
| `build`(이미지마다) | 12 GiB 이상 | 2 CPU · 6 GiB 이상 | 6 GiB 이상 | 400 이하 |
| `up`(startup) | 8 GiB 이상 | 2 CPU · 6 GiB 이상 | 6 GiB 이상 | 400 이하 |
| `repair-registry` | 8 GiB 이상 | 2 CPU · 6 GiB 이상 | 768 MiB 이상 | 400 이하 |
| `smoke` 통과 직전 | 3 GiB 이상 남아 있어야 함 | | | |

서비스 메모리 상한 합계는 6016 MiB이고 DB/WAL 증가에는 상한이 없습니다.

## 순서

**검증 안 됨(문서 작성자 미실행).** `<...>`는 직접 채웁니다.

```bash
export OPENSAMGUK_TASK_OWNER_SESSION=<writer-session-id>
H=tools/localhost-acceptance/harness.py

# 1. 소스 내보내기·fixture·인증서·비공개 compose 생성. 컨테이너는 만들지 않습니다.
python3 "$H" prepare --source <clean-app-checkout> --app-sha <40자 앱 SHA> \
  --docker-sha <40자 Docker SHA> --custody <새 비공개 디렉터리>

# 2. 이미지 6개 순차 빌드(잠금 아래). 오래 걸리고 디스크를 많이 씁니다.
python3 "$H" build --custody <custody> --meta <meta-dir>

# 3. 소스·설정·소유권 재검산
python3 "$H" validate --custody <custody>

# 4. 기동: 기존 같은 이름·label 자원이 하나라도 있으면 거절
python3 "$H" up --custody <custody> --meta <meta-dir>

# 5. nginx -t, HTTPS health, 비인증 경계 경로, world 160, 레지스트리 확인
python3 "$H" smoke --custody <custody>

# 읽기 전용 DB 투영(필요할 때)
python3 "$H" snapshot --custody <custody> --general-id <양의 정수> [--request-id <uuid>]

# 6. 이 스택 소유 자원만 삭제
python3 "$H" down --custody <custody> --meta <meta-dir>
```

- `smoke` 통과는 **사용자 여정 성공이 아닙니다.** ADMIN 로그인, 가입 허용, USER 가입·로그인·입장은 앱 저장소의 별도 runner가 맡습니다.
- `RESET_TURNTERM=2`는 2분(tick 120초)입니다. 2초가 아닙니다.
- `prepare --clone-source-custody <이전 custody>`는 macOS APFS 복제로 공개 소스만 재사용합니다. 바이트·모드가 정확히 같을 때만 쓰며, 복제를 못 하면 전체 복사로 대신하지 않고 실패합니다.
- `repair-registry`는 옛 하네스가 레지스트리 `deployProject`를 compose 프로젝트 이름으로 넣은 결함 하나만 고치는 1회용 명령입니다. 조건이 하나라도 다르면 거절하고 자동 재시도하지 않습니다.

## custody와 비밀값

- custody 디렉터리는 현재 사용자 소유 `0700`, 안의 JSON·로그·키는 `0600`입니다.
- `contract.json`: 프로젝트·nonce·serverId·world·origin·SHA·이미지 ID(요약 가능, 그래도 비공개).
- `fixture.json`: 시험용 ADMIN·USER 계정. runner가 내부에서만 읽습니다.
- `runtime.json`·`compose.json`: DB·JWT·내부 토큰.

> **하지 말 것:** 이 파일들을 출력·커밋하지 않습니다. 이 스택에 `docker compose config`를 터미널로 찍거나
> 컨테이너 inspect·env·로그를 덤프하지 않습니다. 하네스는 오류를 고정 문구로만 돌려줍니다.

## down이 지우는 것과 안 지우는 것

`down`은 모든 자원의 nonce·세션·compose 프로젝트 label을 확인한 뒤 **확인한 컨테이너 ID·network ID·볼륨 이름·이 스택 앱 이미지 태그만** 지웁니다.
Docker 캐시 prune, 공용 base 이미지, 다른 스택, custody, 실패 기록은 건드리지 않습니다. 소유권 확인이 하나라도 실패하면 아무것도 지우지 않습니다.

> **경고:** 이 스택 자원을 `docker compose down --volumes`, `docker volume prune`, `docker system prune`으로 직접 치우지 않습니다.
> 다른 스택의 볼륨·이미지까지 지울 수 있습니다. 항상 하네스 `down`을 씁니다.

## 회귀 시험

```bash
python3 -B tools/localhost-acceptance/test_harness.py -v
python3 -B scripts/test_nginx_campaign_routes.py
```

문제가 생기면 [문제 해결](troubleshooting.md)을 봅니다.
