# 문제 해결

증상별로 원인과 확인 방법을 적습니다. 운영 호스트에서 컨테이너를 재생성·재시작하는 일은 그 대상에 대한 승인을 받은 뒤 합니다.
**검증 안 됨:** 이 문서의 명령은 문서 작성자가 이 판에서 실행하지 않았습니다. 설정 수치는 `origin/main` b39ebaf의 `infra/nginx/nginx.conf`·`harness.py`와 대조했습니다.

## API가 503을 돌려준다

nginx rate limit을 넘으면 nginx 기본값인 **503**이 나갑니다(`limit_req_status`를 바꾸지 않음). 앱이 내려가도 503이 나오므로 둘을 구분해야 합니다.

| 요청 | zone | 한도 |
|---|---|---|
| `GET`·`HEAD` | `api_read_limit` | IP당 10r/s, burst 40, delay 8. 초과 8건부터 대기, 40건 넘으면 503 |
| 그 밖의 모든 메서드(로그인 `POST` 포함, 알 수 없는 메서드도) | `api_limit` | IP당 60r/m, burst 20, nodelay. 넘으면 바로 503 |

두 제한은 API location 10곳(HTTP 5 · HTTPS 5)에 함께 걸려 있고 서로 독립입니다. 읽기 폭주가 로그인·쓰기 몫을 먹지 않습니다.

- **구분법(운영):** nginx error 로그의 `limiting requests ... by zone "api_limit"`(또는 `"api_read_limit"`) 줄이 있으면 rate limit, 없으면 upstream 문제입니다. upstream이면 해당 API 컨테이너의 health부터 봅니다.
- **구분법(localhost 격리 스택):** 이 스택은 컨테이너 로그를 덤프하지 않는 규칙입니다([localhost 격리 스택](localhost.md#custody와-비밀값)). 하네스 결과와 실패 기록으로 판단합니다.
- 화면 하나가 동시에 여러 조회를 보내면 읽기 burst를 넘을 수 있습니다. 한도를 올리는 것은 nginx 설정 변경이며 별도 리뷰 대상입니다.

## nginx 설정을 바꿨는데 그대로다

**rate limit zone의 키를 바꾼 설정은 `nginx -s reload`(HUP)로 반영되지 않습니다.** 새 설정은 거절되고(emerg) nginx는 옛 설정으로 계속 돕니다.
`nginx -t`는 문법만 보므로 통과해도 reload가 실패할 수 있습니다. #77(읽기·쓰기 bucket 분리)이 이런 변경입니다.

- 반영: nginx 컨테이너를 **다시 만듭니다**(zone 공유 메모리가 새로 생깁니다). 공유 스택이면 예를 들어:

  ```bash
  # 검증 안 됨. 운영 호스트에서는 대상별 승인 뒤에만. 재생성 동안 연결이 잠깐 끊깁니다.
  docker compose -p opensamguk-shared -f docker-compose.shared.yml --env-file .env up -d --no-deps --force-recreate nginx
  ```

- 확인: 재생성 뒤 실제 요청으로 확인합니다. `/health` 200은 nginx 자신이 떴다는 뜻일 뿐입니다.
- localhost 격리 스택: `prepare`가 그때의 정본 nginx를 custody에 복사하고 digest를 기록합니다. 저장소의 `nginx.conf`를 바꿔도 기존 custody에는 반영되지 않습니다. 새 `prepare`로 새 custody를 만듭니다. custody 안 파일을 손으로 바꾸거나 HUP으로 우회하지 않습니다.

## HTTP로 열었더니 이상한 포트로 간다 / 로그인이 안 된다

- 정본 nginx의 HTTP 서버는 API·게임 경로를 직접 처리하지만, 그 밖의 `/`는 `https://$host$request_uri`로 redirect합니다. **포트를 붙이지 않으므로** `NGINX_HTTPS_PORT`가 443이 아니면 redirect가 443으로 갑니다. HTTPS 주소로 바로 엽니다.
- 로그인 쿠키는 HTTPS 전제입니다. HTTP에서는 쿠키가 저장되지 않아 로그인이 풀린 것처럼 보일 수 있습니다.

## 웹이 틀린 주소를 부른다

`NEXT_PUBLIC_*`와 web-game의 `GATEWAY_WEB_URL`·`ASSET_PREFIX`는 웹 이미지 **빌드 인수**입니다. 서버 env를 바꿔도 이미 빌드한 이미지는 그대로입니다.
맞는 값으로 다시 빌드합니다([환경 변수](environment-variables.md#빌드-시점-값과-실행-시점-값)).

## `/health`는 200인데 앱이 안 된다

nginx의 `/health`는 nginx 자체 응답입니다. gateway-api·game-api·game-engine readiness, DB seed, 레지스트리를 따로 확인합니다.

## 게임 주소가 404다

- `/game/<서버 ID>`는 소문자 영숫자 1–48자만 받습니다. 대문자는 제어면이 소문자로 정규화합니다.
- `admin`·`map`·`main` 같은 게임 화면 이름은 예약어라 서버 ID로 쓸 수 없습니다(목록은 `nginx.conf`의 `$game_path_web_upstream` map).
- 예약 화면 경로(`/game/map` 등)는 `sam_server` 쿠키로 서버를 고릅니다. 쿠키가 없거나 예약어면 404입니다.

## 서비스는 healthy인데 레지스트리가 비었다

gateway-api는 seed의 `deployProject`가 `opensamguk-s<serverId>`가 아니면 seed 전체를 거절합니다. localhost 격리 스택에서 compose 프로젝트 이름(`osglha<nonce>`)을 넣으면 이렇게 됩니다.
옛 하네스로 만든 스택은 `repair-registry`(1회용)로 고칩니다([localhost 격리 스택](localhost.md#순서)). 기존 공유 DB에서는 `SERVER_REGISTRY_JSON`이 membership을 덮어쓰지 않습니다.

## localhost 하네스가 시작을 거절한다

`REFUSED:` 뒤 고정 문구로 이유가 나옵니다. 자원·기록은 그대로 남습니다.

| 문구 계열 | 원인 | 할 일 |
|---|---|---|
| `GiB free disk required for build/startup` | 여유 디스크가 12 GiB(build)·8 GiB(startup) 미만 | 디스크를 확보합니다. 관문 수치를 낮추지 않습니다 |
| `Docker needs 2 CPUs and 6 GiB memory` · `Insufficient available Docker memory` | Docker VM 할당 또는 다른 컨테이너를 뺀 가용 메모리 부족 | Docker Desktop 자원 설정·다른 스택 정지(소유자 확인 뒤) |
| `Host load5 exceeds ... 400` | 호스트 부하 | 다른 무거운 작업이 끝나길 기다립니다 |
| `Loopback 443 ...` | `127.0.0.1:443` 점유 또는 상태 불확실 | 아래 「443이 이미 쓰인다」. 다른 포트로 바꿔 띄우는 대안은 없습니다 |
| `Project/nonce already exists` · `Foreign resource found` | 같은 이름·label 자원이 이미 있음 | 그 자원을 지우지 말고 새 `prepare`로 새 nonce를 씁니다 |
| `Writer session mismatch` | `OPENSAMGUK_TASK_OWNER_SESSION`이 custody를 만든 세션과 다름 | 맞는 세션에서 실행. `snapshot`은 읽기 전용이라 예외 |
| `Waiting for shared heavy-run owner`(거절 아님) | 다른 작업이 `.locks/heavy-run`을 쥐고 있음 | 기다립니다. 남의 잠금을 지우지 않습니다 |

> **경고:** 디스크를 비우려고 `docker system prune`·`docker builder prune`·`docker volume prune`을 돌리면 다른 스택의 캐시·볼륨까지 지울 수 있습니다.
> 지울 대상의 소유자를 먼저 확인합니다.

## 443이 이미 쓰인다

```bash
# 검증 안 됨. 무엇이 듣고 있는지 보기만 합니다.
lsof -nP -iTCP:443 -sTCP:LISTEN
docker ps --filter publish=443 --format '{{.Names}}\t{{.Ports}}'
```

다른 사람·다른 세션의 컨테이너나 프로세스면 멈추지 말고 소유자에게 알립니다. macOS에서 비루트 bind 시험이 막히면 하네스는 loopback 연결 거절로 비어 있음을 확인하고, 실제 판정은 Docker Desktop의 포트 bind가 합니다.

## Docker Desktop이 「starting」에서 안 넘어간다

`starting` 상태나 엔진 CPU·메모리 0은 준비 완료가 아닙니다. `docker info`가 실제로 응답할 때까지 기다립니다.
CLI 시작 명령이 시간 초과로 끝나도 엔진은 뒤에서 복구 중일 수 있습니다. 반복 restart·reset은 복구를 방해합니다.
