# 운영 주의

되돌리기 어렵거나 다른 스택을 망가뜨릴 수 있는 일을 모았습니다. 이 문서는 운영 작업의 실행 지시나 승인이 아닙니다.
운영 호스트의 배포·초기화·복구는 대상별 승인과 [설치와 배포](installation-and-deployment.md)의 절차(백업·쓰기 정지·사후 검증)를 따릅니다.

## 위험한 명령

| 명령·행동 | 무엇이 문제인가 | 대신 |
|---|---|---|
| 개발 기기에서 `docker compose -f docker-compose.yml up` | `name: opensamguk`, 고정 `container_name: opensamguk-*`, `80:80`·`443:443`을 **모든 인터페이스**에 publish | [localhost 격리 스택](localhost.md) |
| 운영 compose에 `-p <다른 이름>`만 붙여 두 번째 벌 띄우기 | `container_name`이 고정이라 이름이 그대로 충돌. 외부 network `opensamguk-net`과 `COMPOSE_HOST_DIR` bind도 공유 | 같은 호스트에 두 벌을 두지 않습니다. 게임 월드는 `SERVER_ID`·포트가 다른 env로 |
| `docker-compose.yml`(단일)과 shared+server(멀티)를 같은 호스트에서 동시에 | 같은 포트·이름을 다툼. 서로 배타적 | 하나만 |
| shared compose 기본값으로 nginx 기동 | `NGINX_HTTP_PORT`·`NGINX_HTTPS_PORT` 기본 80·443이 호스트 IP 제한 없이 열림 | 방화벽으로 범위를 정합니다. game-api·web-game publish 포트도 같습니다 |
| `docker compose down --volumes`, `docker volume rm`, `docker volume prune` | 계정·게시판·레지스트리(공유) 또는 월드 DB·Redis(게임)가 **영구 삭제** | 검증한 백업이 있고 그 작업이 초기화일 때만. 평소 정지는 `docker compose stop`·`down`(볼륨 유지) |
| `docker system prune`, `docker builder prune`, `docker image prune -a` | 다른 스택의 이미지·빌드 캐시·(옵션에 따라) 볼륨까지 삭제. 원복 이미지가 사라짐 | 지울 대상의 소유자·용도를 먼저 확인 |
| 운영 DB에 새 이미지로 먼저 `up`한 뒤 reset | 새 엔진이 옛 DB를 읽어 migration·저장 형식이 섞임 | 같은 버전 pin·쓰기 정지·검증한 백업·명시 설정을 한 변경 절차로([PEP 초기화 접점](pep-maintenance-reset.md)) |
| deployer journal·`servers/.deployer-*` 파일 삭제, `repair-required` 상태에서 자동 `leave` | 복구에 필요한 기록과 barrier가 사라짐 | [설치와 배포 §업그레이드와 유지보수](installation-and-deployment.md#업그레이드와-유지보수)의 복구 구분 |
| nginx zone 키가 바뀐 설정을 HUP reload로 반영 | 거절되고 옛 설정이 남음(성공처럼 보임) | nginx 컨테이너 재생성 뒤 실제 요청 확인([문제 해결](troubleshooting.md#nginx-설정을-바꿨는데-그대로다)) |
| localhost 격리 스택 자원을 손으로 정리 | nonce 소유 확인 없이 다른 스택을 지울 수 있음 | 하네스 `down` |

> **경고:** 위 명령을 문서에서 그대로 복사해 실행하지 않습니다. 대상 프로젝트(`-p`)·env 파일·호스트를 먼저 확인합니다.

## 비밀값

- 실제 `.env`·`servers/*.env`·`infra/nginx/certs/`는 커밋하지 않습니다(`.gitignore`). 권한은 `600`, 인증서 개인키도 제한된 권한으로.
- `docker compose config`(전체 출력), `docker inspect`의 Env, 컨테이너 로그를 공개 채널·이슈·PR에 붙이지 않습니다. 비밀값이 그대로 나옵니다. 설정 검사는 `config --quiet`로 합니다.
- `JWT_PRIVATE_KEY`는 gateway-api에만 둡니다. board-api·game-api에는 공개키만 둡니다.
- `DEPLOYER_TOKEN`은 배포 권한 그 자체입니다. deployer·socket-proxy 포트는 외부에 열지 않습니다.
- GHCR 로그인은 `--password-stdin`으로 하고 토큰을 명령 인자·Git에 넣지 않습니다.
- maintenance 진입 응답의 lease는 비밀입니다. 로그에 남기지 않습니다.
- localhost 격리 스택의 custody 파일(`fixture.json`·`runtime.json`·`compose.json`)도 출력·커밋하지 않습니다. 하네스가 만든 인증서를 호스트 신뢰 저장소에 설치하지 않습니다.

## 확인 없이 믿지 말 것

- nginx `/health` 200 ≠ 앱 준비 완료.
- 서비스 healthy ≠ seed·레지스트리 정상 ≠ 사용자 여정 성공. localhost `smoke` 통과도 사용자 여정 성공이 아닙니다.
- 백업 checksum·`pg_restore --list`·tar 검사 통과 ≠ 실제 복원 성공.
- 문서·시험 통과 ≠ 새 호스트 설치 성공. 이 저장소 CI는 [중지 상태](development/ci-retirement-2026-10-17.md)입니다.
