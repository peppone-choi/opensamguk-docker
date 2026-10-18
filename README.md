# OpenSamguk Docker

OpenSamguk의 공유 로그인·게시판과 독립 게임 월드를 Docker Compose로 띄우는 저장소입니다.
앱 이미지와 배포 설정의 버전을 함께 고정해 사용합니다. 앱 코드와 이미지는 이 저장소에 없습니다.

- 앱 소스: [OpenSamguk](https://github.com/peppone-choi/opensamguk)
- 이미지·원작 파생 자산 정본: [OpenSamguk Images](https://github.com/peppone-choi/opensamguk-images)
- [MIT 코드 라이선스](LICENSE) · [원작·제3자 고지와 자산 경계](NOTICE)
- 전체 문서 목록: [docs/README.md](docs/README.md)

## 구성 요소

| 경로 | 내용 |
|---|---|
| `docker-compose.shared.yml` | 공유 스택(프로젝트 `opensamguk-shared`): gateway PostgreSQL·Redis, gateway-api, board-api, web-gateway, nginx, deployer, socket-proxy |
| `docker-compose.server.yml` | 게임 월드 스택(월드마다 한 벌, 프로젝트 `opensamguk-s<SERVER_ID>`): game PostgreSQL·Redis, game-engine, game-api, web-game |
| `docker-compose.yml` | 옛 단일 스택(9서비스 한 프로젝트). 멀티서버와 동시에 쓰지 않습니다. |
| `docker-compose.localhost-acceptance.yml` | localhost 격리 스택의 **템플릿(JSON)**. 하네스만 읽습니다. 직접 `docker compose -f`로 쓰지 않습니다. |
| `tools/localhost-acceptance/` | 정확한 앱 SHA 소스에서 이미지 6개를 빌드해 `https://localhost`에 격리 스택을 띄우는 하네스 |
| `infra/nginx/nginx.conf` | 정본 리버스 프록시 설정(라우팅·rate limit·HTTPS redirect) |
| `deployer/` | 수명주기·배포 제어면(Go) |
| `.env.example`, `servers/s1.env.example` | 공유·게임 설정의 가짜 예시. 변수 설명은 [환경 변수](docs/environment-variables.md) |
| `scripts/` | nginx·deployer·승격 회귀 시험과 보조 스크립트 |

## 어떤 경로를 쓰나

| 목적 | 경로 | 안내 |
|---|---|---|
| Linux 호스트에 공유 스택 + 게임 월드 설치 | shared + server compose | [설치와 배포](docs/installation-and-deployment.md) |
| 맥북 등 개발 기기에서 정확한 앱 SHA를 실제 nginx 뒤에서 확인 | localhost 격리 스택 | [localhost 격리 스택](docs/localhost.md) |
| 멀티서버 없이 한 벌만 | `docker-compose.yml` | [오케스트레이션 참고](docs/orchestration-reference.md#단일서버--로컬-빠른-시작-멀티서버-미사용). 아래 경고를 먼저 읽습니다. |

## 빠른 시작

**검증 안 됨:** 아래 명령은 문서 작성자가 이 판에서 실행하지 않았습니다. 각 안내 문서의 전제 조건을 먼저 확인합니다.

### 설치(Linux 호스트)

```bash
cp .env.example .env
cp servers/s1.env.example servers/sdemo.env
chmod 600 .env servers/sdemo.env
# 모든 CHANGE_ME를 실제 값으로 바꾸고 TLS 인증서를 준비한 뒤 설정을 검사합니다.
docker compose -p opensamguk-shared -f docker-compose.shared.yml --env-file .env config --quiet
```

이어지는 네트워크 생성·기동·레지스트리 등록은 [설치와 배포](docs/installation-and-deployment.md)를 따릅니다.

### localhost 격리 스택(개발 기기)

```bash
python3 tools/localhost-acceptance/harness.py prepare --help
```

`prepare → build → validate → up → smoke → down` 순서와 자원 관문(디스크 12 GiB 등)은 [localhost 격리 스택](docs/localhost.md)에 있습니다.

## 먼저 알아야 할 위험

> **경고: 고정 이름과 전체 인터페이스 publish.** compose 세 파일은 `container_name`을 고정합니다(`opensamguk-*`, `s<SERVER_ID>-*`).
> `-p`로 프로젝트 이름만 바꿔도 같은 이름의 다른 컨테이너와 충돌합니다. `docker-compose.yml`은 `80:80`·`443:443`을,
> shared compose는 nginx의 HTTP/HTTPS를 **호스트 IP 제한 없이** publish합니다. 개발 기기에서는 이 파일들을 그대로 `up`하지 말고
> localhost 격리 스택을 씁니다.

> **경고: 볼륨 삭제는 되돌릴 수 없습니다.** `docker compose down --volumes`, `docker volume rm`, `docker system prune --volumes`는
> 계정·게시판·월드 DB를 지웁니다. 검증한 백업 없이 실행하지 않습니다.

> **nginx 설정 변경:** rate limit zone 키를 바꾼 설정은 `nginx -s reload`(HUP)로 반영되지 않고 옛 설정이 남습니다.
> nginx 컨테이너를 다시 만들어 반영하고 실제 요청으로 확인합니다. 자세히는 [문제 해결](docs/troubleshooting.md#nginx-설정을-바꿨는데-그대로다).

전체 목록은 [운영 주의](docs/operations-cautions.md)에 있습니다.

## 버전과 상태

이미지는 `<service>-<앱 Git SHA>` 태그로 고정합니다. 공유 서비스와 게임 API·엔진·웹이 같은
계약을 소비하는지 확인하고, 웹만 새 버전으로 바꾸기 전에 API 호환성을 검증합니다.
`latest`나 새로운 웹 이미지가 데이터·명령·저장 형식의 호환성을 증명하지 않습니다.

Deployer의 일반 `/deploy`는 game-api·web-game만 재시작합니다. game-engine을 포함한 업그레이드,
세계 초기화, DB 복구는 백업·쓰기 정지·사후 검증을 포함한 별도 변경 절차입니다.
`maintenance-v1`은 제어면의 작업을 배수하며 게임 쓰기 프로세스는 따로 정지해야 합니다.

지원 대상으로 문서화한 설치 경로는 **Linux x86-64 호스트의 Docker Engine + `docker compose` plugin**입니다.
최소·권장 CPU/RAM/디스크의 부하 측정 기준은 아직 확정되지 않았습니다([사양 표](docs/installation-and-deployment.md#요건과-사양)).
localhost 격리 스택은 수용 검증용이며 지원 설치 경로가 아닙니다.

이 저장소의 CI는 2026-10-17에 중지됐습니다([기록](docs/development/ci-retirement-2026-10-17.md)). 문서 작성이나 시험 통과는
새 호스트에서의 설치·복구 성공을 뜻하지 않습니다. 실행 결과와 선택한 버전·이미지 digest·백업 영수증은 각 설치자가 보존합니다.
