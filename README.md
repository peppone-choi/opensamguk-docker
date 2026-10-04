# OpenSamguk Docker

OpenSamguk의 공유 로그인·게시판과 독립 게임 월드를 Docker Compose로 설치하는 저장소입니다.
앱 이미지와 배포 설정의 버전을 함께 고정해 사용합니다.

- [설치·이미지 빌드·업그레이드·백업 안내](docs/installation-and-deployment.md)
- [현재 유지보수 reset 접점](docs/pep-maintenance-reset.md)
- [MIT 코드 라이선스](LICENSE) · [원작·제3자 고지와 자산 경계](NOTICE)
- 앱 소스: [OpenSamguk](https://github.com/peppone-choi/opensamguk)
- 이미지·원작 파생 자산 정본: [OpenSamguk Images](https://github.com/peppone-choi/opensamguk-images)

## 설치 경로

지원 대상으로 문서화한 경로는 **Linux x86-64 호스트의 Docker Engine + `docker compose` plugin**입니다.
앱 Dockerfile은 JDK 21 및 Node 22 기반이고 Deployer는 Go 1.23 빌드·Docker 27 CLI 기반입니다.
최소·권장 CPU/RAM/디스크의 부하 측정 기준은 아직 확정되지 않았습니다. Compose에 적힌 메모리
한도와 과거 단일 스택의 사양 표기는 [사양 표](docs/installation-and-deployment.md#요건과-사양)에 구분했습니다.

```text
docker-compose.shared.yml   공유 DB·인증·게시판·웹·nginx·Deployer·socket-proxy
docker-compose.server.yml   게임 월드별 PostgreSQL·Redis·엔진·API·웹
deployer/                   수명주기·배포 제어면
.env.example                공유 설정: 실제 값으로 교체할 가짜 예시
servers/s1.env.example      게임 설정: 실제 값으로 교체할 가짜 예시
```

첫 설치는 예시를 복사하고 키·비밀번호·이미지 버전·TLS 인증서를 준비한 뒤 외부 네트워크,
공유 스택, 게임 스택 순서로 진행합니다. 실행 명령과 DB 레지스트리 초기 등록은 설치 안내를 따릅니다.
예시의 `CHANGE_ME`·`example.invalid`는 실행 가능한 배포 값이 아닙니다.

## 버전과 상태

이미지는 `<service>-<앱 Git SHA>` 태그로 고정합니다. 공유 서비스와 게임 API·엔진·웹이 같은
계약을 소비하는지 확인하고, 웹만 새 버전으로 바꾸기 전에 API 호환성을 검증합니다.
`latest`나 새로운 웹 이미지가 데이터·명령·저장 형식의 호환성을 증명하지 않습니다.

Deployer의 일반 `/deploy`는 game-api·web-game만 재시작합니다. game-engine을 포함한 업그레이드,
세계 초기화, DB 복구는 백업·쓰기 정지·사후 검증을 포함한 별도 변경 절차입니다.
`maintenance-v1`은 제어면의 작업을 배수하며 게임 쓰기 프로세스는 따로 정지해야 합니다.

이 문서는 공개 설치 절차와 소스 계약을 정리한 것입니다. 문서 작성이나 CI 성공은 새 호스트에서의
설치·복구 성공을 뜻하지 않습니다. 실행 결과와 선택한 버전·이미지 digest·백업 영수증을 각 설치자가 보존합니다.
