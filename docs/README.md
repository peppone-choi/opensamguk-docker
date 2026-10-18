# 문서 색인

처음이면 [저장소 README](../README.md)의 「어떤 경로를 쓰나」부터 봅니다.

## 안내

| 문서 | 언제 읽나 |
|---|---|
| [설치와 배포](installation-and-deployment.md) | Linux 호스트에 공유 스택과 게임 월드를 새로 설치·업그레이드·백업할 때 |
| [localhost 격리 스택](localhost.md) | 개발 기기에서 정확한 앱 SHA를 정본 nginx 뒤에 띄워 확인할 때 |
| [환경 변수](environment-variables.md) | `.env`·`servers/*.env`의 각 변수가 무엇이고 어느 서비스가 읽는지 |
| [문제 해결](troubleshooting.md) | 503, nginx 설정 미반영, 443 점유, 자원 관문 거절, 로그인 쿠키 문제 |
| [운영 주의](operations-cautions.md) | 되돌리기 어려운 명령과 비밀값 취급 |

## 참조

| 문서 | 내용 |
|---|---|
| [오케스트레이션 상세 참고](orchestration-reference.md) | 멀티서버 구조, 공개 서버 ID 계약, deployer·maintenance barrier, 버전 고정, web-game 승격 |
| [PEP 유지보수 초기화 접점](pep-maintenance-reset.md) | 단일 사용 maintenance lease reset의 입력 계약 |
| [하네스 원문 README](../tools/localhost-acceptance/README.md) | localhost 하네스의 정본 계약(영어). [localhost 격리 스택](localhost.md)은 이 문서의 길잡이입니다. |

## 작업 기록

당시 상태를 보존한 기록입니다. 본문의 「DRAFT」「PENDING」 같은 상태 표기는 작성 시점 기준이며 현재 상태가 아닐 수 있습니다.

- [API 조회 rate 제한 복구](nginx-api-rate-plan.md) (#76, #77 병합)
- [기존 CI 중지](development/ci-retirement-2026-10-17.md)
- [maintenance idle 진입 계획](plans/2026-09-05-maintenance-idle-entry.md)
- [OPENSAM-177 서버 정의 격리 리뷰](reviews/2026-08-13-opensam-177-server-definition-isolation.md)
