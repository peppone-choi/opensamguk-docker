# PEP 유지보수 초기화 접점

이 접점은 Deployer의 **단일 사용 수명주기 lease**를 사용합니다. `deployer/**`를 포함한 main 반영은
기존 자동 orchestration workflow를 시작하므로 코드 리뷰와 대상 운영 배포 승인은 별도로 확인합니다.
이 문서는 reset 실행 명령이나 운영 승인 영수증이 아닙니다.

기존 `/maintenance/enter`의 비공개 lease를 loopback `POST /servers/reset`의 `X-Maintenance-Lease`로
전달합니다. 현재 경로는 `pep`, `scenario_990002`에 제한됩니다. `operationId`·정확한 `confirm: "RESET pep"`,
40자 소문자 Git SHA인 `imageTag`·`webGameTag`가 필수이며 두 SHA는 **같아야 합니다**.

`imageDigests`는 정확히 `game-api`, `game-engine`, `web-game` 세 키를 갖는 객체입니다.
각 값은 `sha256:<64자 소문자 hex>`이고 **각 태그가 가리키는 최상위 manifest 또는 index digest**입니다.
이미지 config digest, `.Id`, 플랫폼별 하위 manifest digest로 대신하지 않습니다.

Deployer는 임시 env로 같은 SHA 태그의 로컬 이미지를 먼저 inspect합니다. 세 이미지 모두
정확한 repository digest와 `linux/amd64`이면 재pull 없이 진행합니다. 로컬 이미지가 없거나 검증이
안 되면 후보 세 서비스를 pull하고 다시 inspect합니다. 검증 전 canonical env/저널을 쓰거나 볼륨을 내리지 않습니다.
승인된 digest는 reset target·요청 fingerprint·영속 journal에 포함됩니다. 같은 작업 ID에 다른
이미지 digest를 넣으면 HTTP 409로 거절합니다. lease는 한 번 쓰면 재사용할 수 없고 maintenance는 자동으로 열리지 않습니다.
일반 reset은 이미지 pin을 변경할 수 없습니다.

pin만 있고 digest는 없는 legacy journal은 읽기와 Deployer 기동을 허용합니다. 해당 journal의
미완료 작업의 복구 실행은 거절하고 journal과 닫힌 barrier를 보존합니다. 이미 성공한 연결 작업은
작업 종류·서버·요청 fingerprint 및 게시된 env/runtime/registry 사후 조건을 확인한 뒤 저널만 정리합니다.
이 정리 경로는 옛 이미지 재실행을 허용하지 않습니다. 이를 지워 새 요청으로 대체하지 않고
정확한 목표 이미지·데이터 상태를 확인한 복구 절차를 준비합니다.

이 API의 source/CI attestation, 외부 시나리오 선택 바이트, writer quiesce, 백업·공간·PG/Redis pin은
별도 실행 카드의 검증 항목입니다. 호출자는 같은 변경 창에서 그 증거를 확인하고 앱 쓰기를 정지합니다.
`promote-game-server.yml`을 먼저 실행해 새 엔진에 옛 DB를 공급하지 않습니다. 현재
`reset-game-server.yml`은 이 lease/digest 입력을 넘기지 않으므로 검증된 배선 없이 이어 호출하지 않습니다.

초기화 실패는 기존 journal/repair-required 규칙을 따릅니다. 볼륨 삭제 뒤에는 새 목표 상태의 forward recovery와
검증한 백업 복원을 구분합니다. 원래 세계의 복원 성공을 generic repair 결과로 대체하지 않습니다.
백업 checksum·`pg_restore --list`·volume tar 검증은 실제 restore/옛 이미지 부팅 성공을 뜻하지 않습니다.
