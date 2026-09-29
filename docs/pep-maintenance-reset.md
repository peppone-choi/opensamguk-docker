# PEP 유지보수 초기화 접점

이 변경은 배포기의 **단일 사용 수명주기 lease**로만 `pep` 초기화를 허용한다. 운영 작업을 시작하는 명령은 아니다.

기존 `/maintenance/enter`가 반환한 비공개 lease를 loopback `POST /servers/reset`의 `X-Maintenance-Lease`로 전달한다. 요청에는 정확한 `operationId`, `confirm: "RESET pep"`, `scenarioCode: "scenario_990002"`, 40자 소문자 Git SHA인 `imageTag`·`webGameTag`가 필요하다. 배포기는 이미지 핀과 시나리오·세대 변경을 하나의 reset target 및 영속 journal에 기록한 뒤, 서버 볼륨을 내리고 새 세계를 올린다. lease는 한 번 사용하면 재사용할 수 없고 유지보수 상태는 자동으로 열리지 않는다. 일반 초기화 요청은 이미지 핀을 바꿀 수 없다.

이 API는 다음 증거를 **검사하지 않는다**: 동일 최신 main의 W0–W4, 실제 이미지 ID와 태그의 대응, 냉백업·격리 복원·인증 읽기, 외부 시나리오 바이트. 호출자는 그 증거를 독립 검증하고 같은 production lock 아래에서 옛 서비스를 멈춘 뒤 이 접점을 사용해야 한다. `promote-game-server.yml`을 먼저 실행하면 새 엔진이 옛 DB를 읽으므로 사용하지 않는다. 기존 `reset-game-server.yml`도 이 lease를 전달하지 않으므로 그대로 이어 실행할 수 없다.

초기화 중 실패는 기존 reset journal 및 `repair-required` 규칙에 따른다. 냉백업은 별도 검증된 bundle로 남겨야 하며, 실패 시 옛 엔진을 자동 재시작하지 않는다. 정확한 후보 이미지·시나리오 핀을 확인한 새 전환 실행기와 W4 검증기가 리뷰·병합되기 전에는 운영에서 이 접점을 호출하지 않는다.
