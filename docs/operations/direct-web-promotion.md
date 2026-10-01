# 기존 control에서 웹 단독 승격

## 준비 상태

소스와 격리 fixture 검증 단계다. 운영 실행·maintenance 변경·후보 pull·웹 재생성은 아직 하지 않았다. 실제 발급 artifact와 native 후보 검사가 같은 source/platform/config digest임을 확인하고 대상 승인을 받은 뒤에만 실행한다. 기본 실행은 Docker 호출이 없는 `PLAN_ONLY_NOT_EXECUTED`다.

## 승인과 핀

입력은 실행 카드, 발급 후보, 실제 후보 검사 artifact, 옛 이미지의 레지스트리 조회 artifact다. 카드가 각 파일과 executor 소스의 SHA256을 고정한다. `pep`, world1, generation1, 실제 control 컨테이너·시작 시각·binary SHA, Compose SHA, 원본 선택 키와 옛 웹 컨테이너가 모두 맞아야 한다. 승인 범위는 웹 한 서비스와 그 창의 admission뿐이다. API·engine·DB·다른 컨테이너를 바꾸는 명령은 없다.

옛 이미지는 원본 WEB_GAME_TAG, 실제 RepoDigest, 레지스트리 manifest 원문 SHA, manifest의 config digest, linux/amd64, 로컬 원본 태그의 이미지 가용성을 각각 확인한다. Docker `imageId`는 런타임과 로컬 이미지 대조에만 쓴다. manifest/config digest로 치환하지 않는다. 복원은 이미 있는 정확한 옛 로컬 이미지로 하고 pull하지 않는다.

운영 실행에는 카드의 `maintenanceApproval`이 정확한 작업 목록을 승인해야 한다. 카드와 승인 기록은 C0가 실제 사용자 승인으로 채운다. fixture의 승인 문자열은 운영 승인이 아니다.

## 동작

1. `/tmp/opensamguk-production.lock`을 비차단으로 잡는다. 기존 receipt·maintenance marker·lifecycle journal이 있으면 진입하지 않는다.
2. 현재 `/maintenance`가 open이며 원본 identity·pin·이미지·소스가 같은지 확인한다. private receipt를 먼저 fsync한다.
3. 기존 control의 `/maintenance/enter-if-idle`만 호출한다. 새 응답의 admission token은 0600 receipt 안에만 저장한다. control identity와 새 marker inode/dev/mtime/ctime를 함께 기록한다.
4. 승인된 후보 tag@platform digest만 pull한다. WEB_GAME_TAG 한 행을 CAS로 바꾼다. 나머지 행은 해석·출력 없이 그대로 복사하며 소유자·권한과 줄바꿈을 보존한다.
5. native `config --images`에서 웹 이미지 하나만 달라졌음을 확인한다. `up -d --no-deps --pull never --force-recreate web-game`만 실행한다.
6. 실제 Config.Image, 로컬 이미지·RepoDigest·platform, running 상태와 `/api/health`를 확인한다. API·engine·DB·다른 컨테이너 전체 baseline도 다시 맞아야 한다.
7. 성공은 `CANDIDATE_VERIFIED_DRAINED`다. 같은 프로세스의 실패는 ownership·env CAS가 유지될 때만 원래 WEB_GAME_TAG와 로컬 옛 웹을 복원하며 `OLD_VERIFIED_DRAINED`로 남긴다. 두 경우 모두 창을 유지한다.

## 중단과 복구

- marker 파일에는 durable token이 없고 control 재시작 시 admission lease가 사라진다. marker 존재만으로 소유를 주장하지 않는다.
- control 컨테이너·시작 시각·binary, marker identity, lifecycle journal 또는 다른 컨테이너 baseline이 바뀌면 그대로 중단한다. 다른 창의 leave·repair·재진입·marker 삭제는 하지 않는다.
- entry timeout 또는 `ENTER_PENDING`에서 중단되면 소유를 확인할 수 없다. 자동 복구하지 않고 C0가 새 대상 복구 카드를 준비한다.
- pin 직후 프로세스가 죽어 receipt 갱신을 못 했어도 동일 control/marker를 확인할 수 있는 창은 `--recovery-approval`로 옛 웹을 복원할 수 있다. 현재 receipt SHA와 선택 env·파일 identity를 별도 대상 승인에 고정해야 한다. 완료 후에도 drained다.
- 기존 `/maintenance/leave`는 서버 측 lease CAS를 하지 않는다. `--finish-approval`에는 현재 receipt SHA, 원 실행 카드 SHA 및 이 위험의 명시적 확인이 필요하다. 같은 창·검증 완료 단계·웹/핀·소스를 다시 검사한 뒤에만 leave한다. 호출 결과가 불확실하면 자동 재시도하지 않는다.
- 이 client 검사는 서버 측 원자적 lease CAS를 제공하지 않는다. 독립 관리자의 동시 강제 해제·재진입을 배제할 수 없는 창은 finish를 승인하지 않는다. 해당 한계가 남으면 A02를 READY로 보고하지 않는다.

## 이후 배포

WEB_GAME_TAG 핀은 Compose가 재시작과 평소 공유 배포에서 소비한다. 기존 control의 일반 `/deploy`는 IMAGE_TAG와 WEB_GAME_TAG를 함께 치환하고 reset도 웹 핀을 바꿀 수 있으므로, 모든 미래 작업이 새 웹 핀을 보존한다고 주장하지 않는다. 다음 일반 서버 deploy/reset에는 별도 대상 승인과 핀 확인이 필요하다.

## 소스 검증

`python3 -m unittest discover -s scripts -p test_direct_web_promotion.py -v`는 임시 파일과 가짜 Docker 경계만 사용한다. 실제 운영 적용이나 native 후보 검사 근거가 아니다. 적색 변이는 메타 evidence의 임시 전체 사본에서 실행한다. 새 PR 번호 전용 workflow/helper를 제품에 추가하지 않는다.
