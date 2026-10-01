# Web 후보의 hosted pull·Config.Image 검증 준비

이 도구는 아직 운영 경로에 연결되지 않은 source 준비다. 기본 실행은 plan만 만든다.
실 Docker 실행에는 별도 승인이 필요하며, 실제 후보 발급·source 검토가 먼저다.
PR61의 digest 저장·recovery 코드와 C9의 발급 workflow를 변경하지 않는다.

## 입력과 승인

`candidate.json`은 C9의 성공 `VERIFIED_CANDIDATE` artifact 원본이어야 한다.
승인 record는 `web-game-image-probe-approval/v1` schema, target
`github-hosted-ephemeral`, 원본 candidate SHA256, 이 probe 소스 SHA256,
승인 source/issuer40 SHA·발급 run/attempt·platform manifest/config digest를 담는다.
operations는 `pull`, `create-not-start`, `inspect-selected`,
`remove-own-created-container`이며 `operating_actions_authorized=false`다.
`execution_authorized`는 이번 source 준비에서 false다. 실제 수행 승인이 있을 때만 true다.
임의 fixture의 true는 실제 승인이 아니다.

승인된 source는 cf7이며 candidate/index/platform/config/attestation 및 buildargs를
원본 artifact hash에 함께 묶는다. source40과 nominal tag가 같다고 provenance를 대신하지 않는다.
새 C9 issuer guard가 추가되면 새 head/CI/독립 리뷰로 issuer와 candidate를 다시 고정한다.

## 미래 hosted 실행 계약 — 현재 미실행

`scripts/web_game_candidate_probe.py`는 기본 plan-only다. `--execute-hosted`는
위 승인 및 `CI=true`, `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`를 요구한다.
이는 잘못된 실행을 막는 조건이며 운영 접근 권한을 부여하는 기능이 아니다.
[GitHub runner 변수 정본](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

미래 invocation의 입력은 `--candidate <승인 artifact> --approval <승인 record>
--output <새 evidence 파일>`다. source 준비 중에 execute flag를 사용하지 않는다.
발급/검증 workflow에 연결하려면 도구 전달·호출 위치·고정 source/hash 및 ephemeral
runner 자원을 별도 source 검토/승인해야 한다. 지금 등록 가능한 새 workflow는 만들지 않았다.

1. 승인 candidate/source/issuer/run/OCI 종류·pin을 Docker 호출 전 검사한다.
2. fresh CLI config와 고정 local Unix socket만 사용한다. inherited Docker context,
   DOCKER_HOST, GHCR/GITHUB token·기존 credential 파일을 전달하지 않는다.
   공개 후보를 익명 pull할 수 없으면 실패하며 추가 auth로 fallback하지 않는다.
3. `repo:web-game-cf7@<platform-manifest>`를 linux/amd64로 pull한다.
   선택 metadata의 RepoDigest/platform/OCI source labels와 Docker ID를 비교한다.
   Docker ID가 config ID인 store와 manifest ID인 store를 분리해 기록하며 다른 mapping은 거절한다.
4. nonce name/label·network none·read-only·mount/env 주입 없음으로 컨테이너를 **create만** 한다.
   start/run/Compose up 호출은 없다. `.Image`는 방금 pull한 ID,
   `.Config.Image`는 PR61이 요구하는 tag@digest **정확한 문자열**이어야 한다.
   Docker가 digest-only로 정규화하면 이 관문은 적색이며 지원 완료로 표시하지 않는다.
5. 선택 metadata만 저장하고, ownership label·name·미기동 상태가 같은
   자기 컨테이너 ID만 rm한다. force/prune·다른 object 삭제 없음.
   부분 create 실패에도 자기 object만 정리하며 cleanup 실패도 PASS가 아니다.

## 결과의 한계

이 결과는 hosted ephemeral Docker의 실제 image reference 계약 증거다.
운영 control identity·old imageID/config·journal·cross-version repair/rollback,
운영 Docker/Compose 버전·world/generation을 증명하지 않는다. 해당 값은 UNKNOWN을 유지한다.
기존 rollback reference는 plan에 기록만 하고 이 후보 probe에서 pull/create하지 않는다.
운영 rollback과 old control downgrade 지원은 아직 별도 검증·승인 대상이다.
새 후보의 lab404·실제 pep 행동과 서비스 승격도 별도다.

현재 source/fake-command 시험만 수행했으며 Docker/registry/VM 실제 호출은 없다.
`python3 -B -m unittest discover -s scripts -p 'test_web_game_candidate_probe.py' -v`는
정확한 command와 admission·wrong digest/Config.Image·ownership·cleanup·metadata 투영을
가짜 runner로 검사한다. 실제 pull 성공이나 Go template/Docker 버전 호환 검증으로 세지 않는다.
