# API 조회 rate 제한 복구

상태: DRAFT / PENDING 독립리뷰. C0 명시 신호 후 실제 합성1회 완료, 현재 C/운영 반영 없음. [draft PR77](https://github.com/peppone-choi/opensamguk-docker/pull/77).

- GitHub: https://github.com/peppone-choi/opensamguk-docker/issues/76
- Jira: https://pepponechoi-jira.atlassian.net/browse/OPENSAM-362
- 담당: C0 배정 Docker owner 01a14994. 하네스 PR75와 별도 기능.
- 기반: Docker main 0a835164023d18c4cccbab8e1cd23448caacaa0e.

## 확인한 원인

C 소유 nginx image·nonce/session labels·read-only canonical config mount와 hash를 검산했다. 2026-10-17 14:15UTC 이후 api_limit 거절79/access50379, auth/me2·front-info2·visibility4·corps5·const5건이 양쪽에서 일치했다. C 추가 HTTP 요청/설정/DB/서비스 변경0이다. 기존 진단 JSON에는 본문이 없으므로 HTML을 직접 확인한 것으로 표시하지 않는다. 정본에 limit_req_status/error_page 재정의는 없고 nginx 기본 제한 status는503이다. backend admission8개/2초의 독립 영향은 미확정이다.

## C0 확정 복구 범위

일반 GET/HEAD는 per-IP 별도 api_read_limit:10m, rate10r/s·burst40·delay8을 사용한다. 초과8 이후 대기하고 초과40은 기본503으로 거절한다. 제한 대기 이론값은 약(40-8)/10=3.2초이며 실제 합성에서 지연과 거절을 확인한다.

그 외 POST/PATCH/PUT/DELETE/OPTIONS/기타 메서드는 기존 api_limit:10m·60r/m·burst20 nodelay를 유지한다. 로그인 POST도 이 bucket을 쓴다. 앞서 제안했던20r/s·burst80·delay20 및 auth GET 예외는 채택하지 않는다.

두 map은 활성 분류에 $binary_remote_addr, 비활성 분류에 빈 key를 반환한다. 기존 HTTP/TLS 제한10위치에 두 limit_req를 함께 명시한다. 상태코드/TLS/proxy/WS/routing/body cap/제품admission·timeout/USER Then/점수/현재C는 바꾸지 않는다.

## 구현과 검증

1. infra/nginx/nginx.conf: 위 map/zone과 기존10개 위치만 변경. 정적회귀는 메서드분류·두제한 동시적용·쓰기수치·기존status503·원canonical hash로 되돌린 정확한 diff범위를 검사한다.
2. scripts/test_nginx_api_rate_runtime.py: 별도nonce/label/network/container/loopback임시port와 이미설치된 nginx:1.30.5-alpine만 사용한다. canonical API location의 proxy_pass/limit_req는 보존하고 별도3000/8080 upstream HTTP listener로 실제 socket 프록시한다. API location return200 우회는 금지한다. 앱·C443·DB·기존자원·환경파일·이미지pull/build는 사용하지 않는다.
3. C0 명시 신호 뒤 atomic heavy를 취득해 HTTP/TLS 각각 같은32개 GET/HEAD fanout을 기존canonical→수리본에 보낸다. 기존은 실제limiter503이 있고수리본은모두fixture upstream200·queue지연을관측해야한다. 원본sourcehash·요청별원결과/시간/합성nginx로그를별도보존한다.
4. 수리본에서96개읽기폭주가bounded거절과지연을보이고,40개혼합쓰기(POST/PATCH/PUT/DELETE/OPTIONS) 및40개login POST폭주는계속거절되는지검사한다. 읽기/쓰기bucket상호독립·HTTP/TLS쓰기bucket공유를검증한다. 실제upstream503은marker를통해rate503과구분하고그대로보존해야한다. 제한status를바꾸거나실패를숨기지않는다.
5. scripts/test_nginx_api_rate.py 4개와기존campaign static5개,기존synthetic route451회귀를수행한다. 모든합성은auth/role/actualUSER성공으로세지않는다. 실패/미실행은그대로표시한다.
6. 검증완료후별도draftPR·attach·양티켓링크·정확head/원본hash/결과연결. 현재head 독립Claude 접근pending으로병합/C overlay/운영반영은하지않는다. Docker main의기능RED 복구PR만대상이며일반병합은중지상태다.

공식근거: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html (빈key제외·복수limit_req·상속·delay·기본503), https://nginx.org/en/docs/http/ngx_http_map_module.html (map분류).

## 실제 검증 결과

검증 코드 head dee0101a8025a49b3f6d2d6941e80699081bdd08, 원본 canonical hash f0507d5a8bf0ea90cb6cc722b2dde99c2e049c1d517605adbfe764b39721b5e7, 수리 config hash e2a4a6fa66cf4a2583b83f90a7d38c13c6e7dad02e163f6974fc6029f83f4268.

- 정적4+기존정적5 PASS. 실제 proxy 합성13검증 PASS, 기존route451 PASS. 실제합성은각1회이며재실행/기대값·timeout변경없음.
- 원본32fanout HTTP11/TLS10건이limiter503,수리본은양쪽32개전부upstream200. 수리본최대지연HTTP2.3055초/TLS2.5788초.
- 혼합쓰기40개와loginPOST40개는HTTP/TLS각19건씩거절. 읽기96폭주는HTTP53/TLS52건거절,최대3.4018초/4.1466초로지연도관측. 프로세스/전송시간을포함한벽시계값이며이론queue3.2초와같다고하지않음.
- 읽기/쓰기bucket독립·HTTP/TLS쓰기bucket공유·실제upstream503보존통과. 합성원본503HTML관측은현재C의미보존본문을직접관측한것으로확대하지않음.
- 자기합성container/network잔존0·자기heavy정상반환. C11healthy·6image·composehash·원nginxhash보존확인. C추가HTTP요청0·서비스/DB/설정변경0.
- 로컬원본: /Users/apple/Documents/Codex/2026-10-17/nginx-rate-01a14994-run1/result.json 및각case requests.json/nginx.log,existing-route-result.json/log,final-verification.json. 별도CI결과없음/독립Claude현재head리뷰pending. 합성을actualUSER/auth/rolePASS로세지않음.
