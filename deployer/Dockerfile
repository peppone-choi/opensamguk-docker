# deployer 사이드카 — 멀티스테이지.
# 1) golang:1.23-alpine에서 정적 바이너리 빌드.
# 2) docker:27-cli(compose v2 포함) 런타임에 바이너리만 COPY.
#    런타임은 docker compose 명령을 socket-proxy(DOCKER_HOST) 경유로 실행.

# --- 빌드 스테이지 ---
FROM golang:1.23-alpine AS build
WORKDIR /src
# go.mod만 먼저 복사(외부 의존 0 — go.sum 불필요). 레이어 캐시 활용.
COPY go.mod ./
COPY main.go ./
# CGO 끈 정적 바이너리(런타임 alpine에서 그대로 동작).
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/deployer .

# --- 런타임 스테이지 ---
# docker:27-cli 이미지에는 docker CLI + compose v2 플러그인이 포함된다.
FROM docker:27-cli
# 빌드한 정적 바이너리만 가져온다.
COPY --from=build /out/deployer /usr/local/bin/deployer
# compose 파일/서버 env는 호스트에서 /workspace로 마운트(compose.shared.yml 참조).
WORKDIR /workspace
EXPOSE 9000
# docker 접근은 DOCKER_HOST(tcp://socket-proxy:2375)로 — sock 직접 마운트 없음.
ENTRYPOINT ["/usr/local/bin/deployer"]
