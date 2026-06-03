// deployer — opensamguk 멀티서버 버전 bounce 배포 사이드카.
//
// 책임:
//   - GET  /status?project=<p> : 그 서버 env 파일의 IMAGE_TAG + (best-effort) GHCR 가용 태그.
//   - POST /deploy             : 서버 env 파일 IMAGE_TAG 치환 후 스테이트리스(game-api, web-game)만 bounce.
//
// 불변 규칙:
//   - game-engine은 절대 건드리지 않는다(진행 중 desync 방지). bounce 대상은 스테이트리스만.
//   - docker 접근은 socket-proxy 경유(DOCKER_HOST). docker.sock 직접 접근 없음.
//   - 모든 입력(project/tag)은 화이트리스트 정규식으로 검증(주입 방지).
//   - 외부 의존 0 — stdlib만.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// 입력 검증용 화이트리스트 정규식.
var (
	// 프로젝트명 — opensamguk-s<id>만 허용. <id>는 영숫자/언더스코어/하이픈.
	projectRe = regexp.MustCompile(`^opensamguk-s[a-zA-Z0-9_-]+$`)
	// 이미지 태그 — 도커 태그 문자셋(영숫자/점/언더스코어/하이픈).
	tagRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// env 파일에서 IMAGE_TAG= 행을 찾고 교체하기 위한 패턴(멀티라인, 행 단위).
	imageTagLineRe = regexp.MustCompile(`(?m)^IMAGE_TAG=.*$`)
)

// 스테이트리스 bounce 대상 — game-engine은 의도적으로 제외.
var statelessServices = []string{"game-api", "web-game"}

// 환경변수 묶음.
type config struct {
	token         string // Bearer 인증 토큰
	composeDir    string // compose 파일 디렉터리(/workspace)
	serversDir    string // 서버 env 파일 디렉터리(/workspace/servers)
	composeServer string // 서버 compose 파일 절대경로
	ghcrOwner     string // GHCR 패키지 소유자(태그 조회)
	ghcrToken     string // GHCR 조회 토큰(private면 필요, 없으면 익명)
}

func loadConfig() config {
	c := config{
		token:         os.Getenv("DEPLOYER_TOKEN"),
		composeDir:    envOr("COMPOSE_DIR", "/workspace"),
		serversDir:    envOr("SERVERS_DIR", "/workspace/servers"),
		composeServer: envOr("COMPOSE_SERVER_FILE", "/workspace/docker-compose.server.yml"),
		ghcrOwner:     envOr("GHCR_OWNER", "peppone-choi"),
		ghcrToken:     os.Getenv("GHCR_TOKEN"),
	}
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// 서버 env 파일 절대경로 — project명에서 servers/<id>.env 로 매핑.
// 예: opensamguk-s1 → servers/s1.env
func (c config) envFileFor(project string) string {
	id := strings.TrimPrefix(project, "opensamguk-")
	return filepath.Join(c.serversDir, id+".env")
}

// --- 응답 타입 ---

type statusResponse struct {
	Project       string   `json:"project"`
	CurrentTag    string   `json:"currentTag"`
	AvailableTags []string `json:"availableTags"`
}

type deployRequest struct {
	Project string `json:"project"`
	Tag     string `json:"tag"`
}

type deployResponse struct {
	Project string `json:"project"`
	Tag     string `json:"tag"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	cfg := loadConfig()
	if cfg.token == "" {
		log.Fatal("DEPLOYER_TOKEN 미설정 — 인증 토큰 필수")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "up"})
	})
	mux.HandleFunc("/status", cfg.withAuth(cfg.handleStatus))
	mux.HandleFunc("/deploy", cfg.withAuth(cfg.handleDeploy))

	srv := &http.Server{
		Addr:              ":9000",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Println("deployer 리스닝 :9000")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// Bearer 토큰 검증 미들웨어.
func (c config) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		want := "Bearer " + c.token
		// 길이 동일 비교를 위한 단순 상수시간성 보강(stdlib subtle 회피, 외부의존 0 유지).
		if len(auth) != len(want) || !secureEqual(auth, want) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "인증 실패"})
			return
		}
		next(w, r)
	}
}

// 길이 동일한 두 문자열의 상수시간 비교.
func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// GET /status?project=<p>
func (c config) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	project := r.URL.Query().Get("project")
	if !projectRe.MatchString(project) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "잘못된 project — opensamguk-s<id> 형식만 허용"})
		return
	}

	currentTag, err := c.readImageTag(project)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: fmt.Sprintf("env 파일 읽기 실패: %v", err)})
		return
	}

	// best-effort — 실패해도 빈 배열로 반환(상태 조회는 막지 않음).
	tags := c.fetchAvailableTags()

	writeJSON(w, http.StatusOK, statusResponse{
		Project:       project,
		CurrentTag:    currentTag,
		AvailableTags: tags,
	})
}

// POST /deploy {"project":"opensamguk-s1","tag":"v1.3.0"}
func (c config) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body 읽기 실패"})
		return
	}
	var req deployRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
		return
	}

	// 주입 방지 — project/tag 둘 다 화이트리스트 통과해야 함.
	if !projectRe.MatchString(req.Project) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "잘못된 project — opensamguk-s<id> 형식만 허용"})
		return
	}
	if !tagRe.MatchString(req.Tag) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "잘못된 tag — [A-Za-z0-9._-]만 허용"})
		return
	}

	envFile := c.envFileFor(req.Project)
	if _, err := os.Stat(envFile); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: fmt.Sprintf("env 파일 없음: %s", envFile)})
		return
	}

	// 1) 서버 env 파일의 IMAGE_TAG 치환.
	if err := c.writeImageTag(req.Project, req.Tag); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("IMAGE_TAG 치환 실패: %v", err)})
		return
	}

	// 2) 스테이트리스만 pull → up -d --no-deps (game-engine 제외).
	detail, err := c.bounceStateless(req.Project, envFile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deployResponse{
			Project: req.Project, Tag: req.Tag, OK: false, Detail: detail,
		})
		return
	}

	writeJSON(w, http.StatusOK, deployResponse{
		Project: req.Project, Tag: req.Tag, OK: true, Detail: detail,
	})
}

// 서버 env 파일에서 IMAGE_TAG= 값을 읽는다.
func (c config) readImageTag(project string) (string, error) {
	envFile := c.envFileFor(project)
	data, err := os.ReadFile(envFile)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "IMAGE_TAG=") {
			return strings.TrimPrefix(line, "IMAGE_TAG="), nil
		}
	}
	return "", fmt.Errorf("IMAGE_TAG 행 없음")
}

// 서버 env 파일의 IMAGE_TAG= 행을 새 태그로 치환. 행이 없으면 추가.
func (c config) writeImageTag(project, tag string) error {
	envFile := c.envFileFor(project)
	data, err := os.ReadFile(envFile)
	if err != nil {
		return err
	}
	newLine := "IMAGE_TAG=" + tag
	var out string
	if imageTagLineRe.Match(data) {
		out = imageTagLineRe.ReplaceAllString(string(data), newLine)
	} else {
		// 행이 없으면 끝에 추가(개행 보장).
		s := string(data)
		if len(s) > 0 && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		out = s + newLine + "\n"
	}
	// 원자적 쓰기 — 임시 파일 후 rename.
	tmp := envFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, envFile)
}

// 스테이트리스 서비스만 pull 후 up -d --no-deps. game-engine은 절대 미포함.
func (c config) bounceStateless(project, envFile string) (string, error) {
	var sb strings.Builder

	// docker compose -p <project> --env-file <env> -f <server.yml> pull <svc...>
	pullArgs := append([]string{
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"pull",
	}, statelessServices...)
	if out, err := c.runDocker(pullArgs...); err != nil {
		sb.WriteString("=== pull 실패 ===\n")
		sb.WriteString(out)
		return sb.String(), err
	} else {
		sb.WriteString("=== pull ===\n")
		sb.WriteString(out)
	}

	// docker compose -p <project> --env-file <env> -f <server.yml> up -d --no-deps <svc...>
	upArgs := append([]string{
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"up", "-d", "--no-deps",
	}, statelessServices...)
	if out, err := c.runDocker(upArgs...); err != nil {
		sb.WriteString("\n=== up 실패 ===\n")
		sb.WriteString(out)
		return sb.String(), err
	} else {
		sb.WriteString("\n=== up ===\n")
		sb.WriteString(out)
	}

	return sb.String(), nil
}

// docker CLI 실행 — DOCKER_HOST는 환경에서 상속(socket-proxy). stdout+stderr 합쳐 반환.
func (c config) runDocker(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = c.composeDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// GHCR 공개 패키지 태그 목록(best-effort). 실패 시 빈 슬라이스.
// 미해결 가정: private 패키지면 GHCR_TOKEN(read:packages) 필요. 없으면 익명 → 비공개는 빈 배열.
func (c config) fetchAvailableTags() []string {
	tags := []string{}
	// GHCR(GitHub Packages) container 태그는 GitHub REST API로 조회.
	// game-api 패키지 기준 대표 조회(앱 이미지는 같은 태그로 함께 푸시된다고 가정).
	url := fmt.Sprintf(
		"https://api.github.com/users/%s/packages/container/game-api/versions?per_page=50",
		c.ghcrOwner,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return tags
	}
	reqHTTP.Header.Set("Accept", "application/vnd.github+json")
	reqHTTP.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.ghcrToken != "" {
		reqHTTP.Header.Set("Authorization", "Bearer "+c.ghcrToken)
	}
	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return tags
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tags
	}
	var versions []struct {
		Metadata struct {
			Container struct {
				Tags []string `json:"tags"`
			} `json:"container"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return tags
	}
	seen := map[string]bool{}
	for _, v := range versions {
		for _, t := range v.Metadata.Container.Tags {
			if !seen[t] {
				seen[t] = true
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// JSON 응답 헬퍼.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
