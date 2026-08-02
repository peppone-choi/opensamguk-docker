// deployer — opensamguk 멀티서버 버전 bounce 배포 사이드카.
//
// 책임:
//   - GET  /status?project=<p> : 그 서버 env 파일의 IMAGE_TAG + (best-effort) GHCR 가용 태그.
//   - POST /deploy             : 서버 env 파일 IMAGE_TAG/WEB_GAME_TAG 치환 후 스테이트리스만 bounce.
//
// 불변 규칙:
//   - game-engine은 절대 건드리지 않는다(진행 중 desync 방지). bounce 대상은 스테이트리스만.
//   - docker 접근은 socket-proxy 경유(DOCKER_HOST). docker.sock 직접 접근 없음.
//   - 모든 입력(project/tag)은 화이트리스트 정규식으로 검증(주입 방지).
//   - 외부 의존 0 — stdlib만.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 입력 검증용 화이트리스트 정규식.
var (
	// 프로젝트명 — opensamguk-s<public id>만 허용. 내부 key의 s는 여기서만 보인다.
	projectRe = regexp.MustCompile(`^opensamguk-s[a-z0-9]+$`)
	// Public server id. The Docker-only key is always synthesized as s<public id>.
	serverIDRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	// Internal server key used only for Docker resources and server env filenames.
	internalServerKeyRe = regexp.MustCompile(`^s[a-z0-9]+$`)
	// 이미지 태그 — 도커 태그 문자셋(영숫자/점/언더스코어/하이픈).
	tagRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// 스테이트리스 bounce 대상 — game-engine은 의도적으로 제외.
var statelessServices = envList("DEPLOYER_STATELESS_SERVICES", []string{"game-api", "web-game"})
var requiredPromoteImagePrefixes = []string{"game-api-", "game-engine-", "web-game-"}
var sharedEnvServices = envList("DEPLOYER_SHARED_ENV_SERVICES", []string{"gateway-api", "web-gateway", "nginx", "deployer"})
var sharedRegistryReloadServices = envList("DEPLOYER_SHARED_REGISTRY_RELOAD_SERVICES", []string{"gateway-api", "web-gateway", "nginx"})
var reservedPublicServerIDs = map[string]struct{}{
	"all": {},
}
var reservedGameRouteIDs = map[string]struct{}{
	"admin1":           {},
	"admin2":           {},
	"admin5":           {},
	"admin7":           {},
	"admin8":           {},
	"auction":          {},
	"battle-center":    {},
	"betting":          {},
	"board":            {},
	"chief-center":     {},
	"city":             {},
	"coming-soon":      {},
	"diplomacy":        {},
	"generals":         {},
	"global-diplomacy": {},
	"history":          {},
	"inherit":          {},
	"join":             {},
	"mailbox":          {},
	"main":             {},
	"map":              {},
	"my":               {},
	"my-boss":          {},
	"my-cities":        {},
	"my-generals":      {},
	"my-nation":        {},
	"nation":           {},
	"nation-betting":   {},
	"nation-finance":   {},
	"npc-control":      {},
	"rankings":         {},
	"register":         {},
	"select-pool":      {},
	"simulator":        {},
	"tournament":       {},
	"tournament-admin": {},
	"troop":            {},
	"vote":             {},
	"world-log":        {},
}

var serverEnvAllowlist = map[string]envFieldSpec{
	"IMAGE_TAG":                  {Description: "게임 서버 이미지 태그"},
	"GAME_API_PORT":              {Description: "game-api 호스트 포트"},
	"WEB_GAME_PORT":              {Description: "web-game 호스트 포트"},
	"WEB_GAME_TAG":               {Description: "web-game 이미지 태그"},
	"TURN_PROFILE_NAME":          {Description: "턴 프로필"},
	"SCENARIO_SEED_ENABLED":      {Description: "시나리오 자동 시드 활성화"},
	"SCENARIO_CODE":              {Description: "시드할 시나리오 코드"},
	"SERVER_NAME":                {Description: "서버 이름"},
	"SERVER_GENERATION":          {Description: "서버 기수"},
	"GAME_API_URL":               {Description: "game-api 내부 URL"},
	"GATEWAY_API_URL":            {Description: "gateway-api 내부 URL"},
	"JWT_SECRET":                 {Description: "JWT 검증 시크릿", WriteOnly: true},
	"RESET_TURNTERM":             {Description: "리셋: 턴 시간(분)"},
	"RESET_SYNC":                 {Description: "리셋: 시간 동기화"},
	"RESET_FICTION":              {Description: "리셋: NPC 상성"},
	"RESET_EXTEND":               {Description: "리셋: 확장 NPC"},
	"RESET_BLOCK_GENERAL_CREATE": {Description: "리셋: 장수 임의 생성"},
	"RESET_NPCMODE":              {Description: "리셋: NPC 빙의"},
	"RESET_SHOW_IMG_LEVEL":       {Description: "리셋: 이미지 표기"},
	"RESET_AUTORUN_USER_OPTIONS": {Description: "리셋: 휴식 턴 시 장수 턴"},
	"RESET_AUTORUN_USER_MINUTES": {Description: "리셋: 자동 행동 유효 시간"},
	"RESET_JOIN_MODE":            {Description: "리셋: 임관 모드"},
	"RESET_TOURNAMENT_TRIG":      {Description: "리셋: 토너먼트 자동 시작"},
	"RESET_RESERVE_OPEN":         {Description: "리셋: 오픈 예약"},
	"RESET_PRE_RESERVE_OPEN":     {Description: "리셋: 가오픈 예약"},
}

var sharedEnvAllowlist = map[string]envFieldSpec{
	"IMAGE_TAG":               {Description: "공유 스택 이미지 태그"},
	"NGINX_HTTP_PORT":         {Description: "nginx HTTP 호스트 포트"},
	"NGINX_HTTPS_PORT":        {Description: "nginx HTTPS 호스트 포트"},
	"NEXT_PUBLIC_GATEWAY_URL": {Description: "게이트웨이 공개 URL"},
	"NEXT_PUBLIC_IMAGE_CDN":   {Description: "이미지 CDN URL"},
	"COOKIE_SECURE":           {Description: "Secure 쿠키 사용 여부"},
	"JWT_SECRET":              {Description: "JWT 발급 시크릿", WriteOnly: true},
	"ADMIN_PASSWORD":          {Description: "초기 관리자 비밀번호", WriteOnly: true},
	"GHCR_TOKEN":              {Description: "GHCR 조회 토큰", WriteOnly: true},
}

// 환경변수 묶음.
type config struct {
	token                  string // Bearer 인증 토큰
	composeDir             string // compose 파일 디렉터리(/workspace)
	serversDir             string // 서버 env 파일 디렉터리(/workspace/servers)
	composeServer          string // 서버 compose 파일 절대경로
	composeShared          string
	ghcrOwner              string // GHCR 패키지 소유자(태그 조회)
	ghcrToken              string // GHCR 조회 토큰(private면 필요, 없으면 익명)
	ghcrAPIBaseURL         string
	dockerRunner           func(args ...string) (string, error)
	gameAPIInternalPort    string
	gameEngineInternalPort string
	gatewayAPIURL          string
}

func loadConfig() config {
	c := config{
		token:                  os.Getenv("DEPLOYER_TOKEN"),
		composeDir:             envOr("COMPOSE_DIR", "/workspace"),
		serversDir:             envOr("SERVERS_DIR", "/workspace/servers"),
		composeServer:          envOr("COMPOSE_SERVER_FILE", "/workspace/docker-compose.server.yml"),
		composeShared:          envOr("COMPOSE_SHARED_FILE", "/workspace/docker-compose.shared.yml"),
		ghcrOwner:              envOr("GHCR_OWNER", "peppone-choi"),
		ghcrToken:              os.Getenv("GHCR_TOKEN"),
		ghcrAPIBaseURL:         envOr("DEPLOYER_GHCR_API_BASE_URL", "https://api.github.com"),
		gameAPIInternalPort:    envOr("DEPLOYER_GAME_API_INTERNAL_PORT", "8081"),
		gameEngineInternalPort: envOr("DEPLOYER_GAME_ENGINE_INTERNAL_PORT", "8082"),
		gatewayAPIURL:          envOr("DEPLOYER_GATEWAY_API_URL", "http://gateway-api:8080"),
	}
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envList(key string, def []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return def
	}
	return values
}

func internalServerKey(publicID string) string {
	return "s" + publicID
}

func projectForServerID(publicID string) string {
	return "opensamguk-" + internalServerKey(publicID)
}

func (c config) gameAPIURLFor(publicID string) string {
	return "http://" + internalServerKey(publicID) + "-game-api:" + envOrValue(c.gameAPIInternalPort, "8081")
}

func (c config) gameEngineURLFor(publicID string) string {
	return "http://" + internalServerKey(publicID) + "-game-engine:" + envOrValue(c.gameEngineInternalPort, "8082")
}

func (c config) defaultGatewayAPIURL() string {
	return envOrValue(c.gatewayAPIURL, "http://gateway-api:8080")
}

// 서버 env 파일 절대경로 — internal project명에서 servers/s<public id>.env 로 매핑.
// 예: opensamguk-spep → servers/spep.env
func (c config) envFileFor(project string) string {
	internalKey := strings.TrimPrefix(project, "opensamguk-")
	return filepath.Join(c.serversDir, internalKey+".env")
}

func (c config) sharedEnvFile() string {
	return filepath.Join(c.composeDir, ".env")
}

func (c config) serverEnvFileForID(publicID string) string {
	return filepath.Join(c.serversDir, internalServerKey(publicID)+".env")
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

type envPatchRequest struct {
	Values map[string]string `json:"values"`
}

type createServerRequest struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Generation          string `json:"generation"`
	ImageTag            string `json:"imageTag"`
	GameAPIPort         string `json:"gameApiPort"`
	WebGamePort         string `json:"webGamePort"`
	ScenarioCode        string `json:"scenarioCode"`
	ScenarioSeedEnabled *bool  `json:"scenarioSeedEnabled"`
	JWTSecret           string `json:"jwtSecret"`
}

type resetServerRequest struct {
	ID                  string   `json:"id"`
	Confirm             string   `json:"confirm"`
	Generation          string   `json:"generation"`
	ScenarioCode        string   `json:"scenarioCode"`
	ScenarioSeedEnabled *bool    `json:"scenarioSeedEnabled"`
	TurnTerm            string   `json:"turnTerm"`
	Sync                string   `json:"sync"`
	Fiction             string   `json:"fiction"`
	Extend              string   `json:"extend"`
	BlockGeneralCreate  string   `json:"blockGeneralCreate"`
	NPCMode             string   `json:"npcMode"`
	ShowImgLevel        string   `json:"showImgLevel"`
	AutorunUserOptions  []string `json:"autorunUserOptions"`
	AutorunUserMinutes  string   `json:"autorunUserMinutes"`
	JoinMode            string   `json:"joinMode"`
	TournamentTrig      string   `json:"tournamentTrig"`
	ReserveOpen         string   `json:"reserveOpen"`
	PreReserveOpen      string   `json:"preReserveOpen"`
}

type createServerResponse struct {
	OK               bool     `json:"ok"`
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Project          string   `json:"project"`
	RestartRequired  bool     `json:"restartRequired"`
	AffectedServices []string `json:"affectedServices"`
	Detail           string   `json:"detail"`
}

type registryEntry struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Generation    int               `json:"generation"`
	ScenarioCode  string            `json:"scenarioCode,omitempty"`
	GameAPIURL    string            `json:"gameApiUrl"`
	GameEngineURL string            `json:"gameEngineUrl"`
	DeployProject string            `json:"deployProject"`
	Env           map[string]string `json:"env,omitempty"`
}

type envResponse struct {
	OK               bool                `json:"ok"`
	Scope            string              `json:"scope"`
	ID               string              `json:"id,omitempty"`
	RestartRequired  bool                `json:"restartRequired"`
	AffectedServices []string            `json:"affectedServices"`
	Fields           map[string]envField `json:"fields"`
}

type envField struct {
	Key        string         `json:"key"`
	Value      *string        `json:"value"`
	Configured bool           `json:"configured"`
	WriteOnly  bool           `json:"writeOnly"`
	Masked     bool           `json:"masked"`
	Metadata   map[string]any `json:"metadata"`
}

type envFieldSpec struct {
	Description string
	WriteOnly   bool
}

type envLine struct {
	Raw   string
	Key   string
	Value string
	IsKV  bool
}

func main() {
	cfg := loadConfig()
	if len(os.Args) == 2 && os.Args[1] == "--check-registry" {
		os.Exit(checkRegistryCommand(cfg, os.Stderr))
	}
	if len(os.Args) != 1 {
		log.Fatal("usage: deployer [--check-registry]")
	}
	if cfg.token == "" {
		log.Fatal("DEPLOYER_TOKEN 미설정 — 인증 토큰 필수")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "up"})
	})
	mux.HandleFunc("/readyz", cfg.handleReady)
	mux.HandleFunc("/status", cfg.withAuth(cfg.handleStatus))
	mux.HandleFunc("/deploy", cfg.withAuth(cfg.handleDeploy))
	mux.HandleFunc("/servers", cfg.withAuth(cfg.handleServers))
	mux.HandleFunc("/servers/create", cfg.withAuth(cfg.handleServerCreate))
	mux.HandleFunc("/servers/close", cfg.withAuth(cfg.handleServerClose))
	mux.HandleFunc("/servers/reset", cfg.withAuth(cfg.handleServerReset))
	mux.HandleFunc("/env/shared", cfg.withAuth(cfg.handleSharedEnv))
	mux.HandleFunc("/env/server", cfg.withAuth(cfg.handleServerEnv))

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

func checkRegistryCommand(c config, output io.Writer) int {
	if _, err := c.readRegistry(); err != nil {
		fmt.Fprintln(output, "registry validation failed")
		return 1
	}
	fmt.Fprintln(output, "registry validation passed")
	return 0
}

func (c config) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	if _, err := c.readRegistry(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: fmt.Sprintf("레지스트리 준비 실패: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
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

	tempEnvFile, cleanup, err := c.tempImageTagEnvFile(envFile, req.Tag)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("임시 env 생성 실패: %v", err)})
		return
	}
	defer cleanup()

	detail, err := c.pullStateless(req.Project, tempEnvFile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deployResponse{
			Project: req.Project, Tag: req.Tag, OK: false, Detail: detail,
		})
		return
	}

	if err := c.writeImageTag(req.Project, req.Tag); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("IMAGE_TAG/WEB_GAME_TAG 치환 실패: %v", err)})
		return
	}

	upDetail, err := c.upStateless(req.Project, envFile)
	detail += "\n" + upDetail
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

func (c config) handleServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		registry, err := c.readRegistry()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("레지스트리 조회 실패: %v", err)})
			return
		}
		writeJSON(w, http.StatusOK, registry)
	case http.MethodPost:
		c.handleServerCreate(w, r)
	case http.MethodDelete:
		res, status := c.deleteServer(r.URL.Query().Get("id"), r.URL.Query().Get("confirm"))
		writeJSON(w, status, res)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET/POST/DELETE only"})
	}
}

func (c config) handleServerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body 읽기 실패"})
		return
	}
	var req createServerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
		return
	}
	res, status := c.createServer(req)
	writeJSON(w, status, res)
}

func (c config) handleServerClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body 읽기 실패"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
		return
	}
	id, _, err := normalizeCreateServerID(req.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, createServerResponse{OK: false, Detail: err.Error()})
		return
	}
	res, status := c.deleteServer(id, "DELETE "+id)
	writeJSON(w, status, res)
}

func (c config) handleServerReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body 읽기 실패"})
		return
	}
	var req resetServerRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
			return
		}
	}
	rawID := r.URL.Query().Get("id")
	if rawID == "" {
		rawID = req.ID
	}
	res, status := c.resetServer(rawID, req)
	writeJSON(w, status, res)
}

func (c config) handleSharedEnv(w http.ResponseWriter, r *http.Request) {
	c.handleEnv(w, r, envRequestContext{
		scope:            "shared",
		path:             c.sharedEnvFile(),
		allowlist:        sharedEnvAllowlist,
		affectedServices: sharedEnvServices,
	})
}

func (c config) handleServerEnv(w http.ResponseWriter, r *http.Request) {
	id, _, err := normalizeCreateServerID(r.URL.Query().Get("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	c.handleEnv(w, r, envRequestContext{
		scope:            "server",
		id:               id,
		path:             c.serverEnvFileForID(id),
		allowlist:        serverEnvAllowlist,
		affectedServices: statelessServices,
	})
}

type envRequestContext struct {
	scope            string
	id               string
	path             string
	allowlist        map[string]envFieldSpec
	affectedServices []string
}

func (c config) handleEnv(w http.ResponseWriter, r *http.Request, ctx envRequestContext) {
	switch r.Method {
	case http.MethodGet:
		fields, err := readEnvFields(ctx.path, ctx.allowlist)
		if err != nil {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: fmt.Sprintf("env 파일 읽기 실패: %v", err)})
			return
		}
		writeJSON(w, http.StatusOK, envResponse{
			OK:               true,
			Scope:            ctx.scope,
			ID:               ctx.id,
			RestartRequired:  false,
			AffectedServices: []string{},
			Fields:           fields,
		})
	case http.MethodPatch:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "body 읽기 실패"})
			return
		}
		var req envPatchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
			return
		}
		if len(req.Values) == 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "values가 비어 있음"})
			return
		}
		if err := validateEnvPatch(req.Values, ctx.allowlist); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}
		fields, err := patchEnvFile(ctx.path, ctx.allowlist, req.Values)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("env 파일 쓰기 실패: %v", err)})
			return
		}
		affectedServices := append([]string{}, ctx.affectedServices...)
		if ctx.scope == "server" {
			changed, err := c.syncRegistryEntryFromEnv(ctx.id, ctx.path)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("레지스트리 동기화 실패: %v", err)})
				return
			}
			if changed {
				affectedServices = appendUnique(affectedServices, sharedRegistryReloadServices)
				c.startLifecycleJob("reload registry "+ctx.id, c.reloadSharedRegistry)
			}
		}
		writeJSON(w, http.StatusOK, envResponse{
			OK:               true,
			Scope:            ctx.scope,
			ID:               ctx.id,
			RestartRequired:  true,
			AffectedServices: affectedServices,
			Fields:           fields,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET/PATCH only"})
	}
}

func (c config) createServer(req createServerRequest) (createServerResponse, int) {
	id, internalKey, err := normalizeCreateServerID(req.ID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || strings.ContainsAny(name, "\r\n") {
		return createServerResponse{OK: false, ID: id, Detail: "서버 이름이 올바르지 않습니다."}, http.StatusBadRequest
	}
	generation, err := parseGeneration(req.Generation, 1)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: err.Error()}, http.StatusBadRequest
	}
	imageTag := strings.TrimSpace(req.ImageTag)
	if imageTag == "" {
		imageTag = c.sharedEnvValue("IMAGE_TAG")
	}
	if imageTag == "" {
		imageTag = "latest"
	}
	if !tagRe.MatchString(imageTag) {
		return createServerResponse{OK: false, ID: id, Detail: "이미지 태그가 올바르지 않습니다."}, http.StatusBadRequest
	}
	gameAPIPort := strings.TrimSpace(req.GameAPIPort)
	webGamePort := strings.TrimSpace(req.WebGamePort)
	if !isPort(gameAPIPort) || !isPort(webGamePort) {
		return createServerResponse{OK: false, ID: id, Detail: "포트는 1-65535 숫자여야 합니다."}, http.StatusBadRequest
	}
	if gameAPIPort == webGamePort {
		return createServerResponse{OK: false, ID: id, Detail: "game-api와 web-game 포트는 서로 달라야 합니다."}, http.StatusConflict
	}
	if err := c.ensurePortsAvailable(id, map[string]string{
		"GAME_API_PORT": gameAPIPort,
		"WEB_GAME_PORT": webGamePort,
	}); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: err.Error()}, http.StatusConflict
	}
	scenarioCode := strings.TrimSpace(req.ScenarioCode)
	if scenarioCode == "" {
		scenarioCode = "scenario_1010"
	}
	if !isSafeToken(scenarioCode) {
		return createServerResponse{OK: false, ID: id, Detail: "시나리오 코드가 올바르지 않습니다."}, http.StatusBadRequest
	}
	seedEnabled := true
	if req.ScenarioSeedEnabled != nil {
		seedEnabled = *req.ScenarioSeedEnabled
	}
	jwtSecret := strings.TrimSpace(req.JWTSecret)
	if jwtSecret == "" {
		jwtSecret = c.sharedEnvValue("JWT_SECRET")
	}
	if jwtSecret == "" || strings.ContainsAny(jwtSecret, "\r\n") {
		return createServerResponse{OK: false, ID: id, Detail: "공유 JWT_SECRET이 필요합니다."}, http.StatusBadRequest
	}
	envFile := filepath.Join(c.serversDir, internalKey+".env")
	if _, err := os.Stat(envFile); err == nil {
		return createServerResponse{OK: false, ID: id, Detail: "이미 존재하는 서버입니다."}, http.StatusConflict
	} else if !os.IsNotExist(err) {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 확인 실패: %v", err)}, http.StatusInternalServerError
	}
	if err := os.MkdirAll(c.serversDir, 0o755); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("servers 디렉터리 생성 실패: %v", err)}, http.StatusInternalServerError
	}
	gamePassword, err := randomHex(24)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("비밀번호 생성 실패: %v", err)}, http.StatusInternalServerError
	}
	envLines := []envLine{
		{Raw: "SERVER_ID=" + id, Key: "SERVER_ID", Value: id, IsKV: true},
		{Raw: "GHCR_REGISTRY=ghcr.io", Key: "GHCR_REGISTRY", Value: "ghcr.io", IsKV: true},
		{Raw: "GHCR_OWNER=" + c.ghcrOwner, Key: "GHCR_OWNER", Value: c.ghcrOwner, IsKV: true},
		{Raw: "IMAGE_TAG=" + imageTag, Key: "IMAGE_TAG", Value: imageTag, IsKV: true},
		{Raw: "SERVER_NAME=" + name, Key: "SERVER_NAME", Value: name, IsKV: true},
		{Raw: "SERVER_GENERATION=" + strconv.Itoa(generation), Key: "SERVER_GENERATION", Value: strconv.Itoa(generation), IsKV: true},
		{Raw: "GAME_API_PORT=" + gameAPIPort, Key: "GAME_API_PORT", Value: gameAPIPort, IsKV: true},
		{Raw: "WEB_GAME_PORT=" + webGamePort, Key: "WEB_GAME_PORT", Value: webGamePort, IsKV: true},
		{Raw: "GAME_POSTGRES_DB=sammo", Key: "GAME_POSTGRES_DB", Value: "sammo", IsKV: true},
		{Raw: "GAME_POSTGRES_USER=sammo", Key: "GAME_POSTGRES_USER", Value: "sammo", IsKV: true},
		{Raw: "GAME_POSTGRES_PASSWORD=" + gamePassword, Key: "GAME_POSTGRES_PASSWORD", Value: gamePassword, IsKV: true},
		{Raw: "JWT_SECRET=" + jwtSecret, Key: "JWT_SECRET", Value: jwtSecret, IsKV: true},
		{Raw: "TURN_PROFILE_NAME=che:scenario_2", Key: "TURN_PROFILE_NAME", Value: "che:scenario_2", IsKV: true},
		{Raw: "SCENARIO_SEED_ENABLED=" + boolText(seedEnabled), Key: "SCENARIO_SEED_ENABLED", Value: boolText(seedEnabled), IsKV: true},
		{Raw: "SCENARIO_CODE=" + scenarioCode, Key: "SCENARIO_CODE", Value: scenarioCode, IsKV: true},
		{Raw: "GAME_API_URL=" + c.gameAPIURLFor(id), Key: "GAME_API_URL", Value: c.gameAPIURLFor(id), IsKV: true},
		{Raw: "GATEWAY_API_URL=" + envOrValue(c.sharedEnvValue("GATEWAY_API_URL"), c.defaultGatewayAPIURL()), Key: "GATEWAY_API_URL", Value: envOrValue(c.sharedEnvValue("GATEWAY_API_URL"), c.defaultGatewayAPIURL()), IsKV: true},
	}
	if err := writeEnvLinesAtomic(envFile, envLines); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 쓰기 실패: %v", err)}, http.StatusInternalServerError
	}
	entry := registryEntry{
		ID:            id,
		Name:          name,
		Generation:    generation,
		ScenarioCode:  scenarioCode,
		GameAPIURL:    c.gameAPIURLFor(id),
		GameEngineURL: c.gameEngineURLFor(id),
		DeployProject: projectForServerID(id),
		Env:           registryEnvSnapshot(envValuesFromLines(envLines)),
	}
	if err := c.upsertRegistryEntry(entry); err != nil {
		return createServerResponse{OK: false, ID: id, Name: name, Project: entry.DeployProject, Detail: fmt.Sprintf("레지스트리 갱신 실패: %v", err)}, http.StatusInternalServerError
	}
	c.startLifecycleJob("create "+id, func() (string, error) {
		detail, serverErr := c.upServerStack(entry.DeployProject, envFile)
		reloadDetail, reloadErr := c.reloadSharedRegistry()
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		if serverErr != nil {
			return detail, serverErr
		}
		return detail, reloadErr
	})
	return createServerResponse{
		OK:               true,
		ID:               id,
		Name:             name,
		Project:          entry.DeployProject,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 생성 작업을 시작했습니다. 상태가 준비될 때까지 잠시 기다려 주세요.",
	}, http.StatusOK
}

func (c config) deleteServer(rawID string, confirm string) (createServerResponse, int) {
	id, _, err := normalizeCreateServerID(rawID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	if confirm != "DELETE "+id {
		return createServerResponse{OK: false, ID: id, Detail: "삭제 확인 문구가 일치하지 않습니다."}, http.StatusBadRequest
	}
	entry, err := c.registryEntryByID(id)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("레지스트리 조회 실패: %v", err)}, http.StatusInternalServerError
	}
	if entry.ID == "" {
		return createServerResponse{OK: false, ID: id, Detail: "알 수 없는 서버입니다."}, http.StatusNotFound
	}
	envFile := c.serverEnvFileForID(id)
	c.startLifecycleJob("delete "+id, func() (string, error) {
		detail, downErr := c.downServerStack(entry.DeployProject, envFile)
		if downErr != nil {
			return detail, downErr
		}
		removeErr := os.Remove(envFile)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return detail, removeErr
		}
		if _, err := c.removeRegistryEntry(id); err != nil {
			return detail, err
		}
		reloadDetail, reloadErr := c.reloadSharedRegistry()
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		return detail, reloadErr
	})
	return createServerResponse{
		OK:               true,
		ID:               id,
		Name:             entry.Name,
		Project:          entry.DeployProject,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 삭제 작업을 시작했습니다. 목록에서 사라질 때까지 잠시 기다려 주세요.",
	}, http.StatusOK
}

func (c config) resetServer(rawID string, req resetServerRequest) (createServerResponse, int) {
	id, _, err := normalizeCreateServerID(rawID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	if req.Confirm != "RESET "+id {
		return createServerResponse{OK: false, ID: id, Detail: "리셋 확인 문구가 일치하지 않습니다."}, http.StatusBadRequest
	}
	entry, err := c.registryEntryByID(id)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("레지스트리 조회 실패: %v", err)}, http.StatusInternalServerError
	}
	if entry.ID == "" {
		return createServerResponse{OK: false, ID: id, Detail: "알 수 없는 서버입니다."}, http.StatusNotFound
	}
	envFile := c.serverEnvFileForID(id)
	if _, err := os.Stat(envFile); err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("서버 env 확인 실패: %v", err)}, http.StatusInternalServerError
	}
	originalEnv, err := os.ReadFile(envFile)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("서버 env 백업 실패: %v", err)}, http.StatusInternalServerError
	}
	originalEntry := entry
	if strings.TrimSpace(req.Generation) != "" {
		generation, err := parseGeneration(req.Generation, 1)
		if err != nil {
			return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: err.Error()}, http.StatusBadRequest
		}
		entry.Generation = generation
		if err := c.upsertRegistryEntry(entry); err != nil {
			return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("레지스트리 기수 갱신 실패: %v", err)}, http.StatusInternalServerError
		}
	}
	if err := c.applyResetOptions(envFile, req); err != nil {
		_ = c.upsertRegistryEntry(originalEntry)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("리셋 옵션 저장 실패: %v", err)}, http.StatusBadRequest
	}
	if _, err := c.syncRegistryEntryFromEnv(id, envFile); err != nil {
		_ = writeFileAtomic(envFile, originalEnv)
		_ = c.upsertRegistryEntry(originalEntry)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("레지스트리 동기화 실패: %v", err)}, http.StatusInternalServerError
	}
	if updatedEntry, err := c.registryEntryByID(id); err == nil && updatedEntry.ID != "" {
		entry = updatedEntry
	}
	c.startLifecycleJob("reset "+id, func() (string, error) {
		detail, downErr := c.downServerStack(entry.DeployProject, envFile)
		if downErr != nil {
			_ = writeFileAtomic(envFile, originalEnv)
			_ = c.upsertRegistryEntry(originalEntry)
			return detail, downErr
		}
		upDetail, upErr := c.upServerStack(entry.DeployProject, envFile)
		if upDetail != "" {
			detail += "\n=== server up ===\n" + upDetail
		}
		reloadDetail, reloadErr := c.reloadSharedRegistry()
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		if upErr != nil {
			_ = writeFileAtomic(envFile, originalEnv)
			_ = c.upsertRegistryEntry(originalEntry)
			return detail, upErr
		}
		if reloadErr != nil {
			_ = writeFileAtomic(envFile, originalEnv)
			_ = c.upsertRegistryEntry(originalEntry)
			return detail, reloadErr
		}
		return detail, nil
	})
	return createServerResponse{
		OK:               true,
		ID:               id,
		Name:             entry.Name,
		Project:          entry.DeployProject,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 리셋 작업을 시작했습니다. 상태가 준비될 때까지 잠시 기다려 주세요.",
	}, http.StatusOK
}

func (c config) startLifecycleJob(name string, job func() (string, error)) {
	go func() {
		detail, err := job()
		if err != nil {
			log.Printf("server lifecycle job failed name=%s err=%v detail=%s", name, err, detail)
			return
		}
		log.Printf("server lifecycle job completed name=%s detail=%s", name, detail)
	}()
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

func readEnvFields(path string, allowlist map[string]envFieldSpec) (map[string]envField, error) {
	lines, err := readEnvLines(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range lines {
		if line.IsKV {
			values[line.Key] = line.Value
		}
	}
	return buildEnvFields(allowlist, values), nil
}

func validateEnvPatch(values map[string]string, allowlist map[string]envFieldSpec) error {
	for key := range values {
		if _, ok := allowlist[key]; !ok {
			return fmt.Errorf("허용되지 않은 env key: %s", key)
		}
	}
	return nil
}

func patchEnvFile(path string, allowlist map[string]envFieldSpec, updates map[string]string) (map[string]envField, error) {
	lines, err := readEnvLines(path)
	if err != nil {
		return nil, err
	}

	remaining := map[string]string{}
	for key, value := range updates {
		remaining[key] = value
	}

	values := map[string]string{}
	for i := range lines {
		line := &lines[i]
		if line.IsKV {
			if value, ok := remaining[line.Key]; ok {
				line.Value = value
				line.Raw = line.Key + "=" + value
				delete(remaining, line.Key)
			}
			values[line.Key] = line.Value
		}
	}

	remainingKeys := make([]string, 0, len(remaining))
	for key := range remaining {
		remainingKeys = append(remainingKeys, key)
	}
	sort.Strings(remainingKeys)
	for _, key := range remainingKeys {
		value := remaining[key]
		lines = append(lines, envLine{Raw: key + "=" + value, Key: key, Value: value, IsKV: true})
		values[key] = value
	}

	if err := writeEnvLinesAtomic(path, lines); err != nil {
		return nil, err
	}
	return buildEnvFields(allowlist, values), nil
}

func readEnvLines(path string) ([]envLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	parts := strings.Split(text, "\n")
	lines := make([]envLine, 0, len(parts))
	for i, raw := range parts {
		if i == len(parts)-1 && raw == "" {
			continue
		}
		line := envLine{Raw: raw}
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if idx := strings.Index(raw, "="); idx > 0 {
				key := strings.TrimSpace(raw[:idx])
				if isEnvKey(key) {
					line.Key = key
					line.Value = raw[idx+1:]
					line.IsKV = true
				}
			}
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func writeEnvLinesAtomic(path string, lines []envLine) error {
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString(line.Raw)
		sb.WriteByte('\n')
	}
	return writeFileAtomic(path, []byte(sb.String()))
}

type fileAttrs struct {
	mode     os.FileMode
	uid      int
	gid      int
	hasOwner bool
}

func atomicWriteAttrs(path string) fileAttrs {
	attrs := fileAttrs{mode: 0o600}
	if info, err := os.Stat(path); err == nil {
		attrs.mode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			attrs.uid = int(stat.Uid)
			attrs.gid = int(stat.Gid)
			attrs.hasOwner = true
		}
		return attrs
	}
	if info, err := os.Stat(filepath.Dir(path)); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			attrs.uid = int(stat.Uid)
			attrs.gid = int(stat.Gid)
			attrs.hasOwner = true
		}
	}
	return attrs
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	attrs := atomicWriteAttrs(path)
	tmp, err := os.CreateTemp(dir, ".env-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if attrs.hasOwner && os.Geteuid() == 0 {
		if err := tmp.Chown(attrs.uid, attrs.gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(attrs.mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func buildEnvFields(allowlist map[string]envFieldSpec, values map[string]string) map[string]envField {
	fields := map[string]envField{}
	for key, spec := range allowlist {
		value, configured := values[key]
		field := envField{
			Key:        key,
			Configured: configured && value != "",
			WriteOnly:  spec.WriteOnly,
			Masked:     spec.WriteOnly && configured,
			Metadata: map[string]any{
				"description": spec.Description,
			},
		}
		if !spec.WriteOnly && configured {
			v := value
			field.Value = &v
		}
		fields[key] = field
	}
	return fields
}

func isEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeCreateServerID(raw string) (string, string, error) {
	if raw == "" {
		return "", "", fmt.Errorf("서버 id가 필요합니다.")
	}
	if !serverIDRe.MatchString(raw) {
		return "", "", fmt.Errorf("서버 id는 영문 대소문자와 숫자만 허용합니다.")
	}
	id := strings.ToLower(raw)
	if _, reserved := reservedGameRouteIDs[id]; reserved {
		return "", "", fmt.Errorf("서버 id %q는 게임 경로와 충돌해 사용할 수 없습니다.", id)
	}
	if _, reserved := reservedPublicServerIDs[id]; reserved {
		return "", "", fmt.Errorf("서버 id %q는 전체 서버 예약어라 사용할 수 없습니다.", id)
	}
	return id, internalServerKey(id), nil
}

func isPort(value string) bool {
	if value == "" {
		return false
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n >= 1 && n <= 65535
}

func parseGeneration(value string, fallback int) (int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("기수는 0 이상의 숫자여야 합니다.")
	}
	return n, nil
}

func isSafeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' || r == '-' || r == ':' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func envOrValue(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (c config) sharedEnvValue(key string) string {
	lines, err := readEnvLines(c.sharedEnvFile())
	if err != nil {
		return ""
	}
	for _, line := range lines {
		if line.IsKV && line.Key == key {
			return line.Value
		}
	}
	return ""
}

func (c config) upsertRegistryEntry(entry registryEntry) error {
	registry, err := c.readRegistry()
	if err != nil {
		return err
	}
	found := false
	for i := range registry {
		if registry[i].ID == entry.ID {
			registry[i] = entry
			found = true
			break
		}
	}
	if !found {
		registry = append(registry, entry)
	}
	return c.writeRegistry(registry)
}

func (c config) removeRegistryEntry(id string) (registryEntry, error) {
	registry, err := c.readRegistry()
	if err != nil {
		return registryEntry{}, err
	}
	next := make([]registryEntry, 0, len(registry))
	var removed registryEntry
	for _, entry := range registry {
		if entry.ID == id {
			removed = entry
			continue
		}
		next = append(next, entry)
	}
	if removed.ID == "" {
		return registryEntry{}, nil
	}
	return removed, c.writeRegistry(next)
}

func (c config) registryEntryByID(id string) (registryEntry, error) {
	registry, err := c.readRegistry()
	if err != nil {
		return registryEntry{}, err
	}
	for _, entry := range registry {
		if entry.ID == id {
			return entry, nil
		}
	}
	return registryEntry{}, nil
}

func (c config) syncRegistryEntryFromEnv(id string, envFile string) (bool, error) {
	canonicalID, _, err := normalizeCreateServerID(id)
	if err != nil {
		return false, err
	}
	id = canonicalID
	if _, err := os.Stat(c.sharedEnvFile()); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	values, err := readEnvValues(envFile)
	if err != nil {
		return false, err
	}
	current, err := c.registryEntryByID(id)
	if err != nil {
		return false, err
	}
	next := c.registryEntryFromServerEnv(id, values, current)
	if reflect.DeepEqual(current, next) {
		return false, nil
	}
	return true, c.upsertRegistryEntry(next)
}

func (c config) registryEntryFromServerEnv(id string, values map[string]string, current registryEntry) registryEntry {
	next := current
	next.ID = id
	next.DeployProject = projectForServerID(id)
	if name := strings.TrimSpace(values["SERVER_NAME"]); name != "" {
		next.Name = name
	}
	if next.Name == "" {
		next.Name = id
	}
	if rawGeneration := strings.TrimSpace(values["SERVER_GENERATION"]); rawGeneration != "" {
		if generation, err := parseGeneration(rawGeneration, next.Generation); err == nil {
			next.Generation = generation
		}
	}
	if scenarioCode := strings.TrimSpace(values["SCENARIO_CODE"]); scenarioCode != "" {
		next.ScenarioCode = scenarioCode
	}
	if gameAPIURL := strings.TrimSpace(values["GAME_API_URL"]); gameAPIURL != "" {
		next.GameAPIURL = gameAPIURL
	}
	if next.GameAPIURL == "" {
		next.GameAPIURL = c.gameAPIURLFor(id)
	}
	if next.GameEngineURL == "" {
		next.GameEngineURL = c.gameEngineURLFor(id)
	}
	next.Env = registryEnvSnapshot(values)
	return next
}

func registryEnvSnapshot(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, spec := range serverEnvAllowlist {
		if spec.WriteOnly {
			continue
		}
		if value, ok := values[key]; ok {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readEnvValues(path string) (map[string]string, error) {
	lines, err := readEnvLines(path)
	if err != nil {
		return nil, err
	}
	return envValuesFromLines(lines), nil
}

func envValuesFromLines(lines []envLine) map[string]string {
	values := map[string]string{}
	for _, line := range lines {
		if line.IsKV {
			values[line.Key] = line.Value
		}
	}
	return values
}

func (c config) applyResetOptions(envFile string, req resetServerRequest) error {
	values := map[string]string{}
	putSafe := func(key, value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s 값이 올바르지 않습니다.", key)
		}
		values[key] = value
		return nil
	}
	if req.ScenarioCode != "" {
		if !isSafeToken(req.ScenarioCode) {
			return fmt.Errorf("시나리오 코드가 올바르지 않습니다.")
		}
		values["SCENARIO_CODE"] = strings.TrimSpace(req.ScenarioCode)
		values["SCENARIO_SEED_ENABLED"] = "true"
	}
	if req.ScenarioSeedEnabled != nil {
		values["SCENARIO_SEED_ENABLED"] = boolText(*req.ScenarioSeedEnabled)
	}
	if strings.TrimSpace(req.Generation) != "" {
		generation, err := parseGeneration(req.Generation, 1)
		if err != nil {
			return err
		}
		values["SERVER_GENERATION"] = strconv.Itoa(generation)
	}
	for key, value := range map[string]string{
		"RESET_TURNTERM":             req.TurnTerm,
		"RESET_SYNC":                 req.Sync,
		"RESET_FICTION":              req.Fiction,
		"RESET_EXTEND":               req.Extend,
		"RESET_BLOCK_GENERAL_CREATE": req.BlockGeneralCreate,
		"RESET_NPCMODE":              req.NPCMode,
		"RESET_SHOW_IMG_LEVEL":       req.ShowImgLevel,
		"RESET_AUTORUN_USER_MINUTES": req.AutorunUserMinutes,
		"RESET_JOIN_MODE":            req.JoinMode,
		"RESET_TOURNAMENT_TRIG":      req.TournamentTrig,
		"RESET_RESERVE_OPEN":         req.ReserveOpen,
		"RESET_PRE_RESERVE_OPEN":     req.PreReserveOpen,
	} {
		if err := putSafe(key, value); err != nil {
			return err
		}
	}
	if len(req.AutorunUserOptions) > 0 {
		clean := []string{}
		for _, option := range req.AutorunUserOptions {
			option = strings.TrimSpace(option)
			if option == "" {
				continue
			}
			if !isSafeToken(option) {
				return fmt.Errorf("자동 행동 옵션이 올바르지 않습니다.")
			}
			clean = append(clean, option)
		}
		values["RESET_AUTORUN_USER_OPTIONS"] = strings.Join(clean, ",")
	}
	if len(values) == 0 {
		return nil
	}
	spec := map[string]envFieldSpec{}
	for key := range values {
		spec[key] = envFieldSpec{Description: "리셋 옵션"}
	}
	_, err := patchEnvFile(envFile, spec, values)
	return err
}

func (c config) readRegistry() ([]registryEntry, error) {
	lines, err := readEnvLines(c.sharedEnvFile())
	if err != nil {
		return nil, err
	}
	registry := []registryEntry{}
	for _, line := range lines {
		if line.IsKV && line.Key == "SERVER_REGISTRY_JSON" && strings.TrimSpace(line.Value) != "" {
			if err := json.Unmarshal([]byte(line.Value), &registry); err != nil {
				return nil, fmt.Errorf("SERVER_REGISTRY_JSON 파싱 실패: %w", err)
			}
		}
	}
	return canonicalRegistryEntries(registry)
}

func (c config) writeRegistry(registry []registryEntry) error {
	canonical, err := canonicalRegistryEntries(registry)
	if err != nil {
		return err
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	_, err = patchEnvFile(c.sharedEnvFile(), map[string]envFieldSpec{
		"SERVER_REGISTRY_JSON": {Description: "서버 레지스트리"},
	}, map[string]string{"SERVER_REGISTRY_JSON": string(data)})
	return err
}

func canonicalRegistryEntries(registry []registryEntry) ([]registryEntry, error) {
	canonical := make([]registryEntry, 0, len(registry))
	seen := make(map[string]string, len(registry))
	for index, entry := range registry {
		id, _, err := normalizeCreateServerID(entry.ID)
		if err != nil {
			return nil, fmt.Errorf("SERVER_REGISTRY_JSON[%d]의 서버 id %q가 올바르지 않습니다: %w", index, entry.ID, err)
		}
		if previous, exists := seen[id]; exists {
			return nil, fmt.Errorf("SERVER_REGISTRY_JSON에 정규화 후 중복 서버 id %q가 있습니다 (%q, %q)", id, previous, entry.ID)
		}
		expectedProject := projectForServerID(id)
		if entry.DeployProject != "" && strings.ToLower(entry.DeployProject) != expectedProject {
			return nil, fmt.Errorf("SERVER_REGISTRY_JSON[%d]의 deployProject %q가 canonical id %q와 일치하지 않습니다. one-time migration이 필요합니다.", index, entry.DeployProject, id)
		}
		seen[id] = entry.ID
		entry.ID = id
		entry.DeployProject = expectedProject
		canonical = append(canonical, entry)
	}
	return canonical, nil
}

func (c config) ensurePortsAvailable(newID string, requested map[string]string) error {
	for sharedKey, sharedPort := range c.sharedOccupiedPorts() {
		for key, port := range requested {
			if sharedPort == port {
				return fmt.Errorf("%s=%s 는 공유 스택의 %s가 사용 중입니다.", key, port, sharedKey)
			}
		}
	}
	entries, err := os.ReadDir(c.serversDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".env") {
			continue
		}
		internalKey := strings.TrimSuffix(entry.Name(), ".env")
		if !internalServerKeyRe.MatchString(internalKey) {
			continue
		}
		if internalKey == internalServerKey(newID) {
			continue
		}
		lines, err := readEnvLines(filepath.Join(c.serversDir, entry.Name()))
		if err != nil {
			return err
		}
		for _, line := range lines {
			if !line.IsKV {
				continue
			}
			if line.Key != "GAME_API_PORT" && line.Key != "WEB_GAME_PORT" {
				continue
			}
			for key, port := range requested {
				if line.Value == port {
					return fmt.Errorf("%s=%s 는 이미 %s 서버의 %s가 사용 중입니다.", key, port, strings.TrimPrefix(internalKey, "s"), line.Key)
				}
			}
		}
	}
	return nil
}

func (c config) sharedOccupiedPorts() map[string]string {
	return map[string]string{
		"NGINX_HTTP_PORT":  envOrValue(c.sharedEnvValue("NGINX_HTTP_PORT"), "80"),
		"NGINX_HTTPS_PORT": envOrValue(c.sharedEnvValue("NGINX_HTTPS_PORT"), "443"),
		"GATEWAY_API_PORT": envOrValue(c.sharedEnvValue("GATEWAY_API_PORT"), "18081"),
		"WEB_GATEWAY_PORT": envOrValue(c.sharedEnvValue("WEB_GATEWAY_PORT"), "3000"),
		"GAME_API_PORT":    envOrValue(c.sharedEnvValue("GAME_API_PORT"), "18080"),
		"WEB_GAME_PORT":    envOrValue(c.sharedEnvValue("WEB_GAME_PORT"), "3001"),
	}
}

func (c config) upServerStack(project, envFile string) (string, error) {
	return c.runDocker(
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"up", "-d",
	)
}

func (c config) downServerStack(project, envFile string) (string, error) {
	return c.runDocker(
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"down", "--volumes", "--remove-orphans",
	)
}

func (c config) reloadSharedRegistry() (string, error) {
	services := withoutService(sharedRegistryReloadServices, "nginx")
	args := append([]string{
		"compose",
		"--env-file", c.sharedEnvFile(),
		"-f", c.composeShared,
		"up", "-d", "--no-deps",
	}, services...)
	detail, err := c.runDocker(args...)
	if err != nil {
		return detail, err
	}
	nginxDetail, nginxErr := c.runDocker(
		"compose",
		"--env-file", c.sharedEnvFile(),
		"-f", c.composeShared,
		"up", "-d", "--force-recreate", "--no-deps", "nginx",
	)
	if nginxDetail != "" {
		detail += "\n=== nginx reload ===\n" + nginxDetail
	}
	return detail, nginxErr
}

func withoutService(values []string, remove string) []string {
	out := []string{}
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}

func appendUnique(values []string, additions ...[]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, list := range additions {
		for _, value := range list {
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// 서버 env 파일의 app 핀을 새 태그로 치환. game-engine은 실행 중 월드 보호를 위해 bounce하지 않는다.
func (c config) writeImageTag(project, tag string) error {
	envFile := c.envFileFor(project)
	_, err := patchEnvFile(envFile, serverEnvAllowlist, map[string]string{
		"IMAGE_TAG":    tag,
		"WEB_GAME_TAG": tag,
	})
	return err
}

func (c config) tempImageTagEnvFile(envFile, tag string) (string, func(), error) {
	data, err := os.ReadFile(envFile)
	if err != nil {
		return "", func() {}, err
	}
	tmp, err := os.CreateTemp(c.serversDir, ".deploy-*.env")
	if err != nil {
		return "", func() {}, err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if _, err := patchEnvFile(tmpPath, serverEnvAllowlist, map[string]string{
		"IMAGE_TAG":    tag,
		"WEB_GAME_TAG": tag,
	}); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return tmpPath, cleanup, nil
}

// 스테이트리스 서비스만 pull 후 up -d --no-deps. game-engine은 절대 미포함.
func (c config) bounceStateless(project, envFile string) (string, error) {
	pullDetail, err := c.pullStateless(project, envFile)
	if err != nil {
		return pullDetail, err
	}
	upDetail, err := c.upStateless(project, envFile)
	return pullDetail + "\n" + upDetail, err
}

func (c config) pullStateless(project, envFile string) (string, error) {
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
	return sb.String(), nil
}

func (c config) upStateless(project, envFile string) (string, error) {
	var sb strings.Builder

	// docker compose -p <project> --env-file <env> -f <server.yml> up -d --force-recreate --no-deps <svc...>
	upArgs := append([]string{
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"up", "-d", "--force-recreate", "--no-deps",
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
	if c.dockerRunner != nil {
		return c.dockerRunner(args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = c.composeDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c config) fetchAvailableTags() []string {
	rawTags := c.fetchPackageTags("opensamguk")
	return deployableAppTags(rawTags)
}

func (c config) fetchPackageTags(packageName string) []string {
	tags := []string{}
	url := fmt.Sprintf(
		"%s/users/%s/packages/container/%s/versions?per_page=100",
		strings.TrimRight(envOrValue(c.ghcrAPIBaseURL, "https://api.github.com"), "/"),
		url.PathEscape(c.ghcrOwner),
		url.PathEscape(packageName),
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

func deployableAppTags(rawTags []string) []string {
	type candidate struct {
		firstIndex int
		have       map[string]bool
	}
	candidates := map[string]*candidate{}
	for i, rawTag := range rawTags {
		for _, prefix := range requiredPromoteImagePrefixes {
			if !strings.HasPrefix(rawTag, prefix) {
				continue
			}
			suffix := strings.TrimPrefix(rawTag, prefix)
			if suffix == "" || suffix == "latest" || !tagRe.MatchString(suffix) {
				continue
			}
			entry := candidates[suffix]
			if entry == nil {
				entry = &candidate{firstIndex: i, have: map[string]bool{}}
				candidates[suffix] = entry
			}
			if i < entry.firstIndex {
				entry.firstIndex = i
			}
			entry.have[prefix] = true
		}
	}
	complete := make([]struct {
		tag        string
		firstIndex int
	}, 0, len(candidates))
	for tag, entry := range candidates {
		ok := true
		for _, prefix := range requiredPromoteImagePrefixes {
			if !entry.have[prefix] {
				ok = false
				break
			}
		}
		if ok {
			complete = append(complete, struct {
				tag        string
				firstIndex int
			}{tag: tag, firstIndex: entry.firstIndex})
		}
	}
	sort.SliceStable(complete, func(i, j int) bool {
		return complete[i].firstIndex < complete[j].firstIndex
	})
	out := make([]string, 0, len(complete))
	for _, entry := range complete {
		out = append(out, entry.tag)
	}
	return out
}

// JSON 응답 헬퍼.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
