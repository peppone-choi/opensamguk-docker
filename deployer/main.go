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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	"sync"
	"syscall"
	"time"
)

const (
	maxDockerDNSLabelLength         = 63
	internalServerKeyPrefix         = "s"
	gameEngineDockerLabelSuffix     = "-game-engine"
	longestServerDockerLabelSuffix  = "-game-postgres"
	maxPublicServerIDLength         = maxDockerDNSLabelLength - len(internalServerKeyPrefix) - len(longestServerDockerLabelSuffix)
	lifecycleJobIDBytes             = 16
	maintenanceLeaseBytes           = 16
	lifecycleJobMaxEntries          = 128
	lifecycleJobTerminalRetention   = time.Hour
	maintenanceLeaseHeader          = "X-Maintenance-Lease"
	resetVerificationTimeout        = 2 * time.Minute
	resetVerificationPollInterval   = time.Second
	resetVerificationHTTPTimeout    = 5 * time.Second
	authenticatedHTTPDefaultTimeout = 10 * time.Second
	maxVerificationResponseBytes    = 256 << 10
	isolatedServerWorldID           = "1"
	// sharedComposeProjectName은 docker-compose.shared.yml의 고정 project name(top-level
	// `name:`)과 반드시 일치해야 한다. 게임 서버 id가 이 이름과 충돌하는 compose project를
	// 만들어내면 down --volumes가 공유 스택을 파괴할 수 있다(#32).
	sharedComposeProjectName = "opensamguk-shared"
)

// 입력 검증용 화이트리스트 정규식.
var (
	// 프로젝트명 — opensamguk-s<public id>만 허용. 내부 key의 s는 여기서만 보인다.
	projectRe = regexp.MustCompile(`^opensamguk-s[a-z0-9]+$`)
	// Public server id. The Docker-only key is always synthesized as s<public id>.
	serverIDRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	// Internal server key used only for Docker resources and server env filenames.
	internalServerKeyRe = regexp.MustCompile(`^s[a-z0-9]+$`)
	lifecycleJobIDRe    = regexp.MustCompile(`^[a-f0-9]{32}$`)
	// 이미지 태그 — 도커 태그 문자셋(영숫자/점/언더스코어/하이픈).
	tagRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

var (
	errLifecycleJobCapacity              = errors.New("lifecycle job capacity reached")
	errLifecycleOperationConflict        = errors.New("lifecycle operation id is already bound to a different request")
	errDurableOperationSettlementPending = errors.New("durable operation settlement pending")
	errCreatePortsEqual                  = errors.New("game-api와 web-game 포트는 서로 달라야 합니다.")
)

// 스테이트리스 bounce 대상 — game-engine은 의도적으로 제외.
var statelessServices = envList("DEPLOYER_STATELESS_SERVICES", []string{"game-api", "web-game"})
var requiredPromoteImagePrefixes = []string{"game-api-", "game-engine-", "web-game-"}
var sharedEnvServices = envList("DEPLOYER_SHARED_ENV_SERVICES", []string{"gateway-api", "board-api", "web-gateway", "nginx", "deployer"})

// gateway-api owns the DB-backed registry and persists create/delete only after the deployer
// returns confirmed success. Restarting it inside that request can sever the response before
// the DB transaction runs. Only environment-backed web/nginx consumers are reloaded here.
var sharedRegistryReloadServices = envList("DEPLOYER_SHARED_REGISTRY_RELOAD_SERVICES", []string{"web-gateway", "nginx"})
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
	"IMAGE_TAG":                      {Description: "게임 서버 이미지 태그"},
	"GAME_API_PORT":                  {Description: "game-api 호스트 포트"},
	"WEB_GAME_PORT":                  {Description: "web-game 호스트 포트"},
	"WEB_GAME_TAG":                   {Description: "web-game 이미지 태그"},
	"TURN_PROFILE_NAME":              {Description: "턴 프로필"},
	"SCENARIO_SEED_ENABLED":          {Description: "시나리오 자동 시드 활성화"},
	"SCENARIO_CODE":                  {Description: "시드할 시나리오 코드"},
	"SERVER_NAME":                    {Description: "서버 이름"},
	"SERVER_GENERATION":              {Description: "서버 기수"},
	"GAME_API_URL":                   {Description: "game-api 내부 URL"},
	"GATEWAY_API_URL":                {Description: "gateway-api 내부 URL"},
	"INTERNAL_SERVICE_TOKEN":         {Description: "gateway-api 내부 프로필 조회 토큰", WriteOnly: true},
	"JWT_PUBLIC_KEY":                 {Description: "JWT 검증 공개키(비밀 아님, gateway-api와 동일 값)"},
	"JWT_LEGACY_SECRET":              {Description: "레거시 HS256 검증 시크릿", WriteOnly: true},
	"JWT_LEGACY_ACCESS_ACCEPT_UNTIL": {Description: "레거시 토큰 수용 만료 시각"},
	"RESET_TURNTERM":                 {Description: "리셋: 턴 시간(분)"},
	"RESET_SYNC":                     {Description: "리셋: 시간 동기화"},
	"RESET_FICTION":                  {Description: "리셋: NPC 상성"},
	"RESET_EXTEND":                   {Description: "리셋: 확장 NPC"},
	"RESET_BLOCK_GENERAL_CREATE":     {Description: "리셋: 장수 임의 생성"},
	"RESET_NPCMODE":                  {Description: "리셋: NPC 빙의"},
	"RESET_SHOW_IMG_LEVEL":           {Description: "리셋: 이미지 표기"},
	"RESET_AUTORUN_USER_OPTIONS":     {Description: "리셋: 휴식 턴 시 장수 턴"},
	"RESET_AUTORUN_USER_MINUTES":     {Description: "리셋: 자동 행동 유효 시간"},
	"RESET_JOIN_MODE":                {Description: "리셋: 임관 모드"},
	"RESET_TOURNAMENT_TRIG":          {Description: "리셋: 토너먼트 자동 시작"},
	"RESET_RESERVE_OPEN":             {Description: "리셋: 오픈 예약"},
	"RESET_PRE_RESERVE_OPEN":         {Description: "리셋: 가오픈 예약"},
}

var v2ServerDefinitionKeys = map[string]struct{}{
	"SPRING_FLYWAY_LOCATIONS": {},
	"SPRING_PROFILES_ACTIVE":  {},
}

// serverComposeInterpolationKeys lists every variable the v1 server template
// interpolates. A server compose child must not inherit these values from the
// deployer process because Compose gives its shell environment precedence over
// --env-file.
var serverComposeInterpolationKeys = map[string]struct{}{
	"COMPOSE_HOST_DIR":               {},
	"GATEWAY_API_URL":                {},
	"INTERNAL_SERVICE_TOKEN":         {},
	"GAME_API_PORT":                  {},
	"GAME_API_URL":                   {},
	"GAME_POSTGRES_DB":               {},
	"GAME_POSTGRES_PASSWORD":         {},
	"GAME_POSTGRES_USER":             {},
	"GHCR_OWNER":                     {},
	"GHCR_REGISTRY":                  {},
	"IMAGE_TAG":                      {},
	"JWT_PUBLIC_KEY":                 {},
	"JWT_LEGACY_SECRET":              {},
	"JWT_LEGACY_ACCESS_ACCEPT_UNTIL": {},
	"OPENSAMGUK_WORLD_ID":            {},
	"PWD":                            {},
	"RESET_BLOCK_GENERAL_CREATE":     {},
	"RESET_EXTEND":                   {},
	"RESET_FICTION":                  {},
	"RESET_NPCMODE":                  {},
	"RESET_SHOW_IMG_LEVEL":           {},
	"RESET_TURNTERM":                 {},
	"SCENARIO_CODE":                  {},
	"SCENARIO_DIR":                   {},
	"SCENARIO_SEED_ENABLED":          {},
	"SERVER_GENERATION":              {},
	"SERVER_ID":                      {},
	"SERVER_NAME":                    {},
	"TURN_PROFILE_NAME":              {},
	"WEB_GAME_PORT":                  {},
	"WEB_GAME_TAG":                   {},
}

var serverComposeProcessControlKeys = map[string]struct{}{
	"COMPOSE_DISABLE_ENV_FILE": {},
	"COMPOSE_ENV_FILES":        {},
	"COMPOSE_FILE":             {},
	"COMPOSE_PATH_SEPARATOR":   {},
	"COMPOSE_PROFILES":         {},
	"COMPOSE_PROJECT_NAME":     {},
}

var resetLifecycleUpdateKeys = []string{
	"SCENARIO_CODE",
	"SCENARIO_SEED_ENABLED",
	"SERVER_GENERATION",
	"RESET_TURNTERM",
	"RESET_SYNC",
	"RESET_FICTION",
	"RESET_EXTEND",
	"RESET_BLOCK_GENERAL_CREATE",
	"RESET_NPCMODE",
	"RESET_SHOW_IMG_LEVEL",
	"RESET_AUTORUN_USER_OPTIONS",
	"RESET_AUTORUN_USER_MINUTES",
	"RESET_JOIN_MODE",
	"RESET_TOURNAMENT_TRIG",
	"RESET_RESERVE_OPEN",
	"RESET_PRE_RESERVE_OPEN",
}

var registryEnvAllowlist = map[string]struct{}{
	"IMAGE_TAG":                  {},
	"GAME_API_PORT":              {},
	"WEB_GAME_PORT":              {},
	"WEB_GAME_TAG":               {},
	"TURN_PROFILE_NAME":          {},
	"SCENARIO_SEED_ENABLED":      {},
	"SCENARIO_CODE":              {},
	"SERVER_NAME":                {},
	"SERVER_GENERATION":          {},
	"GAME_API_URL":               {},
	"GATEWAY_API_URL":            {},
	"RESET_TURNTERM":             {},
	"RESET_SYNC":                 {},
	"RESET_FICTION":              {},
	"RESET_EXTEND":               {},
	"RESET_BLOCK_GENERAL_CREATE": {},
	"RESET_NPCMODE":              {},
	"RESET_SHOW_IMG_LEVEL":       {},
	"RESET_AUTORUN_USER_OPTIONS": {},
	"RESET_AUTORUN_USER_MINUTES": {},
	"RESET_JOIN_MODE":            {},
	"RESET_TOURNAMENT_TRIG":      {},
	"RESET_RESERVE_OPEN":         {},
	"RESET_PRE_RESERVE_OPEN":     {},
}

var sharedEnvAllowlist = map[string]envFieldSpec{
	"IMAGE_TAG":               {Description: "공유 스택 이미지 태그"},
	"NGINX_HTTP_PORT":         {Description: "nginx HTTP 호스트 포트"},
	"NGINX_HTTPS_PORT":        {Description: "nginx HTTPS 호스트 포트"},
	"NEXT_PUBLIC_GATEWAY_URL": {Description: "게이트웨이 공개 URL"},
	"NEXT_PUBLIC_IMAGE_CDN":   {Description: "이미지 CDN URL"},
	"COOKIE_SECURE":           {Description: "Secure 쿠키 사용 여부"},
	"JWT_PRIVATE_KEY":         {Description: "JWT 서명 개인키(gateway-api 전용)", WriteOnly: true},
	"JWT_PUBLIC_KEY":          {Description: "JWT 검증 공개키(비밀 아님, 서버들이 복사)"},
	"INTERNAL_SERVICE_TOKEN":  {Description: "game-api 내부 프로필 조회 토큰", WriteOnly: true},
	"JWT_LEGACY_SECRET":       {Description: "레거시 HS256 검증 시크릿", WriteOnly: true},
	"ADMIN_PASSWORD":          {Description: "초기 관리자 비밀번호", WriteOnly: true},
	"GHCR_TOKEN":              {Description: "GHCR 조회 토큰", WriteOnly: true},
}

// 환경변수 묶음.
type config struct {
	token                     string // Bearer 인증 토큰
	composeDir                string // compose 파일 디렉터리(/workspace)
	composeHostDir            string
	serversDir                string // 서버 env 파일 디렉터리(/workspace/servers)
	composeServer             string // 서버 compose 파일 절대경로
	composeShared             string
	ghcrOwner                 string // GHCR 패키지 소유자(태그 조회)
	ghcrToken                 string // GHCR 조회 토큰(private면 필요, 없으면 익명)
	ghcrAPIBaseURL            string
	localHTTPBaseURL          string
	authenticatedHTTPTimeout  time.Duration
	dockerRunner              func(args ...string) (string, error)
	dockerRunnerContext       func(context.Context, ...string) (string, error)
	httpGet                   func(context.Context, string) (int, []byte, error)
	gameAPIInternalPort       string
	gameEngineInternalPort    string
	gatewayAPIURL             string
	resetVerifyTimeout        time.Duration
	resetVerifyPollInterval   time.Duration
	lifecycleJobs             *lifecycleJobManager
	lifecycleOperationStore   *durableOperationStore
	maintenanceFile           string
	lifecycleJournalFile      string
	sharedEnvMu               *sync.Mutex
	registryRewriteHook       func()
	lifecycleJournalWriteHook func(lifecycleJournal)
	lifecycleJournalClearHook func()
	operations                *operationCoordinator
}

type lifecycleJobStatus string

const (
	lifecycleJobPending          lifecycleJobStatus = "pending"
	lifecycleJobRunning          lifecycleJobStatus = "running"
	lifecycleJobRecoveryRequired lifecycleJobStatus = "recovery_required"
	lifecycleJobSucceeded        lifecycleJobStatus = "succeeded"
	lifecycleJobFailed           lifecycleJobStatus = "failed"
	lifecycleJobCancelled        lifecycleJobStatus = "cancelled"
)

// lifecycleKind는 gateway-api(DeployService)가 GET /operations/{id} 응답의 `kind`로
// 대조하는 값이다. transition.action(CREATE/CLOSE/RESET)의 remoteKind와 문자열이 같아야 한다.
type lifecycleKind string

const (
	lifecycleKindCreate lifecycleKind = "create"
	lifecycleKindClose  lifecycleKind = "close"
	lifecycleKindReset  lifecycleKind = "reset"
)

type lifecycleJob struct {
	id                   string
	status               lifecycleJobStatus
	finishedAt           time.Time
	operationID          string
	operationFingerprint string
	kind                 lifecycleKind
	subjectID            string
	httpStatus           int
	publicMessage        string
	result               json.RawMessage
	cancel               context.CancelFunc
	cancelRequested      bool
}

// operationResponse는 gateway-api가 원격 lifecycle 작업을 재확인할 때 읽는 공개 본문이다.
// 실행 상세나 원 요청은 durable store에 보관하지 않으므로 이 응답에도 싣지 않는다.
type operationResponse struct {
	OperationID string             `json:"operationId"`
	Kind        lifecycleKind      `json:"kind"`
	SubjectID   string             `json:"subjectId"`
	Status      lifecycleJobStatus `json:"status"`
	HTTPStatus  int                `json:"httpStatus"`
	Message     string             `json:"publicMessage"`
}

// operationNotFoundResponse는 gateway-api의 isExactUnknownOperation이 정확히 3-key로
// 검사하는 404 본문이다. 필드를 더하면 gateway는 Missing이 아니라 Unavailable로 떨어져
// transition을 영구 repair-pending 상태로 남긴다.
type operationNotFoundResponse struct {
	OK          bool   `json:"ok"`
	OperationID string `json:"operationId"`
	Status      string `json:"status"`
}

type lifecycleJobResponse struct {
	ID            string             `json:"id"`
	Status        lifecycleJobStatus `json:"status"`
	PublicMessage string             `json:"publicMessage,omitempty"`
}

type lifecycleJobManager struct {
	mu                sync.Mutex
	jobs              map[string]lifecycleJob
	operationJobs     map[string]string
	maxEntries        int
	terminalRetention time.Duration
	now               func() time.Time
}

var (
	errMaintenanceClosed       = errors.New("maintenance barrier is closed")
	errMaintenanceIdleConflict = errors.New("maintenance idle admission conflict")
	errLifecycleJobNotPending  = errors.New("lifecycle job is no longer pending")
	errMaintenanceLeaseUsed    = errors.New("maintenance lease has already been consumed")
	errDockerUnreachable       = errors.New("docker daemon is unreachable")
)

const (
	// /readyz는 워크플로에서 2초 간격으로 폴링되고 wget -T 5 안에서 돌아야 한다.
	dockerPreflightTimeout     = 3 * time.Second
	dockerPreflightDetailLimit = 300
)

// operationCoordinator serializes every durable control-plane mutation. Unlike
// a host flock, it is also visible to direct API callers through its persisted
// maintenance marker, so a workflow can drain the running deployer before
// replacing containers or shared files.
type operationCoordinator struct {
	mu               sync.Mutex
	cond             *sync.Cond
	closed           bool
	journalPending   bool
	active           *operationLease
	maintenanceLease *maintenanceAdmissionLease
	markerPath       string
	journalPath      string
	jobs             *lifecycleJobManager
	writeMarker      func(string) (bool, error)
}

type maintenanceAdmissionLease struct {
	token       string
	operationID string
	jobID       string
	consumed    bool
}

type operationLease struct {
	coordinator *operationCoordinator
	jobID       string
	ctx         context.Context
	cancel      context.CancelFunc
	done        sync.Once
}

func newOperationCoordinator(markerPath string, journalPath string, jobs *lifecycleJobManager) *operationCoordinator {
	coordinator := &operationCoordinator{
		markerPath:  markerPath,
		journalPath: journalPath,
		jobs:        jobs,
		writeMarker: writeMaintenanceMarkerDurable,
	}
	coordinator.cond = sync.NewCond(&coordinator.mu)
	if stateFilePresent(markerPath) || stateFilePresent(journalPath) {
		// An unreadable marker/journal is treated as present. Starting fail-closed
		// is safer than admitting mutations while persisted lifecycle state is unknown.
		coordinator.closed = true
		coordinator.journalPending = stateFilePresent(journalPath)
	}
	return coordinator
}

func stateFilePresent(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func (c *operationCoordinator) begin(jobID string) (*operationLease, error) {
	return c.beginWithMaintenanceLease(jobID, "", "")
}

func (c *operationCoordinator) beginWithMaintenanceLease(jobID, token, operationID string) (*operationLease, error) {
	if c == nil {
		return nil, errors.New("operation coordinator unavailable")
	}
	c.mu.Lock()
	for c.active != nil && !c.closed {
		c.cond.Wait()
	}
	if c.journalPending || stateFilePresent(c.journalPath) {
		c.closed = true
		c.journalPending = true
		c.mu.Unlock()
		if jobID != "" && c.jobs != nil {
			c.jobs.requestCancel(jobID)
		}
		return nil, errMaintenanceClosed
	}
	if c.closed {
		lease := c.maintenanceLease
		if c.active != nil || jobID == "" || operationID == "" || lease == nil || lease.consumed || !secureEqual(lease.token, token) {
			c.mu.Unlock()
			if jobID != "" && c.jobs != nil {
				c.jobs.requestCancel(jobID)
			}
			return nil, errMaintenanceClosed
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	if jobID != "" {
		if c.jobs == nil || !c.jobs.claim(jobID, cancel) {
			c.mu.Unlock()
			cancel()
			return nil, errLifecycleJobNotPending
		}
	}
	if c.closed {
		c.maintenanceLease.consumed = true
		c.maintenanceLease.operationID = operationID
		c.maintenanceLease.jobID = jobID
	}
	lease := &operationLease{
		coordinator: c,
		jobID:       jobID,
		ctx:         ctx,
		cancel:      cancel,
	}
	c.active = lease
	c.mu.Unlock()
	return lease, nil
}

func (c *operationCoordinator) beginRecovery() (*operationLease, error) {
	if c == nil {
		return nil, errors.New("operation coordinator unavailable")
	}
	c.mu.Lock()
	for c.active != nil {
		c.cond.Wait()
	}
	if !c.journalPending && !stateFilePresent(c.journalPath) {
		c.mu.Unlock()
		return nil, errors.New("lifecycle recovery journal is unavailable")
	}
	c.closed = true
	c.journalPending = true
	ctx, cancel := context.WithCancel(context.Background())
	lease := &operationLease{coordinator: c, ctx: ctx, cancel: cancel}
	c.active = lease
	c.mu.Unlock()
	return lease, nil
}

func (c *operationCoordinator) markLifecycleJournalPending() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.journalPending = true
	if c.active == nil {
		c.closed = true
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *operationCoordinator) clearLifecycleJournalPending() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.journalPending = false
	if !stateFilePresent(c.markerPath) {
		c.closed = false
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *operationCoordinator) lifecycleRecoveryPending() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journalPending || stateFilePresent(c.journalPath) {
		c.journalPending = true
		return true
	}
	return false
}

func (c *operationCoordinator) claimLifecycleJob(lease *operationLease, jobID string) error {
	if c == nil || lease == nil || jobID == "" {
		return errors.New("lifecycle job claim is unavailable")
	}
	c.mu.Lock()
	if c.active != lease {
		c.mu.Unlock()
		return errors.New("operation lease is no longer active")
	}
	if c.closed || lease.Context().Err() != nil {
		c.mu.Unlock()
		if c.jobs != nil {
			c.jobs.requestCancel(jobID)
		}
		return errMaintenanceClosed
	}
	if c.jobs == nil || !c.jobs.claim(jobID, lease.cancel) {
		c.mu.Unlock()
		return errLifecycleJobNotPending
	}
	lease.jobID = jobID
	c.mu.Unlock()
	return nil
}

func (l *operationLease) Context() context.Context {
	if l == nil || l.ctx == nil {
		return context.Background()
	}
	return l.ctx
}

func (l *operationLease) Done() {
	if l == nil || l.coordinator == nil {
		return
	}
	l.done.Do(func() {
		l.cancel()
		coordinator := l.coordinator
		coordinator.mu.Lock()
		if coordinator.active == l {
			if coordinator.journalPending || stateFilePresent(coordinator.journalPath) {
				coordinator.closed = true
			}
			coordinator.active = nil
			coordinator.cond.Broadcast()
		}
		coordinator.mu.Unlock()
	})
}

func (c *operationCoordinator) maintenanceState() maintenanceState {
	if c == nil {
		return maintenanceStateDrained
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maintenanceStateLocked()
}

func (c *operationCoordinator) maintenanceStateLocked() maintenanceState {
	if !c.closed {
		return maintenanceStateOpen
	}
	if c.active != nil {
		return maintenanceStateDraining
	}
	return maintenanceStateDrained
}

func (c *operationCoordinator) enterMaintenance() (maintenanceState, string, error) {
	if c == nil {
		return maintenanceStateDrained, "", errors.New("operation coordinator unavailable")
	}
	c.mu.Lock()
	if !stateFilePresent(c.markerPath) {
		if err := writeMaintenanceMarkerAtomic(c.markerPath); err != nil {
			c.mu.Unlock()
			return maintenanceStateOpen, "", err
		}
	}
	c.closed = true
	active := c.active
	if active != nil {
		active.cancel()
	}
	c.cond.Broadcast()
	c.mu.Unlock()

	if active != nil && active.jobID != "" && c.jobs != nil {
		c.jobs.requestCancel(active.jobID)
	}

	c.mu.Lock()
	for c.active != nil {
		c.cond.Wait()
	}
	if c.maintenanceLease == nil {
		token, err := randomHex(maintenanceLeaseBytes)
		if err != nil {
			state := c.maintenanceStateLocked()
			c.mu.Unlock()
			return state, "", err
		}
		c.maintenanceLease = &maintenanceAdmissionLease{token: token}
	} else if c.maintenanceLease.consumed {
		state := c.maintenanceStateLocked()
		c.mu.Unlock()
		return state, "", errMaintenanceLeaseUsed
	}
	state := c.maintenanceStateLocked()
	token := c.maintenanceLease.token
	c.mu.Unlock()
	return state, token, nil
}

func (c *operationCoordinator) enterMaintenanceIfIdle() (maintenanceState, string, error) {
	if c == nil {
		return maintenanceStateDrained, "", errors.New("operation coordinator unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.maintenanceStateLocked()
	if c.active != nil || c.closed || c.journalPending || stateFilePresent(c.markerPath) || stateFilePresent(c.journalPath) {
		return state, "", errMaintenanceIdleConflict
	}
	token, err := randomHex(maintenanceLeaseBytes)
	if err != nil {
		return state, "", err
	}
	writeMarker := c.writeMarker
	if writeMarker == nil {
		writeMarker = writeMaintenanceMarkerDurable
	}
	committed, err := writeMarker(c.markerPath)
	if err != nil {
		if committed || stateFilePresent(c.markerPath) {
			c.closed = true
			c.maintenanceLease = nil
			c.cond.Broadcast()
		}
		return c.maintenanceStateLocked(), "", err
	}
	if !committed {
		return state, "", errors.New("maintenance marker was not committed")
	}
	c.closed = true
	c.maintenanceLease = &maintenanceAdmissionLease{token: token}
	c.cond.Broadcast()
	return maintenanceStateDrained, token, nil
}

func (c *operationCoordinator) leaveMaintenance() (maintenanceState, error) {
	if c == nil {
		return maintenanceStateDrained, errors.New("operation coordinator unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return maintenanceStateOpen, nil
	}
	if c.active != nil {
		return maintenanceStateDraining, errors.New("maintenance operation is not drained")
	}
	if c.journalPending || stateFilePresent(c.journalPath) {
		c.closed = true
		c.journalPending = true
		return maintenanceStateDrained, errors.New("lifecycle recovery is required before maintenance can open")
	}
	if c.markerPath == "" {
		return maintenanceStateDrained, errors.New("maintenance marker path is unavailable")
	}
	if err := os.Remove(c.markerPath); err != nil && !os.IsNotExist(err) {
		return maintenanceStateDrained, err
	}
	c.maintenanceLease = nil
	c.closed = false
	c.cond.Broadcast()
	return maintenanceStateOpen, nil
}

func writeMaintenanceMarkerAtomic(path string) error {
	if path == "" {
		return errors.New("maintenance marker path is unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte("{\"capability\":\"maintenance-v1\"}\n"))
}

func writeMaintenanceMarkerDurable(path string) (bool, error) {
	return writeMaintenanceMarkerDurableWithSync(path, syncDirectory)
}

func writeMaintenanceMarkerDurableWithSync(path string, syncDir func(string) error) (bool, error) {
	if path == "" {
		return false, errors.New("maintenance marker path is unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return writeFileAtomicWithDurabilityResult(path, []byte("{\"capability\":\"maintenance-v1\"}\n"), true, syncDir)
}

type lifecycleJournal struct {
	Version       int                   `json:"version"`
	Operation     string                `json:"operation"`
	OperationID   string                `json:"operationId,omitempty"`
	OperationKind lifecycleKind         `json:"operationKind,omitempty"`
	Stage         string                `json:"stage,omitempty"`
	ServerID      string                `json:"serverId"`
	Project       string                `json:"project"`
	ResetTarget   *resetLifecycleTarget `json:"resetTarget,omitempty"`
}

type resetLifecycleTarget struct {
	ScenarioCode        string            `json:"scenarioCode"`
	Generation          int               `json:"generation"`
	ScenarioSeedEnabled bool              `json:"scenarioSeedEnabled"`
	Updates             map[string]string `json:"updates,omitempty"`
}

const (
	lifecycleJournalVersion       = 1
	lifecycleJournalStagePrepared = "prepared"
	lifecycleJournalStageEnv      = "env-updated"
	lifecycleJournalStageRegistry = "registry-synced"
	lifecycleJournalStageDown     = "down-pending"
)

func (c config) writeLifecycleJournal(operation string, target serverTarget) error {
	return c.writeLifecycleJournalWithResetTarget(operation, target, nil, "", "")
}

func (c config) writeLinkedLifecycleJournal(operation string, target serverTarget, operationID string, kind lifecycleKind) error {
	return c.writeLifecycleJournalWithResetTarget(operation, target, nil, operationID, kind)
}

func (c config) writeResetLifecycleJournal(target serverTarget, resetTarget resetLifecycleTarget) error {
	return c.writeLinkedResetLifecycleJournal(target, resetTarget, "", "")
}

func (c config) writeLinkedResetLifecycleJournal(target serverTarget, resetTarget resetLifecycleTarget, operationID string, kind lifecycleKind) error {
	normalized, err := normalizeResetLifecycleTarget(resetTarget)
	if err != nil {
		return err
	}
	return c.writeLifecycleJournalWithResetTarget("reset", target, &normalized, operationID, kind)
}

func (c config) writeLifecycleJournalWithResetTarget(operation string, target serverTarget, resetTarget *resetLifecycleTarget, operationID string, kind lifecycleKind) error {
	if c.lifecycleJournalFile == "" {
		return errors.New("lifecycle journal path is unavailable")
	}
	if stateFilePresent(c.lifecycleJournalFile) {
		return errors.New("lifecycle recovery journal is already present")
	}
	if !isLifecycleJournalOperation(operation) {
		return errors.New("unsupported lifecycle journal operation")
	}
	if operation != "reset" && resetTarget != nil {
		return errors.New("only reset journals can carry a reset target")
	}
	if err := validateLifecycleJournalOperationLink(operation, operationID, kind); err != nil {
		return err
	}
	if err := c.writeLifecycleJournalRecord(lifecycleJournal{
		Version:       lifecycleJournalVersion,
		Operation:     operation,
		OperationID:   operationID,
		OperationKind: kind,
		Stage:         lifecycleJournalStagePrepared,
		ServerID:      target.ID,
		Project:       target.Project,
		ResetTarget:   resetTarget,
	}); err != nil {
		return err
	}
	if c.operations != nil {
		c.operations.markLifecycleJournalPending()
	}
	return nil
}

func (c config) advanceLifecycleJournal(stage string) error {
	if !isLifecycleJournalStage(stage) {
		return errors.New("unsupported lifecycle journal stage")
	}
	journal, exists, err := c.readLifecycleJournal()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("lifecycle recovery journal is unavailable")
	}
	journal.Stage = stage
	if err := c.writeLifecycleJournalRecord(journal); err != nil {
		return err
	}
	if c.operations != nil {
		c.operations.markLifecycleJournalPending()
	}
	return nil
}

func isLifecycleJournalOperation(operation string) bool {
	switch operation {
	case "create", "delete", "deploy", "patch", "reset":
		return true
	default:
		return false
	}
}

func isLifecycleJournalStage(stage string) bool {
	switch stage {
	case "", lifecycleJournalStagePrepared, lifecycleJournalStageEnv, lifecycleJournalStageRegistry, lifecycleJournalStageDown:
		return true
	default:
		return false
	}
}

func validateLifecycleJournalOperationLink(operation, operationID string, kind lifecycleKind) error {
	if operationID == "" && kind == "" {
		return nil
	}
	if !lifecycleJobIDRe.MatchString(operationID) {
		return errors.New("lifecycle journal operation id is invalid")
	}
	want := lifecycleKind("")
	switch operation {
	case "create":
		want = lifecycleKindCreate
	case "delete":
		want = lifecycleKindClose
	case "reset":
		want = lifecycleKindReset
	}
	if want == "" || kind != want {
		return errors.New("lifecycle journal operation kind is invalid")
	}
	return nil
}

func (c config) writeLifecycleJournalRecord(journal lifecycleJournal) error {
	payload, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.lifecycleJournalFile), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomicDurable(c.lifecycleJournalFile, append(payload, '\n')); err != nil {
		return err
	}
	if c.lifecycleJournalWriteHook != nil {
		c.lifecycleJournalWriteHook(journal)
	}
	return nil
}

func (c config) readLifecycleJournal() (lifecycleJournal, bool, error) {
	if c.lifecycleJournalFile == "" {
		return lifecycleJournal{}, false, errors.New("lifecycle journal path is unavailable")
	}
	data, err := os.ReadFile(c.lifecycleJournalFile)
	if os.IsNotExist(err) {
		return lifecycleJournal{}, false, nil
	}
	if err != nil {
		return lifecycleJournal{}, false, err
	}
	var journal lifecycleJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return lifecycleJournal{}, false, err
	}
	if journal.Version != lifecycleJournalVersion || !isLifecycleJournalOperation(journal.Operation) || !isLifecycleJournalStage(journal.Stage) {
		return lifecycleJournal{}, false, errors.New("lifecycle journal is invalid")
	}
	if err := validateLifecycleJournalOperationLink(journal.Operation, journal.OperationID, journal.OperationKind); err != nil {
		return lifecycleJournal{}, false, err
	}
	target, err := c.serverTargetForID(journal.ServerID)
	if err != nil || target.Project != journal.Project {
		return lifecycleJournal{}, false, errors.New("lifecycle journal target is invalid")
	}
	journal.ServerID = target.ID
	journal.Project = target.Project
	if journal.Operation != "reset" && journal.ResetTarget != nil {
		return lifecycleJournal{}, false, errors.New("lifecycle journal has an invalid reset target")
	}
	if journal.ResetTarget != nil {
		normalized, err := normalizeResetLifecycleTarget(*journal.ResetTarget)
		if err != nil {
			return lifecycleJournal{}, false, err
		}
		journal.ResetTarget = &normalized
	}
	return journal, true, nil
}

func (c config) clearLifecycleJournal() error {
	if c.lifecycleJournalFile == "" {
		return errors.New("lifecycle journal path is unavailable")
	}
	if c.lifecycleJournalClearHook != nil {
		c.lifecycleJournalClearHook()
	}
	if err := os.Remove(c.lifecycleJournalFile); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := syncDirectory(filepath.Dir(c.lifecycleJournalFile)); err != nil {
		return err
	}
	if c.operations != nil {
		c.operations.clearLifecycleJournalPending()
	}
	return nil
}

func (c config) repairLifecycleJournal() (repairErr error) {
	if c.operations == nil {
		return errors.New("operation coordinator unavailable")
	}
	lease, err := c.operations.beginRecovery()
	if err != nil {
		if preflightErr := c.dockerPreflight(context.Background()); preflightErr != nil {
			return preflightErr
		}
		return err
	}
	defer lease.Done()
	journal, exists, err := c.readLifecycleJournal()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("lifecycle recovery journal is unavailable")
	}
	linkedOperationSettled := false
	defer func() {
		if repairErr == nil || journal.OperationID == "" || linkedOperationSettled {
			return
		}
		if transitionErr := c.transitionDurableLifecycleOperation(journal.OperationID, lifecycleJobRecoveryRequired, http.StatusAccepted, durableOperationMessageRecoveryRequired); transitionErr != nil {
			repairErr = fmt.Errorf("%v; persist recovery-required operation: %w", repairErr, transitionErr)
		}
	}()
	target, err := c.serverTargetForID(journal.ServerID)
	if err != nil || target.Project != journal.Project {
		return errors.New("lifecycle recovery target is invalid")
	}
	if journal.OperationID != "" {
		if operation, ok := c.lifecycleOperationStore.Lookup(journal.OperationID); ok && operation.Status == lifecycleJobSucceeded {
			if err := c.verifySucceededLifecycleJournal(journal, target); err != nil {
				return err
			}
			linkedOperationSettled = true
			return c.clearLifecycleJournal()
		}
	}
	if _, envErr := os.Stat(target.EnvFile); envErr == nil {
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
	} else if !os.IsNotExist(envErr) || (journal.Operation != "create" && journal.Operation != "delete") {
		return envErr
	}
	if err := c.dockerPreflight(lease.Context()); err != nil {
		return err
	}

	switch journal.Operation {
	case "create":
		_, envErr := os.Stat(target.EnvFile)
		entry, entryErr := c.registryEntryByID(target.ID)
		if entryErr != nil {
			return entryErr
		}
		if os.IsNotExist(envErr) && entry.ID == "" {
			// The journal is durable before the atomic env-file creation. A crash
			// in that narrow interval left no lifecycle state to recover.
			if journal.OperationID != "" {
				if err := c.transitionDurableLifecycleOperation(journal.OperationID, lifecycleJobCancelled, http.StatusConflict, durableOperationMessageCancelled); err != nil {
					return err
				}
				linkedOperationSettled = true
			}
			return c.clearLifecycleJournal()
		}
		if envErr != nil {
			return envErr
		}
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
		if entry.ID == "" {
			if _, err := c.syncRegistryEntryFromEnv(target.ID, target.EnvFile); err != nil {
				return err
			}
		}
		if _, err := c.upServerStack(lease.Context(), target.Project, target.EnvFile); err != nil {
			return err
		}
		if _, err := c.reloadSharedRegistry(lease.Context()); err != nil {
			return err
		}
	case "reset":
		if err := c.prepareResetRecovery(journal, target); err != nil {
			return err
		}
		if err := c.reconcileServerRegistry(target); err != nil {
			return err
		}
		if err := c.setRegistryRepairRequired(target.ID, true); err != nil {
			return err
		}
		if err := c.advanceLifecycleJournal(lifecycleJournalStageDown); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if _, err := c.downServerStack(lease.Context(), target.Project, target.EnvFile); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if _, err := c.upServerStack(lease.Context(), target.Project, target.EnvFile); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if err := c.verifyResetRuntime(lease.Context(), target); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if err := c.reconcileServerRegistry(target); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if err := c.setRegistryRepairRequired(target.ID, false); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if _, err := c.reloadSharedRegistry(lease.Context()); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
		if err := c.verifySharedRegistryReload(lease.Context(), target); err != nil {
			return c.markResetRepairRequired(target.ID, err)
		}
	case "patch":
		if err := c.reconcileServerRegistry(target); err != nil {
			return err
		}
		if _, err := c.reloadSharedRegistry(lease.Context()); err != nil {
			return err
		}
	case "deploy":
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
		if _, err := c.upStateless(lease.Context(), target.Project, target.EnvFile); err != nil {
			return err
		}
	case "delete":
		_, envErr := os.Stat(target.EnvFile)
		if envErr == nil {
			if _, err := c.validateServerTarget(target); err != nil {
				return err
			}
			if _, err := c.downServerStack(lease.Context(), target.Project, target.EnvFile); err != nil {
				return err
			}
			if err := os.Remove(target.EnvFile); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else if !os.IsNotExist(envErr) {
			return envErr
		}
		if _, err := c.removeRegistryEntry(target.ID); err != nil {
			return err
		}
		if _, err := c.reloadSharedRegistry(lease.Context()); err != nil {
			return err
		}
	}
	if journal.OperationID != "" {
		if err := c.transitionDurableLifecycleOperation(journal.OperationID, lifecycleJobSucceeded, http.StatusOK, durableOperationSuccessMessage(journal.OperationKind)); err != nil {
			return err
		}
		linkedOperationSettled = true
	}
	return c.clearLifecycleJournal()
}

func (c config) verifySucceededLifecycleJournal(journal lifecycleJournal, target serverTarget) error {
	switch journal.Operation {
	case "create":
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
		entry, err := c.registryEntryByID(target.ID)
		if err != nil {
			return err
		}
		if entry.ID == "" || entry.DeployProject != target.Project {
			return errors.New("completed create postcondition is unavailable")
		}
	case "delete":
		if _, err := os.Stat(target.EnvFile); !os.IsNotExist(err) {
			if err == nil {
				return errors.New("completed close retained its server env")
			}
			return err
		}
		entry, err := c.registryEntryByID(target.ID)
		if err != nil {
			return err
		}
		if entry.ID != "" {
			return errors.New("completed close retained its registry entry")
		}
	case "reset":
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
		if err := c.verifyResetRuntime(context.Background(), target); err != nil {
			return err
		}
		if err := c.reconcileServerRegistry(target); err != nil {
			return err
		}
		if err := c.setRegistryRepairRequired(target.ID, false); err != nil {
			return err
		}
		if err := c.verifySharedRegistryReload(context.Background(), target); err != nil {
			return err
		}
	default:
		return errors.New("linked lifecycle journal operation is invalid")
	}
	return nil
}

func (c config) markResetRepairRequired(id string, cause error) error {
	if markerErr := c.setRegistryRepairRequired(id, true); markerErr != nil {
		return fmt.Errorf("could not durably persist reset repair-required state: %v (original failure: %w)", markerErr, cause)
	}
	return cause
}

func (c config) prepareResetRecovery(journal lifecycleJournal, target serverTarget) error {
	preMutation := journal.Stage == "" || journal.Stage == lifecycleJournalStagePrepared
	resetTarget := resetLifecycleTarget{}
	if journal.ResetTarget != nil {
		resetTarget = *journal.ResetTarget
	} else {
		if preMutation {
			return errors.New("reset recovery target is unavailable before destructive mutation")
		}
		var err error
		resetTarget, err = resetLifecycleTargetForEnv(target.EnvFile, nil)
		if err != nil {
			return err
		}
	}
	if _, err := c.validateServerTarget(target); err != nil {
		return err
	}
	if err := applyResetLifecycleTarget(target.EnvFile, resetTarget); err != nil {
		return err
	}
	if preMutation {
		return c.advanceLifecycleJournal(lifecycleJournalStageEnv)
	}
	values, err := c.validateServerTarget(target)
	if err != nil {
		return err
	}
	_, err = resetRuntimeExpectationFor(values)
	return err
}

func newLifecycleJobManager() *lifecycleJobManager {
	return &lifecycleJobManager{
		jobs:              make(map[string]lifecycleJob),
		operationJobs:     make(map[string]string),
		maxEntries:        lifecycleJobMaxEntries,
		terminalRetention: lifecycleJobTerminalRetention,
		now:               time.Now,
	}
}

func (c config) reserveDurableLifecycleOperation(requestedID string, kind lifecycleKind, subjectID, fingerprint string) (durableOperationRecord, bool, error) {
	if requestedID == "" {
		return durableOperationRecord{}, false, errors.New("durable operation id is required")
	}
	operationID := requestedID
	if c.lifecycleOperationStore == nil {
		return durableOperationRecord{}, false, errors.New("durable operation store unavailable")
	}
	desired := durableOperationRecord{
		OperationID:        operationID,
		Kind:               kind,
		SubjectID:          subjectID,
		RequestFingerprint: fingerprint,
		Status:             lifecycleJobPending,
	}
	record, existing, err := c.lifecycleOperationStore.Reserve(desired)
	if err == nil {
		return record, existing, nil
	}
	// An identical retry may be the trigger that re-attempts a deferred terminal
	// settlement. Do not reinterpret its persistence error as a fresh committed
	// reservation, or the still-pending record would be replayed again.
	if existing {
		return record, true, err
	}
	// The atomic rename may be visible even when directory fsync reports an
	// error. Lookup is the idempotent source of truth for that committed case.
	if committed, ok := c.lifecycleOperationStore.Lookup(operationID); ok {
		if committed.Kind != kind || committed.SubjectID != subjectID || committed.RequestFingerprint != fingerprint {
			return durableOperationRecord{}, false, errLifecycleOperationConflict
		}
		return committed, false, nil
	}
	return durableOperationRecord{}, false, err
}

func lifecycleOperationReplay(record durableOperationRecord, jobID, detail string) createServerResponse {
	if record.PublicMessage != "" {
		detail = record.PublicMessage
	}
	return createServerResponse{
		OK:              record.Status != lifecycleJobFailed && record.Status != lifecycleJobCancelled,
		ID:              record.SubjectID,
		JobID:           jobID,
		OperationID:     record.OperationID,
		OperationStatus: record.Status,
		Detail:          detail,
	}
}

func operationResponseForRecord(record durableOperationRecord) operationResponse {
	return operationResponse{
		OperationID: record.OperationID,
		Kind:        record.Kind,
		SubjectID:   record.SubjectID,
		Status:      record.Status,
		HTTPStatus:  record.HTTPStatus,
		Message:     record.PublicMessage,
	}
}

func (c config) transitionDurableLifecycleOperation(operationID string, status lifecycleJobStatus, httpStatus int, messageID durableOperationMessageID) error {
	if operationID == "" {
		return nil
	}
	if c.lifecycleOperationStore == nil {
		return errors.New("durable operation store unavailable")
	}
	_, err := c.lifecycleOperationStore.Transition(operationID, status, httpStatus, messageID)
	if err == nil {
		return nil
	}
	wantMessage, messageErr := durableOperationPublicMessage(messageID)
	if messageErr != nil {
		return messageErr
	}
	// A directory fsync error can follow a visible committed rename. Confirm the
	// exact state through Lookup before deciding whether the transition failed.
	if committed, ok := c.lifecycleOperationStore.Lookup(operationID); ok && committed.Status == status && committed.HTTPStatus == httpStatus && committed.PublicMessage == wantMessage {
		return nil
	}
	return err
}

func (c config) settleRejectedDurableLifecycleOperation(operationID string, httpStatus int, messageID durableOperationMessageID) error {
	if operationID == "" || httpStatus < http.StatusBadRequest || c.lifecycleOperationStore == nil {
		return nil
	}
	record, ok := c.lifecycleOperationStore.Lookup(operationID)
	if !ok || record.Status != lifecycleJobPending {
		return nil
	}
	return c.transitionDurableLifecycleOperation(operationID, lifecycleJobFailed, httpStatus, messageID)
}

func rejectedDurableOperationSettlementResponse(response createServerResponse, operationID string, messageID durableOperationMessageID) createServerResponse {
	message, err := durableOperationPublicMessage(messageID)
	if err != nil {
		message = durableOperationVerificationFailedMessage
	}
	response.OK = false
	response.JobID = ""
	response.OperationID = operationID
	response.OperationStatus = ""
	response.RestartRequired = false
	response.AffectedServices = nil
	response.Detail = message
	return response
}

func durableOperationSuccessMessage(kind lifecycleKind) durableOperationMessageID {
	switch kind {
	case lifecycleKindCreate:
		return durableOperationMessageCreateSucceeded
	case lifecycleKindClose:
		return durableOperationMessageCloseSucceeded
	default:
		return durableOperationMessageResetSucceeded
	}
}

func durableOperationPreparationFailureMessage(kind lifecycleKind) durableOperationMessageID {
	switch kind {
	case lifecycleKindCreate:
		return durableOperationMessageCreatePreparationFailed
	case lifecycleKindClose:
		return durableOperationMessageClosePreparationFailed
	default:
		return durableOperationMessageResetPreparationFailed
	}
}

func (m *lifecycleJobManager) reserve() (string, error) {
	id, _, err := m.reserveWithOperation("", "", "")
	return id, err
}

func (m *lifecycleJobManager) jobIDForOperation(operationID string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	jobID := m.operationJobs[operationID]
	if _, ok := m.jobs[jobID]; !ok {
		return ""
	}
	return jobID
}

func (m *lifecycleJobManager) reserveWithOperation(operationID string, operationFingerprint string, kind lifecycleKind) (string, bool, error) {
	if m == nil {
		return "", false, errors.New("lifecycle job manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.jobs == nil {
		m.jobs = make(map[string]lifecycleJob)
	}
	if m.operationJobs == nil {
		m.operationJobs = make(map[string]string)
	}
	m.pruneExpiredTerminalLocked(m.currentTimeLocked())
	if operationID != "" {
		if existingID, exists := m.operationJobs[operationID]; exists {
			if existing, exists := m.jobs[existingID]; exists {
				if existing.operationFingerprint != operationFingerprint {
					return "", false, errLifecycleOperationConflict
				}
				return existingID, true, nil
			}
			delete(m.operationJobs, operationID)
		}
	}
	if len(m.jobs) >= m.maxEntries {
		return "", false, errLifecycleJobCapacity
	}
	for attempts := 0; attempts < 4; attempts++ {
		id, err := randomHex(lifecycleJobIDBytes)
		if err != nil {
			return "", false, err
		}
		if _, exists := m.jobs[id]; exists {
			continue
		}
		m.jobs[id] = lifecycleJob{id: id, status: lifecycleJobPending, operationID: operationID, operationFingerprint: operationFingerprint, kind: kind}
		if operationID != "" {
			m.operationJobs[operationID] = id
		}
		return id, false, nil
	}
	return "", false, errors.New("lifecycle job id collision")
}

func (m *lifecycleJobManager) discard(id string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, exists := m.jobs[id]; exists && (job.status == lifecycleJobPending || isTerminalLifecycleJob(job.status)) {
		delete(m.jobs, id)
		if job.operationID != "" && m.operationJobs[job.operationID] == id {
			delete(m.operationJobs, job.operationID)
		}
	}
}

func (m *lifecycleJobManager) requestCancel(id string) (lifecycleJobResponse, bool) {
	if m == nil {
		return lifecycleJobResponse{}, false
	}
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return lifecycleJobResponse{}, false
	}
	var cancel context.CancelFunc
	switch job.status {
	case lifecycleJobPending:
		job.status = lifecycleJobCancelled
		job.finishedAt = m.currentTimeLocked()
		m.jobs[id] = job
	case lifecycleJobRunning:
		job.cancelRequested = true
		cancel = job.cancel
		m.jobs[id] = job
	}
	response := lifecycleJobResponse{ID: job.id, Status: job.status, PublicMessage: job.publicMessage}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return response, true
}

func (m *lifecycleJobManager) claim(id string, cancel context.CancelFunc) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job, exists := m.jobs[id]
	if !exists || job.status != lifecycleJobPending {
		return false
	}
	job.status = lifecycleJobRunning
	job.cancel = cancel
	m.jobs[id] = job
	return true
}

func (m *lifecycleJobManager) start(id string, work func(context.Context) (string, error)) bool {
	ctx, cancel := context.WithCancel(context.Background())
	if !m.claim(id, cancel) {
		cancel()
		return false
	}
	go func() {
		defer cancel()
		_, err := work(ctx)
		status := lifecycleJobSucceeded
		if errors.Is(ctx.Err(), context.Canceled) {
			status = lifecycleJobCancelled
		} else if err != nil {
			status = lifecycleJobFailed
		}
		m.finish(id, status)
	}()
	return true
}

func (m *lifecycleJobManager) finish(id string, status lifecycleJobStatus) {
	m.finishWithPublicMessage(id, status, "")
}

func (m *lifecycleJobManager) finishWithPublicMessage(id string, status lifecycleJobStatus, publicMessage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, exists := m.jobs[id]
	if !exists {
		return
	}
	if isTerminalLifecycleJob(job.status) {
		return
	}
	if job.cancelRequested && status != lifecycleJobRecoveryRequired {
		status = lifecycleJobCancelled
	}
	job.status = status
	job.publicMessage = publicMessage
	if isTerminalLifecycleJob(status) {
		job.finishedAt = m.currentTimeLocked()
	} else {
		job.finishedAt = time.Time{}
	}
	job.cancel = nil
	m.jobs[id] = job
}

// bindOperationSubject는 이 job이 어떤 서버를 대상으로 하는지 기록한다. terminal 시점에
// 결과 본문을 합성할 때 gateway가 대조하는 `id`가 된다.
func (m *lifecycleJobManager) bindOperationSubject(id string, kind lifecycleKind, subjectID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job, exists := m.jobs[id]
	if !exists {
		return
	}
	if kind != "" {
		job.kind = kind
	}
	if subjectID != "" {
		job.subjectID = subjectID
	}
	m.jobs[id] = job
}

// recordOperationResult는 terminal 결과 본문을 그대로 보존한다. 합성으로는 담을 수 없는
// 상세(detail 등)를 유지해야 하는 경로에서 쓴다.
func (m *lifecycleJobManager) recordOperationResult(id string, status lifecycleJobStatus, httpStatus int, result json.RawMessage) {
	if m == nil {
		return
	}
	m.mu.Lock()
	job, exists := m.jobs[id]
	if exists {
		job.httpStatus = httpStatus
		job.result = result
		m.jobs[id] = job
	}
	m.mu.Unlock()
	if exists && isTerminalLifecycleJob(status) {
		m.finish(id, status)
	}
}

// lookupOperation은 operationId로 job을 찾아 gateway 계약 본문을 만든다.
func (m *lifecycleJobManager) lookupOperation(operationID string) (operationResponse, bool) {
	if m == nil {
		return operationResponse{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredTerminalLocked(m.currentTimeLocked())
	jobID, exists := m.operationJobs[operationID]
	if !exists {
		return operationResponse{}, false
	}
	job, exists := m.jobs[jobID]
	if !exists {
		return operationResponse{}, false
	}
	response := operationResponse{OperationID: operationID, Kind: job.kind, SubjectID: job.subjectID, Status: job.status}
	if !isTerminalLifecycleJob(job.status) {
		return response, true
	}
	response.HTTPStatus = job.httpStatus
	if response.HTTPStatus == 0 {
		response.HTTPStatus = http.StatusOK
		if job.status != lifecycleJobSucceeded {
			response.HTTPStatus = http.StatusInternalServerError
		}
	}
	return response, true
}

func (m *lifecycleJobManager) lookup(id string) (lifecycleJobResponse, bool) {
	if m == nil {
		return lifecycleJobResponse{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredTerminalLocked(m.currentTimeLocked())
	job, exists := m.jobs[id]
	if !exists {
		return lifecycleJobResponse{}, false
	}
	return lifecycleJobResponse{ID: job.id, Status: job.status, PublicMessage: job.publicMessage}, true
}

func (m *lifecycleJobManager) currentTimeLocked() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

func (m *lifecycleJobManager) pruneExpiredTerminalLocked(now time.Time) {
	for id, job := range m.jobs {
		if !isTerminalLifecycleJob(job.status) || job.finishedAt.IsZero() {
			continue
		}
		if !now.Before(job.finishedAt.Add(m.terminalRetention)) {
			delete(m.jobs, id)
			if job.operationID != "" && m.operationJobs[job.operationID] == id {
				delete(m.operationJobs, job.operationID)
			}
		}
	}
}

func isTerminalLifecycleJob(status lifecycleJobStatus) bool {
	return status == lifecycleJobSucceeded || status == lifecycleJobFailed || status == lifecycleJobCancelled
}

func loadConfig() (config, error) {
	jobs := newLifecycleJobManager()
	serversDir := envOr("SERVERS_DIR", "/workspace/servers")
	operationStorePath := envOr("DEPLOYER_OPERATION_STORE_FILE", filepath.Join(serversDir, durableOperationStoreFileName))
	operationStore, err := openDurableOperationStore(operationStorePath, durableOperationMaxEntries, durableOperationTerminalRetention)
	if err != nil {
		return config{}, err
	}
	c := config{
		token:                    os.Getenv("DEPLOYER_TOKEN"),
		composeDir:               envOr("COMPOSE_DIR", "/workspace"),
		composeHostDir:           envOr("COMPOSE_HOST_DIR", envOr("PWD", ".")),
		serversDir:               serversDir,
		composeServer:            envOr("COMPOSE_SERVER_FILE", "/workspace/docker-compose.server.yml"),
		composeShared:            envOr("COMPOSE_SHARED_FILE", "/workspace/docker-compose.shared.yml"),
		ghcrOwner:                envOr("GHCR_OWNER", "peppone-choi"),
		ghcrToken:                os.Getenv("GHCR_TOKEN"),
		ghcrAPIBaseURL:           envOr("DEPLOYER_GHCR_API_BASE_URL", "https://api.github.com"),
		localHTTPBaseURL:         "http://localhost:9000",
		authenticatedHTTPTimeout: authenticatedHTTPDefaultTimeout,
		gameAPIInternalPort:      envOr("DEPLOYER_GAME_API_INTERNAL_PORT", "8081"),
		gameEngineInternalPort:   envOr("DEPLOYER_GAME_ENGINE_INTERNAL_PORT", "8082"),
		gatewayAPIURL:            envOr("DEPLOYER_GATEWAY_API_URL", "http://gateway-api:8080"),
		lifecycleJobs:            jobs,
		lifecycleOperationStore:  operationStore,
		maintenanceFile:          envOr("DEPLOYER_MAINTENANCE_FILE", "/workspace/servers/.deployer-maintenance"),
		lifecycleJournalFile:     envOr("DEPLOYER_LIFECYCLE_JOURNAL_FILE", filepath.Join(serversDir, ".deployer-lifecycle-journal")),
		sharedEnvMu:              &sync.Mutex{},
	}
	c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, jobs)
	if err := c.recoverDurableLifecycleOperations(); err != nil {
		return config{}, err
	}
	return c, nil
}

func (c config) recoverDurableLifecycleOperations() error {
	journal, exists, err := c.readLifecycleJournal()
	if err != nil {
		return fmt.Errorf("read lifecycle journal for operation recovery: %w", err)
	}
	linkedOperationID := ""
	if exists {
		linkedOperationID = journal.OperationID
	}
	if err := c.lifecycleOperationStore.Recover(linkedOperationID); err != nil {
		// Repeating Recover is safe and resolves the case where rename committed
		// but directory fsync returned an error after the visible snapshot changed.
		if retryErr := c.lifecycleOperationStore.Recover(linkedOperationID); retryErr != nil {
			return fmt.Errorf("recover durable lifecycle operations: %w", err)
		}
	}
	return nil
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
	return internalServerKeyPrefix + publicID
}

func projectForServerID(publicID string) string {
	return "opensamguk-" + internalServerKey(publicID)
}

func (c config) gameAPIURLFor(publicID string) string {
	return "http://" + internalServerKey(publicID) + "-game-api:" + envOrValue(c.gameAPIInternalPort, "8081")
}

func (c config) gameEngineURLFor(publicID string) string {
	return "http://" + internalServerKey(publicID) + gameEngineDockerLabelSuffix + ":" + envOrValue(c.gameEngineInternalPort, "8082")
}

func isCanonicalServerProject(project string) bool {
	if !projectRe.MatchString(project) {
		return false
	}
	publicID := strings.TrimPrefix(project, "opensamguk-s")
	canonicalID, _, err := normalizeCreateServerID(publicID)
	return err == nil && project == projectForServerID(canonicalID)
}

func (c config) defaultGatewayAPIURL() string {
	return envOrValue(c.gatewayAPIURL, "http://gateway-api:8080")
}

func (c config) webGameURLFor(publicID string) string {
	return "http://" + internalServerKey(publicID) + "-web-game:3001"
}

func (c config) resetVerificationDuration() time.Duration {
	if c.resetVerifyTimeout > 0 {
		return c.resetVerifyTimeout
	}
	return resetVerificationTimeout
}

func (c config) resetVerificationPoll() time.Duration {
	if c.resetVerifyPollInterval > 0 {
		return c.resetVerifyPollInterval
	}
	return resetVerificationPollInterval
}

// getVerificationURL deliberately returns only bounded, non-sensitive response
// bytes. Reset verification observes public health/read state; it never reads a
// container's environment or logs response payloads.
func (c config) getVerificationURL(ctx context.Context, endpoint string) (int, []byte, error) {
	if c.httpGet != nil {
		return c.httpGet(ctx, endpoint)
	}
	requestCtx, cancel := context.WithTimeout(ctx, resetVerificationHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	client := &http.Client{
		Timeout: resetVerificationHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerificationResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxVerificationResponseBytes {
		return 0, nil, errors.New("verification response exceeds the bounded read limit")
	}
	return resp.StatusCode, body, nil
}

type resetRuntimeExpectation struct {
	scenarioCode string
	generation   int
}

func resetRuntimeExpectationFor(values map[string]string) (resetRuntimeExpectation, error) {
	scenarioCode := strings.TrimSpace(envOrValue(values["SCENARIO_CODE"], "scenario_1010"))
	if !isSafeToken(scenarioCode) {
		return resetRuntimeExpectation{}, errors.New("reset scenario code is invalid")
	}
	seedEnabled := strings.ToLower(strings.TrimSpace(envOrValue(values["SCENARIO_SEED_ENABLED"], "true")))
	if seedEnabled != "true" {
		return resetRuntimeExpectation{}, errors.New("reset requires SCENARIO_SEED_ENABLED=true so seeded world state can be verified")
	}
	generation, err := parseGeneration(values["SERVER_GENERATION"], 1)
	if err != nil {
		return resetRuntimeExpectation{}, err
	}
	return resetRuntimeExpectation{scenarioCode: scenarioCode, generation: generation}, nil
}

func (c config) awaitVerification(ctx context.Context, name string, check func(context.Context) error) error {
	verificationCtx, cancel := context.WithTimeout(ctx, c.resetVerificationDuration())
	defer cancel()
	var lastErr error
	for {
		if err := verificationCtx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("%s did not converge before its bounded deadline: %w", name, lastErr)
			}
			return fmt.Errorf("%s verification context ended: %w", name, err)
		}
		lastErr = check(verificationCtx)
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(c.resetVerificationPoll())
		select {
		case <-verificationCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

func (c config) expectHealth(ctx context.Context, endpoint string, expectedStatus string) error {
	statusCode, body, err := c.getVerificationURL(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("health request failed: %w", err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", statusCode)
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return errors.New("health endpoint returned an invalid response")
	}
	if health.Status != expectedStatus {
		return fmt.Errorf("health endpoint reported %q", health.Status)
	}
	return nil
}

func (c config) expectHTTPReady(ctx context.Context, endpoint string) error {
	statusCode, _, err := c.getVerificationURL(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("readiness request failed: %w", err)
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusBadRequest {
		return fmt.Errorf("readiness endpoint returned HTTP %d", statusCode)
	}
	return nil
}

func (c config) verifyResetRuntime(ctx context.Context, target serverTarget) error {
	values, err := c.validateServerTarget(target)
	if err != nil {
		return err
	}
	expected, err := resetRuntimeExpectationFor(values)
	if err != nil {
		return err
	}
	return c.awaitVerification(ctx, "reset runtime readiness", func(verificationCtx context.Context) error {
		if err := c.expectHealth(verificationCtx, c.gameEngineURLFor(target.ID)+"/actuator/health/readiness", "UP"); err != nil {
			return fmt.Errorf("game-engine: %w", err)
		}
		if err := c.expectHealth(verificationCtx, c.gameAPIURLFor(target.ID)+"/health", "up"); err != nil {
			return fmt.Errorf("game-api: %w", err)
		}
		if err := c.expectHTTPReady(verificationCtx, c.webGameURLFor(target.ID)+"/"); err != nil {
			return fmt.Errorf("web-game: %w", err)
		}
		statusCode, body, err := c.getVerificationURL(verificationCtx, c.gameAPIURLFor(target.ID)+"/api/front-info")
		if err != nil {
			return fmt.Errorf("reset data request failed: %w", err)
		}
		if statusCode != http.StatusOK {
			return fmt.Errorf("reset data endpoint returned HTTP %d", statusCode)
		}
		var frontInfo struct {
			Result bool `json:"result"`
			Global struct {
				Scenario   string `json:"scenario"`
				Generation *int   `json:"generation"`
			} `json:"global"`
		}
		if err := json.Unmarshal(body, &frontInfo); err != nil {
			return errors.New("reset data endpoint returned an invalid response")
		}
		if !frontInfo.Result || frontInfo.Global.Scenario != expected.scenarioCode || frontInfo.Global.Generation == nil || *frontInfo.Global.Generation != expected.generation {
			return errors.New("game-api did not expose the reset scenario and generation")
		}
		return nil
	})
}

func (c config) verifySharedRegistryReload(ctx context.Context, target serverTarget) error {
	values, err := c.validateServerTarget(target)
	if err != nil {
		return err
	}
	expected, err := resetRuntimeExpectationFor(values)
	if err != nil {
		return err
	}
	return c.awaitVerification(ctx, "shared registry reload", func(verificationCtx context.Context) error {
		entry, err := c.registryEntryByID(target.ID)
		if err != nil {
			return err
		}
		if entry.ID != target.ID || entry.DeployProject != target.Project || entry.RepairRequired || entry.ScenarioCode != expected.scenarioCode || entry.Generation != expected.generation {
			return errors.New("shared registry is not the final verified reset state")
		}
		if err := c.expectHealth(verificationCtx, strings.TrimRight(c.defaultGatewayAPIURL(), "/")+"/actuator/health/readiness", "UP"); err != nil {
			return fmt.Errorf("gateway-api: %w", err)
		}
		if err := c.expectHTTPReady(verificationCtx, "http://web-gateway:3000/"); err != nil {
			return fmt.Errorf("web-gateway: %w", err)
		}
		if err := c.expectHealth(verificationCtx, "http://nginx/health", "up"); err != nil {
			return fmt.Errorf("nginx: %w", err)
		}
		return nil
	})
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

func (c config) lockSharedEnv() func() {
	if c.sharedEnvMu == nil {
		return func() {}
	}
	c.sharedEnvMu.Lock()
	return c.sharedEnvMu.Unlock
}

func (c config) patchManagedEnvFile(path string, allowlist map[string]envFieldSpec, updates map[string]string) (map[string]envField, error) {
	if filepath.Clean(path) != filepath.Clean(c.sharedEnvFile()) {
		return patchEnvFile(path, allowlist, updates)
	}
	unlock := c.lockSharedEnv()
	defer unlock()
	return patchEnvFile(path, allowlist, updates)
}

func (c config) serverEnvFileForID(publicID string) string {
	return filepath.Join(c.serversDir, internalServerKey(publicID)+".env")
}

// serverTarget is the single authoritative mapping between a public server id,
// its compose project, and its env file. Docker-facing operations must validate
// this mapping again immediately before invoking compose because a host file can
// be changed after request admission.
type serverTarget struct {
	ID          string
	InternalKey string
	Project     string
	EnvFile     string
}

func (c config) serverTargetForID(rawID string) (serverTarget, error) {
	id, internalKey, err := normalizeCreateServerID(rawID)
	if err != nil {
		return serverTarget{}, err
	}
	return serverTarget{
		ID:          id,
		InternalKey: internalKey,
		Project:     projectForServerID(id),
		EnvFile:     filepath.Join(c.serversDir, internalKey+".env"),
	}, nil
}

func (c config) serverTargetForProject(project string) (serverTarget, error) {
	if !isCanonicalServerProject(project) {
		return serverTarget{}, errors.New("잘못된 project — opensamguk-s<id> 형식만 허용")
	}
	target, err := c.serverTargetForID(strings.TrimPrefix(project, "opensamguk-s"))
	if err != nil {
		return serverTarget{}, err
	}
	if target.Project != project {
		return serverTarget{}, errors.New("project와 public server id 매핑이 일치하지 않습니다.")
	}
	return target, nil
}

func (c config) serverEnvDisplayPath(target serverTarget) string {
	return filepath.Join("servers", target.InternalKey+".env")
}

func (c config) validateServerTarget(target serverTarget) (map[string]string, error) {
	return c.validateServerEnvFile(target, target.EnvFile)
}

func (c config) validateServerEnvFile(target serverTarget, envFile string) (map[string]string, error) {
	lines, err := readEnvLines(envFile)
	if err != nil {
		return nil, err
	}
	serverIDCount := 0
	declaredID := ""
	for _, line := range lines {
		if line.IsKV && line.Key == "SERVER_ID" {
			serverIDCount++
			declaredID = line.Value
		}
	}
	if err := validateV1ServerDefinition(lines); err != nil {
		return nil, err
	}
	if serverIDCount != 1 || declaredID != target.ID {
		envLabel := c.serverEnvDisplayPath(target)
		if filepath.Clean(envFile) != filepath.Clean(target.EnvFile) {
			envLabel = "staged server env"
		}
		return nil, fmt.Errorf("SERVER_ID in %s must exactly match canonical public id %s", envLabel, target.ID)
	}
	return envValuesFromLines(lines), nil
}

func validateV1ServerDefinition(lines []envLine) error {
	for index, line := range lines {
		if !line.IsKV {
			trimmed := strings.TrimSpace(line.Raw)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return fmt.Errorf("v1 server definition has unmanaged syntax on line %d", index+1)
			}
			continue
		}
		_, isV2Key := v2ServerDefinitionKeys[line.Key]
		if strings.HasPrefix(line.Key, "V2_") || isV2Key {
			return fmt.Errorf("v1 server definition must not set %s", line.Key)
		}
	}
	return nil
}

func (c config) validateDockerServerTarget(project string, envFile string, allowStagedEnv bool) (serverTarget, error) {
	target, err := c.serverTargetForProject(project)
	if err != nil {
		return serverTarget{}, err
	}
	if !allowStagedEnv && filepath.Clean(envFile) != filepath.Clean(target.EnvFile) {
		return serverTarget{}, errors.New("server env file does not match canonical project mapping")
	}
	if _, err := c.validateServerEnvFile(target, envFile); err != nil {
		return serverTarget{}, err
	}
	return target, nil
}

func (c config) validateRegisteredServerTargets() error {
	registry, err := c.readRegistry()
	if err != nil {
		return err
	}
	for _, entry := range registry {
		target, err := c.serverTargetForID(entry.ID)
		if err != nil {
			return err
		}
		if entry.DeployProject != target.Project {
			return fmt.Errorf("registry project %q does not match server id %q", entry.DeployProject, target.ID)
		}
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
	}
	return nil
}

func (c config) validateRunningServerRegistry(ctx context.Context) error {
	registry, err := c.readRegistry()
	if err != nil {
		return err
	}
	registered := make(map[string]struct{}, len(registry))
	for _, entry := range registry {
		registered[entry.ID] = struct{}{}
	}
	output, err := c.runDockerContext(ctx, "ps", "--filter", "status=running", "--format", `{{.Label "com.docker.compose.project"}}`)
	if err != nil {
		return err
	}
	seenProjects := map[string]struct{}{}
	for _, rawProject := range strings.Split(output, "\n") {
		project := strings.TrimSpace(rawProject)
		if project == "" || project == sharedComposeProjectName {
			continue
		}
		if _, seen := seenProjects[project]; seen {
			continue
		}
		seenProjects[project] = struct{}{}
		if !projectRe.MatchString(project) {
			continue
		}
		target, err := c.serverTargetForProject(project)
		if err != nil {
			return err
		}
		if _, exists := registered[target.ID]; !exists {
			return fmt.Errorf("running server project %q is missing from SERVER_REGISTRY_JSON", project)
		}
		if _, err := c.validateServerTarget(target); err != nil {
			return err
		}
	}
	return nil
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

type maintenanceState string

const (
	maintenanceStateOpen     maintenanceState = "open"
	maintenanceStateDraining maintenanceState = "draining"
	maintenanceStateDrained  maintenanceState = "drained"
)

type maintenanceResponse struct {
	Capability string           `json:"capability"`
	State      maintenanceState `json:"state"`
	Lease      string           `json:"lease,omitempty"`
}

type envPatchRequest struct {
	Values map[string]string `json:"values"`
}

type createServerRequest struct {
	ID                  string `json:"id"`
	OperationID         string `json:"operationId"`
	MaintenanceLease    string `json:"maintenanceLease,omitempty"`
	Name                string `json:"name"`
	Generation          string `json:"generation"`
	ImageTag            string `json:"imageTag"`
	GameAPIPort         string `json:"gameApiPort"`
	WebGamePort         string `json:"webGamePort"`
	ScenarioCode        string `json:"scenarioCode"`
	ScenarioSeedEnabled *bool  `json:"scenarioSeedEnabled"`
	// JWT는 요청으로 받지 않는다 — 항상 공유 .env의 JWT_PUBLIC_KEY(+JWT_LEGACY_*)를
	// 그대로 복사한다(모든 서버가 같은 gateway-api 공개키를 검증해야 하므로 서버별
	// override는 의미가 없다). 과거 jwtSecret 필드는 어떤 테스트/문서도 실사용하지
	// 않아 하위호환 없이 제거했다.
}

type resetServerRequest struct {
	ID                  string   `json:"id"`
	OperationID         string   `json:"operationId"`
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
	OK      bool   `json:"ok"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Project string `json:"project"`
	JobID   string `json:"jobId,omitempty"`
	// gateway-api는 POST 응답에서 바로 operationId/operationStatus를 읽어 transition을
	// 진행시킨다(isConfirmedServerSuccess / parsePostedLifecycleOperation).
	OperationID      string             `json:"operationId,omitempty"`
	OperationStatus  lifecycleJobStatus `json:"operationStatus,omitempty"`
	RestartRequired  bool               `json:"restartRequired"`
	AffectedServices []string           `json:"affectedServices"`
	Detail           string             `json:"detail"`
}

type registryEntry struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Generation     int               `json:"generation"`
	ScenarioCode   string            `json:"scenarioCode,omitempty"`
	GameAPIURL     string            `json:"gameApiUrl"`
	GameEngineURL  string            `json:"gameEngineUrl"`
	DeployProject  string            `json:"deployProject"`
	Env            map[string]string `json:"env,omitempty"`
	RepairRequired bool              `json:"repairRequired,omitempty"`
}

type envResponse struct {
	OK               bool                `json:"ok"`
	Scope            string              `json:"scope"`
	ID               string              `json:"id,omitempty"`
	JobID            string              `json:"jobId,omitempty"`
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
	if handled, status := earlyCommand(os.Args, os.Getenv, os.Stdin, os.Stdout, os.Stderr); handled {
		os.Exit(status)
	}
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("durable operation store initialization failed: %v", err)
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-running-registry-targets" {
		os.Exit(checkRunningRegistryTargetsCommand(cfg, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-registry-targets" {
		os.Exit(checkRegistryTargetsCommand(cfg, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-registry" {
		os.Exit(checkRegistryCommand(cfg, os.Stderr))
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
	mux.HandleFunc("/jobs", cfg.withAuth(cfg.handleLifecycleJob))
	mux.HandleFunc("/jobs/", cfg.withAuth(cfg.handleLifecycleJob))
	mux.HandleFunc("/operations", cfg.withAuth(cfg.handleOperation))
	mux.HandleFunc("/operations/", cfg.withAuth(cfg.handleOperation))
	mux.HandleFunc("/maintenance", cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance)))
	mux.HandleFunc("/maintenance/", cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance)))

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

func earlyCommand(args []string, getenv func(string) string, input io.Reader, output, errOutput io.Writer) (bool, int) {
	const usage = "usage: deployer [--check-running-registry-targets|--check-registry-targets|--check-registry|--authenticated-http METHOD PATH [TIMEOUT_SECONDS]]"
	if len(args) >= 2 && args[1] == "--authenticated-http" {
		if len(args) != 4 && len(args) != 5 {
			fmt.Fprintln(errOutput, usage)
			return true, 2
		}
		timeout := authenticatedHTTPDefaultTimeout
		if len(args) == 5 {
			timeoutSeconds, err := strconv.Atoi(args[4])
			if err != nil || timeoutSeconds < 1 || timeoutSeconds > 300 {
				fmt.Fprintln(errOutput, "authenticated HTTP timeout must be an integer from 1 to 300 seconds")
				return true, 2
			}
			timeout = time.Duration(timeoutSeconds) * time.Second
		}
		cfg := config{
			token:                    getenv("DEPLOYER_TOKEN"),
			localHTTPBaseURL:         "http://localhost:9000",
			authenticatedHTTPTimeout: timeout,
		}
		return true, authenticatedHTTPCommand(cfg, args[2], args[3], input, output, errOutput)
	}
	if len(args) == 1 {
		return false, 0
	}
	if len(args) == 2 {
		switch args[1] {
		case "--check-running-registry-targets", "--check-registry-targets", "--check-registry":
			return false, 0
		}
	}
	fmt.Fprintln(errOutput, usage)
	return true, 2
}

func authenticatedHTTPCommand(c config, method, requestPath string, input io.Reader, output, errOutput io.Writer) int {
	if c.token == "" {
		fmt.Fprintln(errOutput, "DEPLOYER_TOKEN is required")
		return 2
	}
	if !isAuthenticatedHTTPRouteAllowed(method, requestPath) {
		fmt.Fprintln(errOutput, "authenticated HTTP route is invalid")
		return 2
	}
	baseURL := strings.TrimRight(c.localHTTPBaseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:9000"
	}
	timeout := c.authenticatedHTTPTimeout
	if timeout <= 0 {
		timeout = authenticatedHTTPDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var body io.Reader
	if method == http.MethodPost {
		body = input
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL+requestPath, body)
	if err != nil {
		fmt.Fprintln(errOutput, "authenticated HTTP request is invalid")
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(errOutput, "authenticated HTTP request failed")
		return 1
	}
	defer response.Body.Close()
	if _, err := io.Copy(output, response.Body); err != nil {
		fmt.Fprintln(errOutput, "authenticated HTTP response read failed")
		return 1
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		fmt.Fprintln(errOutput, "authenticated HTTP request returned an error status")
		return 8
	}
	return 0
}

func isAuthenticatedHTTPRouteAllowed(method, requestPath string) bool {
	switch method {
	case http.MethodGet:
		if requestPath == "/maintenance" {
			return true
		}
		return strings.HasPrefix(requestPath, "/jobs/") && lifecycleJobIDRe.MatchString(strings.TrimPrefix(requestPath, "/jobs/"))
	case http.MethodPost:
		switch requestPath {
		case "/maintenance/enter", "/maintenance/enter-if-idle", "/maintenance/leave", "/maintenance/repair", "/servers/create":
			return true
		}
		if !strings.HasPrefix(requestPath, "/jobs/") {
			return false
		}
		jobPath := strings.TrimPrefix(requestPath, "/jobs/")
		if !strings.HasSuffix(jobPath, "/cancel") {
			return false
		}
		return lifecycleJobIDRe.MatchString(strings.TrimSuffix(jobPath, "/cancel"))
	default:
		return false
	}
}

func checkRegistryTargetsCommand(c config, output io.Writer) int {
	if err := c.validateRegisteredServerTargets(); err != nil {
		fmt.Fprintln(output, "registry target validation failed")
		return 1
	}
	fmt.Fprintln(output, "registry target validation passed")
	return 0
}

func checkRunningRegistryTargetsCommand(c config, output io.Writer) int {
	if err := c.validateRegisteredServerTargets(); err != nil {
		fmt.Fprintf(output, "running registry target validation failed: %v\n", err)
		return 1
	}
	if err := c.validateRunningServerRegistry(context.Background()); err != nil {
		fmt.Fprintf(output, "running registry target validation failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(output, "running registry target validation passed")
	return 0
}

func checkRegistryCommand(c config, output io.Writer) int {
	if c.operations != nil && c.operations.lifecycleRecoveryPending() {
		fmt.Fprintln(output, "lifecycle recovery is required")
		return 1
	}
	if err := c.validateRegisteredServerTargets(); err != nil {
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
	if c.operations != nil && c.operations.lifecycleRecoveryPending() {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "lifecycle recovery is required"})
		return
	}
	if err := c.validateRegisteredServerTargets(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: fmt.Sprintf("레지스트리 준비 실패: %v", err)})
		return
	}
	// readiness는 "지금 변이를 받을 수 있는가"다. docker에 못 닿으면 모든 compose 호출이
	// 실패하므로 ready가 아니다. 캐시하지 않는다 — 폴링은 2초 간격(워크플로)뿐이고,
	// 캐시는 진행 중인 장애를 정확히 그 게이트에서 숨긴다.
	if err := c.dockerPreflight(r.Context()); err != nil {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleOperation은 gateway-api가 CREATE/CLOSE/RESET transition을 복구할 때 부르는 조회 경로다.
// 응답 형태는 DeployService.parseQueriedLifecycleOperation / isExactUnknownOperation과
// 짝을 이룬다 — 특히 404 본문은 정확히 ok/operationId/status 3-key여야 하며, 필드를
// 더하면 gateway가 Unavailable로 떨어져 transition이 영구 repair-pending으로 남는다.
func (c config) handleOperation(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/operations" || !strings.HasPrefix(r.URL.Path, "/operations/") {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "operation id가 올바르지 않습니다."})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/operations/")
	if strings.Contains(path, "/") || !lifecycleJobIDRe.MatchString(path) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "operation id가 올바르지 않습니다."})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	record, exists := c.lifecycleOperationStore.Lookup(path)
	if !exists {
		writeJSON(w, http.StatusNotFound, operationNotFoundResponse{OK: false, OperationID: path, Status: "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, operationResponseForRecord(record))
}

func (c config) handleLifecycleJob(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/jobs" || !strings.HasPrefix(r.URL.Path, "/jobs/") {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "job id가 올바르지 않습니다."})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) > 2 || parts[0] == "" || !lifecycleJobIDRe.MatchString(parts[0]) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "job id가 올바르지 않습니다."})
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
			return
		}
		job, exists := c.lifecycleJobs.lookup(id)
		if !exists {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "job을 찾을 수 없습니다."})
			return
		}
		writeJSON(w, http.StatusOK, job)
		return
	}
	if parts[1] != "cancel" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "job action이 올바르지 않습니다."})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	job, exists := c.lifecycleJobs.requestCancel(id)
	if !exists {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job을 찾을 수 없습니다."})
		return
	}
	writeJSON(w, http.StatusOK, job)
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

func (c config) withLoopback(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			writeJSON(w, http.StatusForbidden, errorResponse{Error: "loopback 요청만 허용"})
			return
		}
		next(w, r)
	}
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c config) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	respond := func(state maintenanceState, lease string) {
		writeJSON(w, http.StatusOK, maintenanceResponse{Capability: "maintenance-v1", State: state, Lease: lease})
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/maintenance":
		if c.operations == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "maintenance coordinator unavailable"})
			return
		}
		respond(c.operations.maintenanceState(), "")
	case r.Method == http.MethodPost && r.URL.Path == "/maintenance/enter":
		state, lease, err := c.operations.enterMaintenance()
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errMaintenanceLeaseUsed) {
				status = http.StatusConflict
			}
			writeJSON(w, status, errorResponse{Error: "maintenance enter failed"})
			return
		}
		respond(state, lease)
	case r.Method == http.MethodPost && r.URL.Path == "/maintenance/enter-if-idle":
		if c.operations == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "maintenance coordinator unavailable"})
			return
		}
		state, lease, err := c.operations.enterMaintenanceIfIdle()
		if err != nil {
			if errors.Is(err, errMaintenanceIdleConflict) {
				writeJSON(w, http.StatusConflict, errorResponse{Error: "maintenance idle admission unavailable"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "maintenance idle admission failed"})
			return
		}
		respond(state, lease)
	case r.Method == http.MethodPost && r.URL.Path == "/maintenance/leave":
		state, err := c.operations.leaveMaintenance()
		if err != nil {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "maintenance leave failed"})
			return
		}
		respond(state, "")
	case r.Method == http.MethodPost && r.URL.Path == "/maintenance/repair":
		if err := c.repairLifecycleJournal(); err != nil {
			log.Printf("maintenance repair failed: %v", err)
			if errors.Is(err, errDockerUnreachable) {
				w.Header().Set("Retry-After", "5")
				writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusConflict, errorResponse{Error: "lifecycle recovery failed"})
			return
		}
		respond(c.operations.maintenanceState(), "")
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "maintenance endpoint unavailable"})
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
	if _, err := c.serverTargetForProject(project); err != nil {
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
	target, err := c.serverTargetForProject(req.Project)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "잘못된 project — opensamguk-s<id> 형식만 허용"})
		return
	}
	if !tagRe.MatchString(req.Tag) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "잘못된 tag — [A-Za-z0-9._-]만 허용"})
		return
	}
	if _, err := c.validateServerTarget(target); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{Error: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)})
		return
	}
	lease, err := c.beginMutation("")
	if err != nil {
		writeMutationAdmissionError(w, err)
		return
	}
	defer lease.Done()

	envFile := target.EnvFile
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

	detail, err := c.pullStateless(lease.Context(), req.Project, tempEnvFile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deployResponse{
			Project: req.Project, Tag: req.Tag, OK: false, Detail: detail,
		})
		return
	}

	if err := lease.Context().Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "deployment cancelled"})
		return
	}
	if err := c.writeLifecycleJournal("deploy", target); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "lifecycle recovery journal could not be created"})
		return
	}
	if err := c.writeImageTag(req.Project, req.Tag); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("IMAGE_TAG/WEB_GAME_TAG 치환 실패: %v", err)})
		return
	}

	upDetail, err := c.upStateless(lease.Context(), req.Project, envFile)
	detail += "\n" + upDetail
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, deployResponse{
			Project: req.Project, Tag: req.Tag, OK: false, Detail: detail,
		})
		return
	}
	if err := c.clearLifecycleJournal(); err != nil {
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
		res, status := c.deleteServer(r.URL.Query().Get("id"), r.URL.Query().Get("confirm"), "")
		writeCreateServerResponse(w, status, res)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET/POST/DELETE only"})
	}
}

func (c config) handleServerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	headerLease := r.Header.Get(maintenanceLeaseHeader)
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
	if headerLease != "" && req.MaintenanceLease != "" && headerLease != req.MaintenanceLease {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "maintenance lease 전달값이 일치하지 않습니다."})
		return
	}
	maintenanceLease := req.MaintenanceLease
	if headerLease != "" {
		maintenanceLease = headerLease
	}
	if maintenanceLease != "" && !isLoopbackRequest(r) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "maintenance lease requires a loopback request"})
		return
	}
	req.MaintenanceLease = ""
	res, status := c.createServerWithMaintenanceLease(req, maintenanceLease)
	writeCreateServerResponse(w, status, res)
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
		ID          string `json:"id"`
		OperationID string `json:"operationId"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "JSON 파싱 실패"})
		return
	}
	operationID, err := normalizeLifecycleOperationID(req.OperationID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, createServerResponse{OK: false, Detail: err.Error()})
		return
	}
	id, _, err := normalizeCreateServerID(req.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, createServerResponse{OK: false, Detail: err.Error()})
		return
	}
	res, status := c.deleteServer(id, "DELETE "+id, operationID)
	writeCreateServerResponse(w, status, res)
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
	writeCreateServerResponse(w, status, res)
}

func writeCreateServerResponse(w http.ResponseWriter, status int, response createServerResponse) {
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, status, response)
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
	target, err := c.serverTargetForID(r.URL.Query().Get("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	if _, err := c.validateServerTarget(target); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{Error: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)})
		return
	}
	c.handleEnv(w, r, envRequestContext{
		scope:            "server",
		id:               target.ID,
		path:             target.EnvFile,
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
		lease, err := c.beginMutation("")
		if err != nil {
			writeMutationAdmissionError(w, err)
			return
		}
		leaseTransferred := false
		defer func() {
			if !leaseTransferred {
				lease.Done()
			}
		}()
		jobID := ""
		registryReloadNeeded := false
		if ctx.scope == "server" {
			reloadNeeded, preflightErr := c.serverEnvPatchChangesRegistry(ctx.id, ctx.path, req.Values)
			if preflightErr != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("레지스트리 동기화 준비 실패: %v", preflightErr)})
				return
			}
			registryReloadNeeded = reloadNeeded
			if reloadNeeded {
				jobID, err = c.lifecycleJobs.reserve()
				if err != nil {
					detail, status := lifecycleJobReservationFailure(err)
					writeJSON(w, status, errorResponse{Error: detail})
					return
				}
				if err := c.operations.claimLifecycleJob(lease, jobID); err != nil {
					c.lifecycleJobs.discard(jobID)
					writeMutationAdmissionError(w, err)
					return
				}
			}
		}
		if err := lease.Context().Err(); err != nil {
			if jobID != "" {
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
			}
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "mutation cancelled"})
			return
		}
		if registryReloadNeeded {
			target, err := c.serverTargetForID(ctx.id)
			if err != nil {
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "레지스트리 recovery journal을 준비하지 못했습니다."})
				return
			}
			if err := c.writeLifecycleJournal("patch", target); err != nil {
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
				writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "레지스트리 recovery journal을 준비하지 못했습니다."})
				return
			}
		}
		fields, err := c.patchManagedEnvFile(ctx.path, ctx.allowlist, req.Values)
		if err != nil {
			if jobID != "" {
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("env 파일 쓰기 실패: %v", err)})
			return
		}
		if registryReloadNeeded {
			if err := c.advanceLifecycleJournal(lifecycleJournalStageEnv); err != nil {
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "레지스트리 recovery journal을 갱신하지 못했습니다."})
				return
			}
		}
		affectedServices := append([]string{}, ctx.affectedServices...)
		responseJobID := ""
		if ctx.scope == "server" {
			if err := lease.Context().Err(); err != nil {
				if jobID != "" {
					c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
				}
				writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "mutation cancelled"})
				return
			}
			changed, err := c.syncRegistryEntryFromEnv(ctx.id, ctx.path)
			if err != nil {
				if jobID != "" {
					c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
				}
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("레지스트리 동기화 실패: %v", err)})
				return
			}
			if registryReloadNeeded {
				if err := c.advanceLifecycleJournal(lifecycleJournalStageRegistry); err != nil {
					c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
					writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "레지스트리 recovery journal을 갱신하지 못했습니다."})
					return
				}
			}
			if changed {
				if jobID == "" {
					writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "레지스트리 reload 작업을 준비하지 못했습니다."})
					return
				}
				affectedServices = appendUnique(affectedServices, sharedRegistryReloadServices)
				c.startClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, func(jobContext context.Context) (string, error) {
					target, err := c.serverTargetForID(ctx.id)
					if err != nil {
						return "", err
					}
					if err := c.reconcileServerRegistry(target); err != nil {
						return "", err
					}
					detail, err := c.reloadSharedRegistry(jobContext)
					if err != nil {
						return detail, err
					}
					if err := c.clearLifecycleJournal(); err != nil {
						return detail, err
					}
					return detail, nil
				})
				responseJobID = jobID
				leaseTransferred = true
			} else if jobID != "" {
				if err := c.clearLifecycleJournal(); err != nil {
					c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, err)
					writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "레지스트리 recovery journal을 정리하지 못했습니다."})
					return
				}
				c.finishClaimedLifecycleJob(lease, jobID, "reload registry "+ctx.id, nil)
			}
		}
		writeJSON(w, http.StatusOK, envResponse{
			OK:               true,
			Scope:            ctx.scope,
			ID:               ctx.id,
			JobID:            responseJobID,
			RestartRequired:  true,
			AffectedServices: affectedServices,
			Fields:           fields,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET/PATCH only"})
	}
}

func (c config) serverEnvPatchChangesRegistry(id string, path string, updates map[string]string) (bool, error) {
	if _, err := os.Stat(c.sharedEnvFile()); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	values, err := readEnvValues(path)
	if err != nil {
		return false, err
	}
	for key, value := range updates {
		values[key] = value
	}
	current, err := c.registryEntryByID(id)
	if err != nil {
		return false, err
	}
	return !reflect.DeepEqual(current, c.registryEntryFromServerEnv(id, values, current)), nil
}

func (c config) createServer(req createServerRequest) (createServerResponse, int) {
	return c.createServerWithMaintenanceLease(req, "")
}

type normalizedCreateServerRequest struct {
	ID                   string
	InternalKey          string
	Name                 string
	Generation           int
	ImageTag             string
	GameAPIPort          string
	WebGamePort          string
	ScenarioCode         string
	ScenarioSeedEnabled  bool
	JWTPublicKey         string
	JWTLegacySecret      string
	JWTLegacyAcceptUntil string
	InternalServiceToken string
}

func (c config) normalizeCreateServerRequest(req createServerRequest) (normalizedCreateServerRequest, error) {
	id, internalKey, err := normalizeCreateServerID(req.ID)
	if err != nil {
		return normalizedCreateServerRequest{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || strings.ContainsAny(name, "\r\n") {
		return normalizedCreateServerRequest{}, errors.New("서버 이름이 올바르지 않습니다.")
	}
	generation, err := parseGeneration(req.Generation, 1)
	if err != nil {
		return normalizedCreateServerRequest{}, err
	}
	imageTag := strings.TrimSpace(req.ImageTag)
	if imageTag == "" {
		imageTag = c.sharedEnvValue("IMAGE_TAG")
	}
	if imageTag == "" {
		imageTag = "latest"
	}
	if !tagRe.MatchString(imageTag) {
		return normalizedCreateServerRequest{}, errors.New("이미지 태그가 올바르지 않습니다.")
	}
	gameAPIPort := strings.TrimSpace(req.GameAPIPort)
	webGamePort := strings.TrimSpace(req.WebGamePort)
	if !isPort(gameAPIPort) || !isPort(webGamePort) {
		return normalizedCreateServerRequest{}, errors.New("포트는 1-65535 숫자여야 합니다.")
	}
	if gameAPIPort == webGamePort {
		return normalizedCreateServerRequest{}, errCreatePortsEqual
	}
	scenarioCode := strings.TrimSpace(req.ScenarioCode)
	if scenarioCode == "" {
		scenarioCode = "scenario_1010"
	}
	if !isSafeToken(scenarioCode) {
		return normalizedCreateServerRequest{}, errors.New("시나리오 코드가 올바르지 않습니다.")
	}
	seedEnabled := true
	if req.ScenarioSeedEnabled != nil {
		seedEnabled = *req.ScenarioSeedEnabled
	}
	// JWT는 서버별 값을 받지 않는다 — gateway-api가 발급하는 토큰을 검증하려면
	// 모든 서버가 공유 스택과 동일한 공개키를 써야 하므로(서버별 override는 의미가 없다),
	// 항상 공유 .env에서 복사한다.
	jwtPublicKey := c.sharedEnvValue("JWT_PUBLIC_KEY")
	if jwtPublicKey == "" || strings.ContainsAny(jwtPublicKey, "\r\n") {
		return normalizedCreateServerRequest{}, errors.New("공유 JWT_PUBLIC_KEY가 필요합니다.")
	}
	jwtLegacySecret := c.sharedEnvValue("JWT_LEGACY_SECRET")
	if strings.ContainsAny(jwtLegacySecret, "\r\n") {
		return normalizedCreateServerRequest{}, errors.New("공유 JWT_LEGACY_SECRET이 올바르지 않습니다.")
	}
	jwtLegacyAcceptUntil := c.sharedEnvValue("JWT_LEGACY_ACCESS_ACCEPT_UNTIL")
	if strings.ContainsAny(jwtLegacyAcceptUntil, "\r\n") {
		return normalizedCreateServerRequest{}, errors.New("공유 JWT_LEGACY_ACCESS_ACCEPT_UNTIL이 올바르지 않습니다.")
	}
	internalServiceToken := c.sharedEnvValue("INTERNAL_SERVICE_TOKEN")
	if strings.ContainsAny(internalServiceToken, "\r\n") {
		return normalizedCreateServerRequest{}, errors.New("공유 INTERNAL_SERVICE_TOKEN이 올바르지 않습니다.")
	}
	return normalizedCreateServerRequest{
		ID:                   id,
		InternalKey:          internalKey,
		Name:                 name,
		Generation:           generation,
		ImageTag:             imageTag,
		GameAPIPort:          gameAPIPort,
		WebGamePort:          webGamePort,
		ScenarioCode:         scenarioCode,
		ScenarioSeedEnabled:  seedEnabled,
		JWTPublicKey:         jwtPublicKey,
		JWTLegacySecret:      jwtLegacySecret,
		JWTLegacyAcceptUntil: jwtLegacyAcceptUntil,
		InternalServiceToken: internalServiceToken,
	}, nil
}

// JWT 필드는 지문에서 뺀다 — 사용자 입력이 아니라 공유 .env에서 매번 동일하게
// 파생되므로, 지문에 넣어도 판별력이 없고 넣지 않아도 안전하다.
// closeRequestFingerprint는 같은 operationId가 다른 서버를 가리키는 재사용을 거부하기 위한
// 지문이다. close 요청은 서버 id 하나로 완전히 결정된다.
func closeRequestFingerprint(id string) string {
	sum := sha256.Sum256([]byte("close:" + id))
	return hex.EncodeToString(sum[:])
}

func createRequestFingerprint(req normalizedCreateServerRequest) string {
	payload, _ := json.Marshal(struct {
		ID                  string `json:"id"`
		Name                string `json:"name"`
		Generation          int    `json:"generation"`
		ImageTag            string `json:"imageTag"`
		GameAPIPort         string `json:"gameApiPort"`
		WebGamePort         string `json:"webGamePort"`
		ScenarioCode        string `json:"scenarioCode"`
		ScenarioSeedEnabled bool   `json:"scenarioSeedEnabled"`
	}{
		ID:                  req.ID,
		Name:                req.Name,
		Generation:          req.Generation,
		ImageTag:            req.ImageTag,
		GameAPIPort:         req.GameAPIPort,
		WebGamePort:         req.WebGamePort,
		ScenarioCode:        req.ScenarioCode,
		ScenarioSeedEnabled: req.ScenarioSeedEnabled,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func resetRequestFingerprint(id string, target resetLifecycleTarget) string {
	payload, _ := json.Marshal(struct {
		ID     string               `json:"id"`
		Target resetLifecycleTarget `json:"target"`
	}{ID: id, Target: target})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (c config) createServerWithMaintenanceLease(req createServerRequest, maintenanceLease string) (response createServerResponse, responseStatus int) {
	operationID, err := normalizeLifecycleOperationID(req.OperationID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	normalized, err := c.normalizeCreateServerRequest(req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errCreatePortsEqual) {
			status = http.StatusConflict
		}
		return createServerResponse{OK: false, Detail: err.Error()}, status
	}
	id := normalized.ID
	internalKey := normalized.InternalKey
	name := normalized.Name
	generation := normalized.Generation
	imageTag := normalized.ImageTag
	gameAPIPort := normalized.GameAPIPort
	webGamePort := normalized.WebGamePort
	scenarioCode := normalized.ScenarioCode
	seedEnabled := normalized.ScenarioSeedEnabled
	jwtPublicKey := normalized.JWTPublicKey
	jwtLegacySecret := normalized.JWTLegacySecret
	jwtLegacyAcceptUntil := normalized.JWTLegacyAcceptUntil
	internalServiceToken := normalized.InternalServiceToken
	jobID := ""
	newReservation := false
	durableReserved := false
	reservationClaimed := false
	admissionAttempted := false
	defer func() {
		if !durableReserved {
			return
		}
		if err := c.settleRejectedDurableLifecycleOperation(operationID, responseStatus, durableOperationMessageCreatePreparationFailed); err != nil {
			log.Printf("settle rejected create operation unavailable operationId=%s", operationID)
			response = rejectedDurableOperationSettlementResponse(response, operationID, durableOperationMessageCreatePreparationFailed)
			responseStatus = http.StatusServiceUnavailable
		}
	}()
	fingerprint := createRequestFingerprint(normalized)
	if operationID == "" {
		log.Printf("legacy lifecycle request omitted operationId kind=%s subject=%s", lifecycleKindCreate, id)
		jobID, err = c.lifecycleJobs.reserve()
		if err != nil {
			detail, status := lifecycleJobReservationFailure(err)
			return createServerResponse{OK: false, ID: id, Detail: detail}, status
		}
	} else {
		durable, durableExisting, reserveErr := c.reserveDurableLifecycleOperation(operationID, lifecycleKindCreate, id, fingerprint)
		if reserveErr != nil {
			if errors.Is(reserveErr, errLifecycleOperationConflict) {
				return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: "operationId는 다른 서버 생성 요청에 이미 사용되었습니다."}, http.StatusConflict
			}
			detail, status := lifecycleJobReservationFailure(reserveErr)
			return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: detail}, status
		}
		if durableExisting {
			replay := lifecycleOperationReplay(durable, c.lifecycleJobs.jobIDForOperation(operationID), "동일한 서버 생성 요청이 이미 접수되었습니다.")
			replay.Name = name
			replay.Project = projectForServerID(id)
			return replay, http.StatusOK
		}
		durableReserved = true
		var inMemoryExisting bool
		jobID, inMemoryExisting, err = c.lifecycleJobs.reserveWithOperation(operationID, fingerprint, lifecycleKindCreate)
		if err != nil {
			detail, status := lifecycleJobReservationFailure(err)
			return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: detail}, status
		}
		if inMemoryExisting {
			replay := lifecycleOperationReplay(durable, jobID, "동일한 서버 생성 요청이 이미 접수되었습니다.")
			replay.Name = name
			replay.Project = projectForServerID(id)
			return replay, http.StatusOK
		}
	}
	newReservation = true
	defer func() {
		if newReservation && !reservationClaimed && !admissionAttempted {
			c.lifecycleJobs.discard(jobID)
		}
	}()
	if err := c.ensurePortsAvailable(id, map[string]string{
		"GAME_API_PORT": gameAPIPort,
		"WEB_GAME_PORT": webGamePort,
	}); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: err.Error()}, http.StatusConflict
	}
	target := serverTarget{
		ID:          id,
		InternalKey: internalKey,
		Project:     projectForServerID(id),
		EnvFile:     c.serverEnvFileForID(id),
	}
	envFile := target.EnvFile
	if _, err := os.Stat(envFile); err == nil {
		return createServerResponse{OK: false, ID: id, Detail: "이미 존재하는 서버입니다."}, http.StatusConflict
	} else if !os.IsNotExist(err) {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 확인 실패: %v", err)}, http.StatusInternalServerError
	}
	gamePassword, err := randomHex(24)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("비밀번호 생성 실패: %v", err)}, http.StatusInternalServerError
	}
	envLines := []envLine{
		{Raw: "SERVER_ID=" + id, Key: "SERVER_ID", Value: id, IsKV: true},
		{Raw: "OPENSAMGUK_WORLD_ID=" + isolatedServerWorldID, Key: "OPENSAMGUK_WORLD_ID", Value: isolatedServerWorldID, IsKV: true},
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
		{Raw: "JWT_PUBLIC_KEY=" + jwtPublicKey, Key: "JWT_PUBLIC_KEY", Value: jwtPublicKey, IsKV: true},
		{Raw: "JWT_LEGACY_SECRET=" + jwtLegacySecret, Key: "JWT_LEGACY_SECRET", Value: jwtLegacySecret, IsKV: true},
		{Raw: "JWT_LEGACY_ACCESS_ACCEPT_UNTIL=" + jwtLegacyAcceptUntil, Key: "JWT_LEGACY_ACCESS_ACCEPT_UNTIL", Value: jwtLegacyAcceptUntil, IsKV: true},
		{Raw: "INTERNAL_SERVICE_TOKEN=" + internalServiceToken, Key: "INTERNAL_SERVICE_TOKEN", Value: internalServiceToken, IsKV: true},
		{Raw: "TURN_PROFILE_NAME=che:scenario_2", Key: "TURN_PROFILE_NAME", Value: "che:scenario_2", IsKV: true},
		{Raw: "SCENARIO_SEED_ENABLED=" + boolText(seedEnabled), Key: "SCENARIO_SEED_ENABLED", Value: boolText(seedEnabled), IsKV: true},
		{Raw: "SCENARIO_CODE=" + scenarioCode, Key: "SCENARIO_CODE", Value: scenarioCode, IsKV: true},
		{Raw: "GAME_API_URL=" + c.gameAPIURLFor(id), Key: "GAME_API_URL", Value: c.gameAPIURLFor(id), IsKV: true},
		{Raw: "GATEWAY_API_URL=" + envOrValue(c.sharedEnvValue("GATEWAY_API_URL"), c.defaultGatewayAPIURL()), Key: "GATEWAY_API_URL", Value: envOrValue(c.sharedEnvValue("GATEWAY_API_URL"), c.defaultGatewayAPIURL()), IsKV: true},
	}
	entry := registryEntry{
		ID:            id,
		Name:          name,
		Generation:    generation,
		ScenarioCode:  scenarioCode,
		GameAPIURL:    c.gameAPIURLFor(id),
		GameEngineURL: c.gameEngineURLFor(id),
		DeployProject: target.Project,
		Env:           registryEnvSnapshot(envValuesFromLines(envLines)),
	}
	admissionAttempted = true
	lease, err := c.beginMaintenanceCreate(jobID, maintenanceLease, operationID)
	if err != nil {
		if errors.Is(err, errMaintenanceClosed) {
			c.lifecycleJobs.discard(jobID)
		}
		if transitionErr := c.transitionDurableLifecycleOperation(operationID, lifecycleJobCancelled, http.StatusConflict, durableOperationMessageCancelled); transitionErr != nil {
			log.Printf("cancel rejected create operation operationId=%s err=%v", operationID, transitionErr)
		}
		detail, status := mutationAdmissionFailure(err)
		return createServerResponse{OK: false, ID: id, Detail: detail}, status
	}
	reservationClaimed = true
	c.lifecycleJobs.bindOperationSubject(jobID, lifecycleKindCreate, id)
	setupComplete := make(chan error, 1)
	if err := c.startClaimedDurableLifecycleJob(lease, jobID, "create "+id, operationID, lifecycleKindCreate, func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			setupComplete <- err
			return "", err
		}
		if err := os.MkdirAll(c.serversDir, 0o755); err != nil {
			setupComplete <- err
			return "", err
		}
		if _, err := os.Stat(envFile); err == nil {
			err = errors.New("server env already exists")
			setupComplete <- err
			return "", err
		} else if !os.IsNotExist(err) {
			setupComplete <- err
			return "", err
		}
		if err := c.ensurePortsAvailable(id, map[string]string{
			"GAME_API_PORT": gameAPIPort,
			"WEB_GAME_PORT": webGamePort,
		}); err != nil {
			setupComplete <- err
			return "", err
		}
		if err := ctx.Err(); err != nil {
			setupComplete <- err
			return "", err
		}
		var journalErr error
		if operationID != "" {
			journalErr = c.writeLinkedLifecycleJournal("create", target, operationID, lifecycleKindCreate)
		} else {
			journalErr = c.writeLifecycleJournal("create", target)
		}
		if journalErr != nil {
			setupComplete <- journalErr
			return "", journalErr
		}
		if err := writeEnvLinesAtomic(envFile, envLines); err != nil {
			_ = c.clearLifecycleJournal()
			setupComplete <- err
			return "", err
		}
		if err := ctx.Err(); err != nil {
			setupComplete <- err
			return "", err
		}
		if err := c.upsertRegistryEntry(entry); err != nil {
			setupComplete <- err
			return "", err
		}
		setupComplete <- nil
		detail, serverErr := c.upServerStack(ctx, entry.DeployProject, envFile)
		reloadDetail, reloadErr := c.reloadSharedRegistry(ctx)
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		if serverErr != nil {
			return detail, serverErr
		}
		if reloadErr != nil {
			return detail, reloadErr
		}
		return detail, nil
	}); err != nil {
		return createServerResponse{OK: false, ID: id, Name: name, Project: entry.DeployProject, OperationID: operationID, Detail: durableOperationCreatePreparationFailedMessage}, http.StatusInternalServerError
	}
	if err := <-setupComplete; err != nil {
		return createServerResponse{OK: false, ID: id, Name: name, Project: entry.DeployProject, Detail: fmt.Sprintf("서버 생성 준비 실패: %v", err)}, http.StatusInternalServerError
	}
	created := createServerResponse{
		OK:               true,
		ID:               id,
		Name:             name,
		Project:          entry.DeployProject,
		JobID:            jobID,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 생성 작업을 시작했습니다. 상태가 준비될 때까지 잠시 기다려 주세요.",
	}
	if operationID != "" {
		created.OperationID = operationID
		created.OperationStatus = lifecycleJobPending
		if recorded, ok := c.lifecycleJobs.lookup(jobID); ok {
			created.OperationStatus = recorded.Status
		}
	}
	return created, http.StatusOK
}

func (c config) deleteServer(rawID string, confirm string, operationID string) (response createServerResponse, responseStatus int) {
	target, err := c.serverTargetForID(rawID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	id := target.ID
	fingerprint := closeRequestFingerprint(id)
	var durable durableOperationRecord
	durableReserved := false
	rejectionMessageID := durableOperationMessageClosePreparationFailed
	defer func() {
		if !durableReserved {
			return
		}
		if err := c.settleRejectedDurableLifecycleOperation(operationID, responseStatus, rejectionMessageID); err != nil {
			log.Printf("settle rejected close operation unavailable operationId=%s", operationID)
			response = rejectedDurableOperationSettlementResponse(response, operationID, rejectionMessageID)
			responseStatus = http.StatusServiceUnavailable
		}
	}()
	if operationID == "" {
		log.Printf("legacy lifecycle request omitted operationId kind=%s subject=%s", lifecycleKindClose, id)
	} else {
		var durableExisting bool
		durable, durableExisting, err = c.reserveDurableLifecycleOperation(operationID, lifecycleKindClose, id, fingerprint)
		if err != nil {
			if errors.Is(err, errLifecycleOperationConflict) {
				return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: "operationId는 다른 서버 요청에 이미 사용되었습니다."}, http.StatusConflict
			}
			detail, status := lifecycleJobReservationFailure(err)
			return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: detail}, status
		}
		// 이미 접수된 operationId는 레지스트리 상태를 보기 전에 먼저 재생한다. 삭제가 끝난 뒤의
		// 재시도도 durable record만으로 확정할 수 있어야 한다.
		if durableExisting {
			replay := lifecycleOperationReplay(durable, c.lifecycleJobs.jobIDForOperation(operationID), "동일한 서버 종료 요청이 이미 접수되었습니다.")
			replay.Project = target.Project
			return replay, http.StatusOK
		}
		durableReserved = true
	}
	if confirm != "DELETE "+id {
		rejectionMessageID = durableOperationMessageRequestValidationFailed
		return createServerResponse{OK: false, ID: id, Detail: "삭제 확인 문구가 일치하지 않습니다."}, http.StatusBadRequest
	}
	entry, err := c.registryEntryByID(id)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("레지스트리 조회 실패: %v", err)}, http.StatusInternalServerError
	}
	if entry.ID == "" {
		return createServerResponse{OK: false, ID: id, Detail: "알 수 없는 서버입니다."}, http.StatusNotFound
	}
	if entry.DeployProject != target.Project {
		return createServerResponse{OK: false, ID: id, Detail: "레지스트리 project와 서버 id가 일치하지 않습니다."}, http.StatusConflict
	}
	if _, err := c.validateServerTarget(target); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)}, http.StatusConflict
	}
	envFile := target.EnvFile
	jobID := ""
	inMemoryExisting := false
	var reserveErr error
	if operationID == "" {
		jobID, reserveErr = c.lifecycleJobs.reserve()
	} else {
		jobID, inMemoryExisting, reserveErr = c.lifecycleJobs.reserveWithOperation(operationID, fingerprint, lifecycleKindClose)
	}
	if reserveErr != nil {
		detail, status := lifecycleJobReservationFailure(reserveErr)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: detail}, status
	}
	if inMemoryExisting {
		replay := lifecycleOperationReplay(durable, jobID, "동일한 서버 종료 요청이 이미 접수되었습니다.")
		replay.Name = entry.Name
		replay.Project = entry.DeployProject
		return replay, http.StatusOK
	}
	c.lifecycleJobs.bindOperationSubject(jobID, lifecycleKindClose, id)
	lease, err := c.beginMutation(jobID)
	if err != nil {
		c.lifecycleJobs.discard(jobID)
		if transitionErr := c.transitionDurableLifecycleOperation(operationID, lifecycleJobCancelled, http.StatusConflict, durableOperationMessageCancelled); transitionErr != nil {
			log.Printf("cancel rejected close operation operationId=%s err=%v", operationID, transitionErr)
		}
		detail, status := mutationAdmissionFailure(err)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: detail}, status
	}
	releaseStaleAdmission := func() {
		c.lifecycleJobs.finish(jobID, lifecycleJobCancelled)
		lease.Done()
		c.lifecycleJobs.discard(jobID)
	}
	entry, err = c.registryEntryByID(id)
	if err != nil {
		releaseStaleAdmission()
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("레지스트리 조회 실패: %v", err)}, http.StatusInternalServerError
	}
	if entry.ID == "" {
		releaseStaleAdmission()
		return createServerResponse{OK: false, ID: id, Detail: "알 수 없는 서버입니다."}, http.StatusNotFound
	}
	if entry.DeployProject != target.Project {
		releaseStaleAdmission()
		return createServerResponse{OK: false, ID: id, Detail: "레지스트리 project와 서버 id가 일치하지 않습니다."}, http.StatusConflict
	}
	if _, err := c.validateServerTarget(target); err != nil {
		releaseStaleAdmission()
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)}, http.StatusConflict
	}
	if err := c.startClaimedDurableLifecycleJob(lease, jobID, "delete "+id, operationID, lifecycleKindClose, func(ctx context.Context) (string, error) {
		var journalErr error
		if operationID != "" {
			journalErr = c.writeLinkedLifecycleJournal("delete", target, operationID, lifecycleKindClose)
		} else {
			journalErr = c.writeLifecycleJournal("delete", target)
		}
		if journalErr != nil {
			return "", journalErr
		}
		if err := c.advanceLifecycleJournal(lifecycleJournalStageDown); err != nil {
			return "", err
		}
		detail, downErr := c.downServerStack(ctx, target.Project, envFile)
		if downErr != nil {
			return detail, downErr
		}
		if err := ctx.Err(); err != nil {
			return detail, err
		}
		removeErr := os.Remove(envFile)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return detail, removeErr
		}
		if err := ctx.Err(); err != nil {
			return detail, err
		}
		if _, err := c.removeRegistryEntry(id); err != nil {
			return detail, err
		}
		if err := ctx.Err(); err != nil {
			return detail, err
		}
		reloadDetail, reloadErr := c.reloadSharedRegistry(ctx)
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		if reloadErr != nil {
			return detail, reloadErr
		}
		return detail, nil
	}); err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: durableOperationClosePreparationFailedMessage}, http.StatusInternalServerError
	}
	response = createServerResponse{
		OK:               true,
		ID:               id,
		Name:             entry.Name,
		Project:          entry.DeployProject,
		JobID:            jobID,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 삭제 작업을 시작했습니다. 목록에서 사라질 때까지 잠시 기다려 주세요.",
	}
	if operationID != "" {
		response.OperationID = operationID
		response.OperationStatus = lifecycleJobPending
		if recorded, ok := c.lifecycleJobs.lookup(jobID); ok {
			response.OperationStatus = recorded.Status
		}
	}
	return response, http.StatusOK
}

func (c config) resetServer(rawID string, req resetServerRequest) (response createServerResponse, responseStatus int) {
	target, err := c.serverTargetForID(rawID)
	if err != nil {
		return createServerResponse{OK: false, Detail: err.Error()}, http.StatusBadRequest
	}
	id := target.ID
	if req.Confirm != "RESET "+id {
		return createServerResponse{OK: false, ID: id, Detail: "리셋 확인 문구가 일치하지 않습니다."}, http.StatusBadRequest
	}
	requestedOperationID, err := normalizeLifecycleOperationID(req.OperationID)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: err.Error()}, http.StatusBadRequest
	}
	if _, err := c.validateServerTarget(target); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)}, http.StatusConflict
	}
	updates, err := resetEnvUpdates(req)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: err.Error()}, http.StatusBadRequest
	}
	entry, err := c.registryEntryByID(id)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("레지스트리 조회 실패: %v", err)}, http.StatusInternalServerError
	}
	if entry.ID == "" {
		return createServerResponse{OK: false, ID: id, Detail: "알 수 없는 서버입니다."}, http.StatusNotFound
	}
	if entry.DeployProject != target.Project {
		return createServerResponse{OK: false, ID: id, Detail: "레지스트리 project와 서버 id가 일치하지 않습니다."}, http.StatusConflict
	}
	if _, err := c.validateServerTarget(target); err != nil {
		return createServerResponse{OK: false, ID: id, Detail: fmt.Sprintf("서버 env 식별자 검증 실패: %v", err)}, http.StatusConflict
	}
	envFile := target.EnvFile
	if _, err := os.Stat(envFile); err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: fmt.Sprintf("서버 env 확인 실패: %v", err)}, http.StatusInternalServerError
	}
	resetTarget, err := resetLifecycleTargetForEnv(envFile, updates)
	if err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, Detail: err.Error()}, http.StatusBadRequest
	}
	fingerprint := resetRequestFingerprint(id, resetTarget)
	operationID := requestedOperationID
	var operation durableOperationRecord
	durableReserved := false
	defer func() {
		if !durableReserved {
			return
		}
		if err := c.settleRejectedDurableLifecycleOperation(operationID, responseStatus, durableOperationMessageResetPreparationFailed); err != nil {
			log.Printf("settle rejected reset operation unavailable operationId=%s", operationID)
			response = rejectedDurableOperationSettlementResponse(response, operationID, durableOperationMessageResetPreparationFailed)
			responseStatus = http.StatusServiceUnavailable
		}
	}()
	if operationID == "" {
		log.Printf("legacy lifecycle request omitted operationId kind=%s subject=%s", lifecycleKindReset, id)
	} else {
		var existing bool
		operation, existing, err = c.reserveDurableLifecycleOperation(operationID, lifecycleKindReset, id, fingerprint)
		if err != nil {
			if errors.Is(err, errLifecycleOperationConflict) {
				return createServerResponse{OK: false, ID: id, OperationID: operationID, Detail: "operationId는 다른 서버 리셋 요청에 이미 사용되었습니다."}, http.StatusConflict
			}
			detail, status := lifecycleJobReservationFailure(err)
			return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: detail}, status
		}
		if existing {
			replay := lifecycleOperationReplay(operation, c.lifecycleJobs.jobIDForOperation(operationID), "동일한 서버 리셋 요청이 이미 접수되었습니다.")
			replay.Name = entry.Name
			replay.Project = entry.DeployProject
			return replay, http.StatusOK
		}
		durableReserved = true
	}
	jobID := ""
	inMemoryExisting := false
	if operationID == "" {
		jobID, err = c.lifecycleJobs.reserve()
	} else {
		jobID, inMemoryExisting, err = c.lifecycleJobs.reserveWithOperation(operationID, fingerprint, lifecycleKindReset)
	}
	if err != nil {
		detail, status := lifecycleJobReservationFailure(err)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: detail}, status
	}
	if inMemoryExisting {
		replay := lifecycleOperationReplay(operation, jobID, "동일한 서버 리셋 요청이 이미 접수되었습니다.")
		replay.Name = entry.Name
		replay.Project = entry.DeployProject
		return replay, http.StatusOK
	}
	c.lifecycleJobs.bindOperationSubject(jobID, lifecycleKindReset, id)
	lease, err := c.beginMutation(jobID)
	if err != nil {
		c.lifecycleJobs.discard(jobID)
		if transitionErr := c.transitionDurableLifecycleOperation(operationID, lifecycleJobCancelled, http.StatusConflict, durableOperationMessageCancelled); transitionErr != nil {
			log.Printf("cancel rejected reset operation operationId=%s err=%v", operationID, transitionErr)
		}
		detail, status := mutationAdmissionFailure(err)
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: detail}, status
	}
	if err := c.startClaimedDurableLifecycleJob(lease, jobID, "reset "+id, operationID, lifecycleKindReset, func(ctx context.Context) (string, error) {
		failAfterIrreversible := func(detail string, cause error) (string, error) {
			if markerErr := c.setRegistryRepairRequired(id, true); markerErr != nil {
				return detail, fmt.Errorf("reset crossed irreversible volume-removal boundary and could not persist repair-required state: %v (original failure: %w)", markerErr, cause)
			}
			return detail, fmt.Errorf("reset crossed irreversible volume-removal boundary; new desired state was retained and marked repair-required: %w", cause)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if _, err := c.validateServerTarget(target); err != nil {
			return "", err
		}
		var journalErr error
		if operationID != "" {
			journalErr = c.writeLinkedResetLifecycleJournal(target, resetTarget, operationID, lifecycleKindReset)
		} else {
			journalErr = c.writeResetLifecycleJournal(target, resetTarget)
		}
		if journalErr != nil {
			return "", journalErr
		}
		if err := applyResetLifecycleTarget(envFile, resetTarget); err != nil {
			return "", err
		}
		if err := c.advanceLifecycleJournal(lifecycleJournalStageEnv); err != nil {
			return "", err
		}
		if _, err := c.syncRegistryEntryFromEnv(id, envFile); err != nil {
			return "", err
		}
		if err := c.advanceLifecycleJournal(lifecycleJournalStageRegistry); err != nil {
			return "", err
		}
		updatedEntry, err := c.registryEntryByID(id)
		if err != nil || updatedEntry.ID == "" {
			if err != nil {
				return "", err
			}
			return "", errors.New("updated server registry entry is unavailable")
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := c.advanceLifecycleJournal(lifecycleJournalStageDown); err != nil {
			return "", err
		}
		detail, downErr := c.downServerStack(ctx, updatedEntry.DeployProject, envFile)
		if downErr != nil {
			return failAfterIrreversible(detail, fmt.Errorf("server down returned an ambiguous result; reset recovery must complete the destructive reset before reopening: %w", downErr))
		}
		if err := ctx.Err(); err != nil {
			return failAfterIrreversible(detail, err)
		}
		upDetail, upErr := c.upServerStack(ctx, updatedEntry.DeployProject, envFile)
		if upDetail != "" {
			detail += "\n=== server up ===\n" + upDetail
		}
		if upErr != nil {
			retryDetail, retryErr := c.upServerStack(ctx, updatedEntry.DeployProject, envFile)
			if retryDetail != "" {
				detail += "\n=== server forward recovery ===\n" + retryDetail
			}
			if retryErr != nil {
				return failAfterIrreversible(detail, fmt.Errorf("server up failed: %v; forward recovery failed: %w", upErr, retryErr))
			}
		}
		if err := c.verifyResetRuntime(ctx, target); err != nil {
			return failAfterIrreversible(detail, err)
		}
		if err := c.reconcileServerRegistry(target); err != nil {
			return failAfterIrreversible(detail, err)
		}
		if err := c.setRegistryRepairRequired(id, false); err != nil {
			return failAfterIrreversible(detail, err)
		}
		reloadDetail, reloadErr := c.reloadSharedRegistry(ctx)
		if reloadDetail != "" {
			detail += "\n=== shared reload ===\n" + reloadDetail
		}
		if reloadErr != nil {
			return failAfterIrreversible(detail, reloadErr)
		}
		if err := c.verifySharedRegistryReload(ctx, target); err != nil {
			return failAfterIrreversible(detail, err)
		}
		return detail, nil
	}); err != nil {
		return createServerResponse{OK: false, ID: id, Name: entry.Name, Project: entry.DeployProject, OperationID: operationID, Detail: durableOperationResetPreparationFailedMessage}, http.StatusInternalServerError
	}
	response = createServerResponse{
		OK:               true,
		ID:               id,
		Name:             entry.Name,
		Project:          entry.DeployProject,
		JobID:            jobID,
		RestartRequired:  true,
		AffectedServices: append(append([]string{}, sharedRegistryReloadServices...), "server-stack"),
		Detail:           "서버 리셋 작업을 시작했습니다. 상태가 준비될 때까지 잠시 기다려 주세요.",
	}
	if operationID != "" {
		response.OperationID = operationID
		response.OperationStatus = lifecycleJobPending
	}
	return response, http.StatusOK
}

func lifecycleJobReservationFailure(err error) (string, int) {
	if errors.Is(err, errDurableOperationSettlementPending) {
		return "서버 수명주기 작업을 준비하지 못했습니다.", http.StatusServiceUnavailable
	}
	if errors.Is(err, errLifecycleJobCapacity) {
		return "서버 수명주기 작업 대기열이 가득 찼습니다. 잠시 후 다시 시도해 주세요.", http.StatusServiceUnavailable
	}
	return "서버 수명주기 작업을 준비하지 못했습니다.", http.StatusInternalServerError
}

// 모든 변이(deploy/env patch/create/delete/reset)가 지나가는 단일 진입 관문.
// 저널·env·레지스트리를 건드리기 전에 동기적으로 호출되므로, 여기서 막으면
// 어떤 호출자도 되돌릴 수 없는 경계를 넘지 못하고 사유가 HTTP 응답으로 그대로 나간다.
func (c config) admitMutation() error {
	if c.operations == nil {
		return errors.New("operation coordinator unavailable")
	}
	return c.dockerPreflight(context.Background())
}

func (c config) beginMutation(jobID string) (*operationLease, error) {
	if err := c.admitMutation(); err != nil {
		return nil, err
	}
	return c.operations.begin(jobID)
}

func (c config) beginMaintenanceCreate(jobID, maintenanceLease, operationID string) (*operationLease, error) {
	if err := c.admitMutation(); err != nil {
		return nil, err
	}
	return c.operations.beginWithMaintenanceLease(jobID, maintenanceLease, operationID)
}

func writeMutationAdmissionError(w http.ResponseWriter, err error) {
	if errors.Is(err, errDockerUnreachable) {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: err.Error()})
		return
	}
	if errors.Is(err, errMaintenanceClosed) {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "maintenance in progress"})
		return
	}
	if errors.Is(err, errLifecycleJobNotPending) {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "server lifecycle job was cancelled"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "mutation coordinator unavailable"})
}

func mutationAdmissionFailure(err error) (string, int) {
	if errors.Is(err, errDockerUnreachable) {
		return err.Error(), http.StatusServiceUnavailable
	}
	if errors.Is(err, errMaintenanceClosed) {
		return "maintenance in progress", http.StatusServiceUnavailable
	}
	if errors.Is(err, errLifecycleJobNotPending) {
		return "서버 수명주기 작업이 취소되었습니다.", http.StatusConflict
	}
	return "서버 수명주기 잠금을 준비하지 못했습니다.", http.StatusInternalServerError
}

func (c config) startClaimedLifecycleJob(lease *operationLease, id string, name string, job func(context.Context) (string, error)) {
	go func() {
		defer lease.Done()
		_, err := job(lease.Context())
		status := lifecycleJobSucceeded
		if errors.Is(lease.Context().Err(), context.Canceled) {
			status = lifecycleJobCancelled
		} else if err != nil {
			status = lifecycleJobFailed
		}
		c.lifecycleJobs.finish(id, status)
		if err != nil {
			log.Printf("server lifecycle job failed name=%s err=%v", name, err)
			return
		}
		log.Printf("server lifecycle job completed name=%s", name)
	}()
}

func (c config) startClaimedDurableLifecycleJob(lease *operationLease, jobID, name, operationID string, kind lifecycleKind, job func(context.Context) (string, error)) error {
	if err := c.transitionDurableLifecycleOperation(operationID, lifecycleJobRunning, http.StatusAccepted, durableOperationMessageNone); err != nil {
		c.lifecycleJobs.finish(jobID, lifecycleJobFailed)
		lease.Done()
		return err
	}
	go func() {
		defer lease.Done()
		_, workErr := job(lease.Context())
		status := lifecycleJobSucceeded
		transitionStatus := lifecycleJobSucceeded
		httpStatus := http.StatusOK
		messageID := durableOperationSuccessMessage(kind)

		if workErr != nil || errors.Is(lease.Context().Err(), context.Canceled) {
			status = lifecycleJobFailed
			if stateFilePresent(c.lifecycleJournalFile) {
				transitionStatus = lifecycleJobRecoveryRequired
				httpStatus = http.StatusAccepted
				messageID = durableOperationMessageRecoveryRequired
			} else if errors.Is(lease.Context().Err(), context.Canceled) {
				status = lifecycleJobCancelled
				transitionStatus = lifecycleJobCancelled
				httpStatus = http.StatusConflict
				messageID = durableOperationMessageCancelled
			} else {
				transitionStatus = lifecycleJobFailed
				httpStatus = http.StatusInternalServerError
				messageID = durableOperationPreparationFailureMessage(kind)
			}
		}

		transitionErr := c.transitionDurableLifecycleOperation(operationID, transitionStatus, httpStatus, messageID)
		if transitionErr == nil && transitionStatus == lifecycleJobSucceeded {
			if clearErr := c.clearLifecycleJournal(); clearErr != nil {
				log.Printf("server lifecycle journal clear failed after durable success name=%s err=%v", name, clearErr)
			}
		}
		if transitionErr != nil {
			status = lifecycleJobFailed
			log.Printf("server lifecycle durable transition failed name=%s err=%v", name, transitionErr)
		} else if operationID != "" {
			status = transitionStatus
		}
		publicMessage := ""
		if operationID != "" && transitionErr == nil {
			publicMessage, _ = durableOperationPublicMessage(messageID)
		}
		c.lifecycleJobs.finishWithPublicMessage(jobID, status, publicMessage)
		if workErr != nil {
			log.Printf("server lifecycle job failed name=%s err=%v", name, workErr)
			return
		}
		if transitionErr == nil {
			log.Printf("server lifecycle job completed name=%s", name)
		}
	}()
	return nil
}

func (c config) finishClaimedLifecycleJob(lease *operationLease, id string, name string, err error) {
	status := lifecycleJobSucceeded
	if errors.Is(lease.Context().Err(), context.Canceled) {
		status = lifecycleJobCancelled
	} else if err != nil {
		status = lifecycleJobFailed
	}
	c.lifecycleJobs.finish(id, status)
	lease.Done()
	if err != nil {
		log.Printf("server lifecycle job failed name=%s err=%v", name, err)
	}
}

// 서버 env 파일에서 IMAGE_TAG= 값을 읽는다.
func (c config) readImageTag(project string) (string, error) {
	target, err := c.validateDockerServerTarget(project, c.envFileFor(project), false)
	if err != nil {
		return "", err
	}
	envFile := target.EnvFile
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

func writeEnvLinesAtomicDurable(path string, lines []envLine) error {
	var sb strings.Builder
	for _, line := range lines {
		sb.WriteString(line.Raw)
		sb.WriteByte('\n')
	}
	return writeFileAtomicDurable(path, []byte(sb.String()))
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
	return writeFileAtomicWithDurability(path, data, false)
}

func writeFileAtomicDurable(path string, data []byte) error {
	return writeFileAtomicWithDurability(path, data, true)
}

func writeFileAtomicWithDurability(path string, data []byte, durable bool) error {
	_, err := writeFileAtomicWithDurabilityResult(path, data, durable, syncDirectory)
	return err
}

func writeFileAtomicWithDurabilityResult(path string, data []byte, durable bool, syncDir func(string) error) (bool, error) {
	dir := filepath.Dir(path)
	attrs := atomicWriteAttrs(path)
	tmp, err := os.CreateTemp(dir, ".env-write-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if attrs.hasOwner && os.Geteuid() == 0 {
		if err := tmp.Chown(attrs.uid, attrs.gid); err != nil {
			_ = tmp.Close()
			return false, err
		}
	}
	if err := tmp.Chmod(attrs.mode); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if durable {
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return false, err
		}
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	if !durable {
		return true, nil
	}
	if syncDir == nil {
		return true, errors.New("directory sync is unavailable")
	}
	return true, syncDir(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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
	if len(id) > maxPublicServerIDLength {
		return "", "", fmt.Errorf("서버 id는 최대 %d자여야 합니다.", maxPublicServerIDLength)
	}
	if _, reserved := reservedGameRouteIDs[id]; reserved {
		return "", "", fmt.Errorf("서버 id %q는 게임 경로와 충돌해 사용할 수 없습니다.", id)
	}
	if _, reserved := reservedPublicServerIDs[id]; reserved {
		return "", "", fmt.Errorf("서버 id %q는 전체 서버 예약어라 사용할 수 없습니다.", id)
	}
	// id가 만들어내는 compose project명이 공유 스택 project명과 충돌하면 거부한다.
	// 하드코딩된 id 목록이 아니라 실제 파생 결과를 비교해, 접두사 규칙이나 공유
	// project명이 바뀌어도 재발하지 않게 한다(#32).
	if projectForServerID(id) == sharedComposeProjectName {
		return "", "", fmt.Errorf("서버 id %q는 공유 스택 project명과 충돌해 사용할 수 없습니다.", id)
	}
	return id, internalServerKey(id), nil
}

func normalizeLifecycleOperationID(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if !lifecycleJobIDRe.MatchString(raw) {
		return "", fmt.Errorf("operationId는 32자리 소문자 16진수여야 합니다.")
	}
	return raw, nil
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
	unlock := c.lockSharedEnv()
	defer unlock()
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
	unlock := c.lockSharedEnv()
	defer unlock()
	registry, err := c.readRegistryLocked()
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
	return c.writeRegistryLocked(registry)
}

func (c config) setRegistryRepairRequired(id string, repairRequired bool) error {
	unlock := c.lockSharedEnv()
	defer unlock()
	registry, err := c.readRegistryLocked()
	if err != nil {
		return err
	}
	for index := range registry {
		if registry[index].ID != id {
			continue
		}
		if registry[index].RepairRequired == repairRequired {
			return c.writeRegistryLockedDurable(registry)
		}
		registry[index].RepairRequired = repairRequired
		return c.writeRegistryLockedDurable(registry)
	}
	return errors.New("updated server registry entry is unavailable")
}

func (c config) removeRegistryEntry(id string) (registryEntry, error) {
	unlock := c.lockSharedEnv()
	defer unlock()
	registry, err := c.readRegistryLocked()
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
	return removed, c.writeRegistryLocked(next)
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
	unlock := c.lockSharedEnv()
	defer unlock()
	registry, err := c.readRegistryLocked()
	if err != nil {
		return false, err
	}
	current := registryEntry{}
	for _, entry := range registry {
		if entry.ID == id {
			current = entry
			break
		}
	}
	next := c.registryEntryFromServerEnv(id, values, current)
	if reflect.DeepEqual(current, next) {
		return false, nil
	}
	found := false
	for index := range registry {
		if registry[index].ID == id {
			registry[index] = next
			found = true
			break
		}
	}
	if !found {
		registry = append(registry, next)
	}
	return true, c.writeRegistryLocked(registry)
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
	return sanitizeRegistryEnv(values)
}

func sanitizeRegistryEnv(values map[string]string) map[string]string {
	out := map[string]string{}
	for key := range registryEnvAllowlist {
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

func resetEnvUpdates(req resetServerRequest) (map[string]string, error) {
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
			return nil, fmt.Errorf("시나리오 코드가 올바르지 않습니다.")
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
			return nil, err
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
			return nil, err
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
				return nil, fmt.Errorf("자동 행동 옵션이 올바르지 않습니다.")
			}
			clean = append(clean, option)
		}
		values["RESET_AUTORUN_USER_OPTIONS"] = strings.Join(clean, ",")
	}
	return values, nil
}

func isResetLifecycleUpdateKey(key string) bool {
	for _, candidate := range resetLifecycleUpdateKeys {
		if key == candidate {
			return true
		}
	}
	return false
}

func resetLifecycleTargetForEnv(envFile string, requested map[string]string) (resetLifecycleTarget, error) {
	current, err := readEnvValues(envFile)
	if err != nil {
		return resetLifecycleTarget{}, err
	}
	values := make(map[string]string, len(current)+len(requested)+3)
	for key, value := range current {
		values[key] = value
	}
	for key, value := range requested {
		if !isResetLifecycleUpdateKey(key) {
			return resetLifecycleTarget{}, fmt.Errorf("reset target contains an unsupported field %q", key)
		}
		values[key] = value
	}
	for key, value := range map[string]string{
		"SCENARIO_CODE":         "scenario_1010",
		"SCENARIO_SEED_ENABLED": "true",
		"SERVER_GENERATION":     "1",
	} {
		if strings.TrimSpace(values[key]) == "" {
			values[key] = value
		}
	}
	expected, err := resetRuntimeExpectationFor(values)
	if err != nil {
		return resetLifecycleTarget{}, err
	}
	updates := make(map[string]string, len(resetLifecycleUpdateKeys))
	for _, key := range resetLifecycleUpdateKeys {
		value, exists := values[key]
		if !exists {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			if _, requested := requested[key]; !requested {
				continue
			}
		}
		updates[key] = value
	}
	target := resetLifecycleTarget{
		ScenarioCode:        expected.scenarioCode,
		Generation:          expected.generation,
		ScenarioSeedEnabled: true,
		Updates:             updates,
	}
	return normalizeResetLifecycleTarget(target)
}

func normalizeResetLifecycleTarget(target resetLifecycleTarget) (resetLifecycleTarget, error) {
	target.ScenarioCode = strings.TrimSpace(target.ScenarioCode)
	if !isSafeToken(target.ScenarioCode) {
		return resetLifecycleTarget{}, errors.New("reset scenario code is invalid")
	}
	generation, err := parseGeneration(strconv.Itoa(target.Generation), 1)
	if err != nil {
		return resetLifecycleTarget{}, err
	}
	if !target.ScenarioSeedEnabled {
		return resetLifecycleTarget{}, errors.New("reset requires SCENARIO_SEED_ENABLED=true so seeded world state can be verified")
	}
	updates := make(map[string]string, len(target.Updates)+3)
	for key, value := range target.Updates {
		if !isResetLifecycleUpdateKey(key) {
			return resetLifecycleTarget{}, fmt.Errorf("reset target contains an unsupported field %q", key)
		}
		value = strings.TrimSpace(value)
		if strings.ContainsAny(value, "\r\n") {
			return resetLifecycleTarget{}, fmt.Errorf("reset target field %q is invalid", key)
		}
		updates[key] = value
	}
	canonical := map[string]string{
		"SCENARIO_CODE":         target.ScenarioCode,
		"SCENARIO_SEED_ENABLED": "true",
		"SERVER_GENERATION":     strconv.Itoa(generation),
	}
	for key, value := range canonical {
		if current, exists := updates[key]; exists && current != value {
			return resetLifecycleTarget{}, fmt.Errorf("reset target field %q conflicts with its normalized value", key)
		}
		updates[key] = value
	}
	target.Generation = generation
	target.Updates = updates
	return target, nil
}

func applyResetLifecycleTarget(envFile string, target resetLifecycleTarget) error {
	normalized, err := normalizeResetLifecycleTarget(target)
	if err != nil {
		return err
	}
	spec := make(map[string]envFieldSpec, len(normalized.Updates))
	for key := range normalized.Updates {
		spec[key] = envFieldSpec{Description: "리셋 옵션"}
	}
	_, err = patchEnvFile(envFile, spec, normalized.Updates)
	return err
}

func (c config) applyResetOptions(envFile string, req resetServerRequest) error {
	values, err := resetEnvUpdates(req)
	if err != nil {
		return err
	}
	return applyResetUpdates(envFile, values)
}

func applyResetUpdates(envFile string, values map[string]string) error {
	target, err := resetLifecycleTargetForEnv(envFile, values)
	if err != nil {
		return err
	}
	return applyResetLifecycleTarget(envFile, target)
}

func (c config) readRegistry() ([]registryEntry, error) {
	unlock := c.lockSharedEnv()
	defer unlock()
	return c.readRegistryLocked()
}

func (c config) readRegistryLocked() ([]registryEntry, error) {
	lines, err := readEnvLines(c.sharedEnvFile())
	if err != nil {
		return nil, err
	}
	registry, rawRewrite, err := parseRawRegistryEntries(lines)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalRegistryEntries(registry)
	if err != nil {
		return nil, err
	}
	if rawRewrite || !reflect.DeepEqual(registry, canonical) {
		if c.registryRewriteHook != nil {
			c.registryRewriteHook()
		}
		if err := c.writeCanonicalRegistryLocked(lines, canonical); err != nil {
			return nil, err
		}
	}
	return canonical, nil
}

func parseRawRegistryEntries(lines []envLine) ([]registryEntry, bool, error) {
	registry := []registryEntry{}
	assignments := 0
	rewrite := false
	for _, line := range lines {
		if !line.IsKV || line.Key != "SERVER_REGISTRY_JSON" {
			continue
		}
		assignments++
		if strings.TrimSpace(line.Value) == "" {
			registry = []registryEntry{}
			rewrite = true
			continue
		}
		var rawEntries []json.RawMessage
		if err := json.Unmarshal([]byte(line.Value), &rawEntries); err != nil {
			return nil, false, fmt.Errorf("SERVER_REGISTRY_JSON 파싱 실패: %w", err)
		}
		parsed := make([]registryEntry, 0, len(rawEntries))
		for index, rawEntry := range rawEntries {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(rawEntry, &fields); err != nil {
				return nil, false, fmt.Errorf("SERVER_REGISTRY_JSON[%d] 파싱 실패: %w", index, err)
			}
			for key := range fields {
				if !isRegistryEntryJSONField(key) {
					rewrite = true
				}
			}
			var entry registryEntry
			if err := json.Unmarshal(rawEntry, &entry); err != nil {
				return nil, false, fmt.Errorf("SERVER_REGISTRY_JSON[%d] 파싱 실패: %w", index, err)
			}
			parsed = append(parsed, entry)
		}
		registry = parsed
	}
	if assignments > 1 {
		rewrite = true
	}
	return registry, rewrite, nil
}

func isRegistryEntryJSONField(key string) bool {
	switch key {
	case "id", "name", "generation", "scenarioCode", "gameApiUrl", "gameEngineUrl", "deployProject", "env", "repairRequired":
		return true
	default:
		return false
	}
}

func (c config) writeRegistry(registry []registryEntry) error {
	unlock := c.lockSharedEnv()
	defer unlock()
	return c.writeRegistryLocked(registry)
}

func (c config) writeRegistryLocked(registry []registryEntry) error {
	return c.writeRegistryLockedWithDurability(registry, false)
}

func (c config) writeRegistryLockedDurable(registry []registryEntry) error {
	return c.writeRegistryLockedWithDurability(registry, true)
}

func (c config) writeRegistryLockedWithDurability(registry []registryEntry, durable bool) error {
	canonical, err := canonicalRegistryEntries(registry)
	if err != nil {
		return err
	}
	lines, err := readEnvLines(c.sharedEnvFile())
	if err != nil {
		return err
	}
	return c.writeCanonicalRegistryLockedWithDurability(lines, canonical, durable)
}

func (c config) writeCanonicalRegistryLocked(lines []envLine, canonical []registryEntry) error {
	return c.writeCanonicalRegistryLockedWithDurability(lines, canonical, false)
}

func (c config) writeCanonicalRegistryLockedWithDurability(lines []envLine, canonical []registryEntry, durable bool) error {
	data, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	replacement := envLine{Raw: "SERVER_REGISTRY_JSON=" + string(data), Key: "SERVER_REGISTRY_JSON", Value: string(data), IsKV: true}
	next := make([]envLine, 0, len(lines)+1)
	replaced := false
	for _, line := range lines {
		if line.IsKV && line.Key == "SERVER_REGISTRY_JSON" {
			if !replaced {
				next = append(next, replacement)
				replaced = true
			}
			continue
		}
		next = append(next, line)
	}
	if !replaced {
		next = append(next, replacement)
	}
	if durable {
		return writeEnvLinesAtomicDurable(c.sharedEnvFile(), next)
	}
	return writeEnvLinesAtomic(c.sharedEnvFile(), next)
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
		entry.Env = sanitizeRegistryEnv(entry.Env)
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

func (c config) upServerStack(ctx context.Context, project, envFile string) (string, error) {
	if _, err := c.validateDockerServerTarget(project, envFile, false); err != nil {
		return "", err
	}
	return c.runServerDockerContext(ctx,
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"up", "-d",
	)
}

func (c config) reconcileServerRegistry(target serverTarget) error {
	if _, err := c.validateServerTarget(target); err != nil {
		return err
	}
	if _, err := c.syncRegistryEntryFromEnv(target.ID, target.EnvFile); err != nil {
		return err
	}
	entry, err := c.registryEntryByID(target.ID)
	if err != nil {
		return err
	}
	if entry.ID == "" || entry.DeployProject != target.Project {
		return errors.New("server registry is inconsistent with its env file")
	}
	return nil
}

func (c config) downServerStack(ctx context.Context, project, envFile string) (string, error) {
	// Last line of defense right before the destructive call: even if some other
	// caller path bypasses normalizeCreateServerID's collision check upstream,
	// never run `down --volumes --remove-orphans` against the shared stack (#32).
	if project == sharedComposeProjectName {
		return "", fmt.Errorf("공유 스택 project %q에는 down을 실행할 수 없습니다.", project)
	}
	if _, err := c.validateDockerServerTarget(project, envFile, false); err != nil {
		return "", err
	}
	return c.runServerDockerContext(ctx,
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"down", "--volumes", "--remove-orphans",
	)
}

func (c config) reloadSharedRegistry(ctx context.Context) (string, error) {
	services := withoutService(sharedRegistryReloadServices, "nginx")
	args := append([]string{
		"compose",
		"--env-file", c.sharedEnvFile(),
		"-f", c.composeShared,
		"up", "-d", "--no-deps",
	}, services...)
	detail, err := c.runDockerContext(ctx, args...)
	if err != nil {
		return detail, err
	}
	nginxDetail, nginxErr := c.runDockerContext(ctx,
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
	target, err := c.validateDockerServerTarget(project, c.envFileFor(project), false)
	if err != nil {
		return err
	}
	envFile := target.EnvFile
	_, err = patchEnvFile(envFile, serverEnvAllowlist, map[string]string{
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
func (c config) bounceStateless(ctx context.Context, project, envFile string) (string, error) {
	pullDetail, err := c.pullStateless(ctx, project, envFile)
	if err != nil {
		return pullDetail, err
	}
	upDetail, err := c.upStateless(ctx, project, envFile)
	return pullDetail + "\n" + upDetail, err
}

func (c config) pullStateless(ctx context.Context, project, envFile string) (string, error) {
	if _, err := c.validateDockerServerTarget(project, envFile, true); err != nil {
		return "", err
	}
	var sb strings.Builder

	// docker compose -p <project> --env-file <env> -f <server.yml> pull <svc...>
	pullArgs := append([]string{
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"pull",
	}, statelessServices...)
	if out, err := c.runServerDockerContext(ctx, pullArgs...); err != nil {
		sb.WriteString("=== pull 실패 ===\n")
		sb.WriteString(out)
		return sb.String(), err
	} else {
		sb.WriteString("=== pull ===\n")
		sb.WriteString(out)
	}
	return sb.String(), nil
}

func (c config) upStateless(ctx context.Context, project, envFile string) (string, error) {
	if _, err := c.validateDockerServerTarget(project, envFile, false); err != nil {
		return "", err
	}
	var sb strings.Builder

	// docker compose -p <project> --env-file <env> -f <server.yml> up -d --force-recreate --no-deps <svc...>
	upArgs := append([]string{
		"compose", "-p", project,
		"--env-file", envFile,
		"-f", c.composeServer,
		"up", "-d", "--force-recreate", "--no-deps",
	}, statelessServices...)
	if out, err := c.runServerDockerContext(ctx, upArgs...); err != nil {
		sb.WriteString("\n=== up 실패 ===\n")
		sb.WriteString(out)
		return sb.String(), err
	} else {
		sb.WriteString("\n=== up ===\n")
		sb.WriteString(out)
	}

	return sb.String(), nil
}

// docker 데몬 도달성 프리플라이트. socket-proxy가 사라지면 모든 compose 호출이 실패하는데,
// 그건 "애매한 결과"가 아니라 확정적으로 아무 일도 일어나지 않은 상태다. 저널/env를 건드리기
// 전에 이걸로 먼저 걸러서 되돌릴 수 없는 경계를 넘지 않고 깨끗이 실패시킨다.
// version 섹션은 socket-proxy 화이트리스트에 있다(VERSION=1).
func (c config) dockerPreflight(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, dockerPreflightTimeout)
	defer cancel()
	out, err := c.runDockerContext(ctx, "version", "--format", "{{.Server.Version}}")
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(out)
	if detail == "" {
		detail = err.Error()
	}
	if runes := []rune(detail); len(runes) > dockerPreflightDetailLimit {
		detail = string(runes[:dockerPreflightDetailLimit]) + "…"
	}
	return fmt.Errorf("%w: docker 데몬에 접근할 수 없습니다(socket-proxy 상태를 확인해 주세요): %s", errDockerUnreachable, detail)
}

// docker CLI 실행 — DOCKER_HOST는 환경에서 상속(socket-proxy). stdout+stderr 합쳐 반환.
func (c config) runDocker(args ...string) (string, error) {
	return c.runDockerContext(context.Background(), args...)
}

func isServerComposeEnvironmentOverride(key string) bool {
	if strings.HasPrefix(key, "V2_") {
		return true
	}
	if _, exists := v2ServerDefinitionKeys[key]; exists {
		return true
	}
	if _, exists := serverComposeInterpolationKeys[key]; exists {
		return true
	}
	_, exists := serverComposeProcessControlKeys[key]
	return exists
}

func (c config) serverComposeEnvironment(parent []string) []string {
	environment := make([]string, 0, len(parent)+1)
	for _, entry := range parent {
		key, _, hasValue := strings.Cut(entry, "=")
		if !hasValue || isServerComposeEnvironmentOverride(key) {
			continue
		}
		environment = append(environment, entry)
	}
	if c.composeHostDir != "" {
		environment = append(environment, "COMPOSE_HOST_DIR="+c.composeHostDir)
	}
	return environment
}

func (c config) runServerDockerContext(parent context.Context, args ...string) (string, error) {
	return c.runDockerContextWithEnvironment(parent, c.serverComposeEnvironment(os.Environ()), args...)
}

func (c config) runDockerContext(parent context.Context, args ...string) (string, error) {
	return c.runDockerContextWithEnvironment(parent, nil, args...)
}

func (c config) runDockerContextWithEnvironment(parent context.Context, environment []string, args ...string) (string, error) {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return "", err
	}
	if c.dockerRunnerContext != nil {
		out, err := c.dockerRunnerContext(parent, args...)
		if parentErr := parent.Err(); parentErr != nil {
			return out, parentErr
		}
		return out, err
	}
	if c.dockerRunner != nil {
		out, err := c.dockerRunner(args...)
		if parentErr := parent.Err(); parentErr != nil {
			return out, parentErr
		}
		return out, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = c.composeDir
	if environment != nil {
		cmd.Env = environment
	}
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
