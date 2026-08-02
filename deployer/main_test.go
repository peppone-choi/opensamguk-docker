package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerEnvGetPatchHappyPath(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "# server\nSERVER_ID=pep\nIMAGE_TAG=v1\nGAME_API_PORT=8101\nJWT_SECRET=old-secret\n")

	res := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodGet, "/env/server?id=PEP", "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", res.Code, res.Body.String())
	}
	body := decodeEnvResponse(t, res)
	if body.Scope != "server" || body.ID != "pep" {
		t.Fatalf("response = %#v", body)
	}
	if fieldValue(t, body.Fields, "IMAGE_TAG") != "v1" {
		t.Fatalf("IMAGE_TAG field = %#v", body.Fields["IMAGE_TAG"])
	}

	res = envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=PEP", `{"values":{"IMAGE_TAG":"v2","GAME_API_PORT":"8201","WEB_GAME_TAG":"v3"}}`)
	if res.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", res.Code, res.Body.String())
	}
	body = decodeEnvResponse(t, res)
	if !body.OK || !body.RestartRequired {
		t.Fatalf("patch response = %#v", body)
	}
	if strings.Join(body.AffectedServices, ",") != "game-api,web-game" {
		t.Fatalf("affected services = %#v", body.AffectedServices)
	}

	data := readFile(t, filepath.Join(cfg.serversDir, "spep.env"))
	if !strings.Contains(data, "# server\nSERVER_ID=pep\nIMAGE_TAG=v2\nGAME_API_PORT=8201\nJWT_SECRET=old-secret\nWEB_GAME_TAG=v3\n") {
		t.Fatalf("env comments/order not preserved:\n%s", data)
	}
	mode := fileMode(t, filepath.Join(cfg.serversDir, "spep.env"))
	if mode != 0o600 {
		t.Fatalf("env mode = %#o, want 0600", mode)
	}
}

func TestServerEnvRejectsNonPublicID(t *testing.T) {
	cfg := testConfig(t)
	res := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodGet, "/env/server?id=pep-1", "")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("GET status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestServerCloseRejectsWhitespaceAroundPublicID(t *testing.T) {
	cfg := testConfig(t)
	res := envRequest(t, cfg.withAuth(cfg.handleServerClose), http.MethodPost, "/servers/close", `{"id":" pep "}`)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestLifecycleJobEndpointAuthenticationAndBoundaries(t *testing.T) {
	cfg := testConfig(t)
	id, err := cfg.lifecycleJobs.reserve()
	if err != nil {
		t.Fatalf("reserve lifecycle job: %v", err)
	}
	handler := cfg.withAuth(cfg.handleLifecycleJob)

	unauthorizedRequest := httptest.NewRequest(http.MethodGet, "/jobs/"+id, nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler(unauthorizedResponse, unauthorizedRequest)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d body=%s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}

	method := envRequest(t, handler, http.MethodPost, "/jobs/"+id, "")
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d body=%s", method.Code, method.Body.String())
	}
	for _, target := range []string{"/jobs", "/jobs/", "/jobs/not-a-job", "/jobs/ABCDEF0123456789ABCDEF0123456789", "/jobs/" + id + "/extra"} {
		res := envRequest(t, handler, http.MethodGet, target, "")
		if res.Code != http.StatusBadRequest {
			t.Fatalf("malformed %s status = %d body=%s", target, res.Code, res.Body.String())
		}
	}
	unknown := envRequest(t, handler, http.MethodGet, "/jobs/00000000000000000000000000000000", "")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown status = %d body=%s", unknown.Code, unknown.Body.String())
	}

	res := envRequest(t, handler, http.MethodGet, "/jobs/"+id, "")
	if res.Code != http.StatusOK {
		t.Fatalf("status lookup = %d body=%s", res.Code, res.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		t.Fatalf("decode job response: %v", err)
	}
	if len(raw) != 2 || raw["id"] == nil || raw["status"] == nil {
		t.Fatalf("job response leaked fields: %#v", raw)
	}
	var body lifecycleJobResponse
	if err := json.Unmarshal(mustMarshal(t, raw), &body); err != nil {
		t.Fatalf("decode lifecycle response: %v", err)
	}
	if body.ID != id || body.Status != lifecycleJobPending {
		t.Fatalf("lifecycle response = %#v", body)
	}

	restarted := cfg
	restarted.lifecycleJobs = newLifecycleJobManager()
	afterRestart := envRequest(t, restarted.withAuth(restarted.handleLifecycleJob), http.MethodGet, "/jobs/"+id, "")
	if afterRestart.Code != http.StatusNotFound {
		t.Fatalf("restart lookup status = %d body=%s", afterRestart.Code, afterRestart.Body.String())
	}
}

func TestLifecycleJobStatusTracksReloadAndRedactsFailure(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\n")
	enteredReload := make(chan struct{})
	releaseReload := make(chan struct{})
	var enteredOnce sync.Once
	cfg.dockerRunner = func(args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "gateway-api web-gateway") {
			enteredOnce.Do(func() { close(enteredReload) })
			<-releaseReload
		}
		return "sensitive docker output", nil
	}

	patch := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", patch.Code, patch.Body.String())
	}
	body := decodeEnvResponse(t, patch)
	if !lifecycleJobIDRe.MatchString(body.JobID) {
		t.Fatalf("PATCH job id = %q", body.JobID)
	}
	select {
	case <-enteredReload:
	case <-time.After(time.Second):
		t.Fatal("shared registry reload did not start")
	}
	running := lifecycleJobLookup(t, cfg, body.JobID)
	if running.Status != lifecycleJobRunning {
		t.Fatalf("reload job status while blocked = %q", running.Status)
	}
	close(releaseReload)
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, body.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("reload completion = %#v", completed)
	}

	failing := testConfig(t)
	writeEnv(t, filepath.Join(failing.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(failing.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\n")
	failing.dockerRunner = func(args ...string) (string, error) {
		return "sensitive docker output", errors.New("sensitive docker failure")
	}
	failedPatch := envRequest(t, failing.withAuth(failing.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`)
	if failedPatch.Code != http.StatusOK {
		t.Fatalf("failed PATCH status = %d body=%s", failedPatch.Code, failedPatch.Body.String())
	}
	failedBody := decodeEnvResponse(t, failedPatch)
	failed := waitForLifecycleJob(t, failing.lifecycleJobs, failedBody.JobID, lifecycleJobFailed)
	if failed.Status != lifecycleJobFailed {
		t.Fatalf("failed job = %#v", failed)
	}
	response := envRequest(t, failing.withAuth(failing.handleLifecycleJob), http.MethodGet, "/jobs/"+failedBody.JobID, "")
	if response.Code != http.StatusOK {
		t.Fatalf("failed job endpoint = %d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sensitive docker") || strings.Contains(response.Body.String(), "failure") {
		t.Fatalf("failed job leaked docker detail: %s", response.Body.String())
	}
}

func TestConcurrentAuthenticatedCreatesWaitForPriorLifecycleTransaction(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")

	firstDockerCall := make(chan struct{})
	releaseFirstDockerCall := make(chan struct{})
	var blockFirstDockerCall sync.Once
	var releaseFirstDockerOnce sync.Once
	releaseDocker := func() {
		releaseFirstDockerOnce.Do(func() { close(releaseFirstDockerCall) })
	}
	cfg.dockerRunner = func(args ...string) (string, error) {
		blockFirstDockerCall.Do(func() {
			close(firstDockerCall)
			<-releaseFirstDockerCall
		})
		return "ok\n", nil
	}
	defer releaseDocker()

	handler := cfg.withAuth(cfg.handleServerCreate)
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/servers/create", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		handler(res, req)
		return res
	}

	firstResponse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResponse <- request(`{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101"}`)
	}()
	first := <-firstResponse
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d body=%s", first.Code, first.Body.String())
	}
	var firstBody createServerResponse
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first create response: %v", err)
	}

	select {
	case <-firstDockerCall:
	case <-time.After(time.Second):
		t.Fatal("first create did not enter Docker work")
	}

	secondResponse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		secondResponse <- request(`{"id":"foo","name":"둘 서버","gameApiPort":"8102","webGamePort":"3102"}`)
	}()
	select {
	case second := <-secondResponse:
		t.Fatalf("second create bypassed active lifecycle transaction: status=%d body=%s", second.Code, second.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	releaseDocker()
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, firstBody.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("first job completion = %#v", completed)
	}

	var second *httptest.ResponseRecorder
	select {
	case second = <-secondResponse:
	case <-time.After(time.Second):
		t.Fatal("second create did not resume after first lifecycle transaction")
	}
	if second.Code != http.StatusOK {
		t.Fatalf("second create status = %d body=%s", second.Code, second.Body.String())
	}
	var secondBody createServerResponse
	if err := json.NewDecoder(second.Body).Decode(&secondBody); err != nil {
		t.Fatalf("decode second create response: %v", err)
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, secondBody.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("second job completion = %#v", completed)
	}

	registry, err := cfg.readRegistry()
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	ids := map[string]bool{}
	for _, entry := range registry {
		ids[entry.ID] = true
	}
	if !ids["pep"] || !ids["foo"] || len(ids) != 2 {
		t.Fatalf("concurrent creates lost registry entries: %#v", registry)
	}
}

func TestCreateServerOperationIDRecoversAmbiguousPostWithoutSecondMutation(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")

	firstDockerCall := make(chan struct{})
	releaseFirstDockerCall := make(chan struct{})
	var blockFirstDockerCall sync.Once
	var releaseFirstDockerOnce sync.Once
	releaseDocker := func() {
		releaseFirstDockerOnce.Do(func() { close(releaseFirstDockerCall) })
	}
	cfg.dockerRunner = func(args ...string) (string, error) {
		blockFirstDockerCall.Do(func() {
			close(firstDockerCall)
			<-releaseFirstDockerCall
		})
		return "ok\n", nil
	}
	defer releaseDocker()

	operationID := "0123456789abcdef0123456789abcdef"
	body := `{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101","operationId":"` + operationID + `"}`
	first := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", body)
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d body=%s", first.Code, first.Body.String())
	}
	var firstBody createServerResponse
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first create response: %v", err)
	}
	select {
	case <-firstDockerCall:
	case <-time.After(time.Second):
		t.Fatal("first create did not enter Docker work")
	}

	retry := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", body)
	if retry.Code != http.StatusOK {
		t.Fatalf("ambiguous POST retry status = %d body=%s", retry.Code, retry.Body.String())
	}
	var retryBody createServerResponse
	if err := json.NewDecoder(retry.Body).Decode(&retryBody); err != nil {
		t.Fatalf("decode retry create response: %v", err)
	}
	if retryBody.JobID != firstBody.JobID {
		t.Fatalf("ambiguous POST retry returned job %q, want %q", retryBody.JobID, firstBody.JobID)
	}
	if got := strings.Count(readFile(t, filepath.Join(cfg.composeDir, ".env")), `"id":"pep"`); got != 1 {
		t.Fatalf("ambiguous POST mutated registry %d times", got)
	}
	releaseDocker()
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, firstBody.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("idempotent create completion = %#v", completed)
	}
}

func TestCreateServerOperationIDBindsNormalizedPayloadBeforeRetryResolution(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	dockerStarted := make(chan struct{})
	releaseDocker := make(chan struct{})
	var started sync.Once
	cfg.dockerRunner = func(args ...string) (string, error) {
		started.Do(func() {
			close(dockerStarted)
			<-releaseDocker
		})
		return "ok\n", nil
	}
	defer close(releaseDocker)

	operationID := "fedcba9876543210fedcba9876543210"
	first := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"PEP","name":" 첫 서버 ","generation":"01","imageTag":" v1 ","gameApiPort":"8101","webGamePort":"3101","scenarioCode":" scenario_1010 ","operationId":"`+operationID+`"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first create = %d body=%s", first.Code, first.Body.String())
	}
	var firstBody createServerResponse
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first create: %v", err)
	}
	select {
	case <-dockerStarted:
	case <-time.After(time.Second):
		t.Fatal("first create did not enter Docker")
	}

	retry := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"pep","name":"첫 서버","generation":"1","imageTag":"v1","gameApiPort":"8101","webGamePort":"3101","scenarioCode":"scenario_1010","operationId":"`+operationID+`"}`)
	if retry.Code != http.StatusOK {
		t.Fatalf("normalized retry = %d body=%s", retry.Code, retry.Body.String())
	}
	var retryBody createServerResponse
	if err := json.NewDecoder(retry.Body).Decode(&retryBody); err != nil {
		t.Fatalf("decode normalized retry: %v", err)
	}
	if retryBody.JobID != firstBody.JobID || retryBody.ID != "pep" {
		t.Fatalf("normalized retry response = %#v first=%#v", retryBody, firstBody)
	}

	different := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"foo","name":"다른 서버","gameApiPort":"8102","webGamePort":"3102","operationId":"`+operationID+`"}`)
	if different.Code != http.StatusConflict {
		t.Fatalf("different operation payload = %d body=%s", different.Code, different.Body.String())
	}
	var differentBody createServerResponse
	if err := json.NewDecoder(different.Body).Decode(&differentBody); err != nil {
		t.Fatalf("decode different payload response: %v", err)
	}
	if differentBody.OK || differentBody.JobID != "" {
		t.Fatalf("different payload reused lifecycle response: %#v", differentBody)
	}

	invalid := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"pep","name":"첫 서버","gameApiPort":"bad","webGamePort":"3101","operationId":"`+operationID+`"}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid retry bypassed validation = %d body=%s", invalid.Code, invalid.Body.String())
	}
}

func TestLifecycleCancelDrainsDockerWorkBeforeReleasingOperationLock(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\n")

	dockerStarted := make(chan struct{})
	dockerCanceled := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once
	cfg.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		startOnce.Do(func() { close(dockerStarted) })
		<-ctx.Done()
		cancelOnce.Do(func() { close(dockerCanceled) })
		return "sensitive docker output", ctx.Err()
	}

	patch := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", patch.Code, patch.Body.String())
	}
	patchBody := decodeEnvResponse(t, patch)
	select {
	case <-dockerStarted:
	case <-time.After(time.Second):
		t.Fatal("lifecycle job did not enter cancellable Docker work")
	}

	cancel := envRequest(t, cfg.withAuth(cfg.handleLifecycleJob), http.MethodPost, "/jobs/"+patchBody.JobID+"/cancel", "")
	if cancel.Code != http.StatusOK {
		t.Fatalf("cancel status = %d body=%s", cancel.Code, cancel.Body.String())
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, patchBody.JobID, lifecycleJobCancelled); completed.Status != lifecycleJobCancelled {
		t.Fatalf("cancelled job completion = %#v", completed)
	}
	select {
	case <-dockerCanceled:
	case <-time.After(time.Second):
		t.Fatal("Docker work did not receive lifecycle cancellation")
	}

	sharedPatch := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		sharedPatch <- envRequest(t, cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	}()
	select {
	case response := <-sharedPatch:
		if response.Code != http.StatusOK {
			t.Fatalf("shared PATCH after cancel status = %d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("operation lock remained held after cancelled lifecycle job drained")
	}
}

func TestMaintenanceAPIBearerLoopbackAndIdempotency(t *testing.T) {
	cfg := testConfig(t)
	handler := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))

	unauthorized := httptest.NewRecorder()
	unauthorizedRequest := httptest.NewRequest(http.MethodGet, "/maintenance", nil)
	unauthorizedRequest.RemoteAddr = "127.0.0.1:31000"
	handler(unauthorized, unauthorizedRequest)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized maintenance status = %d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	nonLoopback := httptest.NewRecorder()
	nonLoopbackRequest := httptest.NewRequest(http.MethodGet, "/maintenance", nil)
	nonLoopbackRequest.Header.Set("Authorization", "Bearer test-token")
	nonLoopbackRequest.RemoteAddr = "198.51.100.4:31000"
	handler(nonLoopback, nonLoopbackRequest)
	if nonLoopback.Code != http.StatusForbidden {
		t.Fatalf("non-loopback maintenance status = %d body=%s", nonLoopback.Code, nonLoopback.Body.String())
	}

	get := loopbackRequest(t, handler, http.MethodGet, "/maintenance", "")
	getRaw := append([]byte(nil), get.Body.Bytes()...)
	if get.Code != http.StatusOK || decodeMaintenanceResponse(t, get).State != maintenanceStateOpen {
		t.Fatalf("initial maintenance response = %d body=%s", get.Code, get.Body.String())
	}
	var getPayload map[string]any
	if err := json.Unmarshal(getRaw, &getPayload); err != nil {
		t.Fatalf("decode maintenance GET payload: %v", err)
	}
	if _, leaked := getPayload["lease"]; leaked {
		t.Fatalf("maintenance GET leaked lease: %#v", getPayload)
	}
	lease := ""
	for attempt := 0; attempt < 2; attempt++ {
		enter := loopbackRequest(t, handler, http.MethodPost, "/maintenance/enter", "")
		body := decodeMaintenanceResponse(t, enter)
		if enter.Code != http.StatusOK || body.State != maintenanceStateDrained || !lifecycleJobIDRe.MatchString(body.Lease) {
			t.Fatalf("maintenance enter attempt %d = %d body=%s", attempt, enter.Code, enter.Body.String())
		}
		if attempt == 0 {
			lease = body.Lease
		} else if body.Lease != lease {
			t.Fatalf("idempotent maintenance enter changed lease %q -> %q", lease, body.Lease)
		}
	}
	if _, err := os.Stat(cfg.maintenanceFile); err != nil {
		t.Fatalf("maintenance marker missing after enter: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		leave := loopbackRequest(t, handler, http.MethodPost, "/maintenance/leave", "")
		body := decodeMaintenanceResponse(t, leave)
		if leave.Code != http.StatusOK || body.State != maintenanceStateOpen || body.Lease != "" {
			t.Fatalf("maintenance leave attempt %d = %d body=%s", attempt, leave.Code, leave.Body.String())
		}
	}
	if _, err := os.Stat(cfg.maintenanceFile); !os.IsNotExist(err) {
		t.Fatalf("maintenance marker remained after leave: %v", err)
	}
}

func TestMaintenanceLeasePermitsOnlyOneLoopbackIdempotentCreate(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	dockerStarted := make(chan struct{})
	releaseDocker := make(chan struct{})
	var started sync.Once
	cfg.dockerRunner = func(args ...string) (string, error) {
		started.Do(func() {
			close(dockerStarted)
			<-releaseDocker
		})
		return "ok\n", nil
	}
	defer func() {
		select {
		case <-releaseDocker:
		default:
			close(releaseDocker)
		}
	}()

	maintenanceHandler := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))
	enter := loopbackRequest(t, maintenanceHandler, http.MethodPost, "/maintenance/enter", "")
	entered := decodeMaintenanceResponse(t, enter)
	if enter.Code != http.StatusOK || entered.State != maintenanceStateDrained || !lifecycleJobIDRe.MatchString(entered.Lease) {
		t.Fatalf("maintenance enter = %d", enter.Code)
	}

	operationID := "0123456789abcdef0123456789abcdef"
	body := `{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101","operationId":"` + operationID + `"}`
	createHandler := cfg.withAuth(cfg.handleServerCreate)
	requestCreate := func(remoteAddr, lease string, requestBody string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/servers/create", bytes.NewBufferString(requestBody))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		if lease != "" {
			req.Header.Set(maintenanceLeaseHeader, lease)
		}
		req.RemoteAddr = remoteAddr
		res := httptest.NewRecorder()
		createHandler(res, req)
		return res
	}

	nonLoopback := requestCreate("198.51.100.4:31000", entered.Lease, body)
	if nonLoopback.Code != http.StatusForbidden {
		t.Fatalf("non-loopback leased create = %d", nonLoopback.Code)
	}

	first := requestCreate("127.0.0.1:31000", entered.Lease, body)
	firstRaw := append([]byte(nil), first.Body.Bytes()...)
	if first.Code != http.StatusOK {
		t.Fatalf("leased create = %d body=%s", first.Code, first.Body.String())
	}
	var firstBody createServerResponse
	if err := json.Unmarshal(firstRaw, &firstBody); err != nil {
		t.Fatalf("decode leased create: %v", err)
	}
	if !lifecycleJobIDRe.MatchString(firstBody.JobID) || strings.Contains(string(firstRaw), entered.Lease) {
		t.Fatal("leased create did not return exactly one redacted lifecycle job")
	}
	select {
	case <-dockerStarted:
	case <-time.After(time.Second):
		t.Fatal("leased create did not enter Docker work")
	}

	retry := requestCreate("198.51.100.4:31000", "", body)
	if retry.Code != http.StatusOK {
		t.Fatalf("idempotent retry after ambiguous leased create = %d body=%s", retry.Code, retry.Body.String())
	}
	var retryBody createServerResponse
	if err := json.NewDecoder(retry.Body).Decode(&retryBody); err != nil {
		t.Fatalf("decode idempotent retry: %v", err)
	}
	if retryBody.JobID != firstBody.JobID {
		t.Fatalf("idempotent retry job %q, want %q", retryBody.JobID, firstBody.JobID)
	}

	secondBody := `{"id":"foo","name":"둘 서버","gameApiPort":"8102","webGamePort":"3102","operationId":"fedcba9876543210fedcba9876543210"}`
	second := requestCreate("127.0.0.1:31000", entered.Lease, secondBody)
	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") != "5" {
		t.Fatalf("second leased create = %d retry=%q body=%s", second.Code, second.Header().Get("Retry-After"), second.Body.String())
	}
	blocked := envRequest(t, cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("direct mutation while leased create runs = %d", blocked.Code)
	}
	cfg.operations.mu.Lock()
	lease := cfg.operations.maintenanceLease
	leaseValid := lease != nil && lease.consumed && lease.operationID == operationID && lease.jobID == firstBody.JobID
	cfg.operations.mu.Unlock()
	if !leaseValid {
		t.Fatal("maintenance lease was not consumed by the matching create only")
	}

	close(releaseDocker)
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, firstBody.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("leased create completion = %#v", completed)
	}
	get := loopbackRequest(t, maintenanceHandler, http.MethodGet, "/maintenance", "")
	getRaw := append([]byte(nil), get.Body.Bytes()...)
	if get.Code != http.StatusOK || decodeMaintenanceResponse(t, get).State != maintenanceStateDrained || strings.Contains(string(getRaw), "lease") {
		t.Fatal("completed leased create did not leave a redacted drained marker")
	}
	leave := loopbackRequest(t, maintenanceHandler, http.MethodPost, "/maintenance/leave", "")
	if leave.Code != http.StatusOK || decodeMaintenanceResponse(t, leave).State != maintenanceStateOpen {
		t.Fatalf("maintenance leave after leased create = %d body=%s", leave.Code, leave.Body.String())
	}
}

func TestMaintenanceLeaseAcceptedFromCreateBodyAndNeverReturned(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	cfg.dockerRunner = func(args ...string) (string, error) { return "ok\n", nil }
	maintenance := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))
	enter := loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/enter", "")
	entered := decodeMaintenanceResponse(t, enter)
	if enter.Code != http.StatusOK || !lifecycleJobIDRe.MatchString(entered.Lease) {
		t.Fatalf("maintenance enter = %d body=%s", enter.Code, enter.Body.String())
	}
	body := `{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101","operationId":"0123456789abcdef0123456789abcdef","maintenanceLease":"` + entered.Lease + `"}`
	request := httptest.NewRequest(http.MethodPost, "/servers/create", bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:31000"
	response := httptest.NewRecorder()
	cfg.withAuth(cfg.handleServerCreate)(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("body lease create = %d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), entered.Lease) {
		t.Fatalf("create response leaked maintenance lease: %s", response.Body.String())
	}
}

func TestPersistedMaintenanceMarkerStartsClosedUntilLeave(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "COOKIE_SECURE=false\n")
	if err := writeMaintenanceMarkerAtomic(cfg.maintenanceFile); err != nil {
		t.Fatalf("write maintenance marker: %v", err)
	}
	restarted := cfg
	restarted.lifecycleJobs = newLifecycleJobManager()
	restarted.operations = newOperationCoordinator(restarted.maintenanceFile, restarted.lifecycleJournalFile, restarted.lifecycleJobs)
	handler := restarted.withAuth(restarted.withLoopback(restarted.handleMaintenance))

	get := loopbackRequest(t, handler, http.MethodGet, "/maintenance", "")
	if get.Code != http.StatusOK || decodeMaintenanceResponse(t, get).State != maintenanceStateDrained {
		t.Fatalf("marker boot state = %d body=%s", get.Code, get.Body.String())
	}
	blocked := envRequest(t, restarted.withAuth(restarted.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("closed marker mutation = %d retry=%q body=%s", blocked.Code, blocked.Header().Get("Retry-After"), blocked.Body.String())
	}
	leave := loopbackRequest(t, handler, http.MethodPost, "/maintenance/leave", "")
	if leave.Code != http.StatusOK || decodeMaintenanceResponse(t, leave).State != maintenanceStateOpen {
		t.Fatalf("marker leave = %d body=%s", leave.Code, leave.Body.String())
	}
	open := envRequest(t, restarted.withAuth(restarted.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if open.Code != http.StatusOK {
		t.Fatalf("mutation after marker leave = %d body=%s", open.Code, open.Body.String())
	}
}

func TestLifecycleJournalSurvivesRestartAndRequiresVerifiedRepair(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","deployProject":"opensamguk-spep","repairRequired":true}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\n")
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeLifecycleJournal("reset", target); err != nil {
		t.Fatalf("write crash journal: %v", err)
	}

	restarted := cfg
	restarted.lifecycleJobs = newLifecycleJobManager()
	restarted.operations = newOperationCoordinator(restarted.maintenanceFile, restarted.lifecycleJournalFile, restarted.lifecycleJobs)
	calls := &dockerCallRecorder{}
	restarted.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "recovered\n", nil
	}
	maintenance := restarted.withAuth(restarted.withLoopback(restarted.handleMaintenance))

	ready := envRequest(t, restarted.handleReady, http.MethodGet, "/readyz", "")
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("journal restart readiness = %d body=%s", ready.Code, ready.Body.String())
	}
	blocked := envRequest(t, restarted.withAuth(restarted.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("journal restart direct mutation = %d retry=%q body=%s", blocked.Code, blocked.Header().Get("Retry-After"), blocked.Body.String())
	}
	leave := loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/leave", "")
	if leave.Code != http.StatusConflict {
		t.Fatalf("journal restart leave = %d body=%s", leave.Code, leave.Body.String())
	}

	repair := loopbackRequest(t, maintenance, http.MethodPost, "/maintenance/repair", "")
	if repair.Code != http.StatusOK || decodeMaintenanceResponse(t, repair).State != maintenanceStateOpen {
		t.Fatalf("journal repair = %d body=%s", repair.Code, repair.Body.String())
	}
	if calls.count() != 3 {
		t.Fatalf("journal repair Docker calls = %#v", calls.snapshot())
	}
	if _, err := os.Stat(restarted.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("journal remained after verified repair: %v", err)
	}
	if persisted := readFile(t, filepath.Join(restarted.composeDir, ".env")); strings.Contains(persisted, `"repairRequired":true`) {
		t.Fatalf("verified reset repair retained repair-required state:\n%s", persisted)
	}
	open := envRequest(t, restarted.withAuth(restarted.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if open.Code != http.StatusOK {
		t.Fatalf("mutation after verified repair = %d body=%s", open.Code, open.Body.String())
	}
}

func TestCreateJournalBeforeEnvIsClearedAfterRestartWhenNoStateWasWritten(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "SERVER_REGISTRY_JSON=[]\n")
	target, err := cfg.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeLifecycleJournal("create", target); err != nil {
		t.Fatalf("write create journal: %v", err)
	}

	restarted := cfg
	restarted.lifecycleJobs = newLifecycleJobManager()
	restarted.operations = newOperationCoordinator(restarted.maintenanceFile, restarted.lifecycleJournalFile, restarted.lifecycleJobs)
	if err := restarted.repairLifecycleJournal(); err != nil {
		t.Fatalf("repair no-op create journal: %v", err)
	}
	if _, err := os.Stat(restarted.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("no-op create journal remained: %v", err)
	}
	if state := restarted.operations.maintenanceState(); state != maintenanceStateOpen {
		t.Fatalf("coordinator remained closed after verified no-op create recovery: %s", state)
	}
}

func TestRestartedMaintenanceMarkerRejectsDirectMutationsAndLosesInMemoryJob(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "COOKIE_SECURE=false\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	maintenanceHandler := cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance))
	enter := loopbackRequest(t, maintenanceHandler, http.MethodPost, "/maintenance/enter", "")
	entered := decodeMaintenanceResponse(t, enter)
	if enter.Code != http.StatusOK || !lifecycleJobIDRe.MatchString(entered.Lease) {
		t.Fatalf("maintenance enter before restart = %d", enter.Code)
	}
	lostJobID, err := cfg.lifecycleJobs.reserve()
	if err != nil {
		t.Fatalf("reserve in-memory job before restart: %v", err)
	}

	restarted := cfg
	restarted.lifecycleJobs = newLifecycleJobManager()
	restarted.operations = newOperationCoordinator(restarted.maintenanceFile, restarted.lifecycleJournalFile, restarted.lifecycleJobs)
	restartedMaintenance := restarted.withAuth(restarted.withLoopback(restarted.handleMaintenance))
	get := loopbackRequest(t, restartedMaintenance, http.MethodGet, "/maintenance", "")
	getRaw := append([]byte(nil), get.Body.Bytes()...)
	if get.Code != http.StatusOK || decodeMaintenanceResponse(t, get).State != maintenanceStateDrained || strings.Contains(string(getRaw), "lease") {
		t.Fatal("restart did not retain a redacted closed marker")
	}

	blocked := envRequest(t, restarted.withAuth(restarted.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("direct PATCH after restart = %d retry=%q", blocked.Code, blocked.Header().Get("Retry-After"))
	}
	staleCreate := httptest.NewRequest(http.MethodPost, "/servers/create", bytes.NewBufferString(`{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101","operationId":"0123456789abcdef0123456789abcdef"}`))
	staleCreate.Header.Set("Authorization", "Bearer test-token")
	staleCreate.Header.Set("Content-Type", "application/json")
	staleCreate.Header.Set(maintenanceLeaseHeader, entered.Lease)
	staleCreate.RemoteAddr = "127.0.0.1:31000"
	staleCreateResponse := httptest.NewRecorder()
	restarted.withAuth(restarted.handleServerCreate)(staleCreateResponse, staleCreate)
	if staleCreateResponse.Code != http.StatusServiceUnavailable || staleCreateResponse.Header().Get("Retry-After") != "5" {
		t.Fatalf("stale lease create after restart = %d retry=%q", staleCreateResponse.Code, staleCreateResponse.Header().Get("Retry-After"))
	}
	lost := envRequest(t, restarted.withAuth(restarted.handleLifecycleJob), http.MethodGet, "/jobs/"+lostJobID, "")
	if lost.Code != http.StatusNotFound {
		t.Fatalf("lost in-memory job lookup = %d body=%s", lost.Code, lost.Body.String())
	}
}

func TestMaintenanceEnterCancelsActiveWorkAndRejectsNewMutationUntilRunnerReturns(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\n")
	enteredDocker := make(chan struct{})
	cancelObserved := make(chan struct{})
	releaseDocker := make(chan struct{})
	var enteredOnce sync.Once
	var cancelledOnce sync.Once
	cfg.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		enteredOnce.Do(func() { close(enteredDocker) })
		<-ctx.Done()
		cancelledOnce.Do(func() { close(cancelObserved) })
		<-releaseDocker
		return "", ctx.Err()
	}

	patch := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("start active mutation = %d body=%s", patch.Code, patch.Body.String())
	}
	jobID := decodeEnvResponse(t, patch).JobID
	select {
	case <-enteredDocker:
	case <-time.After(time.Second):
		t.Fatal("active lifecycle work did not enter Docker")
	}

	enterResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		enterResult <- loopbackRequest(t, cfg.withAuth(cfg.withLoopback(cfg.handleMaintenance)), http.MethodPost, "/maintenance/enter", "")
	}()
	select {
	case <-cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("maintenance enter did not cancel active Docker context")
	}
	select {
	case response := <-enterResult:
		t.Fatalf("maintenance enter returned before Docker runner drained: %d body=%s", response.Code, response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	blocked := envRequest(t, cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)
	if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("new mutation during maintenance = %d retry=%q body=%s", blocked.Code, blocked.Header().Get("Retry-After"), blocked.Body.String())
	}
	close(releaseDocker)
	var entered *httptest.ResponseRecorder
	select {
	case entered = <-enterResult:
	case <-time.After(time.Second):
		t.Fatal("maintenance enter did not return after Docker runner drained")
	}
	if entered.Code != http.StatusOK || decodeMaintenanceResponse(t, entered).State != maintenanceStateDrained {
		t.Fatalf("maintenance enter result = %d body=%s", entered.Code, entered.Body.String())
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, jobID, lifecycleJobCancelled); completed.Status != lifecycleJobCancelled {
		t.Fatalf("active lifecycle status = %#v", completed)
	}
}

func TestPendingCreateCancelBeforeClaimHasNoMutation(t *testing.T) {
	cfg := testConfig(t)
	sharedEnv := "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n"
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), sharedEnv)
	firstDockerStarted := make(chan struct{})
	releaseFirstDocker := make(chan struct{})
	var blockFirst sync.Once
	var dockerMu sync.Mutex
	var dockerCalls []string
	cfg.dockerRunner = func(args ...string) (string, error) {
		dockerMu.Lock()
		dockerCalls = append(dockerCalls, strings.Join(args, " "))
		dockerMu.Unlock()
		blockFirst.Do(func() {
			close(firstDockerStarted)
			<-releaseFirstDocker
		})
		return "", nil
	}
	first := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"pep","name":"첫 서버","gameApiPort":"8101","webGamePort":"3101"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first create = %d body=%s", first.Code, first.Body.String())
	}
	select {
	case <-firstDockerStarted:
	case <-time.After(time.Second):
		t.Fatal("first create did not occupy the coordinator")
	}

	operationID := "0123456789abcdef0123456789abcdef"
	secondBody := `{"id":"foo","name":"둘 서버","gameApiPort":"8102","webGamePort":"3102","operationId":"` + operationID + `"}`
	secondResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		secondResult <- envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", secondBody)
	}()
	jobID := waitForOperationJobID(t, cfg.lifecycleJobs, operationID)
	cancel := envRequest(t, cfg.withAuth(cfg.handleLifecycleJob), http.MethodPost, "/jobs/"+jobID+"/cancel", "")
	if cancel.Code != http.StatusOK {
		t.Fatalf("pending cancel = %d body=%s", cancel.Code, cancel.Body.String())
	}
	var cancelled lifecycleJobResponse
	if err := json.NewDecoder(cancel.Body).Decode(&cancelled); err != nil {
		t.Fatalf("decode pending cancel: %v", err)
	}
	if cancelled.Status != lifecycleJobCancelled {
		t.Fatalf("pending cancel status = %#v", cancelled)
	}
	close(releaseFirstDocker)
	select {
	case second := <-secondResult:
		if second.Code != http.StatusConflict {
			t.Fatalf("cancelled pending create = %d body=%s", second.Code, second.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled pending create remained blocked")
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, jobID, lifecycleJobCancelled); completed.Status != lifecycleJobCancelled {
		t.Fatalf("pending job after admission release = %#v", completed)
	}
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "sfoo.env")); !os.IsNotExist(err) {
		t.Fatalf("cancelled pending create wrote env: %v", err)
	}
	if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); strings.Contains(shared, `"id":"foo"`) {
		t.Fatalf("cancelled pending create wrote registry: %s", shared)
	}
	dockerMu.Lock()
	defer dockerMu.Unlock()
	for _, call := range dockerCalls {
		if strings.Contains(call, "opensamguk-sfoo") {
			t.Fatalf("cancelled pending create reached Docker: %q", call)
		}
	}
}

func TestClaimCancelRaceCancelledBeforeClaimNeverMutates(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		cfg := testConfig(t)
		sharedEnv := "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n"
		writeEnv(t, filepath.Join(cfg.composeDir, ".env"), sharedEnv)
		calls := &dockerCallRecorder{}
		cfg.dockerRunner = func(args ...string) (string, error) {
			calls.record(args...)
			return "", nil
		}
		active, err := cfg.beginMutation("")
		if err != nil {
			t.Fatalf("attempt %d begin active operation: %v", attempt, err)
		}
		operationID := fmt.Sprintf("%032x", attempt+1)
		req := createServerRequest{ID: "foo", Name: "경쟁 서버", GameAPIPort: "8102", WebGamePort: "3102", OperationID: operationID}
		createResult := make(chan struct {
			response createServerResponse
			status   int
		}, 1)
		go func() {
			response, status := cfg.createServer(req)
			createResult <- struct {
				response createServerResponse
				status   int
			}{response, status}
		}()
		jobID := waitForOperationJobID(t, cfg.lifecycleJobs, operationID)
		cancelResult := make(chan lifecycleJobResponse, 1)
		go func() {
			response, _ := cfg.lifecycleJobs.requestCancel(jobID)
			cancelResult <- response
		}()
		go active.Done()
		cancelled := <-cancelResult
		result := <-createResult
		if cancelled.Status == lifecycleJobCancelled {
			if result.status != http.StatusConflict {
				t.Fatalf("attempt %d cancelled-before-claim response = %#v", attempt, result)
			}
			if _, err := os.Stat(filepath.Join(cfg.serversDir, "sfoo.env")); !os.IsNotExist(err) {
				t.Fatalf("attempt %d cancelled-before-claim wrote env: %v", attempt, err)
			}
			if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); shared != sharedEnv {
				t.Fatalf("attempt %d cancelled-before-claim wrote registry: %s", attempt, shared)
			}
			if calls.count() != 0 {
				t.Fatalf("attempt %d cancelled-before-claim reached Docker: %#v", attempt, calls.snapshot())
			}
		}
		waitForAnyTerminalLifecycleJob(t, cfg.lifecycleJobs, jobID)
	}
}

func TestMaintenanceClosedRejectsEveryMutationHandler(t *testing.T) {
	cfg := testConfig(t)
	sharedEnv := `COOKIE_SECURE=false
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`
	serverEnv := "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_PORT=8101\nWEB_GAME_PORT=3101\nGAME_API_URL=http://spep-game-api:8081\n"
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), sharedEnv)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), serverEnv)
	if err := writeMaintenanceMarkerAtomic(cfg.maintenanceFile); err != nil {
		t.Fatal(err)
	}
	cfg.operations = newOperationCoordinator(cfg.maintenanceFile, cfg.lifecycleJournalFile, cfg.lifecycleJobs)
	cfg.dockerRunner = func(args ...string) (string, error) {
		t.Fatalf("maintenance-closed mutation reached Docker: %q", args)
		return "", nil
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
		body    string
	}{
		{"deploy", cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"opensamguk-spep","tag":"v2"}`},
		{"shared env", cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`},
		{"server env", cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`},
		{"create", cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"foo","name":"둘 서버","gameApiPort":"8102","webGamePort":"3102"}`},
		{"close", cfg.withAuth(cfg.handleServerClose), http.MethodPost, "/servers/close", `{"id":"pep"}`},
		{"delete", cfg.withAuth(cfg.handleServers), http.MethodDelete, "/servers?id=pep&confirm=DELETE%20pep", ""},
		{"reset", cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := envRequest(t, testCase.handler, testCase.method, testCase.target, testCase.body)
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
				t.Fatalf("%s maintenance response = %d retry=%q body=%s", testCase.name, response.Code, response.Header().Get("Retry-After"), response.Body.String())
			}
		})
	}
	if got := readFile(t, filepath.Join(cfg.composeDir, ".env")); got != sharedEnv {
		t.Fatalf("maintenance-closed mutation changed shared env:\n%s", got)
	}
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); got != serverEnv {
		t.Fatalf("maintenance-closed mutation changed server env:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "sfoo.env")); !os.IsNotExist(err) {
		t.Fatalf("maintenance-closed create wrote env: %v", err)
	}
}

func TestLifecycleJobCapacityFailsBeforeCreateMutationAndPrunesTerminal(t *testing.T) {
	cfg := testConfig(t)
	original := "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n"
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), original)
	for i := 0; i < lifecycleJobMaxEntries; i++ {
		if _, err := cfg.lifecycleJobs.reserve(); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	res := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"pep","name":"통일 서버","gameApiPort":"8101","webGamePort":"3101"}`)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity create status = %d body=%s", res.Code, res.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "spep.env")); !os.IsNotExist(err) {
		t.Fatalf("server env mutated on capacity failure: %v", err)
	}
	if got := readFile(t, filepath.Join(cfg.composeDir, ".env")); got != original {
		t.Fatalf("registry mutated on capacity failure:\n%s", got)
	}

	now := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	manager := newLifecycleJobManager()
	manager.maxEntries = 1
	manager.now = func() time.Time { return now }
	id, err := manager.reserve()
	if err != nil {
		t.Fatalf("reserve terminal job: %v", err)
	}
	if !manager.start(id, func(context.Context) (string, error) { return "", nil }) {
		t.Fatal("start terminal job")
	}
	waitForLifecycleJob(t, manager, id, lifecycleJobSucceeded)
	now = now.Add(lifecycleJobTerminalRetention)
	secondID, err := manager.reserve()
	if err != nil {
		t.Fatalf("expired terminal job was not pruned: %v", err)
	}
	if secondID == id {
		t.Fatalf("new lifecycle id reused expired id: %q", secondID)
	}
	if _, exists := manager.lookup(id); exists {
		t.Fatalf("expired terminal job %q still exists", id)
	}
}

func TestServerEnvPatchCancelsLifecycleReservationWithoutReloadOrOnSetupFailure(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep","env":{"IMAGE_TAG":"v1","SERVER_NAME":"통일 서버","SERVER_GENERATION":"1","GAME_API_URL":"http://spep-game-api:8081"}}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\nJWT_SECRET=old-secret\n")
	noReload := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"JWT_SECRET":"new-secret"}}`)
	if noReload.Code != http.StatusOK {
		t.Fatalf("no-reload PATCH status = %d body=%s", noReload.Code, noReload.Body.String())
	}
	if body := decodeEnvResponse(t, noReload); body.JobID != "" {
		t.Fatalf("no-reload PATCH retained job id %q", body.JobID)
	}
	for i := 0; i < lifecycleJobMaxEntries; i++ {
		if _, err := cfg.lifecycleJobs.reserve(); err != nil {
			t.Fatalf("no-reload PATCH leaked reservation at %d: %v", i, err)
		}
	}

	setupFailure := testConfig(t)
	failed := envRequest(t, setupFailure.withAuth(setupFailure.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"IMAGE_TAG":"v2"}}`)
	if failed.Code != http.StatusConflict {
		t.Fatalf("setup-failure PATCH status = %d body=%s", failed.Code, failed.Body.String())
	}
	for i := 0; i < lifecycleJobMaxEntries; i++ {
		if _, err := setupFailure.lifecycleJobs.reserve(); err != nil {
			t.Fatalf("setup-failure PATCH leaked reservation at %d: %v", i, err)
		}
	}
}

func TestReadyzRequiresCanonicalRegistry(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\n")

	res := envRequest(t, cfg.handleReady, http.MethodGet, "/readyz", "")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"status":"ready"`) {
		t.Fatalf("valid readiness = %d body=%s", res.Code, res.Body.String())
	}

	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"spep","deployProject":"opensamguk-spep"}]
`)
	res = envRequest(t, cfg.handleReady, http.MethodGet, "/readyz", "")
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), "one-time migration") {
		t.Fatalf("invalid readiness = %d body=%s", res.Code, res.Body.String())
	}
}

func TestCheckRegistryCommandValidAndLegacyRegistryExitBehavior(t *testing.T) {
	cfg := testConfig(t)
	cfg.token = ""
	var output bytes.Buffer

	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\n")
	if code := checkRegistryCommand(cfg, &output); code != 0 {
		t.Fatalf("valid registry exit code = %d, want 0", code)
	}
	if got := output.String(); got != "registry validation passed\n" {
		t.Fatalf("valid registry output = %q", got)
	}

	output.Reset()
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"spep","deployProject":"opensamguk-spep"}]
`)
	if code := checkRegistryCommand(cfg, &output); code != 1 {
		t.Fatalf("legacy registry exit code = %d, want 1", code)
	}
	if got := output.String(); got != "registry validation failed\n" {
		t.Fatalf("legacy registry output = %q", got)
	}
}

func TestDeployPromotesApiAndWebGameTags(t *testing.T) {
	cfg := testConfig(t)
	envFile := filepath.Join(cfg.serversDir, "s1.env")
	writeEnv(t, envFile, "# server\nSERVER_ID=1\nIMAGE_TAG=v1\nWEB_GAME_TAG=v-old\nJWT_SECRET=old-secret\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"opensamguk-s1","tag":"v2"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body deployResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.Project != "opensamguk-s1" || body.Tag != "v2" {
		t.Fatalf("deploy response = %#v", body)
	}

	data := readFile(t, envFile)
	for _, want := range []string{"IMAGE_TAG=v2\n", "WEB_GAME_TAG=v2\n", "JWT_SECRET=old-secret\n"} {
		if !strings.Contains(data, want) {
			t.Fatalf("env missing %q:\n%s", want, data)
		}
	}
	recorded := calls.snapshot()
	if len(recorded) != 2 {
		t.Fatalf("docker calls = %#v", recorded)
	}
	if !strings.Contains(recorded[0], "pull game-api web-game") {
		t.Fatalf("pull call = %q", recorded[0])
	}
	if !strings.Contains(recorded[1], "up -d --force-recreate --no-deps game-api web-game") {
		t.Fatalf("up call = %q", recorded[1])
	}
}

func TestDeployDoesNotMutateEnvWhenPullFails(t *testing.T) {
	cfg := testConfig(t)
	envFile := filepath.Join(cfg.serversDir, "s1.env")
	original := "# server\nSERVER_ID=1\nIMAGE_TAG=v1\nWEB_GAME_TAG=v-old\nJWT_SECRET=old-secret\n"
	writeEnv(t, envFile, original)
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "web-game Error not found\n", errors.New("pull failed")
	}

	res := envRequest(t, cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"opensamguk-s1","tag":"missing"}`)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	if got := readFile(t, envFile); got != original {
		t.Fatalf("env mutated after failed pull:\n%s", got)
	}
}

func TestFetchAvailableTagsReturnsOnlyCompleteDeployableAppTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/owner/packages/container/opensamguk/versions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"metadata":{"container":{"tags":["game-api-missing-web","game-api-complete"]}}},
			{"metadata":{"container":{"tags":["game-engine-complete","web-game-complete"]}}},
			{"metadata":{"container":{"tags":["game-api-latest","game-engine-latest","web-game-latest"]}}},
			{"metadata":{"container":{"tags":["web-game-second","game-engine-second","game-api-second"]}}}
		]`))
	}))
	defer srv.Close()

	cfg := testConfig(t)
	cfg.ghcrAPIBaseURL = srv.URL

	got := cfg.fetchAvailableTags()
	if strings.Join(got, ",") != "complete,second" {
		t.Fatalf("available tags = %#v", got)
	}
}

func TestServerEnvPatchSyncsRegistrySnapshotAndReloadsShared(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\nJWT_SECRET=old-secret\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerEnv),
		http.MethodPatch,
		"/env/server?id=PEP",
		`{"values":{"IMAGE_TAG":"v2","SERVER_NAME":"새 서버","SERVER_GENERATION":"0","GAME_API_URL":"http://spep-game-api-new:8081","RESET_TURNTERM":"30","JWT_SECRET":"new-secret"}}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", res.Code, res.Body.String())
	}
	body := decodeEnvResponse(t, res)
	if !lifecycleJobIDRe.MatchString(body.JobID) {
		t.Fatalf("PATCH job id = %q", body.JobID)
	}
	affected := strings.Join(body.AffectedServices, ",")
	for _, want := range []string{"game-api", "web-game", "gateway-api", "web-gateway", "nginx"} {
		if !strings.Contains(affected, want) {
			t.Fatalf("affected services missing %q: %#v", want, body.AffectedServices)
		}
	}

	registry, err := cfg.readRegistry()
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if len(registry) != 1 {
		t.Fatalf("registry = %#v", registry)
	}
	entry := registry[0]
	if entry.ID != "pep" || entry.Name != "새 서버" || entry.Generation != 0 || entry.GameAPIURL != "http://spep-game-api-new:8081" {
		t.Fatalf("registry entry not synced: %#v", entry)
	}
	for key, want := range map[string]string{
		"IMAGE_TAG":         "v2",
		"SERVER_NAME":       "새 서버",
		"SERVER_GENERATION": "0",
		"GAME_API_URL":      "http://spep-game-api-new:8081",
		"RESET_TURNTERM":    "30",
	} {
		if entry.Env[key] != want {
			t.Fatalf("registry env[%s]=%q want %q in %#v", key, entry.Env[key], want, entry.Env)
		}
	}
	if _, ok := entry.Env["JWT_SECRET"]; ok {
		t.Fatalf("registry env leaked JWT_SECRET: %#v", entry.Env)
	}
	if strings.Contains(readFile(t, filepath.Join(cfg.composeDir, ".env")), "new-secret") {
		t.Fatalf("shared registry leaked secret:\n%s", readFile(t, filepath.Join(cfg.composeDir, ".env")))
	}
	waitForCalls(t, calls.count, 2)
	recorded := calls.snapshot()
	if len(recorded) != 2 {
		t.Fatalf("docker calls = %#v", recorded)
	}
	if !strings.Contains(recorded[0], "gateway-api web-gateway") || strings.Contains(recorded[0], " nginx") {
		t.Fatalf("shared reload call = %q", recorded[0])
	}
	if !strings.Contains(recorded[1], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", recorded[1])
	}
}

func TestSharedEnvRejectsUnknownKey(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\n")

	res := envRequest(t, cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"DEPLOYER_TOKEN":"leak"}}`)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("PATCH status = %d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(readFile(t, filepath.Join(cfg.composeDir, ".env")), "DEPLOYER_TOKEN=leak") {
		t.Fatalf("unknown key was written")
	}
}

func TestServerEnvMasksWriteOnlySecrets(t *testing.T) {
	cfg := testConfig(t)
	envFile := filepath.Join(cfg.serversDir, "spep.env")
	writeEnv(t, envFile, "SERVER_ID=pep\nIMAGE_TAG=v1\nJWT_SECRET=old-secret\n")

	res := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodGet, "/env/server?id=pep", "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", res.Code, res.Body.String())
	}
	body := decodeEnvResponse(t, res)
	secret := body.Fields["JWT_SECRET"]
	if !secret.Configured || !secret.WriteOnly || !secret.Masked {
		t.Fatalf("JWT_SECRET metadata = %#v", secret)
	}
	if secret.Value != nil {
		t.Fatalf("JWT_SECRET raw value leaked: %#v", *secret.Value)
	}
	if strings.Contains(res.Body.String(), "old-secret") {
		t.Fatalf("GET leaked raw secret: %s", res.Body.String())
	}

	res = envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"JWT_SECRET":"new-secret"}}`)
	if res.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "new-secret") {
		t.Fatalf("PATCH leaked raw secret: %s", res.Body.String())
	}
	if !strings.Contains(readFile(t, envFile), "JWT_SECRET=new-secret\n") {
		t.Fatalf("secret was not written:\n%s", readFile(t, envFile))
	}
}

func TestCreateServerWritesEnvRegistryAndStartsCompose(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"pep","name":"통일 서버","generation":"3","gameApiPort":"8101","webGamePort":"3101","imageTag":"v2","scenarioCode":"scenario_1010"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" || !lifecycleJobIDRe.MatchString(body.JobID) {
		t.Fatalf("create response = %#v", body)
	}

	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "spep.env"))
	for _, want := range []string{
		"SERVER_ID=pep\n",
		"IMAGE_TAG=v2\n",
		"SERVER_NAME=통일 서버\n",
		"SERVER_GENERATION=3\n",
		"GAME_API_PORT=8101\n",
		"WEB_GAME_PORT=3101\n",
		"JWT_SECRET=shared-secret\n",
		"SCENARIO_SEED_ENABLED=true\n",
		"GAME_API_URL=http://spep-game-api:8081\n",
	} {
		if !strings.Contains(serverEnv, want) {
			t.Fatalf("server env missing %q:\n%s", want, serverEnv)
		}
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"pep"`) ||
		!strings.Contains(sharedEnv, `"generation":3`) ||
		!strings.Contains(sharedEnv, `"scenarioCode":"scenario_1010"`) ||
		!strings.Contains(sharedEnv, `"deployProject":"opensamguk-spep"`) {
		t.Fatalf("registry not updated:\n%s", sharedEnv)
	}
	waitForCalls(t, calls.count, 3)
	recorded := calls.snapshot()
	if len(recorded) != 3 {
		t.Fatalf("docker calls = %#v", recorded)
	}
	if !strings.Contains(recorded[0], "compose -p opensamguk-spep") ||
		!strings.Contains(recorded[0], "--env-file "+filepath.Join(cfg.serversDir, "spep.env")) ||
		strings.Contains(recorded[0], "--no-deps") {
		t.Fatalf("server compose call = %q", recorded[0])
	}
	if !strings.Contains(recorded[1], "gateway-api web-gateway") || strings.Contains(recorded[1], " nginx") {
		t.Fatalf("shared reload call = %q", recorded[1])
	}
	if !strings.Contains(recorded[2], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", recorded[2])
	}
}

func TestCreateServerCanonicalizesUppercaseIDAndPreventsCaseCollision(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"A1","name":"대소문자 서버","gameApiPort":"8111","webGamePort":"3111"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "a1" || body.Project != "opensamguk-sa1" {
		t.Fatalf("create response = %#v", body)
	}
	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "sa1.env"))
	if !strings.Contains(serverEnv, "SERVER_ID=a1\n") {
		t.Fatalf("canonical server env missing:\n%s", serverEnv)
	}
	if !strings.Contains(readFile(t, filepath.Join(cfg.composeDir, ".env")), `"id":"a1"`) {
		t.Fatalf("registry did not persist canonical id")
	}
	waitForCalls(t, calls.count, 1)
	recorded := calls.snapshot()
	if len(recorded) == 0 || !strings.Contains(recorded[0], "compose -p opensamguk-sa1") {
		t.Fatalf("compose call = %#v", recorded)
	}

	res = envRequest(t, cfg.withAuth(cfg.handleServerCreate), http.MethodPost, "/servers/create", `{"id":"a1","name":"중복 서버","gameApiPort":"8111","webGamePort":"3111"}`)
	if res.Code != http.StatusConflict {
		t.Fatalf("case-collision status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestPublicServerIDContract(t *testing.T) {
	publicID, internalKey, err := normalizeCreateServerID("pep")
	if err != nil {
		t.Fatalf("normalize pep: %v", err)
	}
	if publicID != "pep" || internalKey != "spep" || projectForServerID(publicID) != "opensamguk-spep" {
		t.Fatalf("public mapping = public=%q internal=%q project=%q", publicID, internalKey, projectForServerID(publicID))
	}
	cfg := testConfig(t)
	if got, want := cfg.serverEnvFileForID(publicID), filepath.Join(cfg.serversDir, "spep.env"); got != want {
		t.Fatalf("env file = %q, want %q", got, want)
	}
	publicID, internalKey, err = normalizeCreateServerID("A1")
	if err != nil || publicID != "a1" || internalKey != "sa1" || projectForServerID(publicID) != "opensamguk-sa1" {
		t.Fatalf("uppercase mapping = public=%q internal=%q err=%v", publicID, internalKey, err)
	}
	publicID, internalKey, err = normalizeCreateServerID("S1")
	if err != nil || publicID != "s1" || internalKey != "ss1" {
		t.Fatalf("leading s must stay public: public=%q internal=%q err=%v", publicID, internalKey, err)
	}
}

func TestPublicServerIDLengthFitsLongestDockerDNSLabelAndCanonicalizesMixedCase(t *testing.T) {
	if maxPublicServerIDLength != 48 {
		t.Fatalf("max public id length = %d, want 48", maxPublicServerIDLength)
	}
	raw := strings.Repeat("aB", 24)
	publicID, internalKey, err := normalizeCreateServerID(raw)
	if err != nil {
		t.Fatalf("normalize 48-character mixed-case id: %v", err)
	}
	if want := strings.ToLower(raw); publicID != want {
		t.Fatalf("canonical public id = %q, want %q", publicID, want)
	}
	if internalKey != "s"+publicID {
		t.Fatalf("internal key = %q, want s+public id", internalKey)
	}
	if got := len(internalKey + "-game-postgres"); got != 63 {
		t.Fatalf("game-postgres Docker DNS label length = %d, want 63", got)
	}
	if _, _, err := normalizeCreateServerID(strings.Repeat("a", 49)); err == nil {
		t.Fatal("normalize 49-character id unexpectedly succeeded")
	}
}

func TestProjectBoundariesRejectOverlongCanonicalPublicID(t *testing.T) {
	cfg := testConfig(t)
	publicID := strings.Repeat("a", 49)
	project := "opensamguk-s" + publicID

	status := envRequest(t, cfg.withAuth(cfg.handleStatus), http.MethodGet, "/status?project="+project, "")
	if status.Code != http.StatusBadRequest {
		t.Fatalf("overlong status project = %d body=%s", status.Code, status.Body.String())
	}

	deploy := envRequest(t, cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"`+project+`","tag":"v1"}`)
	if deploy.Code != http.StatusBadRequest {
		t.Fatalf("overlong deploy project = %d body=%s", deploy.Code, deploy.Body.String())
	}

	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"`+publicID+`","deployProject":"`+project+`"}]`+"\n")
	if _, err := cfg.readRegistry(); err == nil {
		t.Fatal("overlong registry public id unexpectedly succeeded")
	}
}

func TestServerTargetIdentityMismatchFailsBeforeReadinessAndDockerMutation(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=other\nIMAGE_TAG=v1\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "", nil
	}

	if response := envRequest(t, cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"opensamguk-spep","tag":"v2"}`); response.Code != http.StatusConflict {
		t.Fatalf("mismatched deploy = %d body=%s", response.Code, response.Body.String())
	}
	if response := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodDelete, "/servers?id=pep&confirm=DELETE%20pep", ""); response.Code != http.StatusConflict {
		t.Fatalf("mismatched delete = %d body=%s", response.Code, response.Body.String())
	}
	if response := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset?id=pep", `{"confirm":"RESET pep"}`); response.Code != http.StatusConflict {
		t.Fatalf("mismatched reset = %d body=%s", response.Code, response.Body.String())
	}
	if response := envRequest(t, cfg.handleReady, http.MethodGet, "/readyz", ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("mismatched readiness = %d body=%s", response.Code, response.Body.String())
	}
	if _, err := cfg.upServerStack(context.Background(), "opensamguk-spep", filepath.Join(cfg.serversDir, "spep.env")); err == nil {
		t.Fatal("mismatched target reached compose up")
	}
	if calls.count() != 0 {
		t.Fatalf("mismatched target reached Docker: %#v", calls.snapshot())
	}
}

func TestStagedDockerEnvMustMatchTargetIdentity(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\n")
	stagedEnv := filepath.Join(cfg.serversDir, ".deploy-mismatch.env")
	writeEnv(t, stagedEnv, "SERVER_ID=other\nIMAGE_TAG=v2\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "", nil
	}

	if _, err := cfg.pullStateless(context.Background(), "opensamguk-spep", stagedEnv); err == nil {
		t.Fatal("mismatched staged env reached compose pull")
	}
	if calls.count() != 0 {
		t.Fatalf("mismatched staged env reached Docker: %#v", calls.snapshot())
	}
}

func TestPublicServerIDRejectsNonAlphanumericValues(t *testing.T) {
	for _, value := range []string{"", " pep", "pep ", "pep-1", "pep_1", "pep.1", "pep/1", "한글"} {
		if _, _, err := normalizeCreateServerID(value); err == nil {
			t.Fatalf("normalizeCreateServerID(%q) unexpectedly succeeded", value)
		}
	}
}

func TestPublicServerIDRejectsReservedGameRoutesAfterCanonicalization(t *testing.T) {
	for route := range reservedGameRouteIDs {
		for _, raw := range []string{route, strings.ToUpper(route)} {
			if _, _, err := normalizeCreateServerID(raw); err == nil {
				t.Fatalf("normalizeCreateServerID(%q) unexpectedly accepted reserved game route", raw)
			}
		}
	}
	if _, _, err := normalizeCreateServerID("JOIN"); err == nil || !strings.Contains(err.Error(), `"join"는 게임 경로와 충돌`) {
		t.Fatalf("reserved-route error = %v", err)
	}
}

func TestPublicServerIDRejectsAllServerSentinelAfterCanonicalization(t *testing.T) {
	if _, _, err := normalizeCreateServerID("ALL"); err == nil || !strings.Contains(err.Error(), `"all"는 전체 서버 예약어`) {
		t.Fatalf("all-server sentinel error = %v", err)
	}
}

func TestServerComposeExportsPublicIDAndSynthesizesInternalNames(t *testing.T) {
	compose := readFile(t, filepath.Join("..", "docker-compose.server.yml"))
	for _, want := range []string{
		"name: opensamguk-s${SERVER_ID}",
		"container_name: s${SERVER_ID}-game-api",
		"SERVER_ID: ${SERVER_ID}",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	if strings.Contains(compose, "SERVER_ID: s${SERVER_ID}") {
		t.Fatalf("compose leaked internal key as public SERVER_ID")
	}
}

func TestNginxRouteReservationsAndApiProxyContract(t *testing.T) {
	nginx := readFile(t, filepath.Join("..", "infra", "nginx", "nginx.conf"))
	const suffix = `)(?:/|$)`
	var routeLists [][]string
	for _, prefix := range []string{`~^/game/(?:`, `location ~ ^/game/(?:`} {
		for remaining := nginx; ; {
			start := strings.Index(remaining, prefix)
			if start < 0 {
				break
			}
			remaining = remaining[start+len(prefix):]
			end := strings.Index(remaining, suffix)
			if end < 0 {
				t.Fatalf("nginx route pattern missing suffix after %q", remaining)
			}
			routes := strings.Split(remaining[:end], "|")
			sort.Strings(routes)
			routeLists = append(routeLists, routes)
			remaining = remaining[end+len(suffix):]
		}
	}
	if len(routeLists) != 3 {
		t.Fatalf("nginx reserved route list count = %d, want 3", len(routeLists))
	}

	gameRoutes := make([]string, 0, len(reservedGameRouteIDs))
	for route := range reservedGameRouteIDs {
		gameRoutes = append(gameRoutes, route)
	}
	sort.Strings(gameRoutes)
	pathRoutes := append([]string{"all"}, gameRoutes...)
	sort.Strings(pathRoutes)
	if strings.Join(routeLists[0], ",") != strings.Join(pathRoutes, ",") {
		t.Fatalf("nginx path reservations = %v, want %v", routeLists[0], pathRoutes)
	}
	for _, routes := range routeLists[1:] {
		if strings.Join(routes, ",") != strings.Join(gameRoutes, ",") {
			t.Fatalf("nginx cookie route reservations = %v, want %v", routes, gameRoutes)
		}
	}
	cookieStart := strings.Index(nginx, `~^(?:`)
	if cookieStart < 0 {
		t.Fatal("nginx cookie reservation map is missing")
	}
	cookieEnd := strings.Index(nginx[cookieStart:], `)$ "";`)
	if cookieEnd < 0 {
		t.Fatal("nginx cookie reservation map is malformed")
	}
	cookieRoutes := strings.Split(nginx[cookieStart+len(`~^(?:`):cookieStart+cookieEnd], "|")
	sort.Strings(cookieRoutes)
	if strings.Join(cookieRoutes, ",") != strings.Join(pathRoutes, ",") {
		t.Fatalf("nginx cookie reservation map = %v, want %v", cookieRoutes, pathRoutes)
	}
	for _, forbidden := range []string{"[a-z0-9]+", "location ~ ^/game/[a-z0-9]+"} {
		if strings.Contains(nginx, forbidden) {
			t.Fatalf("nginx permits unbounded public server ids with %q", forbidden)
		}
	}
	for _, want := range []string{
		`"~^/game/(?<path_public_server_id>[a-z0-9]{1,48})(?:/|$)"`,
		`"~^(?<cookie_web_public_server_id>[a-z0-9]{1,48})$"`,
		`location ~ "^/game/[a-z0-9]{1,48}(?:/|$)"`,
	} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("nginx bounded route is missing %q", want)
		}
	}
	if got := strings.Count(nginx, `location ~ "^/game/[a-z0-9]{1,48}(?:/|$)"`); got != 2 {
		t.Fatalf("nginx bounded route locations = %d, want HTTP and TLS", got)
	}
	if got := strings.Count(nginx, `location ~ "^/game/[a-z0-9]{1,48}/_next/static(?:/|$)"`); got != 2 {
		t.Fatalf("nginx bounded static locations = %d, want HTTP and TLS", got)
	}

	for _, forbidden := range []string{"game_cookie_api_upstream", "location /api/admin/", "location = /api/game", "location ^~ /api/game/"} {
		if strings.Contains(nginx, forbidden) {
			t.Fatalf("nginx still has direct game API route %q", forbidden)
		}
	}
	if got := strings.Count(nginx, "location /api/ {\n            proxy_pass http://web_gateway/api/;"); got != 2 {
		t.Fatalf("web-gateway API proxy count = %d, want 2", got)
	}
}

func TestDeployOrchestrationValidatesCandidateBeforeControlPlaneMutation(t *testing.T) {
	workflow := readFile(t, filepath.Join("..", ".github", "workflows", "deploy-orchestration.yml"))

	for _, want := range []string{
		"exec 9>/tmp/opensamguk-production.lock",
		"flock -w 1800 9",
		"sudo docker run --rm --read-only --network none",
		"-e COMPOSE_DIR=/workspace",
		`-v "$STACK/.env:/workspace/.env:ro"`,
		`-v "$STACK/servers:/workspace/servers:ro"`,
		"opensamguk-deployer:local --check-registry",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("control-plane deployment missing %q", want)
		}
	}

	build := strings.Index(workflow, "$COMPOSE build deployer")
	check := strings.Index(workflow, "opensamguk-deployer:local --check-registry")
	deployer := strings.Index(workflow, "$COMPOSE up -d --force-recreate --no-deps deployer")
	healthz := strings.Index(workflow, "http://localhost:9000/healthz")
	readyz := strings.Index(workflow, "http://localhost:9000/readyz")
	nginxMarker := "$COMPOSE up -d --force-recreate --no-deps nginx"
	nginx := strings.Index(workflow, nginxMarker)
	if build < 0 || check < 0 || deployer < 0 || healthz < 0 || readyz < 0 || nginx < 0 {
		t.Fatalf("missing deployment ordering markers: build=%d check=%d deployer=%d healthz=%d readyz=%d nginx=%d", build, check, deployer, healthz, readyz, nginx)
	}
	if !(build < check && check < deployer && deployer < healthz && healthz < readyz && readyz < nginx) {
		t.Fatalf("unexpected deployment ordering: build=%d check=%d deployer=%d healthz=%d readyz=%d nginx=%d", build, check, deployer, healthz, readyz, nginx)
	}
	if strings.Contains(workflow[check:deployer], "--env-file") {
		t.Fatal("candidate registry check must not receive the shared env through command-line injection")
	}

	postcondition := workflow[nginx+len(nginxMarker):]
	for _, want := range []string{"http://localhost:9000/healthz", "http://localhost:9000/readyz"} {
		if !strings.Contains(postcondition, want) {
			t.Fatalf("unlocked endpoint postcondition missing %q", want)
		}
	}
}

func TestDeployOrchestrationProbesARunningRegisteredServer(t *testing.T) {
	workflow := readFile(t, filepath.Join("..", ".github", "workflows", "deploy-orchestration.yml"))
	if strings.Contains(workflow, "print(server_id)\n                  break") {
		t.Fatal("route probe must not stop at the first registry entry before checking whether it is running")
	}

	candidates := strings.Index(workflow, `SERVER_IDS="$(python3 - "$STACK/.env" <<'PY'`)
	loop := strings.Index(workflow, "for SERVER_ID in $SERVER_IDS; do")
	running := strings.Index(workflow, `grep -Fxq "${INTERNAL_ID}-web-game"`)
	checked := strings.Index(workflow, "route_checked=true")
	skip := strings.Index(workflow, "no running registered server; game route check skipped")
	if candidates < 0 || loop < 0 || running < 0 || checked < 0 || skip < 0 {
		t.Fatalf("missing route-probe markers: candidates=%d loop=%d running=%d checked=%d skip=%d", candidates, loop, running, checked, skip)
	}
	if !(candidates < loop && loop < running && running < checked && checked < skip) {
		t.Fatalf("unexpected route-probe order: candidates=%d loop=%d running=%d checked=%d skip=%d", candidates, loop, running, checked, skip)
	}
}

func TestRecreateWorkflowRetriesIdempotentlyAndDrainsCancellationBeforeUnlock(t *testing.T) {
	workflow := readFile(t, filepath.Join("..", ".github", "workflows", "recreate-server.yml"))
	for _, want := range []string{
		"timeout-minutes: 45",
		"WORKFLOW_DEADLINE=$((SECONDS + 2400))",
		"deadline_remaining",
		"run_bounded",
		"docker_exec_bounded",
		"exec 9>/tmp/opensamguk-production.lock",
		"flock -w 300 9",
		"CLIENT_OPERATION_ID",
		`"operationId": os.environ["CLIENT_OPERATION_ID"]`,
		`"maintenanceLease": os.environ["MAINTENANCE_LEASE"]`,
		"export MAINTENANCE_LEASE",
		"maintenance_enter_fields",
		"for create_attempt in 1 2 3",
		"payload.get(\"jobId\")",
		"http://localhost:9000/jobs/$1",
		"http://localhost:9000/jobs/$1/cancel",
		"cancel_and_await_lifecycle_job",
		"for attempt in 1 2 3",
		"--header=\"Authorization: Bearer $DEPLOYER_TOKEN\"",
		"for attempt in $(seq 1 12)",
		"for poll_attempt in $(seq 1 240)",
		"local drain_deadline=$((SECONDS + 60))",
		"timeout --foreground -k 2",
		"timeout -k 2 10 wget",
		"-T 5",
		"--max-time 10",
		"pending|running|cancelled)",
		"failed)",
		"lifecycle job returned an HTTP error or was lost after deployer restart",
		"bounded lifecycle cancellation/drain could not be confirmed",
		"maintenance barrier did not reopen after lifecycle terminal and server postconditions",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("recreate workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{`echo "$RESPONSE"`, `echo "$JOB_RESPONSE"`, `grep -q '"ok":true'`, `echo "$CANCEL_RESPONSE"`} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("recreate workflow leaks or trusts raw response with %q", forbidden)
		}
	}

	lock := strings.Index(workflow, "exec 9>/tmp/opensamguk-production.lock")
	enter := strings.Index(workflow, "maintenance_post /maintenance/enter")
	merge := strings.Index(workflow, "git merge --ff-only origin/main")
	operationID := strings.Index(workflow, "CLIENT_OPERATION_ID")
	create := strings.Index(workflow, "http://localhost:9000/servers/create")
	parse := strings.Index(workflow, "payload.get(\"jobId\")")
	poll := strings.LastIndex(workflow, "$(lifecycle_status \"$JOB_ID\" \"$WORKFLOW_DEADLINE\")")
	succeeded := strings.Index(workflow, "succeeded)")
	postconditions := strings.Index(workflow, "for i in $(seq 1 90); do")
	leave := strings.LastIndex(workflow, "maintenance_post /maintenance/leave")
	if lock < 0 || enter < 0 || merge < 0 || operationID < 0 || create < 0 || parse < 0 || poll < 0 || succeeded < 0 || postconditions < 0 || leave < 0 {
		t.Fatalf("missing lease lifecycle markers: lock=%d enter=%d merge=%d operationID=%d create=%d parse=%d poll=%d succeeded=%d postconditions=%d leave=%d", lock, enter, merge, operationID, create, parse, poll, succeeded, postconditions, leave)
	}
	if !(lock < enter && enter < merge && merge < operationID && operationID < create && create < parse && parse < poll && poll < succeeded && succeeded < postconditions && postconditions < leave) {
		t.Fatalf("unexpected closed-barrier ordering: lock=%d enter=%d merge=%d operationID=%d create=%d parse=%d poll=%d succeeded=%d postconditions=%d leave=%d", lock, enter, merge, operationID, create, parse, poll, succeeded, postconditions, leave)
	}
	if strings.Contains(workflow[enter:create], "maintenance_post /maintenance/leave") {
		t.Fatal("recreate must not reopen maintenance before the leased create")
	}
	for _, forbidden := range []string{"while [[ -z \"$JOB_ID\" ]]", "while true", "lifecycle job lookup remained unavailable; retrying", "lifecycle job cancellation could not be confirmed"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("recreate workflow retained an unbounded lifecycle path: %q", forbidden)
		}
	}
}

func TestRecreateWorkflowLostJobAbortsBoundedAndKeepsMarkerClosed(t *testing.T) {
	run := runRecreateWorkflowWithLostJob(t)
	if run.err == nil {
		t.Fatalf("lost-job recreate workflow unexpectedly succeeded: %s", run.output)
	}
	if strings.Contains(run.output, "0123456789abcdef0123456789abcdef") {
		t.Fatal("recreate workflow leaked its maintenance lease")
	}
	if !strings.Contains(run.output, "lifecycle job returned an HTTP error or was lost after deployer restart") {
		t.Fatalf("lost-job recreate workflow did not fail promptly: %s", run.output)
	}
	if strings.Contains(run.dockerCalls, "leave") {
		t.Fatalf("lost-job recreate workflow reopened maintenance: %s", run.dockerCalls)
	}
}

func TestRecreateWorkflowAcceptAndStallPathsAreBoundedAndFailClosed(t *testing.T) {
	run := runRecreateWorkflowWithCreateTimeout(t)
	if run.err == nil {
		t.Fatalf("stalled-create recreate workflow unexpectedly succeeded: %s", run.output)
	}
	if !strings.Contains(run.output, "server creation did not return a lifecycle job after 3 bounded attempts") {
		t.Fatalf("stalled-create workflow did not report its bounded failure: %s", run.output)
	}
	if strings.Contains(run.dockerCalls, "leave") {
		t.Fatalf("stalled-create workflow reopened maintenance: %s", run.dockerCalls)
	}
}

func TestRecreateWorkflowRunBoundedHardKillsTermIgnoringChild(t *testing.T) {
	workflow := readFile(t, filepath.Join("..", ".github", "workflows", "recreate-server.yml"))
	if !strings.Contains(workflow, "timeout --foreground -k 2") {
		t.Fatal("recreate workflow run_bounded is missing a TERM-to-KILL escalation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "timeout", "--foreground", "-k", "2", "1", "bash", "-c", `trap '' TERM; while :; do :; done`)
	started := time.Now()
	err := command.Run()
	elapsed := time.Since(started)
	if ctx.Err() != nil {
		t.Fatalf("hard-kill timeout did not stop TERM-ignoring child within the outer guard: %v", ctx.Err())
	}
	if err == nil {
		t.Fatal("TERM-ignoring child unexpectedly survived bounded timeout")
	}
	if elapsed < 2*time.Second || elapsed > 5*time.Second {
		t.Fatalf("hard-kill timeout elapsed=%s, want TERM then KILL within bounds", elapsed)
	}
}

func TestMaintenanceWorkflowsKeepCredentialsOutOfHostDockerArguments(t *testing.T) {
	workflows := map[string]string{
		"deploy":   readFile(t, filepath.Join("..", ".github", "workflows", "deploy-orchestration.yml")),
		"recreate": readFile(t, filepath.Join("..", ".github", "workflows", "recreate-server.yml")),
		"start":    readFile(t, filepath.Join("..", ".github", "workflows", "start-server.yml")),
	}
	for name, workflow := range workflows {
		t.Run(name, func(t *testing.T) {
			for _, forbidden := range []string{
				`DEPLOYER_TOKEN="$(grep`,
				"docker exec -e",
				"-e DEPLOYER_TOKEN=",
				"-e MAINTENANCE_LEASE=",
			} {
				if strings.Contains(workflow, forbidden) {
					t.Fatalf("%s workflow exposes a credential in host Docker argv with %q", name, forbidden)
				}
			}
		})
	}
	recreate := workflows["recreate"]
	for _, want := range []string{`"maintenanceLease": os.environ["MAINTENANCE_LEASE"]`, `<<<"$BODY"`, "cat > /tmp/recreate-server.json"} {
		if !strings.Contains(recreate, want) {
			t.Fatalf("recreate workflow is missing stdin/body lease transport %q", want)
		}
	}
	if strings.Contains(recreate, "X-Maintenance-Lease") {
		t.Fatal("recreate workflow still carries the maintenance lease in an HTTP/Docker command argument")
	}
}

func TestMaintenanceWorkflowOrderingAndLegacyFailClosedBoundary(t *testing.T) {
	deploy := readFile(t, filepath.Join("..", ".github", "workflows", "deploy-orchestration.yml"))
	start := readFile(t, filepath.Join("..", ".github", "workflows", "start-server.yml"))
	recreate := readFile(t, filepath.Join("..", ".github", "workflows", "recreate-server.yml"))

	assertOrder := func(t *testing.T, workflow string, labels ...string) {
		t.Helper()
		previous := -1
		for _, label := range labels {
			index := strings.Index(workflow, label)
			if index < 0 || index <= previous {
				t.Fatalf("unexpected workflow ordering labels=%q index=%d previous=%d", labels, index, previous)
			}
			previous = index
		}
	}
	assertOrder(t, deploy,
		"exec 9>/tmp/opensamguk-production.lock",
		"maintenance_post /maintenance/enter",
		"git merge --ff-only origin/main",
		"$COMPOSE up -d --force-recreate --no-deps deployer",
		"deployer_ready=true",
		"maintenance_post /maintenance/leave",
	)
	assertOrder(t, start,
		"exec 9>/tmp/opensamguk-production.lock",
		"maintenance_post /maintenance/enter",
		"git merge --ff-only origin/main",
		`sudo sed -i "s/^IMAGE_TAG=.*`,
		"maintenance_post /maintenance/leave",
	)
	assertOrder(t, recreate,
		"exec 9>/tmp/opensamguk-production.lock",
		"maintenance_post /maintenance/enter",
		"git merge --ff-only origin/main",
		"http://localhost:9000/servers/create",
		"for i in $(seq 1 90); do",
		"maintenance_post /maintenance/leave",
	)

	for name, workflow := range map[string]string{"deploy": deploy, "start": start, "recreate": recreate} {
		t.Run(name, func(t *testing.T) {
			legacy := strings.Index(workflow, "running deployer lacks a valid maintenance-v1 capability")
			marker := strings.Index(workflow, `: > "$STACK/servers/.deployer-maintenance"`)
			merge := strings.Index(workflow, "git merge --ff-only origin/main")
			if legacy < 0 || marker < 0 || merge < 0 || !(legacy < marker && marker < merge) {
				t.Fatalf("%s legacy/fresh ordering legacy=%d marker=%d merge=%d", name, legacy, marker, merge)
			}
			legacyBlock := workflow[legacy:marker]
			if !strings.Contains(legacyBlock, "exit 1") {
				t.Fatalf("%s legacy capability failure does not abort before fresh marker", name)
			}
		})
	}
}

func TestStartWorkflowRejectsOverlongAndMismatchedCanonicalServerEnvBeforeMutation(t *testing.T) {
	workflow := readFile(t, filepath.Join("..", ".github", "workflows", "start-server.yml"))
	for _, want := range []string{
		"server_id must be at most 48 ASCII alphanumeric characters",
		`INTERNAL_ID="s${PUBLIC_ID}"`,
		`ENV_FILE="servers/${INTERNAL_ID}.env"`,
		"SERVER_ID in $ENV_FILE must exactly match canonical public id $PUBLIC_ID",
		`ENV_SERVER_ID="$(sudo awk -F= '$1 == "SERVER_ID" && NF == 2 { print $2 }' "$ENV_FILE")"`,
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("start workflow missing %q", want)
		}
	}

	maxLength := strings.Index(workflow, "server_id must be at most 48 ASCII alphanumeric characters")
	canonicalEnv := strings.Index(workflow, `ENV_SERVER_ID="$(sudo awk -F= '$1 == "SERVER_ID" && NF == 2 { print $2 }' "$ENV_FILE")"`)
	imageMutation := strings.Index(workflow, `sudo sed -i "s/^IMAGE_TAG=.*`)
	compose := strings.Index(workflow, `sudo docker compose -p "$PROJECT"`)
	if maxLength < 0 || canonicalEnv < 0 || imageMutation < 0 || compose < 0 {
		t.Fatalf("missing start ordering markers: max=%d canonicalEnv=%d imageMutation=%d compose=%d", maxLength, canonicalEnv, imageMutation, compose)
	}
	if !(maxLength < canonicalEnv && canonicalEnv < imageMutation && imageMutation < compose) {
		t.Fatalf("start validation must precede mutation and compose: max=%d canonicalEnv=%d imageMutation=%d compose=%d", maxLength, canonicalEnv, imageMutation, compose)
	}
}

func TestStartWorkflowRejectsOverlongAndMismatchedEnvBeforeMutation(t *testing.T) {
	overlong := runStartWorkflow(t, strings.Repeat("a", 49), "v2", "", "")
	if overlong.err == nil {
		t.Fatalf("overlong start unexpectedly succeeded: %s", overlong.output)
	}
	if !strings.Contains(overlong.output, "server_id must be at most 48 ASCII alphanumeric characters") {
		t.Fatalf("overlong start output = %q", overlong.output)
	}
	if overlong.dockerCalls != "" {
		t.Fatalf("overlong start reached Docker: %q", overlong.dockerCalls)
	}

	const original = "SERVER_ID=other\nIMAGE_TAG=v1\n"
	mismatch := runStartWorkflow(t, "PEP", "v2", "spep", original)
	if mismatch.err == nil {
		t.Fatalf("mismatched env start unexpectedly succeeded: %s", mismatch.output)
	}
	if !strings.Contains(mismatch.output, "SERVER_ID in servers/spep.env must exactly match canonical public id pep") {
		t.Fatalf("mismatched env output = %q", mismatch.output)
	}
	if mismatch.dockerCalls != "" {
		t.Fatalf("mismatched env start reached Docker: %q", mismatch.dockerCalls)
	}
	if got := readFile(t, mismatch.envFile); got != original {
		t.Fatalf("mismatched env was mutated before validation:\n%s", got)
	}
}

func TestStartWorkflowPreservesPublicToInternalServerIDMapping(t *testing.T) {
	run := runStartWorkflow(t, "S1", "", "ss1", "SERVER_ID=s1\nIMAGE_TAG=v1\n")
	if run.err != nil {
		t.Fatalf("s1 start failed: %v output=%s", run.err, run.output)
	}
	if !strings.Contains(run.dockerCalls, "compose -p opensamguk-ss1") {
		t.Fatalf("s1 start Docker project mapping = %q", run.dockerCalls)
	}
	if got := readFile(t, run.envFile); !strings.Contains(got, "SERVER_ID=s1\n") || !strings.Contains(got, "IMAGE_TAG=v1\n") {
		t.Fatalf("s1 env mapping = %q", got)
	}
}

func TestCreateServerUsesConfiguredInternalUrls(t *testing.T) {
	cfg := testConfig(t)
	cfg.gameAPIInternalPort = "18080"
	cfg.gatewayAPIURL = "http://gateway-api:18081"
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"2","name":"호환 서버","gameApiPort":"8201","webGamePort":"3201"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}

	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "s2.env"))
	if !strings.Contains(serverEnv, "GAME_API_URL=http://s2-game-api:18080\n") {
		t.Fatalf("server env GAME_API_URL did not use override:\n%s", serverEnv)
	}
	if !strings.Contains(serverEnv, "GATEWAY_API_URL=http://gateway-api:18081\n") {
		t.Fatalf("server env GATEWAY_API_URL did not use override:\n%s", serverEnv)
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"2"`) || !strings.Contains(sharedEnv, `"gameApiUrl":"http://s2-game-api:18080"`) {
		t.Fatalf("registry GAME_API_URL did not use override:\n%s", sharedEnv)
	}
}

func TestCreateServerAllowsGenerationZeroForAlpha(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"0","name":"알파 서버","generation":"0","gameApiPort":"8100","webGamePort":"3100"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}

	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "s0.env"))
	if !strings.Contains(serverEnv, "SERVER_GENERATION=0\n") {
		t.Fatalf("server env did not carry generation zero:\n%s", serverEnv)
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"generation":0`) {
		t.Fatalf("registry did not carry generation zero:\n%s", sharedEnv)
	}
}

func TestServersGetReturnsRegistry(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"3","name":"테스트 서버","generation":4,"gameApiUrl":"http://s3-game-api:8081","gameEngineUrl":"http://s3-game-engine:8082","deployProject":"opensamguk-s3"}]
`)

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodGet, "/servers", "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", res.Code, res.Body.String())
	}
	var body []registryEntry
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body) != 1 || body[0].ID != "3" || body[0].Generation != 4 {
		t.Fatalf("registry response = %#v", body)
	}
}

func TestRegistryReadSanitizesLegacyEnvSecretsBeforePersistingOrResponding(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","env":{"IMAGE_TAG":"v1","RESET_SYNC":"1","JWT_SECRET":"jwt-should-never-return","ADMIN_PASSWORD":"password-should-never-return","API_TOKEN":"token-should-never-return","CUSTOM_VALUE":"custom-should-never-return"}}]
`)

	registry, err := cfg.readRegistry()
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if len(registry) != 1 || registry[0].Env["IMAGE_TAG"] != "v1" || registry[0].Env["RESET_SYNC"] != "1" {
		t.Fatalf("sanitized registry = %#v", registry)
	}
	for _, key := range []string{"JWT_SECRET", "ADMIN_PASSWORD", "API_TOKEN", "CUSTOM_VALUE"} {
		if _, found := registry[0].Env[key]; found {
			t.Fatalf("registry retained secret or arbitrary env key %q: %#v", key, registry[0].Env)
		}
	}
	persisted := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	for _, secret := range []string{"jwt-should-never-return", "password-should-never-return", "token-should-never-return", "custom-should-never-return"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("legacy registry secret remained persisted: %s", persisted)
		}
	}

	response := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodGet, "/servers", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET servers = %d body=%s", response.Code, response.Body.String())
	}
	for _, secret := range []string{"jwt-should-never-return", "password-should-never-return", "token-should-never-return", "custom-should-never-return"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("GET servers leaked legacy registry secret: %s", response.Body.String())
		}
	}
}

func TestRegistryRawTopLevelSecretsAndDuplicateAssignmentsAreRemovedOnGet(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","JWT_SECRET":"first-top-level-secret","env":{"IMAGE_TAG":"v1"}}]
SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","JWT_SECRET":"later-top-level-secret","ADMIN_PASSWORD":"later-password","env":{"IMAGE_TAG":"v2","API_TOKEN":"later-token"}}]
`)

	response := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodGet, "/servers", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET servers = %d body=%s", response.Code, response.Body.String())
	}
	for _, secret := range []string{"first-top-level-secret", "later-top-level-secret", "later-password", "later-token"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("GET servers leaked raw registry secret %q: %s", secret, response.Body.String())
		}
	}
	persisted := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if got := strings.Count(persisted, "SERVER_REGISTRY_JSON="); got != 1 {
		t.Fatalf("registry assignments = %d, want exactly one:\n%s", got, persisted)
	}
	for _, secret := range []string{"first-top-level-secret", "later-top-level-secret", "later-password", "later-token", `"JWT_SECRET"`, `"ADMIN_PASSWORD"`, `"API_TOKEN"`} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("raw registry secret or field remained persisted %q:\n%s", secret, persisted)
		}
	}
	if !strings.Contains(persisted, `"IMAGE_TAG":"v2"`) {
		t.Fatalf("canonical last registry assignment was not retained:\n%s", persisted)
	}
}

func TestRegistryMigrationSerializesWithSharedPatchWithoutLosingEitherUpdate(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `COOKIE_SECURE=false
SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","JWT_SECRET":"first-secret"}]
SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","JWT_SECRET":"later-secret","env":{"IMAGE_TAG":"v1"}}]
`)
	rewriteStarted := make(chan struct{})
	releaseRewrite := make(chan struct{})
	var rewriteOnce sync.Once
	cfg.registryRewriteHook = func() {
		rewriteOnce.Do(func() {
			close(rewriteStarted)
			<-releaseRewrite
		})
	}

	type result struct{ response *httptest.ResponseRecorder }
	getResult := make(chan result, 1)
	go func() {
		getResult <- result{response: envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodGet, "/servers", "")}
	}()
	select {
	case <-rewriteStarted:
	case <-time.After(time.Second):
		t.Fatal("registry migration did not reach its serialized rewrite")
	}
	patchResult := make(chan result, 1)
	go func() {
		patchResult <- result{response: envRequest(t, cfg.withAuth(cfg.handleSharedEnv), http.MethodPatch, "/env/shared", `{"values":{"COOKIE_SECURE":"true"}}`)}
	}()
	select {
	case patch := <-patchResult:
		t.Fatalf("shared PATCH bypassed registry rewrite lock: %d body=%s", patch.response.Code, patch.response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseRewrite)
	get := <-getResult
	if get.response.Code != http.StatusOK {
		t.Fatalf("GET servers = %d body=%s", get.response.Code, get.response.Body.String())
	}
	patch := <-patchResult
	if patch.response.Code != http.StatusOK {
		t.Fatalf("shared PATCH = %d body=%s", patch.response.Code, patch.response.Body.String())
	}
	persisted := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(persisted, "COOKIE_SECURE=true\n") || strings.Count(persisted, "SERVER_REGISTRY_JSON=") != 1 || strings.Contains(persisted, "first-secret") || strings.Contains(persisted, "later-secret") {
		t.Fatalf("serialized registry migration lost an update or secret:\n%s", persisted)
	}
}

func TestReadRegistryCanonicalizesPublicID(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"A1","name":"대소문자 서버","deployProject":"opensamguk-sA1"}]
`)

	registry, err := cfg.readRegistry()
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if len(registry) != 1 || registry[0].ID != "a1" || registry[0].DeployProject != "opensamguk-sa1" {
		t.Fatalf("canonical registry = %#v", registry)
	}
}

func TestReadRegistryRejectsAmbiguousLegacyInternalIDWithoutMutatingSource(t *testing.T) {
	cfg := testConfig(t)
	const registryLine = `SERVER_REGISTRY_JSON=[{"id":"spep","name":"레거시 추론 금지","deployProject":"opensamguk-spep"}]`
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), registryLine+"\n")

	if _, err := cfg.readRegistry(); err == nil || !strings.Contains(err.Error(), "one-time migration") {
		t.Fatalf("legacy registry error = %v", err)
	}
	if got := readFile(t, filepath.Join(cfg.composeDir, ".env")); got != registryLine+"\n" {
		t.Fatalf("legacy registry source mutated:\n%s", got)
	}
}

func TestReadRegistryRejectsInvalidEntryWithoutMutatingSource(t *testing.T) {
	cfg := testConfig(t)
	const registryLine = `SERVER_REGISTRY_JSON=[{"id":"a1","name":"정상"},{"id":"not-valid","name":"잘못됨"}]`
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), registryLine+"\n")

	if _, err := cfg.readRegistry(); err == nil {
		t.Fatal("read registry unexpectedly accepted invalid id")
	}
	if got := readFile(t, filepath.Join(cfg.composeDir, ".env")); got != registryLine+"\n" {
		t.Fatalf("read registry mutated invalid source:\n%s", got)
	}
}

func TestReadRegistryRejectsCanonicalIDCollision(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"A1","name":"대문자"},{"id":"a1","name":"소문자"}]
`)

	if _, err := cfg.readRegistry(); err == nil {
		t.Fatal("read registry unexpectedly accepted A1/a1 collision")
	}
}

func TestCreateServerRejectsPortCollisions(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nGAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		t.Fatalf("docker should not be called for a port collision: %#v", args)
		return "", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"1","name":"통일 서버","gameApiPort":"3101","webGamePort":"3201"}`)
	if res.Code != http.StatusConflict {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OK || !strings.Contains(body.Detail, "GAME_API_PORT") || !strings.Contains(body.Detail, "WEB_GAME_PORT") {
		t.Fatalf("collision response = %#v", body)
	}

	res = envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"2","name":"중복 서버","gameApiPort":"3301","webGamePort":"3301"}`)
	if res.Code != http.StatusConflict {
		t.Fatalf("same-request duplicate port status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestCreateServerRejectsSharedPortCollision(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\nGAME_API_PORT=18080\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		t.Fatalf("docker should not be called for a shared port collision: %#v", args)
		return "", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"1","name":"통일 서버","gameApiPort":"18080","webGamePort":"3201"}`)
	if res.Code != http.StatusConflict {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OK || !strings.Contains(body.Detail, "공유 스택") || !strings.Contains(body.Detail, "GAME_API_PORT") {
		t.Fatalf("shared collision response = %#v", body)
	}
}

func TestDeleteServerStopsStackRemovesEnvAndRegistry(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"},{"id":"keep","name":"빼섭","gameApiUrl":"http://skeep-game-api:8081","gameEngineUrl":"http://skeep-game-engine:8082","deployProject":"opensamguk-skeep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nGAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerClose), http.MethodPost, "/servers/close", `{"id":"PEP"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" || !lifecycleJobIDRe.MatchString(body.JobID) {
		t.Fatalf("delete response = %#v", body)
	}
	waitForCalls(t, calls.count, 3)
	waitForMissing(t, filepath.Join(cfg.serversDir, "spep.env"))
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "spep.env")); !os.IsNotExist(err) {
		t.Fatalf("server env still exists or unexpected error: %v", err)
	}
	waitForContentNotContaining(t, filepath.Join(cfg.composeDir, ".env"), `"id":"pep"`)
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if strings.Contains(sharedEnv, `"id":"pep"`) || !strings.Contains(sharedEnv, `"id":"keep"`) {
		t.Fatalf("registry not pruned correctly:\n%s", sharedEnv)
	}
	recorded := calls.snapshot()
	if len(recorded) != 3 {
		t.Fatalf("docker calls = %#v", recorded)
	}
	if !strings.Contains(recorded[0], "compose -p opensamguk-spep") || !strings.Contains(recorded[0], "down --volumes --remove-orphans") {
		t.Fatalf("delete compose call = %q", recorded[0])
	}
	if !strings.Contains(recorded[1], "gateway-api web-gateway") || strings.Contains(recorded[1], " nginx") {
		t.Fatalf("shared reload call = %q", recorded[1])
	}
	if !strings.Contains(recorded[2], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", recorded[2])
	}
}

func TestDeleteServerKeepsRegistryWhenDownFails(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nGAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "down failed\n", errors.New("compose down failed")
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodDelete, "/servers?id=PEP&confirm=DELETE%20pep", "")
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d body=%s", res.Code, res.Body.String())
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "spep.env")); err != nil {
		t.Fatalf("server env should remain on down failure: %v", err)
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"pep"`) {
		t.Fatalf("registry was pruned before down success:\n%s", sharedEnv)
	}
}

func TestResetServerRecreatesStackWithVolumes(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "ok\n", nil
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerReset),
		http.MethodPost,
		"/servers/reset",
		`{"id":"PEP","confirm":"RESET pep","generation":"2","scenarioCode":"scenario_1002","turnTerm":"30","sync":"1","fiction":"0","extend":"1","blockGeneralCreate":"2","npcMode":"2","showImgLevel":"3","autorunUserOptions":["develop","battle"],"autorunUserMinutes":"1440","joinMode":"onlyRandom","tournamentTrig":"1","reserveOpen":"2026-06-10 20:00","preReserveOpen":"2026-06-10 19:00"}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" || !lifecycleJobIDRe.MatchString(body.JobID) {
		t.Fatalf("reset response = %#v", body)
	}
	waitForCalls(t, calls.count, 4)
	recorded := calls.snapshot()
	if len(recorded) != 4 {
		t.Fatalf("docker calls = %#v", recorded)
	}
	if !strings.Contains(recorded[0], "down --volumes --remove-orphans") {
		t.Fatalf("reset down call = %q", recorded[0])
	}
	if !strings.Contains(recorded[1], "up -d") {
		t.Fatalf("reset up call = %q", recorded[1])
	}
	if !strings.Contains(recorded[2], "gateway-api web-gateway") || strings.Contains(recorded[2], " nginx") {
		t.Fatalf("shared reload call = %q", recorded[2])
	}
	if !strings.Contains(recorded[3], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", recorded[3])
	}
	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "spep.env"))
	for _, want := range []string{
		"SCENARIO_CODE=scenario_1002\n",
		"SCENARIO_SEED_ENABLED=true\n",
		"SERVER_GENERATION=2\n",
		"RESET_TURNTERM=30\n",
		"RESET_SYNC=1\n",
		"RESET_FICTION=0\n",
		"RESET_EXTEND=1\n",
		"RESET_BLOCK_GENERAL_CREATE=2\n",
		"RESET_NPCMODE=2\n",
		"RESET_SHOW_IMG_LEVEL=3\n",
		"RESET_AUTORUN_USER_OPTIONS=develop,battle\n",
		"RESET_AUTORUN_USER_MINUTES=1440\n",
		"RESET_JOIN_MODE=onlyRandom\n",
		"RESET_TOURNAMENT_TRIG=1\n",
		"RESET_RESERVE_OPEN=2026-06-10 20:00\n",
		"RESET_PRE_RESERVE_OPEN=2026-06-10 19:00\n",
	} {
		if !strings.Contains(serverEnv, want) {
			t.Fatalf("server env missing %q:\n%s", want, serverEnv)
		}
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"pep"`) ||
		!strings.Contains(sharedEnv, `"generation":2`) ||
		!strings.Contains(sharedEnv, `"scenarioCode":"scenario_1002"`) {
		t.Fatalf("registry generation/scenario was not updated:\n%s", sharedEnv)
	}
}

func TestResetServerAllowsGenerationZeroForAlpha(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "ok\n", nil
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerReset),
		http.MethodPost,
		"/servers/reset",
		`{"id":"pep","confirm":"RESET pep","generation":"0","scenarioCode":"scenario_1010"}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	waitForContent(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_GENERATION=0\n")
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"generation":0`) ||
		!strings.Contains(sharedEnv, `"scenarioCode":"scenario_1010"`) {
		t.Fatalf("registry generation/scenario was not updated to zero:\n%s", sharedEnv)
	}
}

func TestResetServerRetainsDesiredStateAndMarksRepairRequiredWhenDownFails(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	original := "SERVER_ID=pep\nSCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n"
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), original)
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		return "down failed\n", errors.New("compose down failed")
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerReset),
		http.MethodPost,
		"/servers/reset?id=pep",
		`{"confirm":"RESET pep","scenarioCode":"scenario_1002","turnTerm":"30"}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var resetBody createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&resetBody); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, resetBody.JobID, lifecycleJobFailed); completed.Status != lifecycleJobFailed {
		t.Fatalf("failed reset lifecycle result = %#v", completed)
	}
	waitForCalls(t, calls.count, 2)
	recorded := calls.snapshot()
	if len(recorded) != 2 || !strings.Contains(recorded[0], "down --volumes --remove-orphans") || !strings.Contains(recorded[1], " up -d") {
		t.Fatalf("reset should attempt one forward up after failed down, calls=%#v", recorded)
	}
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); !strings.Contains(got, "SCENARIO_CODE=scenario_1002\n") || !strings.Contains(got, "RESET_TURNTERM=30\n") || strings.Contains(got, "SCENARIO_CODE=scenario_1010\n") {
		t.Fatalf("failed reset did not retain new desired env after irreversible down:\n%s", got)
	}
	if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); !strings.Contains(shared, `"scenarioCode":"scenario_1002"`) || !strings.Contains(shared, `"repairRequired":true`) {
		t.Fatalf("failed reset did not retain and mark repair-required registry state:\n%s", shared)
	}
}

func TestResetServerAttemptsOneForwardUpAfterDownErrorWithoutRepairMarker(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nSCENARIO_CODE=scenario_1010\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		if strings.Contains(strings.Join(args, " "), "down --volumes --remove-orphans") {
			return "down returned an error\n", errors.New("compose down uncertain")
		}
		return "recovered\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_1002"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var resetBody createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&resetBody); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, resetBody.JobID, lifecycleJobFailed); completed.Status != lifecycleJobFailed {
		t.Fatalf("down-error reset completion = %#v", completed)
	}
	recorded := calls.snapshot()
	if len(recorded) != 2 || !strings.Contains(recorded[0], "down --volumes --remove-orphans") || !strings.Contains(recorded[1], " up -d") {
		t.Fatalf("down-error recovery calls = %#v", recorded)
	}
	if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); strings.Contains(shared, `"repairRequired":true`) {
		t.Fatalf("successful down-error recovery retained repair-required marker:\n%s", shared)
	}
	if _, err := os.Stat(cfg.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("successful down-error recovery retained journal: %v", err)
	}
}

func TestResetServerForwardRecoversAfterDownCancellation(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nSCENARIO_CODE=scenario_1010\n")
	calls := &dockerCallRecorder{}
	downStarted := make(chan struct{})
	var downStartedOnce sync.Once
	cfg.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		calls.record(args...)
		if strings.Contains(strings.Join(args, " "), "down --volumes --remove-orphans") {
			downStartedOnce.Do(func() { close(downStarted) })
			<-ctx.Done()
			return "down cancelled\n", ctx.Err()
		}
		return "forward recovered\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_1002"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var resetBody createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&resetBody); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	select {
	case <-downStarted:
	case <-time.After(time.Second):
		t.Fatal("reset never reached the destructive down call")
	}
	maintenanceDone := make(chan error, 1)
	go func() {
		_, _, err := cfg.operations.enterMaintenance()
		maintenanceDone <- err
	}()
	select {
	case err := <-maintenanceDone:
		if err != nil {
			t.Fatalf("maintenance cancellation failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("maintenance did not wait for bounded forward recovery")
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, resetBody.JobID, lifecycleJobCancelled); completed.Status != lifecycleJobCancelled {
		t.Fatalf("cancelled reset lifecycle result = %#v", completed)
	}
	recorded := calls.snapshot()
	if len(recorded) != 2 || !strings.Contains(recorded[0], "down --volumes --remove-orphans") || !strings.Contains(recorded[1], " up -d") {
		t.Fatalf("cancelled down must still perform one forward recovery: %#v", recorded)
	}
	if _, err := os.Stat(cfg.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("successful cancelled-down recovery retained journal: %v", err)
	}
}

func TestResetServerRetriesForwardRecoveryAfterFirstUpFailure(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nSCENARIO_CODE=scenario_1010\n")
	calls := &dockerCallRecorder{}
	serverUpAttempts := 0
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls.record(args...)
		call := strings.Join(args, " ")
		if strings.Contains(call, "compose -p opensamguk-spep") && strings.Contains(call, " up -d") {
			serverUpAttempts++
			if serverUpAttempts == 1 {
				return "first up failed\n", errors.New("compose up failed")
			}
		}
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_1002"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var resetBody createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&resetBody); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, resetBody.JobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("forward recovery completion = %#v", completed)
	}
	if serverUpAttempts != 2 {
		t.Fatalf("server up attempts = %d, want 2; calls=%#v", serverUpAttempts, calls.snapshot())
	}
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); !strings.Contains(got, "SCENARIO_CODE=scenario_1002\n") {
		t.Fatalf("forward recovery did not retain new desired env:\n%s", got)
	}
	if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); strings.Contains(shared, `"repairRequired":true`) {
		t.Fatalf("successful forward recovery retained repair-required marker:\n%s", shared)
	}
}

func TestConcurrentServerPatchThenResetFailurePreservesPatchSnapshot(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"before","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep","env":{"IMAGE_TAG":"v1","SERVER_NAME":"before","SERVER_GENERATION":"1","GAME_API_URL":"http://spep-game-api:8081"}}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_ID=pep\nIMAGE_TAG=v1\nSERVER_NAME=before\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\nSCENARIO_CODE=scenario_1010\n")
	patchReloadStarted := make(chan struct{})
	releasePatchReload := make(chan struct{})
	var patchReloadOnce sync.Once
	cfg.dockerRunner = func(args ...string) (string, error) {
		call := strings.Join(args, " ")
		if strings.Contains(call, "gateway-api web-gateway") {
			patchReloadOnce.Do(func() {
				close(patchReloadStarted)
				<-releasePatchReload
			})
			return "reload complete\n", nil
		}
		if strings.Contains(call, "down --volumes --remove-orphans") {
			return "down failed\n", errors.New("compose down failed")
		}
		return "ok\n", nil
	}
	defer func() {
		select {
		case <-releasePatchReload:
		default:
			close(releasePatchReload)
		}
	}()

	patch := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=pep", `{"values":{"SERVER_NAME":"patched"}}`)
	if patch.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%s", patch.Code, patch.Body.String())
	}
	patchJobID := decodeEnvResponse(t, patch).JobID
	if !lifecycleJobIDRe.MatchString(patchJobID) {
		t.Fatalf("PATCH job id = %q", patchJobID)
	}
	select {
	case <-patchReloadStarted:
	case <-time.After(time.Second):
		t.Fatal("PATCH did not hold the coordinator through registry reload")
	}

	type resetResult struct {
		response *httptest.ResponseRecorder
	}
	resetResultCh := make(chan resetResult, 1)
	go func() {
		resetResultCh <- resetResult{response: envRequest(t, cfg.withAuth(cfg.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_1002"}`)}
	}()
	select {
	case result := <-resetResultCh:
		t.Fatalf("reset bypassed PATCH-held coordinator lease: status=%d body=%s", result.response.Code, result.response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	close(releasePatchReload)
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, patchJobID, lifecycleJobSucceeded); completed.Status != lifecycleJobSucceeded {
		t.Fatalf("PATCH completion = %#v", completed)
	}
	var resetResponse *httptest.ResponseRecorder
	select {
	case result := <-resetResultCh:
		resetResponse = result.response
	case <-time.After(time.Second):
		t.Fatal("reset did not begin after PATCH released the coordinator lease")
	}
	if resetResponse.Code != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resetResponse.Code, resetResponse.Body.String())
	}
	var resetBody createServerResponse
	if err := json.NewDecoder(resetResponse.Body).Decode(&resetBody); err != nil {
		t.Fatalf("decode reset response: %v", err)
	}
	if completed := waitForLifecycleJob(t, cfg.lifecycleJobs, resetBody.JobID, lifecycleJobFailed); completed.Status != lifecycleJobFailed {
		t.Fatalf("reset completion = %#v", completed)
	}
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); !strings.Contains(got, "SERVER_NAME=patched\n") || !strings.Contains(got, "SCENARIO_CODE=scenario_1002\n") {
		t.Fatalf("failed reset did not retain patched new desired env:\n%s", got)
	}
	if shared := readFile(t, filepath.Join(cfg.composeDir, ".env")); !strings.Contains(shared, `"name":"patched"`) || !strings.Contains(shared, `"scenarioCode":"scenario_1002"`) || strings.Contains(shared, `"repairRequired":true`) {
		t.Fatalf("forward-recovered reset did not retain the patched registry state:\n%s", shared)
	}
}

func TestStatelessServicesExcludeGameEngine(t *testing.T) {
	joined := strings.Join(statelessServices, ",")
	if strings.Contains(joined, "game-engine") {
		t.Fatalf("stateless services must not include game-engine: %s", joined)
	}
}

type dockerCallRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *dockerCallRecorder) record(args ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(args, " "))
}

func (r *dockerCallRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *dockerCallRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func testConfig(t *testing.T) config {
	t.Helper()
	root := t.TempDir()
	serversDir := filepath.Join(root, "servers")
	if err := os.MkdirAll(serversDir, 0o755); err != nil {
		t.Fatal(err)
	}
	jobs := newLifecycleJobManager()
	maintenanceFile := filepath.Join(serversDir, ".deployer-maintenance")
	lifecycleJournalFile := filepath.Join(serversDir, ".deployer-lifecycle-journal")
	return config{
		token:                "test-token",
		composeDir:           root,
		serversDir:           serversDir,
		composeServer:        filepath.Join(root, "docker-compose.server.yml"),
		composeShared:        filepath.Join(root, "docker-compose.shared.yml"),
		ghcrOwner:            "owner",
		ghcrAPIBaseURL:       "https://api.github.com",
		lifecycleJobs:        jobs,
		maintenanceFile:      maintenanceFile,
		lifecycleJournalFile: lifecycleJournalFile,
		sharedEnvMu:          &sync.Mutex{},
		operations:           newOperationCoordinator(maintenanceFile, lifecycleJournalFile, jobs),
	}
}

func envRequest(t *testing.T, handler http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler(res, req)
	return res
}

func loopbackRequest(t *testing.T, handler http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:31000"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler(res, req)
	return res
}

func decodeMaintenanceResponse(t *testing.T, response *httptest.ResponseRecorder) maintenanceResponse {
	t.Helper()
	var body maintenanceResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode maintenance response: %v body=%s", err, response.Body.String())
	}
	if body.Capability != "maintenance-v1" {
		t.Fatalf("maintenance capability = %#v", body)
	}
	return body
}

func waitForOperationJobID(t *testing.T, manager *lifecycleJobManager, operationID string) string {
	t.Helper()
	for i := 0; i < 200; i++ {
		manager.mu.Lock()
		id := manager.operationJobs[operationID]
		manager.mu.Unlock()
		if id != "" {
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("operation %q did not reserve a lifecycle job", operationID)
	return ""
}

func waitForAnyTerminalLifecycleJob(t *testing.T, manager *lifecycleJobManager, id string) lifecycleJobResponse {
	t.Helper()
	for i := 0; i < 200; i++ {
		if job, exists := manager.lookup(id); exists && isTerminalLifecycleJob(job.Status) {
			return job
		}
		time.Sleep(5 * time.Millisecond)
	}
	job, exists := manager.lookup(id)
	t.Fatalf("lifecycle job id=%s status=%q exists=%t did not become terminal", id, job.Status, exists)
	return lifecycleJobResponse{}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func lifecycleJobLookup(t *testing.T, cfg config, id string) lifecycleJobResponse {
	t.Helper()
	res := envRequest(t, cfg.withAuth(cfg.handleLifecycleJob), http.MethodGet, "/jobs/"+id, "")
	if res.Code != http.StatusOK {
		t.Fatalf("job lookup status = %d body=%s", res.Code, res.Body.String())
	}
	var job lifecycleJobResponse
	if err := json.NewDecoder(res.Body).Decode(&job); err != nil {
		t.Fatalf("decode job lookup: %v", err)
	}
	return job
}

func waitForLifecycleJob(t *testing.T, manager *lifecycleJobManager, id string, want lifecycleJobStatus) lifecycleJobResponse {
	t.Helper()
	for i := 0; i < 200; i++ {
		if job, exists := manager.lookup(id); exists && job.Status == want {
			return job
		}
		time.Sleep(5 * time.Millisecond)
	}
	job, exists := manager.lookup(id)
	t.Fatalf("lifecycle job id=%s status=%q exists=%t, want %q", id, job.Status, exists, want)
	return lifecycleJobResponse{}
}

func decodeEnvResponse(t *testing.T, res *httptest.ResponseRecorder) envResponse {
	t.Helper()
	var body envResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, res.Body.String())
	}
	return body
}

func fieldValue(t *testing.T, fields map[string]envField, key string) string {
	t.Helper()
	field, ok := fields[key]
	if !ok {
		t.Fatalf("missing field %s", key)
	}
	if field.Value == nil {
		t.Fatalf("field %s value is nil", key)
	}
	return *field.Value
}

func writeEnv(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

type startWorkflowRun struct {
	output      string
	err         error
	dockerCalls string
	envFile     string
}

func commandEnvironment(values ...string) []string {
	keys := map[string]struct{}{}
	for _, value := range values {
		if index := strings.IndexByte(value, '='); index > 0 {
			keys[value[:index]] = struct{}{}
		}
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, value := range os.Environ() {
		if index := strings.IndexByte(value, '='); index > 0 {
			if _, replaced := keys[value[:index]]; replaced {
				continue
			}
		}
		environment = append(environment, value)
	}
	return append(environment, values...)
}

func runStartWorkflow(t *testing.T, serverID, imageTag, envFileName, envContent string) startWorkflowRun {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	stack := filepath.Join(home, "opensamguk-docker")
	servers := filepath.Join(stack, "servers")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(servers, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, filepath.Join(stack, ".env"), "DEPLOYER_TOKEN=test-token\n")
	envFile := ""
	if envFileName != "" {
		envFile = filepath.Join(servers, envFileName+".env")
		writeEnv(t, envFile, envContent)
	}

	dockerLog := filepath.Join(root, "docker.calls")
	writeExecutable(t, filepath.Join(bin, "flock"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "git"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "sudo"), "#!/usr/bin/env bash\nexec \"$@\"\n")
	writeExecutable(t, filepath.Join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "docker"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$WORKFLOW_DOCKER_LOG\"\nif [[ \"${1:-}\" == \"exec\" ]]; then\n  if [[ \"$*\" == *\"/maintenance/leave\"* ]]; then\n    printf '{\\\"capability\\\":\\\"maintenance-v1\\\",\\\"state\\\":\\\"open\\\"}\\n'\n  else\n    printf '{\\\"capability\\\":\\\"maintenance-v1\\\",\\\"state\\\":\\\"drained\\\"}\\n'\n  fi\n  exit 0\nfi\nif [[ \"${1:-}\" == \"ps\" ]]; then\n  printf '%s\\n' ss1-game-api ss1-game-engine ss1-web-game\nfi\n")
	writeExecutable(t, filepath.Join(bin, "curl"), "#!/usr/bin/env bash\nurl=\"${!#}\"\nif [[ \"$url\" == *\"/health\" ]]; then\n  printf '{\"status\":\"up\"}\\n'\nfi\n")

	script := workflowRunScript(t, filepath.Join("..", ".github", "workflows", "start-server.yml"))
	scriptPath := filepath.Join(root, "start-server.sh")
	writeExecutable(t, scriptPath, script)
	cmd := exec.Command("bash", scriptPath)
	cmd.Env = commandEnvironment(
		"HOME="+home,
		"PATH="+bin+":"+os.Getenv("PATH"),
		"SERVER_ID="+serverID,
		"IMAGE_TAG="+imageTag,
		"WORKFLOW_DOCKER_LOG="+dockerLog,
	)
	out, err := cmd.CombinedOutput()
	dockerCalls, readErr := os.ReadFile(dockerLog)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return startWorkflowRun{
		output:      string(out),
		err:         err,
		dockerCalls: string(dockerCalls),
		envFile:     envFile,
	}
}

func runRecreateWorkflowWithLostJob(t *testing.T) startWorkflowRun {
	return runRecreateWorkflowWithScenario(t, false)
}

func runRecreateWorkflowWithCreateTimeout(t *testing.T) startWorkflowRun {
	return runRecreateWorkflowWithScenario(t, true)
}

func runRecreateWorkflowWithScenario(t *testing.T, stallCreate bool) startWorkflowRun {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	stack := filepath.Join(home, "opensamguk-docker")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(filepath.Join(stack, "servers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, filepath.Join(stack, ".env"), "DEPLOYER_TOKEN=test-token\n")
	dockerLog := filepath.Join(root, "docker.calls")
	writeExecutable(t, filepath.Join(bin, "flock"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "git"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "sudo"), "#!/usr/bin/env bash\nexec \"$@\"\n")
	writeExecutable(t, filepath.Join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "timeout"), "#!/usr/bin/env bash\nset -euo pipefail\nargs=\"$*\"\nif [[ \"${WORKFLOW_TIMEOUT_STALL_CREATE:-false}\" == true && \"$args\" == *\"/servers/create\"* ]]; then\n  exit 124\nfi\nif [[ \"${1:-}\" == \"--foreground\" ]]; then\n  shift\nfi\nif [[ \"${1:-}\" == \"-k\" ]]; then\n  shift 2\nfi\nshift\nexec \"$@\"\n")
	writeExecutable(t, filepath.Join(bin, "python3"), "#!/usr/bin/env bash\nargs=\"$*\"\nif [[ \"$args\" == *\"state\\\"] + \\\":\\\"\"* ]]; then\n  printf 'drained:0123456789abcdef0123456789abcdef\\n'\nelif [[ \"$args\" == *\"payload.get(\\\"jobId\\\")\"* ]]; then\n  printf 'abcdef0123456789abcdef0123456789\\n'\nelif [[ \"$args\" == *\"import secrets\"* ]]; then\n  printf 'abcdef0123456789abcdef0123456789\\n'\nelif [[ \"$args\" == *\"json.dumps\"* ]]; then\n  printf '{}\\n'\nelse\n  printf 'drained\\n'\nfi\n")
	dockerScript := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "exec" ]]; then
  args="$*"
  if [[ "$args" == *"/maintenance/enter"* ]]; then
    printf '{"capability":"maintenance-v1","state":"drained","lease":"0123456789abcdef0123456789abcdef"}\n'
    exit 0
  fi
  if [[ "$args" == *"/maintenance/leave"* ]]; then
    printf 'leave\n' >> "$WORKFLOW_DOCKER_LOG"
    printf '{"capability":"maintenance-v1","state":"open"}\n'
    exit 0
  fi
  if [[ "$args" == *"/maintenance"* ]]; then
    printf '{"capability":"maintenance-v1","state":"drained"}\n'
    exit 0
  fi
  if [[ "$args" == *"/servers/create"* ]]; then
    printf '{"jobId":"abcdef0123456789abcdef0123456789"}\n'
    exit 0
  fi
  if [[ "$args" == *"/jobs/"* ]]; then
    exit 8
  fi
fi
if [[ "$1" == "ps" ]]; then
  printf '%s\n' opensamguk-deployer
fi
`
	writeExecutable(t, filepath.Join(bin, "docker"), dockerScript)

	script := workflowRunScript(t, filepath.Join("..", ".github", "workflows", "recreate-server.yml"))
	scriptPath := filepath.Join(root, "recreate-server.sh")
	writeExecutable(t, scriptPath, script)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", scriptPath)
	cmd.Env = commandEnvironment(
		"HOME="+home,
		"PATH="+bin+":"+os.Getenv("PATH"),
		"SERVER_ID=pep",
		"SERVER_NAME=테스트",
		"GENERATION=0",
		"IMAGE_TAG=",
		"SCENARIO_CODE=scenario_1010",
		"GAME_API_PORT=8101",
		"WEB_GAME_PORT=3101",
		"WORKFLOW_DOCKER_LOG="+dockerLog,
		"WORKFLOW_TIMEOUT_STALL_CREATE="+strconv.FormatBool(stallCreate),
	)
	output, err := cmd.CombinedOutput()
	dockerCalls, readErr := os.ReadFile(dockerLog)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("lost-job recreate workflow exceeded its bounded abort deadline: %s calls=%s", output, dockerCalls)
	}
	return startWorkflowRun{
		output:      string(output),
		err:         err,
		dockerCalls: string(dockerCalls),
	}
}

func workflowRunScript(t *testing.T, path string) string {
	t.Helper()
	lines := strings.Split(readFile(t, path), "\n")
	const marker = "        run: |"
	collecting := false
	var script []string
	for _, line := range lines {
		if !collecting {
			if line == marker {
				collecting = true
			}
			continue
		}
		if line == "" {
			script = append(script, "")
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			break
		}
		script = append(script, strings.TrimPrefix(line, "          "))
	}
	if len(script) == 0 {
		t.Fatalf("workflow %s has no run script", path)
	}
	return strings.Join(script, "\n") + "\n"
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func waitForCalls(t *testing.T, callCount func() int, want int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if callCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForContent(t *testing.T, path, want string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if data, err := os.ReadFile(path); err == nil && string(data) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForMissing(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForContentNotContaining(t *testing.T, path, needle string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if data, err := os.ReadFile(path); err == nil && !strings.Contains(string(data), needle) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
