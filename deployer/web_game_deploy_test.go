package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func webDeployFixture(t *testing.T) (config, webGameDeployRequest, string, string) {
	t.Helper()
	cfg := testConfig(t)
	file := filepath.Join(cfg.serversDir, "spep.env")
	original := "# preserve\nSERVER_ID=pep\nIMAGE_TAG=old-api\nWEB_GAME_TAG=old-web\nOPENSAMGUK_WORLD_ID=1\nSERVER_GENERATION=1\nSCENARIO_DIR=/data/scenarios\nTOPDOWN_MAP_ROOT=/app/data/map/topdown\nTOPDOWN_BAKE_ID=synthetic-unused\nUNRELATED=synthetic\n"
	writeEnv(t, file, original)
	registry := `SERVER_REGISTRY_JSON=[{"id":"pep","name":"fixture","generation":1,"gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep","env":{"UNKNOWN_FIXTURE":"synthetic"}}]` + "\n"
	writeEnv(t, cfg.sharedEnvFile(), registry)
	cfg.registryRewriteHook = func() { t.Fatal("web deployment reached registry rewrite") }
	req := webGameDeployRequest{Project: "opensamguk-spep", webGameDeployTarget: webGameDeployTarget{
		Tag: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64), ExpectedWebGameTag: "old-web", ExpectedWorldID: 1, ExpectedGeneration: 1,
	}}
	return cfg, req, original, registry
}

func webDeployJSON(t *testing.T, req webGameDeployRequest) string {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func webDeployRunner(calls *dockerCallRecorder, pin string) func(...string) (string, error) {
	return func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if len(args) > 0 && args[0] == "inspect" {
			return "ghcr.io/peppone-choi/opensamguk:web-game-" + pin + "\n", nil
		}
		return "ok\n", nil
	}
}

func TestWebGameDeployPersistsOnlyWebDigestAndVerifiesOneContainer(t *testing.T) {
	cfg, req, original, registry := webDeployFixture(t)
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = webDeployRunner(calls, req.pin())
	response := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	want := strings.Replace(original, "WEB_GAME_TAG=old-web", "WEB_GAME_TAG="+req.pin(), 1)
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); got != want {
		t.Fatalf("unrelated env changed: %q", got)
	}
	if readFile(t, cfg.sharedEnvFile()) != registry {
		t.Fatal("shared registry changed")
	}
	got := calls.snapshot()
	if len(got) != 3 || !strings.HasSuffix(got[0], "pull web-game") ||
		!strings.HasSuffix(got[1], "up -d --force-recreate --no-deps --no-build --pull never web-game") ||
		got[2] != "inspect spep-web-game --format {{.Config.Image}}" {
		t.Fatalf("scope=%#v", got)
	}
	for _, call := range got {
		if strings.Contains(call, "game-api") || strings.Contains(call, "game-engine") {
			t.Fatalf("expanded scope: %q", call)
		}
	}
	if _, err := os.Stat(cfg.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("journal remains: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(cfg.serversDir, ".web-deploy-*.env")); len(matches) != 0 {
		t.Fatalf("temporary env remains: %v", matches)
	}
}

func TestWebGameDeployRejectsUnknownFieldsPinsWorldAndRegistryBeforePull(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		change func(*webGameDeployRequest)
		extra  string
	}{
		{"mutable tag", func(r *webGameDeployRequest) { r.Tag = "latest" }, ""},
		{"invalid digest", func(r *webGameDeployRequest) { r.Digest = "sha256:bad" }, ""},
		{"missing expected pin", func(r *webGameDeployRequest) { r.ExpectedWebGameTag = "" }, ""},
		{"wrong pin", func(r *webGameDeployRequest) { r.ExpectedWebGameTag = "other" }, ""},
		{"wrong world", func(r *webGameDeployRequest) { r.ExpectedWorldID = 2 }, ""},
		{"wrong generation", func(r *webGameDeployRequest) { r.ExpectedGeneration = 2 }, ""},
		{"unknown project", func(r *webGameDeployRequest) { r.Project = "opensamguk-sother" }, ""},
		{"service injection", func(r *webGameDeployRequest) {}, `,"service":"game-api"`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, req, original, registry := webDeployFixture(t)
			testCase.change(&req)
			calls := &dockerCallRecorder{}
			cfg.dockerRunner = webDeployRunner(calls, req.pin())
			body := webDeployJSON(t, req)
			if testCase.extra != "" {
				body = strings.TrimSuffix(body, "}") + testCase.extra + "}"
			}
			res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", body)
			if res.Code != http.StatusBadRequest && res.Code != http.StatusConflict {
				t.Fatalf("status=%d", res.Code)
			}
			if len(calls.snapshot()) != 0 || readFile(t, filepath.Join(cfg.serversDir, "spep.env")) != original || readFile(t, cfg.sharedEnvFile()) != registry {
				t.Fatal("rejected request mutated or pulled")
			}
		})
	}
	cfg, req, original, _ := webDeployFixture(t)
	writeEnv(t, cfg.sharedEnvFile(), "SERVER_REGISTRY_JSON=[]\n")
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = webDeployRunner(calls, req.pin())
	res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
	if res.Code != http.StatusConflict || len(calls.snapshot()) != 0 || readFile(t, filepath.Join(cfg.serversDir, "spep.env")) != original {
		t.Fatal("unregistered target was deployed")
	}
}

func TestWebGameDeployPreservesAuthenticationLoopbackAndMaintenanceAdmission(t *testing.T) {
	cfg, req, original, _ := webDeployFixture(t)
	cfg.dockerRunner = func(...string) (string, error) { t.Fatal("unauthorized call reached Docker"); return "", nil }
	handler := cfg.webGameDeployHTTPHandler()
	unauthorized := httptest.NewRequest(http.MethodPost, "/deploy/web-game", strings.NewReader(webDeployJSON(t, req)))
	unauthorized.RemoteAddr = "127.0.0.1:31000"
	unauthorized.Header.Set("Authorization", "Bearer invalid-synthetic-token")
	denied := httptest.NewRecorder()
	handler(denied, unauthorized)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth=%d", denied.Code)
	}
	if got := envRequest(t, handler, http.MethodPost, "/deploy/web-game", webDeployJSON(t, req)); got.Code != http.StatusForbidden {
		t.Fatalf("non-loopback=%d", got.Code)
	}
	if _, _, err := cfg.operations.enterMaintenance(); err != nil {
		t.Fatal(err)
	}
	cfg.dockerRunner = func(...string) (string, error) { return "29.0.0\n", nil }
	if got := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed maintenance=%d", got.Code)
	}
	if readFile(t, filepath.Join(cfg.serversDir, "spep.env")) != original {
		t.Fatal("closed barrier changed pin")
	}
	if !isAuthenticatedHTTPRouteAllowed(http.MethodPost, "/deploy/web-game") || isAuthenticatedHTTPRouteAllowed(http.MethodPost, "/deploy") {
		t.Fatal("CLI route selector expanded to legacy deploy")
	}
}

func TestWebGameDeployPullFailureLeavesDesiredPinAndJournalUntouched(t *testing.T) {
	cfg, req, original, _ := webDeployFixture(t)
	cfg.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		return "SYNTHETIC_PRIVATE_SENTINEL", errors.New("pull failed")
	}
	res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
	if res.Code != http.StatusInternalServerError || strings.Contains(res.Body.String(), "SYNTHETIC_PRIVATE_SENTINEL") {
		t.Fatal("unsafe failure")
	}
	if readFile(t, filepath.Join(cfg.serversDir, "spep.env")) != original {
		t.Fatal("failed pull changed desired pin")
	}
	if _, err := os.Stat(cfg.lifecycleJournalFile); !os.IsNotExist(err) {
		t.Fatalf("pull failure wrote journal: %v", err)
	}
}

func TestWebGameDeployFailureRepairsOnlyTheApprovedWebPin(t *testing.T) {
	cfg, req, _, registry := webDeployFixture(t)
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if strings.Contains(strings.Join(args, " "), "up -d") {
			return "", errors.New("injected recreate failure")
		}
		return "ok\n", nil
	}
	res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", res.Code)
	}
	journal, exists, err := cfg.readLifecycleJournal()
	if err != nil || !exists || journal.Operation != "deploy-web" || journal.WebGameTarget == nil {
		t.Fatalf("journal=%#v exists=%v err=%v", journal, exists, err)
	}
	if lease, err := cfg.beginMutation(""); !errors.Is(err, errMaintenanceClosed) || lease != nil {
		t.Fatal("pending failure did not close admission")
	}
	cfg.dockerRunner = webDeployRunner(calls, req.pin())
	if err := cfg.repairLifecycleJournal(); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls.snapshot() {
		if strings.Contains(call, "game-api") || strings.Contains(call, "game-engine") {
			t.Fatalf("repair scope expanded: %q", call)
		}
	}
	if readFile(t, cfg.sharedEnvFile()) != registry {
		t.Fatal("repair changed registry")
	}
}

func TestWebGameDeployPreparedCrashDoesNotRecreateAndRejectsUnexpectedDesiredPin(t *testing.T) {
	cfg, req, original, _ := webDeployFixture(t)
	target, err := cfg.serverTargetForProject(req.Project)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeLifecycleJournalWithResetTarget("deploy-web", target, nil, "", "", &req.webGameDeployTarget); err != nil {
		t.Fatal(err)
	}
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = webDeployRunner(calls, "old-web")
	if err := cfg.repairLifecycleJournal(); err != nil {
		t.Fatal(err)
	}
	if len(calls.snapshot()) != 1 || !strings.HasPrefix(calls.snapshot()[0], "inspect ") || readFile(t, target.EnvFile) != original {
		t.Fatal("pre-write crash mutated web")
	}
	if err := cfg.writeLifecycleJournalWithResetTarget("deploy-web", target, nil, "", "", &req.webGameDeployTarget); err != nil {
		t.Fatal(err)
	}
	writeEnv(t, target.EnvFile, strings.Replace(original, "WEB_GAME_TAG=old-web", "WEB_GAME_TAG=unexpected", 1))
	calls = &dockerCallRecorder{}
	cfg.dockerRunner = webDeployRunner(calls, "unexpected")
	if err := cfg.repairLifecycleJournal(); err == nil || len(calls.snapshot()) != 0 {
		t.Fatal("repair silently accepted unapproved pin")
	}
}

func TestConcurrentWebDeploysSerializeAndRejectTheStaleExpectedPin(t *testing.T) {
	cfg, req, _, _ := webDeployFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	cfg.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		if strings.HasSuffix(strings.Join(args, " "), "pull web-game") {
			once.Do(func() { close(started); <-release })
		}
		if args[0] == "inspect" {
			return "ghcr.io/peppone-choi/opensamguk:web-game-" + req.pin() + "\n", nil
		}
		return "ok\n", nil
	}
	handler := cfg.webGameDeployHTTPHandler()
	done := make(chan int, 2)
	go func() {
		done <- loopbackRequest(t, handler, http.MethodPost, "/deploy/web-game", webDeployJSON(t, req)).Code
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first deployment did not reach pull")
	}
	second := req
	second.Tag = strings.Repeat("c", 40)
	go func() {
		done <- loopbackRequest(t, handler, http.MethodPost, "/deploy/web-game", webDeployJSON(t, second)).Code
	}()
	close(release)
	statuses := map[int]int{}
	for i := 0; i < 2; i++ {
		select {
		case status := <-done:
			statuses[status]++
		case <-time.After(2 * time.Second):
			t.Fatal("serialized requests did not finish")
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestWebGameDeployRejectsDuplicateScopedConfiguration(t *testing.T) {
	for _, duplicate := range []string{"WEB_GAME_TAG=old-web", "IMAGE_TAG=old-api", "OPENSAMGUK_WORLD_ID=1", "SERVER_GENERATION=1"} {
		t.Run(strings.Split(duplicate, "=")[0], func(t *testing.T) {
			cfg, req, original, _ := webDeployFixture(t)
			file := filepath.Join(cfg.serversDir, "spep.env")
			original += duplicate + "\n"
			writeEnv(t, file, original)
			calls := &dockerCallRecorder{}
			cfg.dockerRunner = webDeployRunner(calls, req.pin())
			res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
			if res.Code != http.StatusConflict || len(calls.snapshot()) != 0 || readFile(t, file) != original {
				t.Fatal("ambiguous scoped configuration was used")
			}
		})
	}
}

func TestWebGameDeployWrongRunningImageRetainsRecoveryJournal(t *testing.T) {
	cfg, req, _, _ := webDeployFixture(t)
	calls := &dockerCallRecorder{}
	cfg.dockerRunner = webDeployRunner(calls, "wrong-image")
	res := loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req))
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("wrong running image status=%d", res.Code)
	}
	journal, exists, err := cfg.readLifecycleJournal()
	if err != nil || !exists || journal.Operation != "deploy-web" {
		t.Fatalf("wrong image did not retain recovery: exists=%v err=%v", exists, err)
	}
}

func TestWebGameDeploySerializesBehindLegacyDeployAndRejectsChangedPin(t *testing.T) {
	cfg, req, _, _ := webDeployFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	calls := &dockerCallRecorder{}
	cfg.dockerRunnerContext = func(ctx context.Context, args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if strings.HasSuffix(strings.Join(args, " "), "pull game-api web-game") {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "ok\n", nil
	}
	legacyDone := make(chan int, 1)
	go func() {
		legacyDone <- loopbackRequest(t, cfg.withAuth(cfg.handleDeploy), http.MethodPost, "/deploy", `{"project":"opensamguk-spep","tag":"new-legacy"}`).Code
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("legacy deployment did not reach pull")
	}
	webDone := make(chan int, 1)
	go func() {
		webDone <- loopbackRequest(t, cfg.webGameDeployHTTPHandler(), http.MethodPost, "/deploy/web-game", webDeployJSON(t, req)).Code
	}()
	releaseOnce.Do(func() { close(release) })
	select {
	case status := <-legacyDone:
		if status != http.StatusOK {
			t.Fatalf("legacy status=%d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy deployment did not finish")
	}
	select {
	case status := <-webDone:
		if status != http.StatusConflict {
			t.Fatalf("stale web request status=%d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued web deployment did not finish")
	}
	for _, call := range calls.snapshot() {
		if strings.HasSuffix(call, "pull web-game") || strings.HasSuffix(call, "--pull never web-game") {
			t.Fatalf("stale web deployment reached Docker: %q", call)
		}
	}
}
