package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerEnvGetPatchHappyPath(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.serversDir, "s1.env"), "# server\nIMAGE_TAG=v1\nGAME_API_PORT=8101\nJWT_SECRET=old-secret\n")

	res := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodGet, "/env/server?id=s1", "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", res.Code, res.Body.String())
	}
	body := decodeEnvResponse(t, res)
	if body.Scope != "server" {
		t.Fatalf("scope = %q", body.Scope)
	}
	if fieldValue(t, body.Fields, "IMAGE_TAG") != "v1" {
		t.Fatalf("IMAGE_TAG field = %#v", body.Fields["IMAGE_TAG"])
	}

	res = envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=s1", `{"values":{"IMAGE_TAG":"v2","GAME_API_PORT":"8201"}}`)
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

	data := readFile(t, filepath.Join(cfg.serversDir, "s1.env"))
	if !strings.Contains(data, "# server\nIMAGE_TAG=v2\nGAME_API_PORT=8201\nJWT_SECRET=old-secret\n") {
		t.Fatalf("env comments/order not preserved:\n%s", data)
	}
	mode := fileMode(t, filepath.Join(cfg.serversDir, "s1.env"))
	if mode != 0o600 {
		t.Fatalf("env mode = %#o, want 0600", mode)
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
	envFile := filepath.Join(cfg.serversDir, "s1.env")
	writeEnv(t, envFile, "IMAGE_TAG=v1\nJWT_SECRET=old-secret\n")

	res := envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodGet, "/env/server?id=s1", "")
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

	res = envRequest(t, cfg.withAuth(cfg.handleServerEnv), http.MethodPatch, "/env/server?id=s1", `{"values":{"JWT_SECRET":"new-secret"}}`)
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
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodPost, "/servers", `{"id":"1","name":"통일 서버","gameApiPort":"8101","webGamePort":"3101","imageTag":"v2","scenarioCode":"scenario_1010"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "s1" || body.Project != "opensamguk-s1" {
		t.Fatalf("create response = %#v", body)
	}

	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "s1.env"))
	for _, want := range []string{
		"SERVER_ID=1\n",
		"IMAGE_TAG=v2\n",
		"GAME_API_PORT=8101\n",
		"WEB_GAME_PORT=3101\n",
		"JWT_SECRET=shared-secret\n",
		"SCENARIO_SEED_ENABLED=true\n",
		"GAME_API_URL=http://s1-game-api:8081\n",
	} {
		if !strings.Contains(serverEnv, want) {
			t.Fatalf("server env missing %q:\n%s", want, serverEnv)
		}
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"s1"`) || !strings.Contains(sharedEnv, `"deployProject":"opensamguk-s1"`) {
		t.Fatalf("registry not updated:\n%s", sharedEnv)
	}
	waitForCalls(t, func() int { return len(calls) }, 3)
	if len(calls) != 3 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "compose -p opensamguk-s1") || strings.Contains(calls[0], "--no-deps") {
		t.Fatalf("server compose call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "gateway-api web-gateway") || strings.Contains(calls[1], " nginx") {
		t.Fatalf("shared reload call = %q", calls[1])
	}
	if !strings.Contains(calls[2], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", calls[2])
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
	if !strings.Contains(sharedEnv, `"gameApiUrl":"http://s2-game-api:18080"`) {
		t.Fatalf("registry GAME_API_URL did not use override:\n%s", sharedEnv)
	}
}

func TestCreateServerRejectsPortCollisions(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "GAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
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
SERVER_REGISTRY_JSON=[{"id":"s1","name":"통일 서버","gameApiUrl":"http://s1-game-api:8081","gameEngineUrl":"http://s1-game-engine:8082","deployProject":"opensamguk-s1"},{"id":"spep","name":"빼섭","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "s1.env"), "GAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "ok\n", nil
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodDelete, "/servers?id=s1&confirm=DELETE%20s1", "")
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "s1" || body.Project != "opensamguk-s1" {
		t.Fatalf("delete response = %#v", body)
	}
	waitForCalls(t, func() int { return len(calls) }, 3)
	waitForMissing(t, filepath.Join(cfg.serversDir, "s1.env"))
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "s1.env")); !os.IsNotExist(err) {
		t.Fatalf("server env still exists or unexpected error: %v", err)
	}
	waitForContentNotContaining(t, filepath.Join(cfg.composeDir, ".env"), `"id":"s1"`)
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if strings.Contains(sharedEnv, `"id":"s1"`) || !strings.Contains(sharedEnv, `"id":"spep"`) {
		t.Fatalf("registry not pruned correctly:\n%s", sharedEnv)
	}
	if len(calls) != 3 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "compose -p opensamguk-s1") || !strings.Contains(calls[0], "down --volumes --remove-orphans") {
		t.Fatalf("delete compose call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "gateway-api web-gateway") || strings.Contains(calls[1], " nginx") {
		t.Fatalf("shared reload call = %q", calls[1])
	}
	if !strings.Contains(calls[2], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", calls[2])
	}
}

func TestDeleteServerKeepsRegistryWhenDownFails(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"s1","name":"통일 서버","gameApiUrl":"http://s1-game-api:8081","gameEngineUrl":"http://s1-game-engine:8082","deployProject":"opensamguk-s1"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "s1.env"), "GAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	cfg.dockerRunner = func(args ...string) (string, error) {
		return "down failed\n", errors.New("compose down failed")
	}

	res := envRequest(t, cfg.withAuth(cfg.handleServers), http.MethodDelete, "/servers?id=s1&confirm=DELETE%20s1", "")
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d body=%s", res.Code, res.Body.String())
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "s1.env")); err != nil {
		t.Fatalf("server env should remain on down failure: %v", err)
	}
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if !strings.Contains(sharedEnv, `"id":"s1"`) {
		t.Fatalf("registry was pruned before down success:\n%s", sharedEnv)
	}
}

func TestResetServerRecreatesStackWithVolumes(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"s1","name":"통일 서버","gameApiUrl":"http://s1-game-api:8081","gameEngineUrl":"http://s1-game-engine:8082","deployProject":"opensamguk-s1"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "s1.env"), "SCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "ok\n", nil
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerReset),
		http.MethodPost,
		"/servers/reset?id=s1",
		`{"confirm":"RESET s1","scenarioCode":"scenario_1002","turnTerm":"30","sync":"1","fiction":"0","extend":"1","blockGeneralCreate":"2","npcMode":"2","showImgLevel":"3","autorunUserOptions":["develop","battle"],"autorunUserMinutes":"1440","joinMode":"onlyRandom","tournamentTrig":"1","reserveOpen":"2026-06-10 20:00","preReserveOpen":"2026-06-10 19:00"}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	var body createServerResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.ID != "s1" || body.Project != "opensamguk-s1" {
		t.Fatalf("reset response = %#v", body)
	}
	waitForCalls(t, func() int { return len(calls) }, 4)
	if len(calls) != 4 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "down --volumes --remove-orphans") {
		t.Fatalf("reset down call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "up -d") {
		t.Fatalf("reset up call = %q", calls[1])
	}
	if !strings.Contains(calls[2], "gateway-api web-gateway") || strings.Contains(calls[2], " nginx") {
		t.Fatalf("shared reload call = %q", calls[2])
	}
	if !strings.Contains(calls[3], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", calls[3])
	}
	serverEnv := readFile(t, filepath.Join(cfg.serversDir, "s1.env"))
	for _, want := range []string{
		"SCENARIO_CODE=scenario_1002\n",
		"SCENARIO_SEED_ENABLED=true\n",
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
}

func TestResetServerStopsBeforeUpWhenDownFails(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"s1","name":"통일 서버","gameApiUrl":"http://s1-game-api:8081","gameEngineUrl":"http://s1-game-engine:8082","deployProject":"opensamguk-s1"}]
`)
	original := "SCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n"
	writeEnv(t, filepath.Join(cfg.serversDir, "s1.env"), original)
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "down failed\n", errors.New("compose down failed")
	}

	res := envRequest(
		t,
		cfg.withAuth(cfg.handleServerReset),
		http.MethodPost,
		"/servers/reset?id=s1",
		`{"confirm":"RESET s1","scenarioCode":"scenario_1002","turnTerm":"30"}`,
	)
	if res.Code != http.StatusOK {
		t.Fatalf("RESET status = %d body=%s", res.Code, res.Body.String())
	}
	waitForCalls(t, func() int { return len(calls) }, 1)
	if len(calls) != 1 || !strings.Contains(calls[0], "down --volumes --remove-orphans") {
		t.Fatalf("reset should stop after failed down, calls=%#v", calls)
	}
	waitForContent(t, filepath.Join(cfg.serversDir, "s1.env"), original)
	if got := readFile(t, filepath.Join(cfg.serversDir, "s1.env")); got != original {
		t.Fatalf("env was not restored after failed reset:\n%s", got)
	}
}

func TestStatelessServicesExcludeGameEngine(t *testing.T) {
	joined := strings.Join(statelessServices, ",")
	if strings.Contains(joined, "game-engine") {
		t.Fatalf("stateless services must not include game-engine: %s", joined)
	}
}

func testConfig(t *testing.T) config {
	t.Helper()
	root := t.TempDir()
	serversDir := filepath.Join(root, "servers")
	if err := os.MkdirAll(serversDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return config{
		token:         "test-token",
		composeDir:    root,
		serversDir:    serversDir,
		composeServer: filepath.Join(root, "docker-compose.server.yml"),
		composeShared: filepath.Join(root, "docker-compose.shared.yml"),
		ghcrOwner:     "owner",
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
