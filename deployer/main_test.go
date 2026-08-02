package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestServerEnvGetPatchHappyPath(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "# server\nIMAGE_TAG=v1\nGAME_API_PORT=8101\nJWT_SECRET=old-secret\n")

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
	if !strings.Contains(data, "# server\nIMAGE_TAG=v2\nGAME_API_PORT=8201\nJWT_SECRET=old-secret\nWEB_GAME_TAG=v3\n") {
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

func TestReadyzRequiresCanonicalRegistry(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep"}]
`)

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
	writeEnv(t, envFile, "# server\nIMAGE_TAG=v1\nWEB_GAME_TAG=v-old\nJWT_SECRET=old-secret\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	if len(calls) != 2 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "pull game-api web-game") {
		t.Fatalf("pull call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "up -d --force-recreate --no-deps game-api web-game") {
		t.Fatalf("up call = %q", calls[1])
	}
}

func TestDeployDoesNotMutateEnvWhenPullFails(t *testing.T) {
	cfg := testConfig(t)
	envFile := filepath.Join(cfg.serversDir, "s1.env")
	original := "# server\nIMAGE_TAG=v1\nWEB_GAME_TAG=v-old\nJWT_SECRET=old-secret\n"
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
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "IMAGE_TAG=v1\nSERVER_NAME=통일 서버\nSERVER_GENERATION=1\nGAME_API_URL=http://spep-game-api:8081\nJWT_SECRET=old-secret\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	waitForCalls(t, func() int { return len(calls) }, 2)
	if len(calls) != 2 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "gateway-api web-gateway") || strings.Contains(calls[0], " nginx") {
		t.Fatalf("shared reload call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", calls[1])
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
	writeEnv(t, envFile, "IMAGE_TAG=v1\nJWT_SECRET=old-secret\n")

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
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" {
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
	waitForCalls(t, func() int { return len(calls) }, 3)
	if len(calls) != 3 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "compose -p opensamguk-spep") ||
		!strings.Contains(calls[0], "--env-file "+filepath.Join(cfg.serversDir, "spep.env")) ||
		strings.Contains(calls[0], "--no-deps") {
		t.Fatalf("server compose call = %q", calls[0])
	}
	if !strings.Contains(calls[1], "gateway-api web-gateway") || strings.Contains(calls[1], " nginx") {
		t.Fatalf("shared reload call = %q", calls[1])
	}
	if !strings.Contains(calls[2], "--force-recreate --no-deps nginx") {
		t.Fatalf("nginx reload call = %q", calls[2])
	}
}

func TestCreateServerCanonicalizesUppercaseIDAndPreventsCaseCollision(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), "IMAGE_TAG=v1\nJWT_SECRET=shared-secret\nSERVER_REGISTRY_JSON=[]\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	waitForCalls(t, func() int { return len(calls) }, 1)
	if len(calls) == 0 || !strings.Contains(calls[0], "compose -p opensamguk-sa1") {
		t.Fatalf("compose call = %#v", calls)
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
	stepStart := strings.Index(workflow, "      - name: Validate registry, recreate deployer, and reload nginx\n")
	if stepStart < 0 {
		t.Fatal("control-plane deployment step not found")
	}
	nextStep := strings.Index(workflow[stepStart:], "\n      - name: Verify orchestration endpoints\n")
	if nextStep < 0 {
		t.Fatal("unlocked endpoint postcondition step not found")
	}
	step := workflow[stepStart : stepStart+nextStep]

	for _, want := range []string{
		"exec 9>/tmp/opensamguk-production.lock",
		"flock -w 1800 9",
		"sudo docker run --rm --read-only --network none",
		"-e COMPOSE_DIR=/workspace",
		`-v "$STACK/.env:/workspace/.env:ro"`,
		"opensamguk-deployer:local --check-registry",
	} {
		if !strings.Contains(step, want) {
			t.Fatalf("control-plane deployment step missing %q", want)
		}
	}

	build := strings.Index(step, "$COMPOSE build deployer")
	check := strings.Index(step, "opensamguk-deployer:local --check-registry")
	deployer := strings.Index(step, "$COMPOSE up -d --force-recreate --no-deps deployer")
	healthz := strings.Index(step, "http://localhost:9000/healthz")
	readyz := strings.Index(step, "http://localhost:9000/readyz")
	nginx := strings.Index(step, "$COMPOSE up -d --force-recreate --no-deps nginx")
	if build < 0 || check < 0 || deployer < 0 || healthz < 0 || readyz < 0 || nginx < 0 {
		t.Fatalf("missing deployment ordering markers: build=%d check=%d deployer=%d healthz=%d readyz=%d nginx=%d", build, check, deployer, healthz, readyz, nginx)
	}
	if !(build < check && check < deployer && deployer < healthz && healthz < readyz && readyz < nginx) {
		t.Fatalf("unexpected deployment ordering: build=%d check=%d deployer=%d healthz=%d readyz=%d nginx=%d", build, check, deployer, healthz, readyz, nginx)
	}
	if strings.Contains(step[check:deployer], "--env-file") {
		t.Fatal("candidate registry check must not receive the shared env through command-line injection")
	}

	postcondition := workflow[stepStart+nextStep:]
	for _, want := range []string{"http://localhost:9000/healthz", "http://localhost:9000/readyz"} {
		if !strings.Contains(postcondition, want) {
			t.Fatalf("unlocked endpoint postcondition missing %q", want)
		}
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
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"},{"id":"keep","name":"빼섭","gameApiUrl":"http://skeep-game-api:8081","gameEngineUrl":"http://skeep-game-engine:8082","deployProject":"opensamguk-skeep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "GAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" {
		t.Fatalf("delete response = %#v", body)
	}
	waitForCalls(t, func() int { return len(calls) }, 3)
	waitForMissing(t, filepath.Join(cfg.serversDir, "spep.env"))
	if _, err := os.Stat(filepath.Join(cfg.serversDir, "spep.env")); !os.IsNotExist(err) {
		t.Fatalf("server env still exists or unexpected error: %v", err)
	}
	waitForContentNotContaining(t, filepath.Join(cfg.composeDir, ".env"), `"id":"pep"`)
	sharedEnv := readFile(t, filepath.Join(cfg.composeDir, ".env"))
	if strings.Contains(sharedEnv, `"id":"pep"`) || !strings.Contains(sharedEnv, `"id":"keep"`) {
		t.Fatalf("registry not pruned correctly:\n%s", sharedEnv)
	}
	if len(calls) != 3 {
		t.Fatalf("docker calls = %#v", calls)
	}
	if !strings.Contains(calls[0], "compose -p opensamguk-spep") || !strings.Contains(calls[0], "down --volumes --remove-orphans") {
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
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "GAME_API_PORT=8101\nWEB_GAME_PORT=3101\n")
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
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_GENERATION=1\nSCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n")
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	if !body.OK || body.ID != "pep" || body.Project != "opensamguk-spep" {
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
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), "SERVER_GENERATION=1\nSCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n")
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

func TestResetServerStopsBeforeUpWhenDownFails(t *testing.T) {
	cfg := testConfig(t)
	writeEnv(t, filepath.Join(cfg.composeDir, ".env"), `IMAGE_TAG=v1
JWT_SECRET=shared-secret
SERVER_REGISTRY_JSON=[{"id":"pep","name":"통일 서버","gameApiUrl":"http://spep-game-api:8081","gameEngineUrl":"http://spep-game-engine:8082","deployProject":"opensamguk-spep"}]
`)
	original := "SCENARIO_CODE=scenario_1010\nSCENARIO_SEED_ENABLED=true\n"
	writeEnv(t, filepath.Join(cfg.serversDir, "spep.env"), original)
	calls := []string{}
	cfg.dockerRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
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
	waitForCalls(t, func() int { return len(calls) }, 1)
	if len(calls) != 1 || !strings.Contains(calls[0], "down --volumes --remove-orphans") {
		t.Fatalf("reset should stop after failed down, calls=%#v", calls)
	}
	waitForContent(t, filepath.Join(cfg.serversDir, "spep.env"), original)
	if got := readFile(t, filepath.Join(cfg.serversDir, "spep.env")); got != original {
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
		token:          "test-token",
		composeDir:     root,
		serversDir:     serversDir,
		composeServer:  filepath.Join(root, "docker-compose.server.yml"),
		composeShared:  filepath.Join(root, "docker-compose.shared.yml"),
		ghcrOwner:      "owner",
		ghcrAPIBaseURL: "https://api.github.com",
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
