package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
