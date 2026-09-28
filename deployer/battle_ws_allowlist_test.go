package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRenderBattleWSAllowlistOnlyCanonicalRegistryMembers(t *testing.T) {
	entry := func(id string) registryEntry {
		return registryEntry{ID: id, DeployProject: projectForServerID(id),
			GameAPIURL: "http://s" + id + "-game-api:8081"}
	}
	pep, alpha, broken := entry("pep"), entry("alpha"), entry("test")
	broken.RepairRequired = true
	got, err := renderBattleWSAllowlist([]registryEntry{pep, broken, alpha})
	if err != nil || string(got) != "alpha http://salpha-game-api:8081;\npep http://spep-game-api:8081;\n" {
		t.Fatalf("allowlist = %q, err = %v", got, err)
	}
	for _, invalid := range []registryEntry{
		{ID: "PEP", DeployProject: pep.DeployProject, GameAPIURL: pep.GameAPIURL},
		{ID: "../", DeployProject: pep.DeployProject, GameAPIURL: pep.GameAPIURL},
		{ID: "pep", DeployProject: "other", GameAPIURL: pep.GameAPIURL},
		{ID: "pep", DeployProject: pep.DeployProject, GameAPIURL: "http://other:8081"},
	} {
		if _, err := renderBattleWSAllowlist([]registryEntry{invalid}); err == nil {
			t.Fatalf("invalid entry entered allowlist: %+v", invalid)
		}
	}
	if _, err := renderBattleWSAllowlist([]registryEntry{pep, pep}); err == nil {
		t.Fatal("duplicate server entered allowlist")
	}
}

func TestBattleWSAllowlistSyncDeniesMissingOrCorruptRegistryAndRestoresOnValidationFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	var calls [][]string
	cfg := config{composeDir: root, composeShared: filepath.Join(root, "docker-compose.shared.yml"),
		dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
			calls = append(calls, append([]string{}, args...))
			return "", nil
		}}
	if err := os.WriteFile(path, []byte("SERVER_REGISTRY_JSON=[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	degraded, err := cfg.syncBattleWSAllowlist(context.Background())
	if degraded || err != nil {
		t.Fatalf("empty registry sync: degraded=%v err=%v", degraded, err)
	}
	if got, err := os.ReadFile(cfg.battleWSAllowlistPath()); err != nil || len(got) != 0 {
		t.Fatalf("missing registry must deny all: %q, %v", got, err)
	}
	valid := `SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","gameApiUrl":"http://spep-game-api:8081"}]` + "\n"
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	degraded, err = cfg.syncBattleWSAllowlist(context.Background())
	if degraded || err != nil {
		t.Fatalf("valid registry sync: degraded=%v err=%v", degraded, err)
	}
	before, err := os.ReadFile(cfg.battleWSAllowlistPath())
	if err != nil || string(before) != "pep http://spep-game-api:8081;\n" {
		t.Fatalf("allowlist = %q, %v", before, err)
	}
	if !reflect.DeepEqual(calls[len(calls)-1], []string{"compose", "--env-file", path,
		"-f", cfg.composeShared, "run", "--rm", "--no-deps", "nginx", "nginx", "-t"}) {
		t.Fatalf("candidate nginx configuration was not tested: %v", calls)
	}
	if err := os.WriteFile(path, []byte("SERVER_REGISTRY_JSON=broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	degraded, err = cfg.syncBattleWSAllowlist(context.Background())
	if !degraded || err != nil {
		t.Fatalf("corrupt registry sync: degraded=%v err=%v", degraded, err)
	}
	if got, _ := os.ReadFile(cfg.battleWSAllowlistPath()); len(got) != 0 {
		t.Fatalf("corrupt registry retained a route: %q", got)
	}
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.dockerRunnerContext = func(_ context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "nginx -t") {
			return "", errors.New("bad config")
		}
		return "", nil
	}
	if _, err := cfg.syncBattleWSAllowlist(context.Background()); err == nil {
		t.Fatal("invalid nginx config passed validation")
	}
	if got, _ := os.ReadFile(cfg.battleWSAllowlistPath()); len(got) != 0 {
		t.Fatalf("validation failure did not restore deny-all map: %q", got)
	}
}

func TestRegistryReloadPublishesAllowlistBeforeHUPAndRevokesDeletedServer(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	valid := `SERVER_REGISTRY_JSON=[{"id":"pep","deployProject":"opensamguk-spep","gameApiUrl":"http://spep-game-api:8081"}]` + "\n"
	if err := os.WriteFile(envPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	cfg := config{composeDir: root, composeShared: filepath.Join(root, "docker-compose.shared.yml"),
		battleWSAllowlistEnabled: true,
		dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
			calls = append(calls, strings.Join(args, " "))
			return "", nil
		}}
	if _, err := cfg.reloadSharedRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.HasSuffix(calls[0], "run --rm --no-deps nginx nginx -t") ||
		!strings.HasSuffix(calls[1], "up -d --no-deps web-gateway") ||
		!strings.HasSuffix(calls[2], "kill --signal HUP nginx") {
		t.Fatalf("allowlist validation/reload ordering = %v", calls)
	}
	if got, _ := os.ReadFile(cfg.battleWSAllowlistPath()); string(got) != "pep http://spep-game-api:8081;\n" {
		t.Fatalf("registered server missing from allowlist: %q", got)
	}
	if err := os.WriteFile(envPath, []byte("SERVER_REGISTRY_JSON=[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := cfg.reloadSharedRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(cfg.battleWSAllowlistPath()); len(got) != 0 {
		t.Fatalf("deleted server still allowed: %q", got)
	}
	if len(calls) != 3 || !strings.HasSuffix(calls[2], "kill --signal HUP nginx") {
		t.Fatalf("deletion did not reload nginx: %v", calls)
	}
	if err := os.WriteFile(envPath, []byte("SERVER_REGISTRY_JSON=corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := cfg.reloadSharedRegistry(context.Background()); err == nil {
		t.Fatal("corrupt registry did not report failure")
	}
	if got, _ := os.ReadFile(cfg.battleWSAllowlistPath()); len(got) != 0 {
		t.Fatalf("corrupt registry reopened a route: %q", got)
	}
	if len(calls) != 3 || !strings.HasSuffix(calls[2], "kill --signal HUP nginx") {
		t.Fatalf("corrupt registry did not reload deny-all map: %v", calls)
	}
}
