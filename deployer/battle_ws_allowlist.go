package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const battleWSAllowlistFile = "battle-ws-allowlist.map"

var regexpCanonicalPublicServerID = regexp.MustCompile(`^[a-z0-9]+$`)

func (c config) battleWSAllowlistPath() string {
	return filepath.Join(c.composeDir, "infra", "nginx", "runtime", battleWSAllowlistFile)
}

// Only canonical registry entries with the expected fixed internal game-api address
// can enter the nginx map. The URL from the registry is never copied into nginx.
func renderBattleWSAllowlist(entries []registryEntry) ([]byte, error) {
	ids := make([]string, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		id := entry.ID
		if id == "" || len(id) > maxPublicServerIDLength ||
			!regexpCanonicalPublicServerID.MatchString(id) || seen[id] ||
			entry.DeployProject != projectForServerID(id) ||
			entry.GameAPIURL != fmt.Sprintf("http://s%s-game-api:8081", id) {
			return nil, fmt.Errorf("battle websocket allowlist has an invalid registry entry")
		}
		seen[id] = true
		if !entry.RepairRequired {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&out, "%s http://s%s-game-api:8081;\n", id, id)
	}
	return []byte(out.String()), nil
}

// Atomically publish, test the complete candidate nginx configuration, then let
// the caller recreate/HUP nginx. A failed config test restores the last valid map.
func (c config) syncBattleWSAllowlist(ctx context.Context) (bool, error) {
	registry, registryErr := c.readRegistry()
	content, renderErr := renderBattleWSAllowlist(registry)
	degraded := registryErr != nil || renderErr != nil
	if degraded {
		content = []byte{} // malformed/missing registry closes every WS route
	}
	path := c.battleWSAllowlistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return degraded, err
	}
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return degraded, readErr
	}
	if err := writeFileAtomicDurable(path, content); err != nil {
		return degraded, err
	}
	// The map carries public IDs only. The nginx master can read it even when
	// container root and host file ownership differ.
	if err := os.Chmod(path, 0o644); err != nil {
		return degraded, err
	}
	_, validationErr := c.runDockerContext(ctx, "compose", "--env-file", c.sharedEnvFile(),
		"-f", c.composeShared, "run", "--rm", "--no-deps", "nginx", "nginx", "-t")
	if validationErr != nil {
		if readErr == nil {
			if err := writeFileAtomicDurable(path, previous); err != nil {
				return degraded, fmt.Errorf("nginx validation failed and allowlist restore failed: %w", err)
			}
			_ = os.Chmod(path, 0o644)
		} else {
			if err := os.Remove(path); err != nil {
				return degraded, fmt.Errorf("nginx validation failed and allowlist remove failed: %w", err)
			}
			_ = syncDirectory(filepath.Dir(path))
		}
		// Docker diagnostics can contain interpolated environment values. Never
		// return or log their text when a server-scoped signing key is configured.
		return degraded, errors.New("battle websocket nginx config validation failed")
	}
	return degraded, nil
}
