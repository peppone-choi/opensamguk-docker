package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

var resetManifestDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var resetImageOwner = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
var resetImageServices = [...]string{"game-api", "game-engine", "web-game"}

func normalizeResetImageDigests(pins map[string]string) (map[string]string, error) {
	if len(pins) != len(resetImageServices) {
		return nil, errors.New("maintenance reset requires exactly three image digests")
	}
	normalized := make(map[string]string, len(pins))
	for _, service := range resetImageServices {
		if !resetManifestDigest.MatchString(pins[service]) {
			return nil, fmt.Errorf("maintenance reset image digest is invalid for %s", service)
		}
		normalized[service] = pins[service]
	}
	return normalized, nil
}

func hasResetImagePins(target resetLifecycleTarget) bool {
	_, api := target.Updates["IMAGE_TAG"]
	_, web := target.Updates["WEB_GAME_TAG"]
	return api || web || len(target.ImageDigests) != 0
}

func normalizeResetImageTarget(target *resetLifecycleTarget) error {
	if !hasResetImagePins(*target) {
		return nil
	}
	tag := target.Updates["IMAGE_TAG"]
	if !gitSHA40.MatchString(tag) || tag != target.Updates["WEB_GAME_TAG"] {
		return errors.New("maintenance reset requires matching immutable image tags")
	}
	pins, err := normalizeResetImageDigests(target.ImageDigests)
	if err != nil {
		return err
	}
	target.ImageDigests = pins
	return nil
}

func (c config) verifyResetCandidateImages(ctx context.Context, envFile string, target resetLifecycleTarget) error {
	values, err := readEnvValues(envFile)
	if err != nil {
		return errors.New("candidate image registry settings are unavailable")
	}
	registry := values["GHCR_REGISTRY"]
	if registry == "" {
		registry = "ghcr.io"
	}
	owner := values["GHCR_OWNER"]
	if owner == "" {
		owner = c.ghcrOwner
	}
	if registry != "ghcr.io" || !resetImageOwner.MatchString(owner) {
		return errors.New("candidate image registry settings are invalid")
	}
	repository := registry + "/" + owner + "/opensamguk"
	const format = `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`
	for _, service := range resetImageServices {
		reference := repository + ":" + service + "-" + target.Updates["IMAGE_TAG"]
		out, err := c.runServerDockerContext(ctx, "image", "inspect", "--format", format, reference)
		if err != nil {
			return fmt.Errorf("candidate image inspection is unavailable for %s", service)
		}
		var observed struct {
			RepoDigests  []string `json:"repoDigests"`
			OS           string   `json:"os"`
			Architecture string   `json:"architecture"`
		}
		if err := json.Unmarshal([]byte(out), &observed); err != nil || observed.OS != "linux" || observed.Architecture != "amd64" {
			return fmt.Errorf("candidate image platform is unverified for %s", service)
		}
		expected := repository + "@" + target.ImageDigests[service]
		matched := false
		for _, digest := range observed.RepoDigests {
			if digest == expected {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("candidate image digest is unverified for %s", service)
		}
	}
	return nil
}
