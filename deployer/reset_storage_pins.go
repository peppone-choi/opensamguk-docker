package main

import (
	"context"
	"encoding/json"
	"errors"
)

var resetStorageServices = [...]string{"game-postgres", "game-redis"}

func normalizeResetStorageImageDigests(pins map[string]string) (map[string]string, error) {
	if len(pins) != 2 {
		return nil, errors.New("reset requires both immutable storage image digests")
	}
	clean := make(map[string]string, 2)
	for _, service := range resetStorageServices {
		if !resetManifestDigest.MatchString(pins[service]) {
			return nil, errors.New("reset storage image digest is invalid")
		}
		clean[service] = pins[service]
	}
	return clean, nil
}
func resetStorageReference(service, digest string) string {
	if service == "game-postgres" {
		return "postgres:16-alpine@" + digest
	}
	if service == "game-redis" {
		return "redis:7-alpine@" + digest
	}
	return ""
}
func normalizeResetStorageTarget(target *resetLifecycleTarget) error {
	_, hasPG := target.Updates["GAME_POSTGRES_IMAGE"]
	_, hasRedis := target.Updates["GAME_REDIS_IMAGE"]
	if len(target.StorageImageDigests) == 0 && !hasPG && !hasRedis {
		return nil
	}
	pins, err := normalizeResetStorageImageDigests(target.StorageImageDigests)
	if err != nil {
		return err
	}
	if !hasResetImagePins(*target) {
		return errors.New("storage pins require the same immutable app reset target")
	}
	for _, service := range resetStorageServices {
		key := "GAME_POSTGRES_IMAGE"
		if service == "game-redis" {
			key = "GAME_REDIS_IMAGE"
		}
		expected := resetStorageReference(service, pins[service])
		if current, exists := target.Updates[key]; exists && current != expected {
			return errors.New("storage reference conflicts with the bound digest")
		}
		target.Updates[key] = expected
	}
	target.StorageImageDigests = pins
	return nil
}
func resetLifecycleTargetForEnvWithStorageDigests(envFile string, updates, digests, storage map[string]string) (resetLifecycleTarget, error) {
	appUpdates := make(map[string]string, len(updates))
	for key, value := range updates {
		if key == "GAME_POSTGRES_IMAGE" || key == "GAME_REDIS_IMAGE" {
			return resetLifecycleTarget{}, errors.New("storage reference must come from typed digest pins")
		}
		appUpdates[key] = value
	}
	target, err := resetLifecycleTargetForEnvWithImageDigests(envFile, appUpdates, digests)
	if err != nil {
		return resetLifecycleTarget{}, err
	}
	target.StorageImageDigests = storage
	return normalizeResetLifecycleTarget(target)
}
func (c config) verifyResetCandidateStorageImages(ctx context.Context, target resetLifecycleTarget) error {
	if len(target.StorageImageDigests) == 0 {
		return nil
	}
	pins, err := normalizeResetStorageImageDigests(target.StorageImageDigests)
	if err != nil {
		return err
	}
	const format = `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`
	for _, service := range resetStorageServices {
		out, err := c.runServerDockerContext(ctx, "image", "inspect", "--format", format, resetStorageReference(service, pins[service]))
		if err != nil {
			return errors.New("candidate storage image inspection is unavailable")
		}
		var observed struct {
			RepoDigests  []string `json:"repoDigests"`
			OS           string   `json:"os"`
			Architecture string   `json:"architecture"`
		}
		if json.Unmarshal([]byte(out), &observed) != nil || observed.OS != "linux" || observed.Architecture != "amd64" {
			return errors.New("candidate storage platform is unverified")
		}
		name := "postgres"
		if service == "game-redis" {
			name = "redis"
		}
		matched := false
		for _, digest := range observed.RepoDigests {
			if digest == name+"@"+pins[service] || digest == "docker.io/library/"+name+"@"+pins[service] {
				matched = true
			}
		}
		if !matched {
			return errors.New("candidate storage digest is unverified")
		}
	}
	return nil
}
