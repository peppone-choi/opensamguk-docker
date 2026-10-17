package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var webGameDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var webGamePinnedTagRE = regexp.MustCompile(`^[0-9a-f]{40}@sha256:[0-9a-f]{64}$`)

// This separate route fails closed on older deployers; /deploy keeps its API/web behavior.
// WEB_GAME_TAG=commit@sha256:digest is consumed by the existing compose template as
// repo:web-game-commit@sha256:digest, including after later ordinary recreates.
type webGameDeployTarget struct {
	Tag                string `json:"tag"`
	Digest             string `json:"digest"`
	ExpectedWebGameTag string `json:"expectedWebGameTag"`
	ExpectedWorldID    int    `json:"expectedWorldId"`
	ExpectedGeneration int    `json:"expectedGeneration"`
}

type webGameDeployRequest struct {
	Project string `json:"project"`
	webGameDeployTarget
}

type webGameDeployResponse struct {
	Project string `json:"project"`
	Service string `json:"service"`
	Tag     string `json:"tag"`
	Digest  string `json:"digest"`
	OK      bool   `json:"ok"`
}

func validateWebGameDeployTarget(target *webGameDeployTarget) error {
	if target == nil || target.ExpectedWorldID <= 0 || target.ExpectedWorldID > 2147483647 || target.ExpectedGeneration <= 0 || target.ExpectedGeneration > 2147483647 || !gitSHA40.MatchString(target.Tag) || !webGameDigestRE.MatchString(target.Digest) ||
		(!tagRe.MatchString(target.ExpectedWebGameTag) && !webGamePinnedTagRE.MatchString(target.ExpectedWebGameTag)) {
		return errors.New("web deployment requires a commit SHA, sha256 digest and expected current web pin")
	}
	return nil
}

func validateJournalWebGameTarget(operation string, target *webGameDeployTarget) error {
	if operation == "deploy-web" {
		return validateWebGameDeployTarget(target)
	}
	if target != nil {
		return errors.New("only a web deployment journal can carry a web target")
	}
	return nil
}

func (target webGameDeployTarget) pin() string { return target.Tag + "@" + target.Digest }

func validateWebGameEnvUniqueness(envFile string) error {
	lines, err := readEnvLines(envFile)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, line := range lines {
		if !line.IsKV {
			continue
		}
		switch line.Key {
		case "WEB_GAME_TAG", "IMAGE_TAG", "OPENSAMGUK_WORLD_ID", "SERVER_GENERATION":
			if seen[line.Key] {
				return errors.New("duplicate scoped web deployment configuration")
			}
			seen[line.Key] = true
		}
	}
	return nil
}

func readWebGamePin(envFile string) (string, error) {
	if err := validateWebGameEnvUniqueness(envFile); err != nil {
		return "", err
	}
	values, err := readEnvValues(envFile)
	if err != nil {
		return "", err
	}
	pin := values["WEB_GAME_TAG"]
	if pin == "" {
		pin = values["IMAGE_TAG"]
	}
	if pin == "" {
		pin = "latest"
	}
	return pin, nil
}

func (c config) requireRegisteredWebGameTarget(target serverTarget, approved webGameDeployTarget) error {
	if err := validateWebGameEnvUniqueness(target.EnvFile); err != nil {
		return err
	}
	values, err := c.validateServerTarget(target)
	if err != nil {
		return err
	}
	worldID, err := strconv.Atoi(envOrValue(values["OPENSAMGUK_WORLD_ID"], "1"))
	if err != nil || worldID != approved.ExpectedWorldID {
		return errors.New("approved process world does not match server configuration")
	}
	generation, err := strconv.Atoi(envOrValue(values["SERVER_GENERATION"], "1"))
	if err != nil || generation != approved.ExpectedGeneration {
		return errors.New("approved server generation does not match server configuration")
	}
	unlock := c.lockSharedEnv()
	defer unlock()
	lines, err := readEnvLines(c.sharedEnvFile())
	if err != nil {
		return err
	}
	// Existing readRegistry may sanitize/rewrite the shared env. This check never writes it.
	registry, _, err := parseRawRegistryEntries(lines)
	if err != nil {
		return err
	}
	entries, err := canonicalRegistryEntries(registry)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.ID != target.ID {
			continue
		}
		if entry.DeployProject != target.Project || entry.Generation != approved.ExpectedGeneration || entry.RepairRequired ||
			entry.GameAPIURL != envOrValue(values["GAME_API_URL"], c.gameAPIURLFor(target.ID)) ||
			entry.GameEngineURL != c.gameEngineURLFor(target.ID) {
			return errors.New("registered target differs from the approved server")
		}
		return nil
	}
	return errors.New("server is not registered")
}

func (c config) requireExpectedWebGamePin(target serverTarget, approved webGameDeployTarget) error {
	if err := c.requireRegisteredWebGameTarget(target, approved); err != nil {
		return err
	}
	pin, err := readWebGamePin(target.EnvFile)
	if err != nil {
		return err
	}
	if pin != approved.ExpectedWebGameTag {
		return errors.New("current web image pin differs from the approved expected pin")
	}
	return nil
}

func (c config) webGameDeployHTTPHandler() http.HandlerFunc {
	return c.withAuth(c.withLoopback(c.handleWebGameDeploy))
}

func (c config) handleWebGameDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "POST only"})
		return
	}
	var req webGameDeployRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<16)+1))
	if err != nil || len(body) > 1<<16 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid web deployment request"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid web deployment request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid web deployment request"})
		return
	}
	target, err := c.serverTargetForProject(req.Project)
	if err != nil || validateWebGameDeployTarget(&req.webGameDeployTarget) != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid web deployment target or pin"})
		return
	}
	lease, err := c.beginMutation("")
	if err != nil {
		writeMutationAdmissionError(w, err)
		return
	}
	defer lease.Done()

	// Recheck after serialized admission, never against a stale pre-admission snapshot.
	if err := c.requireExpectedWebGamePin(target, req.webGameDeployTarget); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "web deployment precondition failed"})
		return
	}
	temp, cleanup, err := c.tempWebGamePinEnvFile(target.EnvFile, req.pin())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not prepare web image pin"})
		return
	}
	defer cleanup()
	if err := c.pullWebGame(lease.Context(), target.Project, temp); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web image pull failed; desired pin unchanged"})
		return
	}
	if err := c.requireExpectedWebGamePin(target, req.webGameDeployTarget); err != nil {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "web deployment precondition changed"})
		return
	}
	if err := lease.Context().Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "web deployment cancelled"})
		return
	}
	if err := c.writeLifecycleJournalWithResetTarget("deploy-web", target, nil, "", "", &req.webGameDeployTarget); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "could not persist scoped web recovery journal"})
		return
	}
	if err := lease.Context().Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "web deployment cancelled; scoped recovery required"})
		return
	}
	if err := writeWebGamePinDurable(target.EnvFile, req.pin()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web pin write failed; scoped recovery required"})
		return
	}
	if err := c.advanceLifecycleJournal(lifecycleJournalStageEnv); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web pin journal update failed; scoped recovery required"})
		return
	}
	if err := c.upWebGame(lease.Context(), target.Project, target.EnvFile); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web recreate failed; scoped recovery required"})
		return
	}
	if err := c.verifyWebGamePin(lease.Context(), target, req.pin()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web image verification failed; scoped recovery required"})
		return
	}
	if err := c.clearLifecycleJournal(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "web recovery journal settlement failed"})
		return
	}
	writeJSON(w, http.StatusOK, webGameDeployResponse{Project: target.Project, Service: "web-game", Tag: req.Tag, Digest: req.Digest, OK: true})
}

// Only the web image key is changed. Existing runtime env and the compose file
// remain the source for all other service configuration on recreate/recovery.
func writeWebGamePinDurable(envFile, pin string) error {
	if !webGamePinnedTagRE.MatchString(pin) {
		return errors.New("invalid durable web image pin")
	}
	if err := validateWebGameEnvUniqueness(envFile); err != nil {
		return err
	}
	lines, err := readEnvLines(envFile)
	if err != nil {
		return err
	}
	replaced := false
	for i := range lines {
		if lines[i].IsKV && lines[i].Key == "WEB_GAME_TAG" {
			lines[i].Value = pin
			lines[i].Raw = "WEB_GAME_TAG=" + pin
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, envLine{Raw: "WEB_GAME_TAG=" + pin, Key: "WEB_GAME_TAG", Value: pin, IsKV: true})
	}
	return writeEnvLinesAtomicDurable(envFile, lines)
}

func (c config) tempWebGamePinEnvFile(envFile, pin string) (string, func(), error) {
	data, err := os.ReadFile(envFile)
	if err != nil {
		return "", nil, err
	}
	temp, err := os.CreateTemp(c.serversDir, ".web-deploy-*.env")
	if err != nil {
		return "", nil, err
	}
	name := temp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		cleanup()
		return "", nil, err
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := patchEnvFile(name, serverEnvAllowlist, map[string]string{"WEB_GAME_TAG": pin}); err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}

func (c config) pullWebGame(ctx context.Context, project, envFile string) error {
	if _, err := c.validateDockerServerTarget(project, envFile, true); err != nil {
		return err
	}
	_, err := c.runServerDockerContext(ctx, "compose", "-p", project, "--env-file", envFile,
		"-f", c.composeServer, "pull", "web-game")
	return err
}

func (c config) upWebGame(ctx context.Context, project, envFile string) error {
	if _, err := c.validateDockerServerTarget(project, envFile, false); err != nil {
		return err
	}
	_, err := c.runServerDockerContext(ctx, "compose", "-p", project, "--env-file", envFile,
		"-f", c.composeServer, "up", "-d", "--force-recreate", "--no-deps", "--no-build", "--pull", "never", "web-game")
	return err
}

func (c config) verifyWebGamePin(ctx context.Context, target serverTarget, pin string) error {
	values, err := readEnvValues(target.EnvFile)
	if err != nil {
		return err
	}
	registry := envOrValue(values["GHCR_REGISTRY"], "ghcr.io")
	owner := envOrValue(values["GHCR_OWNER"], "peppone-choi")
	repo := registry + "/" + owner + "/opensamguk"
	expected := repo + ":web-game-" + pin
	out, err := c.runServerDockerContext(ctx, "inspect", internalServerKey(target.ID)+"-web-game", "--format", "{{.Config.Image}}")
	if err != nil {
		return err
	}
	actual := strings.TrimSpace(out)
	if actual == expected {
		return nil
	}
	if _, digest, ok := strings.Cut(pin, "@"); ok && actual == repo+"@"+digest {
		return nil
	}
	return errors.New("running web image does not match the scoped desired pin")
}

func (c config) repairWebGameDeploy(ctx context.Context, target serverTarget, journal lifecycleJournal) error {
	if err := validateWebGameDeployTarget(journal.WebGameTarget); err != nil {
		return err
	}
	if err := c.requireRegisteredWebGameTarget(target, *journal.WebGameTarget); err != nil {
		return err
	}
	pin, err := readWebGamePin(target.EnvFile)
	if err != nil {
		return err
	}
	approved := journal.WebGameTarget.pin()
	if pin == journal.WebGameTarget.ExpectedWebGameTag && pin != approved && journal.Stage == lifecycleJournalStagePrepared {
		// A crash before the atomic pin write is a no-op only after the old image is verified.
		return c.verifyWebGamePin(ctx, target, pin)
	}
	if pin != approved {
		return errors.New("web recovery desired pin differs from the journal target")
	}
	if err := c.upWebGame(ctx, target.Project, target.EnvFile); err != nil {
		return err
	}
	return c.verifyWebGamePin(ctx, target, approved)
}
