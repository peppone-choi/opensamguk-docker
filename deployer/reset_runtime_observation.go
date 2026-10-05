package main

import (
	"context"
	"reflect"
	"regexp"
	"time"
)

// Collection is source preparation only: no receipt file is issued and no
// caller/worker is wired. These observations do not prove seed/tick/roles.
type resetRuntimeContainer struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	ImageID   string   `json:"image"`
	Running   *bool    `json:"running"`
	Status    string   `json:"status"`
	Project   string   `json:"project"`
	Service   string   `json:"service"`
	ServerIDs []string `json:"serverIds"`
}
type resetRuntimeImage struct {
	RepoDigests  []string `json:"repoDigests"`
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
}
type resetRuntimeObservation struct {
	Version           int                              `json:"version"`
	ServerID          string                           `json:"serverId"`
	WorldID           int                              `json:"worldId"`
	OperationID       string                           `json:"operationId"`
	AppSourceSHA      string                           `json:"appSourceSha"`
	TargetFingerprint string                           `json:"targetFingerprint"`
	Evidence          resetExecutionEvidenceRefs       `json:"evidence"`
	StartedAt         time.Time                        `json:"startedAt"`
	CompletedAt       time.Time                        `json:"completedAt"`
	Containers        map[string]resetRuntimeContainer `json:"containers"`
	ImageDigests      map[string]string                `json:"imageDigests"`
	Raw               resetAdminCurrentObservation     `json:"raw"`
}
type resetRuntimeRawSource func(context.Context, resetExecutionPhaseBinding) (resetAdminCurrentObservation, error)

var resetRuntimeRepository = regexp.MustCompile(`^ghcr.io/[a-z0-9][a-z0-9._-]*/opensamguk$`)

// Only these non-secret SERVER_ID entries are selected. Config.Env itself is
// never returned/logged, even on a rejected observation.
const resetRuntimeContainerFormat = `{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},"status":{{json .State.Status}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"serverIds":[{{range .Config.Env}}{{if eq (index (split . "=") 0) "SERVER_ID"}}{{json .}},{{end}}{{end}}null]}`

// The source wrapper supplies the private raw credential and canonical pep
// origin. The injectable source exists for isolated tests, never request input.
func (c config) collectResetD101Runtime(ctx context.Context, binding resetExecutionPhaseBinding, appRepository string) (resetRuntimeObservation, error) {
	if binding.AcceptedAtUnix <= 0 || time.Unix(binding.AcceptedAtUnix, 0).After(time.Now()) || c.lifecycleOperationStore == nil {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	fingerprint, err := resetExecutionRequestFingerprint("pep", binding.Target, binding.Evidence)
	operation, found := c.lifecycleOperationStore.Lookup(binding.OperationID)
	if err != nil || !found || operation.Kind != lifecycleKindReset || operation.SubjectID != "pep" ||
		operation.CreatedAt.Unix() != binding.AcceptedAtUnix || operation.RequestFingerprint != fingerprint ||
		(operation.Status != lifecycleJobRunning && operation.Status != lifecycleJobSucceeded) {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	evidence, err := c.readResetExecutionEvidence(binding.OperationID, binding.Target, binding.Evidence, time.Unix(binding.AcceptedAtUnix, 0))
	if err != nil {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	return c.collectResetD101RuntimeWithSource(ctx, binding, evidence, appRepository, c.observeResetD101AdminCurrent, time.Now)
}

func (c config) collectResetD101RuntimeWithSource(ctx context.Context, binding resetExecutionPhaseBinding, evidence resetExecutionEvidence, appRepository string, rawSource resetRuntimeRawSource, clock func() time.Time) (resetRuntimeObservation, error) {
	plan := evidence.Plan
	if rawSource == nil || clock == nil || ctx == nil || ctx.Err() != nil ||
		!resetRuntimeRepository.MatchString(appRepository) ||
		binding.OperationID != plan.OperationID || !reflect.DeepEqual(binding.Target, plan.Target) ||
		plan.ServerID != "pep" || plan.WorldID != 1 || !gitSHA40.MatchString(plan.AppSourceSHA) ||
		plan.TargetFingerprint != resetRequestFingerprint("pep", binding.Target) ||
		plan.Target.ScenarioCode != "scenario_3190" || plan.Target.Generation != 0 ||
		!validResetFiveImageDigests(plan.NewImageDigests) || len(evidence.Preflight.StoppedContainerIDs) != 5 ||
		binding.Evidence.ApprovalPlanSHA != evidence.Preflight.ApprovalPlanSHA || !resetEvidenceSHA.MatchString(binding.Evidence.ExecutionReceiptSHA) ||
		validateResetApprovalPlan(plan, binding.OperationID, binding.Target, time.Unix(plan.WindowOpensAtUnix, 0)) != nil ||
		validateResetPreflight(evidence.Preflight, plan, binding.Evidence.ApprovalPlanSHA, time.Unix(evidence.Preflight.ObservedAtUnix, 0)) != nil {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	started := clock()
	if started.Unix() < plan.WindowOpensAtUnix || started.Unix() >= plan.RecoveryDeadlineUnix {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	deadline := started.Add(resetPreflightMaxAge)
	if recovery := time.Unix(plan.RecoveryDeadlineUnix, 0); recovery.Before(deadline) {
		deadline = recovery
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	result := resetRuntimeObservation{Version: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID,
		AppSourceSHA: plan.AppSourceSHA, TargetFingerprint: plan.TargetFingerprint, Evidence: binding.Evidence, StartedAt: started,
		Containers: map[string]resetRuntimeContainer{}, ImageDigests: map[string]string{}}
	ids := map[string]bool{}
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		container, err := c.observeResetRuntimeContainer(bounded, service)
		if err != nil || container.ID == evidence.Preflight.StoppedContainerIDs[service] || ids[container.ID] {
			return resetRuntimeObservation{}, errResetExecutionEvidence
		}
		ids[container.ID] = true
		out, err := c.runServerDockerContext(bounded, "image", "inspect", "--format", `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, container.ImageID)
		var image resetRuntimeImage
		if err != nil || len(out) > resetEvidenceMaxBytes || decodeResetPrivateJSON([]byte(out), &image) != nil ||
			image.OS != "linux" || image.Architecture != "amd64" || !resetRuntimePinMatches(image.RepoDigests, service, appRepository, plan.NewImageDigests[service]) {
			return resetRuntimeObservation{}, errResetExecutionEvidence
		}
		result.Containers[service] = container
		result.ImageDigests[service] = plan.NewImageDigests[service]
	}
	raw, err := rawSource(bounded, binding)
	if err != nil || validateResetD101AdminCurrent(raw.Current) != nil || raw.ObservedAt.Before(started) {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	result.Raw = raw
	// Detect replacement/stop/env identity drift during the raw observation.
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		current, err := c.observeResetRuntimeContainer(bounded, service)
		if err != nil || !reflect.DeepEqual(current, result.Containers[service]) {
			return resetRuntimeObservation{}, errResetExecutionEvidence
		}
	}
	result.CompletedAt = clock()
	if bounded.Err() != nil || result.CompletedAt.Before(started) || !result.CompletedAt.Before(deadline) ||
		raw.ObservedAt.After(result.CompletedAt) {
		return resetRuntimeObservation{}, errResetExecutionEvidence
	}
	return result, nil
}

func resetRuntimePinMatches(digests []string, service, appRepository, pin string) bool {
	for _, digest := range digests {
		switch service {
		case "game-api", "game-engine", "web-game":
			if digest == appRepository+"@"+pin {
				return true
			}
		case "game-postgres":
			if digest == "postgres@"+pin || digest == "docker.io/library/postgres@"+pin {
				return true
			}
		case "game-redis":
			if digest == "redis@"+pin || digest == "docker.io/library/redis@"+pin {
				return true
			}
		}
	}
	return false
}
func (c config) observeResetRuntimeContainer(ctx context.Context, service string) (resetRuntimeContainer, error) {
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", resetRuntimeContainerFormat, "spep-"+service)
	// Null terminates the Go template array without exposing all environment.
	// Decode it separately so a missing/duplicate SERVER_ID stays distinguishable.
	var envelope struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		ImageID   string    `json:"image"`
		Running   *bool     `json:"running"`
		Status    string    `json:"status"`
		Project   string    `json:"project"`
		Service   string    `json:"service"`
		ServerIDs []*string `json:"serverIds"`
	}
	if err != nil || len(out) > resetEvidenceMaxBytes || decodeResetPrivateJSON([]byte(out), &envelope) != nil ||
		!resetEvidenceSHA.MatchString(envelope.ID) || !resetManifestDigest.MatchString(envelope.ImageID) ||
		envelope.Name != "/spep-"+service || envelope.Running == nil || !*envelope.Running || envelope.Status != "running" ||
		envelope.Project != "opensamguk-spep" || envelope.Service != service || len(envelope.ServerIDs) == 0 ||
		envelope.ServerIDs[len(envelope.ServerIDs)-1] != nil {
		return resetRuntimeContainer{}, errResetExecutionEvidence
	}
	values := []string{}
	for _, v := range envelope.ServerIDs[:len(envelope.ServerIDs)-1] {
		if v == nil {
			return resetRuntimeContainer{}, errResetExecutionEvidence
		}
		values = append(values, *v)
	}
	if (service == "game-api" || len(values) > 0) && (len(values) != 1 || values[0] != "SERVER_ID=pep") {
		return resetRuntimeContainer{}, errResetExecutionEvidence
	}
	return resetRuntimeContainer{envelope.ID, envelope.Name, envelope.ImageID, envelope.Running, envelope.Status, envelope.Project, envelope.Service, values}, nil
}
