package main

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

// The caller supplies exactly one physical Docker command. A command must not
// bundle another Docker operation: each operation needs a fresh core callback.
// Unknown authority and an expired original cutoff execute zero commands.
func runResetD101CandidateCommand(ctx context.Context, admission resetD101CandidateAdmission,
	beforeCommand func(context.Context) error, command func(context.Context) (string, error)) (string, error) {
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil || command == nil ||
		!validResetD101CandidateCommandAdmission(admission, time.Now()) {
		return "", errResetExecutionEvidence
	}
	if err := beforeCommand(ctx); err != nil {
		return "", errResetExecutionEvidence
	}
	if ctx.Err() != nil || !validResetD101CandidateCommandAdmission(admission, time.Now()) {
		return "", errResetExecutionEvidence
	}
	out, err := command(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(admission.Cutoff()) {
		return "", errResetExecutionEvidence
	}
	return out, nil
}

func validResetD101CandidateCommandAdmission(admission resetD101CandidateAdmission, now time.Time) bool {
	target := admission.Target()
	server := admission.Server()
	return lifecycleJobIDRe.MatchString(admission.OperationID()) &&
		resetEvidenceSHA.MatchString(admission.ApprovalIntentSHA()) &&
		resetEvidenceSHA.MatchString(admission.TargetFingerprint()) &&
		resetEvidenceSHA.MatchString(admission.SelectedSourceReceiptSHA()) &&
		gitSHA40.MatchString(admission.AppSourceSHA()) &&
		server.ID == "pep" && server.Project == "opensamguk-spep" &&
		target.ScenarioCode == "scenario_3190" && target.Generation == 0 && target.ScenarioSeedEnabled &&
		resetRequestFingerprint("pep", target) == admission.TargetFingerprint() &&
		validResetFiveImageDigests(admission.ImagePins()) &&
		!admission.Cutoff().IsZero() && now.Before(admission.Cutoff())
}

// This checks only the fixed outer evidence fields. C8 compares the actual CLI
// option/provenance maps with the signed selected original; the unused options
// receipt field is not an authority and may be empty. This does not prove the
// child exit code or authorize live stack promotion.
func requireResetD101CandidateEvidenceEnvelope(admission resetD101CandidateAdmission,
	evidence resetD101CandidateSeedEvidence) error {
	if !validResetD101CandidateCommandAdmission(admission, evidence.StartedAt) ||
		!resetEvidenceSHA.MatchString(evidence.WorkerContainerID) ||
		!resetEvidenceSHA.MatchString(evidence.PostgresContainerID) ||
		!resetEvidenceSHA.MatchString(evidence.RedisContainerID) ||
		evidence.WorkerContainerID == evidence.PostgresContainerID ||
		evidence.WorkerContainerID == evidence.RedisContainerID ||
		evidence.PostgresContainerID == evidence.RedisContainerID ||
		!resetManifestDigest.MatchString(evidence.WorkerImageID) ||
		!resetEvidenceSHA.MatchString(evidence.GenerationProvenanceSHA) ||
		evidence.SelectedSourceReceiptSHA != admission.SelectedSourceReceiptSHA() ||
		evidence.ActualGeneration != "0" ||
		evidence.StartedAt.IsZero() || evidence.CompletedAt.IsZero() ||
		evidence.CompletedAt.Before(evidence.StartedAt) ||
		!evidence.CompletedAt.Before(admission.Cutoff()) ||
		len(evidence.Original) == 0 || len(evidence.Original) > resetEvidenceMaxBytes {
		return errResetExecutionEvidence
	}
	repository, digest, separated := strings.Cut(evidence.WorkerRepoDigest, "@")
	if !separated || !resetRuntimeRepository.MatchString(repository) ||
		digest != admission.ImagePins()["game-engine"] {
		return errResetExecutionEvidence
	}
	return nil
}

// The approved native candidate Compose contains only the two storage
// services. Its operation-scoped project, volumes and private network are
// checked against the immutable command plan before the first Docker command.
func resetD101CandidateStorageUpArgs(admission resetD101CandidateAdmission) []string {
	r := admission.CandidateResources()
	return []string{"compose", "-p", r.Project, "--env-file", admission.Server().EnvFile,
		"-f", r.CandidateComposeFile, "up", "-d", "--wait", "--no-deps", "game-postgres", "game-redis"}
}

func (c config) prepareResetD101CandidateStorage(ctx context.Context, admission resetD101CandidateAdmission,
	beforeCommand func(context.Context) error) (string, string, error) {
	r := admission.CandidateResources()
	if !validResetD101CandidateCommandAdmission(admission, time.Now()) ||
		!validResetD101CandidateResources(r, admission.OperationID()) ||
		requireResetD101CandidateCompose(r, admission.OperationID(), admission.ImagePins()) != nil {
		return "", "", errResetExecutionEvidence
	}
	if _, err := c.validateServerTarget(admission.Server()); err != nil {
		return "", "", errResetExecutionEvidence
	}
	if _, err := runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
		// Re-read the fixed native original after fresh authority, immediately
		// before Compose consumes it. The server env still belongs to the core.
		if requireResetD101CandidateCompose(r, admission.OperationID(), admission.ImagePins()) != nil {
			return "", errResetExecutionEvidence
		}
		return c.runServerDockerContext(ctx, resetD101CandidateStorageUpArgs(admission)...)
	}); err != nil {
		return "", "", err
	}
	ids := map[string]string{}
	for _, service := range []string{"game-postgres", "game-redis"} {
		var observed resetRuntimeContainer
		_, err := runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
			var err error
			observed, err = c.observeResetRuntimeContainerProject(ctx, service, r.Project)
			return "", err
		})
		if err != nil || !resetEvidenceSHA.MatchString(observed.ID) {
			return "", "", errResetExecutionEvidence
		}
		ids[service] = observed.ID
		var image resetRuntimeImage
		_, err = runResetD101CandidateCommand(ctx, admission, beforeCommand, func(ctx context.Context) (string, error) {
			out, err := c.runServerDockerContext(ctx, "image", "inspect", "--format",
				`{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, observed.ImageID)
			if err != nil || len(out) > resetEvidenceMaxBytes || json.Unmarshal([]byte(out), &image) != nil {
				return "", errResetExecutionEvidence
			}
			return "", nil
		})
		if err != nil || image.OS != "linux" || image.Architecture != "amd64" ||
			!resetRuntimePinMatches(image.RepoDigests, service, "", admission.ImagePins()[service]) {
			return "", "", errResetExecutionEvidence
		}
	}
	if ids["game-postgres"] == ids["game-redis"] {
		return "", "", errResetExecutionEvidence
	}
	return ids["game-postgres"], ids["game-redis"], nil
}

const resetD101SeedChildEntrypoint = "/app/d101-seed-only-entrypoint"

var resetD101SeedChildFiles = map[string]int64{
	"/run/d101/installation.json":      64 * 1024,
	"/run/d101/root-pins.json":         16 * 1024,
	"/run/d101/seed-approval.json":     64 * 1024,
	"/run/d101/selected-envelope.json": 96 * 1024,
	"/run/d101/configuration.json":     64 * 1024,
	"/run/d101/resolver-decision.json": 64 * 1024,
	"/run/d101/typed-target.json":      16 * 1024,
	"/run/d101/password":               4096,
}

// The material producer validates its originals at issuance. Re-read all eight
// native originals before each physical command so an intervening replacement
// cannot turn its returned path labels into authority. No password bytes escape.
func (c config) requireResetD101SeedChildBindings(material resetD101SeedChildMaterial) error {
	bindings := material.Bindings()
	if len(bindings) != len(resetD101SeedChildFiles) || !resetEvidenceSHA.MatchString(material.InstallationSHA) {
		return errResetExecutionEvidence
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		limit, allowed := resetD101SeedChildFiles[binding.ChildPath]
		host, err := resetD101SeedHostPath(c, binding.LocalPath)
		if !allowed || seen[binding.ChildPath] || err != nil || host != binding.HostPath ||
			!resetEvidenceSHA.MatchString(binding.SHA) {
			return errResetExecutionEvidence
		}
		seen[binding.ChildPath] = true
		original, err := d101custody.ReadPrivate(binding.LocalPath, limit)
		if binding.ChildPath == "/run/d101/password" {
			defer clear(original.Bytes)
		}
		if err != nil || original.SHA256 != binding.SHA {
			return errResetExecutionEvidence
		}
		if binding.ChildPath == "/run/d101/installation.json" && binding.SHA != material.InstallationSHA {
			return errResetExecutionEvidence
		}
	}
	return nil
}

func resetD101SeedChildName(op string) string { return "d101-seed-" + op }

func (c config) resetD101SeedChildCreateArgs(a resetD101CandidateAdmission, material resetD101SeedChildMaterial) ([]string, error) {
	imageRepository := "ghcr.io/" + c.ghcrOwner + "/opensamguk"
	if !validResetD101CandidateCommandAdmission(a, time.Now()) ||
		!validResetD101CandidateResources(a.CandidateResources(), a.OperationID()) ||
		!resetRuntimeRepository.MatchString(imageRepository) ||
		!resetManifestDigest.MatchString(a.ImagePins()["game-engine"]) ||
		material.PostgresContainerID == "" || net.ParseIP(material.DatabaseAddress) == nil ||
		net.ParseIP(material.DatabaseAddress).To4() == nil || len(material.Bindings()) != len(resetD101SeedChildFiles) {
		return nil, errResetExecutionEvidence
	}
	args := []string{"create", "--name", resetD101SeedChildName(a.OperationID()),
		"--network", a.CandidateResources().Network, "--user", "0:0", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges"}
	seen := map[string]bool{}
	for _, binding := range material.Bindings() {
		if _, allowed := resetD101SeedChildFiles[binding.ChildPath]; !allowed || seen[binding.ChildPath] ||
			!filepath.IsAbs(binding.HostPath) || strings.ContainsAny(binding.HostPath, ",\r\n") {
			return nil, errResetExecutionEvidence
		}
		seen[binding.ChildPath] = true
		args = append(args, "--mount", "type=bind,src="+binding.HostPath+",dst="+binding.ChildPath+",readonly")
	}
	if len(seen) != len(resetD101SeedChildFiles) {
		return nil, errResetExecutionEvidence
	}
	args = append(args, "--entrypoint", resetD101SeedChildEntrypoint,
		imageRepository+"@"+a.ImagePins()["game-engine"])
	return args, nil
}

type resetD101SeedChildJob struct {
	ID              string
	Name            string
	ImageID         string
	ImageRef        string
	Status          string
	Running         bool
	ExitCode        int
	Network         string
	User            string
	Entrypoint      []string
	Cmd             []string
	ReadOnly        bool
	Privileged      bool
	CapDrop         []string
	SecurityOptions []string
	Mounts          []resetD101CapsMount
}

const resetD101SeedChildInspectFormat = `{"id":{{json .Id}},"name":{{json .Name}},"imageId":{{json .Image}},"imageRef":{{json .Config.Image}},"status":{{json .State.Status}},"running":{{json .State.Running}},"exitCode":{{json .State.ExitCode}},"network":{{json .HostConfig.NetworkMode}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"readOnly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"capDrop":{{json .HostConfig.CapDrop}},"securityOptions":{{json .HostConfig.SecurityOpt}},"mounts":[{{range .Mounts}}{"type":{{json .Type}},"source":{{json .Source}},"destination":{{json .Destination}},"rw":{{json .RW}}},{{end}}null]}`

func decodeResetD101SeedChildJob(wire string, id string) (resetD101SeedChildJob, error) {
	var raw struct {
		ID, Name, ImageID, ImageRef, Status, Network, User string
		Running, ReadOnly, Privileged                      *bool
		ExitCode                                           *int
		Entrypoint, Cmd, CapDrop, SecurityOptions          []string
		Mounts                                             []*resetD101CapsMount
	}
	if len(wire) > 16*1024 || decodeResetPrivateJSON([]byte(wire), &raw) != nil ||
		raw.ID != id || !resetManifestDigest.MatchString(raw.ImageID) || raw.Running == nil ||
		raw.ReadOnly == nil || !*raw.ReadOnly || raw.Privileged == nil || *raw.Privileged ||
		raw.ExitCode == nil || len(raw.Entrypoint) != 1 || raw.Entrypoint[0] != resetD101SeedChildEntrypoint ||
		len(raw.Cmd) != 0 || raw.User != "0:0" || !reflect.DeepEqual(raw.CapDrop, []string{"ALL"}) ||
		len(raw.SecurityOptions) != 1 ||
		(raw.SecurityOptions[0] != "no-new-privileges" && raw.SecurityOptions[0] != "no-new-privileges=true") ||
		len(raw.Mounts) != len(resetD101SeedChildFiles)+1 || raw.Mounts[len(raw.Mounts)-1] != nil {
		return resetD101SeedChildJob{}, errResetExecutionEvidence
	}
	job := resetD101SeedChildJob{ID: raw.ID, Name: raw.Name, ImageID: raw.ImageID, ImageRef: raw.ImageRef,
		Status: raw.Status, Running: *raw.Running, ExitCode: *raw.ExitCode, Network: raw.Network,
		User: raw.User, Entrypoint: raw.Entrypoint, Cmd: raw.Cmd, ReadOnly: *raw.ReadOnly,
		Privileged: *raw.Privileged, CapDrop: raw.CapDrop, SecurityOptions: raw.SecurityOptions}
	for _, mount := range raw.Mounts[:len(raw.Mounts)-1] {
		if mount == nil {
			return resetD101SeedChildJob{}, errResetExecutionEvidence
		}
		job.Mounts = append(job.Mounts, *mount)
	}
	return job, nil
}

func requireResetD101SeedChildJob(job resetD101SeedChildJob, a resetD101CandidateAdmission,
	material resetD101SeedChildMaterial, imageRef string) error {
	if job.Name != "/"+resetD101SeedChildName(a.OperationID()) || job.ImageRef != imageRef ||
		job.Network != a.CandidateResources().Network || len(job.Mounts) != len(resetD101SeedChildFiles) {
		return errResetExecutionEvidence
	}
	wanted := map[string]string{}
	for _, binding := range material.Bindings() {
		wanted[binding.ChildPath] = binding.HostPath
	}
	for _, mount := range job.Mounts {
		if mount.Type != "bind" || mount.RW || wanted[mount.Destination] != mount.Source || mount.Source == "" {
			return errResetExecutionEvidence
		}
		delete(wanted, mount.Destination)
	}
	if len(wanted) != 0 {
		return errResetExecutionEvidence
	}
	return nil
}

func decodeResetD101SeedChildOutput(output string) ([]byte, error) {
	if len(output) == 0 || len(output) > 32*1024+len(resetD101CandidateSeedOutputPrefix)+1 ||
		!strings.HasPrefix(output, resetD101CandidateSeedOutputPrefix) || !strings.HasSuffix(output, "\n") {
		return nil, errResetExecutionEvidence
	}
	wire := strings.TrimSuffix(strings.TrimPrefix(output, resetD101CandidateSeedOutputPrefix), "\n")
	if len(wire) == 0 || len(wire) > 32*1024 || strings.ContainsAny(wire, "\r\n") {
		return nil, errResetExecutionEvidence
	}
	var receipt resetD101CandidateSeedReceipt
	if requireResetIntentShape([]byte(wire), reflect.TypeOf(receipt)) != nil ||
		decodeResetPrivateJSON([]byte(wire), &receipt) != nil || receipt.SchemaVersion != 1 ||
		receipt.Kind != "D101_SEED_ONLY_RESULT_V1" || receipt.ObservedGeneration == nil ||
		*receipt.ObservedGeneration != 0 {
		return nil, errResetExecutionEvidence
	}
	return []byte(wire), nil
}

// The only production seeder supplied to the Root pipeline. The fixed
// installation is required before storage startup; a failed child is retained
// for reconciliation and never removed or retried by this worker.
func (c config) runResetD101CandidateSeed(ctx context.Context, a resetD101CandidateAdmission,
	beforeCommand func(context.Context) error) (resetD101CandidateSeedEvidence, error) {
	closed := resetD101CandidateSeedEvidence{}
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil ||
		!validResetD101CandidateCommandAdmission(a, time.Now()) ||
		c.requireResetD101SeedMaterialInputs(a) != nil {
		return closed, errResetExecutionEvidence
	}
	pgID, redisID, err := c.prepareResetD101CandidateStorage(ctx, a, beforeCommand)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	material, err := c.prepareResetD101SeedChildMaterial(ctx, a, pgID, beforeCommand)
	if err != nil || material.PostgresContainerID != pgID {
		return closed, errResetExecutionEvidence
	}
	return c.runResetD101CandidateSeedChild(ctx, a, material, pgID, redisID, beforeCommand)
}

func (c config) runResetD101CandidateSeedChild(ctx context.Context, a resetD101CandidateAdmission,
	material resetD101SeedChildMaterial, pgID, redisID string,
	beforeCommand func(context.Context) error) (resetD101CandidateSeedEvidence, error) {
	return c.runResetD101CandidateSeedChildWithVerifier(ctx, a, material, pgID, redisID,
		beforeCommand, func() error { return c.requireResetD101SeedChildBindings(material) })
}

// The verifier seam permits isolated command-order tests; production always
// supplies the native custody verifier above. It is not an installation flag.
func (c config) runResetD101CandidateSeedChildWithVerifier(ctx context.Context, a resetD101CandidateAdmission,
	material resetD101SeedChildMaterial, pgID, redisID string,
	beforeCommand func(context.Context) error, verify func() error) (resetD101CandidateSeedEvidence, error) {
	closed := resetD101CandidateSeedEvidence{}
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil || verify == nil ||
		!resetEvidenceSHA.MatchString(pgID) || !resetEvidenceSHA.MatchString(redisID) || pgID == redisID ||
		material.PostgresContainerID != pgID || !resetEvidenceSHA.MatchString(material.InstallationSHA) ||
		verify() != nil {
		return closed, errResetExecutionEvidence
	}
	args, err := c.resetD101SeedChildCreateArgs(a, material)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	imageRef := "ghcr.io/" + c.ghcrOwner + "/opensamguk@" + a.ImagePins()["game-engine"]
	guard := func(ctx context.Context) error {
		if beforeCommand(ctx) != nil || verify() != nil {
			return errResetExecutionEvidence
		}
		return nil
	}
	bounded, cancel := context.WithDeadline(ctx, a.Cutoff())
	defer cancel()
	call := func(args ...string) (string, error) {
		return runResetD101CandidateCommand(bounded, a, guard, func(ctx context.Context) (string, error) {
			return c.runServerDockerContext(ctx, args...)
		})
	}
	out, err := call(args...)
	id := strings.TrimSpace(out)
	if err != nil || !resetEvidenceSHA.MatchString(id) {
		return closed, errResetExecutionEvidence
	}
	inspect := func() (resetD101SeedChildJob, error) {
		wire, err := call("inspect", "--format", resetD101SeedChildInspectFormat, id)
		if err != nil {
			return resetD101SeedChildJob{}, errResetExecutionEvidence
		}
		job, err := decodeResetD101SeedChildJob(wire, id)
		if err != nil || requireResetD101SeedChildJob(job, a, material, imageRef) != nil {
			return resetD101SeedChildJob{}, errResetExecutionEvidence
		}
		return job, nil
	}
	created, err := inspect()
	if err != nil || created.Status != "created" || created.Running {
		return closed, errResetExecutionEvidence
	}
	imageWire, err := call("image", "inspect", "--format",
		`{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, created.ImageID)
	var image resetRuntimeImage
	if err != nil || len(imageWire) > 16*1024 || decodeResetPrivateJSON([]byte(imageWire), &image) != nil ||
		image.OS != "linux" || image.Architecture != "amd64" ||
		!resetRuntimePinMatches(image.RepoDigests, "game-engine", "ghcr.io/"+c.ghcrOwner+"/opensamguk", a.ImagePins()["game-engine"]) {
		return closed, errResetExecutionEvidence
	}
	started := time.Now()
	if _, err := call("start", id); err != nil {
		return closed, errResetExecutionEvidence
	}
	waited, err := call("wait", id)
	if err != nil || strings.TrimSpace(waited) != "0" {
		return closed, errResetExecutionEvidence
	}
	finished, err := inspect()
	if err != nil || finished.Status != "exited" || finished.Running || finished.ExitCode != 0 ||
		finished.ImageID != created.ImageID {
		return closed, errResetExecutionEvidence
	}
	output, err := call("logs", id)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	original, err := decodeResetD101SeedChildOutput(output)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	again, err := inspect()
	completed := time.Now()
	if err != nil || !reflect.DeepEqual(finished, again) || completed.Before(started) ||
		!completed.Before(a.Cutoff()) || bounded.Err() != nil || verify() != nil {
		return closed, errResetExecutionEvidence
	}
	var receipt resetD101CandidateSeedReceipt
	if decodeResetPrivateJSON(original, &receipt) != nil || receipt.OriginalOp != a.OperationID() ||
		receipt.ApprovalIntentSHA != a.ApprovalIntentSHA() || receipt.TargetFingerprint != a.TargetFingerprint() ||
		receipt.AppSourceSHA != a.AppSourceSHA() || !reflect.DeepEqual(receipt.ImagePins, a.ImagePins()) ||
		receipt.SelectedSourceReceiptSHA != a.SelectedSourceReceiptSHA() ||
		!resetEvidenceSHA.MatchString(receipt.OptionProvenance["SERVER_GENERATION"]) {
		return closed, errResetExecutionEvidence
	}
	evidence := resetD101CandidateSeedEvidence{WorkerContainerID: id, PostgresContainerID: pgID,
		RedisContainerID: redisID, WorkerImageID: created.ImageID, WorkerRepoDigest: imageRef,
		SelectedSourceReceiptSHA: receipt.SelectedSourceReceiptSHA,
		GenerationProvenanceSHA:  receipt.OptionProvenance["SERVER_GENERATION"],
		ActualGeneration:         "0", StartedAt: started, CompletedAt: completed, Original: original}
	if requireResetD101CandidateEvidenceEnvelope(a, evidence) != nil {
		return closed, errResetExecutionEvidence
	}
	return evidence, nil
}
