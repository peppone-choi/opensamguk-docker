package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type resetExecutionEvidenceRefs struct {
	ApprovalPlanSHA     string `json:"approvalPlanSha256,omitempty"`
	ExecutionReceiptSHA string `json:"executionReceiptSha256,omitempty"`
}

type resetExecutionEvidence struct {
	Plan      resetApprovalPlan
	Preflight resetPreflightReceipt
}

// Every new execution phase calls this function again. A prior successful read
// grants no later mutation. This source is not an operating approval.
func (c config) readResetExecutionEvidence(operationID string, target resetLifecycleTarget, refs resetExecutionEvidenceRefs, now time.Time) (resetExecutionEvidence, error) {
	var evidence resetExecutionEvidence
	if !resetEvidenceSHA.MatchString(refs.ApprovalPlanSHA) || !resetEvidenceSHA.MatchString(refs.ExecutionReceiptSHA) {
		return evidence, errResetExecutionEvidence
	}
	if err := readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), operationID, refs.ApprovalPlanSHA, 0, &evidence.Plan); err != nil {
		return evidence, errResetExecutionEvidence
	}
	if err := validateResetApprovalPlan(evidence.Plan, operationID, target, now); err != nil {
		return evidence, errResetExecutionEvidence
	}
	if err := readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-preflights"), operationID, refs.ExecutionReceiptSHA, 0, &evidence.Preflight); err != nil {
		return evidence, errResetExecutionEvidence
	}
	if err := validateResetPreflight(evidence.Preflight, evidence.Plan, refs.ApprovalPlanSHA, now); err != nil {
		return evidence, errResetExecutionEvidence
	}
	return evidence, nil
}

// The bind-mounted stack/backup filesystem is read now, not copied from JSON.
// DockerDataRoot's same-device relationship must also be attested by the locked
// host issuer: the sidecar cannot infer it from its remote socket-proxy.
func observeResetFilesystem(path string) (uint64, resetSpaceObservation, error) {
	var fs syscall.Statfs_t
	var stat syscall.Stat_t
	if syscall.Statfs(path, &fs) != nil || syscall.Stat(path, &stat) != nil || fs.Bsize <= 0 {
		return 0, resetSpaceObservation{}, errResetExecutionEvidence
	}
	bytes, err := checkedResetSpaceProduct(uint64(fs.Bavail), uint64(fs.Bsize))
	if err != nil {
		return 0, resetSpaceObservation{}, errResetExecutionEvidence
	}
	inodes := uint64(fs.Ffree)
	return uint64(stat.Dev), resetSpaceObservation{AvailableBytes: &bytes, AvailableInodes: &inodes}, nil
}

func checkedResetSpaceProduct(left, right uint64) (uint64, error) {
	if right != 0 && left > ^uint64(0)/right {
		return 0, errResetExecutionEvidence
	}
	return left * right, nil
}

// No Docker pull/build/up/stop/delete is performed here. All five old containers
// must already be stopped by the approved host procedure and match the receipt.
func (c config) verifyResetStoppedContainers(ctx context.Context, evidence resetExecutionEvidence) error {
	const format = `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"status":{{json .State.Status}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}`
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		if ctx.Err() != nil {
			return errResetExecutionEvidence
		}
		out, err := c.runServerDockerContext(ctx, "inspect", "--format", format, "spep-"+service)
		if err != nil {
			return errResetExecutionEvidence
		}
		var observed struct {
			ID      string `json:"id"`
			Image   string `json:"image"`
			Running *bool  `json:"running"`
			Status  string `json:"status"`
			Project string `json:"project"`
			Service string `json:"service"`
		}
		if json.Unmarshal([]byte(out), &observed) != nil || observed.ID != evidence.Preflight.StoppedContainerIDs[service] ||
			observed.Running == nil || *observed.Running || observed.Status != "exited" || observed.Project != "opensamguk-spep" ||
			observed.Service != service || !resetManifestDigest.MatchString(observed.Image) {
			return errResetExecutionEvidence
		}
		imageOut, err := c.runServerDockerContext(ctx, "image", "inspect", "--format", "{{json .RepoDigests}}", observed.Image)
		if err != nil {
			return errResetExecutionEvidence
		}
		var digests []string
		if json.Unmarshal([]byte(imageOut), &digests) != nil {
			return errResetExecutionEvidence
		}
		matched := false
		for _, digest := range digests {
			if strings.HasSuffix(digest, "@"+evidence.Plan.OldImageDigests[service]) {
				matched = true
			}
		}
		if !matched {
			return errResetExecutionEvidence
		}
	}
	return nil
}

func (c config) verifyResetLiveSpace(evidence resetExecutionEvidence) error {
	device, observed, err := observeResetFilesystem(c.composeDir)
	if err != nil || evidence.Preflight.FilesystemDevice == nil || device != *evidence.Preflight.FilesystemDevice {
		return errResetExecutionEvidence
	}
	backup := filepath.Join(c.composeDir, "backups", "pep", evidence.Plan.OperationID)
	info, err := os.Lstat(backup)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errResetExecutionEvidence
	}
	backupDevice, _, err := observeResetFilesystem(backup)
	if err != nil || backupDevice != device {
		return errResetExecutionEvidence
	}
	return verifyResetRemainingSpace(evidence.Plan.SpaceBudget.RecoveryBytes, evidence.Preflight.UnfinishedTemporaryBytes,
		evidence.Preflight.RemainingNewFileCount, evidence.Plan.SpaceBudget.InodeReserve, observed)
}

func (c config) verifyResetInitialExecutionGuard(ctx context.Context, operationID string, target resetLifecycleTarget, refs resetExecutionEvidenceRefs) error {
	evidence, err := c.readResetExecutionEvidence(operationID, target, refs, time.Now())
	if err != nil {
		return errResetExecutionEvidence
	}
	// Every command respects the same absolute deletion cutoff; never spend a
	// fresh five-minute Docker budget beyond the approved stage deadline.
	phaseCtx, cancel := context.WithDeadline(ctx, time.Unix(evidence.Plan.DestructiveCutoffUnix, 0))
	defer cancel()
	if c.verifyResetStoppedContainers(phaseCtx, evidence) != nil || c.verifyResetLiveSpace(evidence) != nil {
		return errResetExecutionEvidence
	}
	// Slow observations must not grant a phase after the preflight has expired.
	if phaseCtx.Err() != nil || validateResetApprovalPlan(evidence.Plan, operationID, target, time.Now()) != nil ||
		validateResetPreflight(evidence.Preflight, evidence.Plan, refs.ApprovalPlanSHA, time.Now()) != nil {
		return errResetExecutionEvidence
	}
	return nil
}
