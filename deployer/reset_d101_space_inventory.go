package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"
)

// Pre-intent leaf: no later intent/card/manifest hash may be required here.
type resetD101SpaceSourceReference struct {
	LogicalArtifactID string `json:"logicalArtifactId"`
	RawSHA            string `json:"rawSha256"`
	ByteLength        uint64 `json:"byteLength"`
}
type resetD101SpaceBudgetInventory struct {
	SchemaVersion     int                                      `json:"schemaVersion"`
	Kind              string                                   `json:"kind"`
	OperationID       string                                   `json:"operationId"`
	TargetFingerprint string                                   `json:"typedTargetFingerprint"`
	AppSourceSHA      string                                   `json:"appSourceSha"`
	DockerSourceSHA   string                                   `json:"dockerSourceSha"`
	OldImageDigests   map[string]string                        `json:"oldImageDigests"`
	NewImageDigests   map[string]string                        `json:"newImageDigests"`
	SpaceBudget       resetSpaceBudget                         `json:"spaceBudget"`
	SourceReferences  map[string]resetD101SpaceSourceReference `json:"sourceReferences"`
}
type resetD101SpaceFilesystem struct {
	Device          string `json:"device"`
	AvailableBytes  uint64 `json:"availableBytes"`
	AvailableInodes uint64 `json:"availableInodes"`
	ObservedAtUTC   string `json:"observedAtUtc"`
}
type resetD101SpaceInventoryReceipt struct {
	SchemaVersion          int                                 `json:"schemaVersion"`
	Kind                   string                              `json:"kind"`
	OperationID            string                              `json:"operationId"`
	TargetFingerprint      string                              `json:"typedTargetFingerprint"`
	AppSourceSHA           string                              `json:"appSourceSha"`
	DockerSourceSHA        string                              `json:"dockerSourceSha"`
	OldImageDigests        map[string]string                   `json:"oldImageDigests"`
	NewImageDigests        map[string]string                   `json:"newImageDigests"`
	Stage                  string                              `json:"stage"`
	BudgetInventorySHA     string                              `json:"budgetInventorySha256"`
	SpaceBudget            resetSpaceBudget                    `json:"spaceBudget"`
	FilesystemPaths        map[string]string                   `json:"filesystemPaths"`
	FilesystemObservations map[string]resetD101SpaceFilesystem `json:"filesystemObservations"`
	RequiredBytes          uint64                              `json:"requiredBytes"`
	RequiredInodes         uint64                              `json:"requiredInodes"`
	ObservedAtUTC          string                              `json:"observedAtUtc"`
	ProducerIdentity       string                              `json:"producerIdentity"`
	Scope                  string                              `json:"scope"`
}

// Supplied by the fixed native installer, never an HTTP body or env flag.
type resetD101SpaceInventoryPins struct {
	BudgetDirectory   string
	BudgetSHA         string
	OperationID       string
	TargetFingerprint string
	AppSourceSHA      string
	DockerSourceSHA   string
	OldImageDigests   map[string]string
	NewImageDigests   map[string]string
	SourceDirectories map[string]string
	FilesystemPaths   map[string]string
	ProducerIdentity  string
}
type resetD101SpaceBudgetEvidence struct {
	budget   resetD101SpaceBudgetInventory
	original []byte
	sources  map[string][]byte
}

func (v resetD101SpaceBudgetEvidence) BudgetOriginal() []byte {
	return append([]byte(nil), v.original...)
}
func (v resetD101SpaceBudgetEvidence) SourceOriginal(id string) ([]byte, error) {
	original, ok := v.sources[id]
	if !ok {
		return nil, errResetExecutionEvidence
	}
	return append([]byte(nil), original...), nil
}

// This independent verifier establishes actual unpacked/backup/recovery/temp
// upper bounds and file/inode projections from the supplied originals. Statfs
// cannot establish these allocations. Missing verifier always denies issuance.
type resetD101SpaceBudgetVerifier func(context.Context, resetD101SpaceBudgetEvidence) error

var resetD101SpaceSourceIDs = []string{"candidate", "backup", "recovery", "temporary"}
var resetD101SpaceFilesystemIDs = []string{"servers", "backup", "candidate", "dockerDataRoot"}

func decodeResetD101SpaceBudgetInventory(wire []byte, pins resetD101SpaceInventoryPins) (resetD101SpaceBudgetInventory, error) {
	var value resetD101SpaceBudgetInventory
	if len(wire) == 0 || len(wire) > 32*1024 || !utf8.Valid(wire) || !resetEvidenceSHA.MatchString(pins.BudgetSHA) || resetD101OriginalSHA(wire) != pins.BudgetSHA ||
		requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_SPACE_BUDGET_INVENTORY_V1" ||
		!lifecycleJobIDRe.MatchString(value.OperationID) || value.OperationID != pins.OperationID || !resetEvidenceSHA.MatchString(value.TargetFingerprint) || value.TargetFingerprint != pins.TargetFingerprint ||
		!gitSHA40.MatchString(value.AppSourceSHA) || value.AppSourceSHA != pins.AppSourceSHA || !gitSHA40.MatchString(value.DockerSourceSHA) || value.DockerSourceSHA != pins.DockerSourceSHA ||
		!validResetFiveImageDigests(value.OldImageDigests) || !validResetFiveImageDigests(value.NewImageDigests) || !reflect.DeepEqual(value.OldImageDigests, pins.OldImageDigests) || !reflect.DeepEqual(value.NewImageDigests, pins.NewImageDigests) || len(value.SourceReferences) != 4 {
		return resetD101SpaceBudgetInventory{}, errResetExecutionEvidence
	}
	if _, err := resetRequiredSpace(value.SpaceBudget); err != nil {
		return resetD101SpaceBudgetInventory{}, errResetExecutionEvidence
	}
	for _, id := range resetD101SpaceSourceIDs {
		ref, ok := value.SourceReferences[id]
		if !ok || ref.LogicalArtifactID != id || !resetEvidenceSHA.MatchString(ref.RawSHA) || ref.ByteLength == 0 || ref.ByteLength > resetEvidenceMaxBytes {
			return resetD101SpaceBudgetInventory{}, errResetExecutionEvidence
		}
	}
	return value, nil
}

func decodeResetD101SpaceInventoryReceipt(wire []byte, sha string, pins resetD101SpaceInventoryPins, budget resetD101SpaceBudgetInventory, now time.Time) (resetD101SpaceInventoryReceipt, error) {
	var value resetD101SpaceInventoryReceipt
	if len(wire) == 0 || len(wire) > 32*1024 || !utf8.Valid(wire) || !resetEvidenceSHA.MatchString(sha) || resetD101OriginalSHA(wire) != sha ||
		requireResetIntentShape(wire, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(wire, &value) != nil || value.SchemaVersion != 1 || value.Kind != "D101_SPACE_INVENTORY_V1" || value.Stage != "BEFORE_ADMISSION" || value.Scope != "HOST_STATFS_ONLY" ||
		value.OperationID != budget.OperationID || value.TargetFingerprint != budget.TargetFingerprint || value.AppSourceSHA != budget.AppSourceSHA || value.DockerSourceSHA != budget.DockerSourceSHA ||
		!reflect.DeepEqual(value.OldImageDigests, budget.OldImageDigests) || !reflect.DeepEqual(value.NewImageDigests, budget.NewImageDigests) || value.BudgetInventorySHA != pins.BudgetSHA || !reflect.DeepEqual(value.SpaceBudget, budget.SpaceBudget) ||
		value.ProducerIdentity != pins.ProducerIdentity || !resetD101KeyID.MatchString(value.ProducerIdentity) || !reflect.DeepEqual(value.FilesystemPaths, pins.FilesystemPaths) || len(value.FilesystemPaths) != 4 || len(value.FilesystemObservations) != 4 || now.Unix() <= 0 {
		return resetD101SpaceInventoryReceipt{}, errResetExecutionEvidence
	}
	required, err := resetRequiredSpace(budget.SpaceBudget)
	observed, timeErr := resetD101RecoveryUTC(value.ObservedAtUTC)
	if err != nil || timeErr != nil || observed.After(now) || value.RequiredBytes != required.Bytes || value.RequiredInodes != required.Inodes {
		return resetD101SpaceInventoryReceipt{}, errResetExecutionEvidence
	}
	device := ""
	for _, id := range resetD101SpaceFilesystemIDs {
		path, exists := value.FilesystemPaths[id]
		fs, ok := value.FilesystemObservations[id]
		dev, devErr := strconv.ParseUint(fs.Device, 10, 64)
		at, atErr := resetD101RecoveryUTC(fs.ObservedAtUTC)
		if !exists || !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path || devErr != nil || dev == 0 || strconv.FormatUint(dev, 10) != fs.Device || (device != "" && device != fs.Device) || atErr != nil || at.After(observed) || observed.Sub(at) >= resetPreflightMaxAge ||
			fs.AvailableBytes < required.Bytes || fs.AvailableInodes < required.Inodes {
			return resetD101SpaceInventoryReceipt{}, errResetExecutionEvidence
		}
		device = fs.Device
	}
	return value, nil
}

func produceResetD101SpaceInventory(ctx context.Context, pins resetD101SpaceInventoryPins, verify resetD101SpaceBudgetVerifier) ([]byte, string, error) {
	return produceResetD101SpaceInventoryWithSources(ctx, pins, verify, 0, observeResetFilesystem, time.Now)
}

// UID/observer/clock seams belong to isolated fixtures. Production always uses
// UID0 and current native Statfs/Stat, including the actual Docker data root.
func produceResetD101SpaceInventoryWithSources(ctx context.Context, pins resetD101SpaceInventoryPins, verify resetD101SpaceBudgetVerifier, uid uint32,
	observe func(string) (uint64, resetSpaceObservation, error), clock func() time.Time) ([]byte, string, error) {
	if ctx == nil || ctx.Err() != nil || verify == nil || observe == nil || clock == nil || len(pins.SourceDirectories) != 4 || len(pins.FilesystemPaths) != 4 || !resetD101KeyID.MatchString(pins.ProducerIdentity) {
		return nil, "", errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	startedMonotonic := time.Now()
	started := clock()
	// Freeze installer maps before passing a separate evidence copy to verifier.
	cloneMap := func(input map[string]string) map[string]string {
		result := make(map[string]string, len(input))
		for id, value := range input {
			result[id] = value
		}
		return result
	}
	pins.SourceDirectories = cloneMap(pins.SourceDirectories)
	pins.FilesystemPaths = cloneMap(pins.FilesystemPaths)
	pins.OldImageDigests = cloneMap(pins.OldImageDigests)
	pins.NewImageDigests = cloneMap(pins.NewImageDigests)
	budgetWire, err := readResetPrivateCustody(pins.BudgetDirectory, pins.OperationID, uid)
	budget, decodeErr := decodeResetD101SpaceBudgetInventory(budgetWire, pins)
	if err != nil || decodeErr != nil {
		return nil, "", errResetExecutionEvidence
	}
	sources := make(map[string][]byte, 4)
	paths := map[string]bool{filepath.Join(pins.BudgetDirectory, pins.OperationID+".json"): true}
	for _, id := range resetD101SpaceSourceIDs {
		dir := pins.SourceDirectories[id]
		path := filepath.Join(dir, pins.OperationID+".json")
		original, readErr := readResetPrivateCustody(dir, pins.OperationID, uid)
		ref := budget.SourceReferences[id]
		if readErr != nil || paths[path] || uint64(len(original)) != ref.ByteLength || resetD101OriginalSHA(original) != ref.RawSHA {
			return nil, "", errResetExecutionEvidence
		}
		paths[path] = true
		sources[id] = original
	}
	verifierSources := make(map[string][]byte, 4)
	for id, wire := range sources {
		verifierSources[id] = append([]byte(nil), wire...)
	}
	// Fresh decode prevents verifier mutation from changing later comparisons.
	verifierBudget, budgetErr := decodeResetD101SpaceBudgetInventory(budgetWire, pins)
	if budgetErr != nil || verify(bounded, resetD101SpaceBudgetEvidence{verifierBudget, append([]byte(nil), budgetWire...), verifierSources}) != nil || bounded.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	filesystems := make(map[string]resetD101SpaceFilesystem, 4)
	for _, id := range resetD101SpaceFilesystemIDs {
		path := pins.FilesystemPaths[id]
		resolved, resolveErr := filepath.EvalSymlinks(path)
		before, statErr := os.Lstat(path)
		if resolveErr != nil || resolved != path || statErr != nil || !before.IsDir() || before.Mode().Perm()&0022 != 0 {
			return nil, "", errResetExecutionEvidence
		}
		stat, ok := before.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uid {
			return nil, "", errResetExecutionEvidence
		}
		device, space, observeErr := observe(path)
		at := clock()
		after, afterErr := os.Lstat(path)
		if observeErr != nil || device == 0 || uint64(stat.Dev) != device || space.AvailableBytes == nil || space.AvailableInodes == nil || afterErr != nil || !os.SameFile(before, after) || after.Mode().Perm() != before.Mode().Perm() || at.Before(started) || at.Sub(started) >= resetPreflightMaxAge || bounded.Err() != nil || verifyResetSpaceBudget(budget.SpaceBudget, space) != nil {
			return nil, "", errResetExecutionEvidence
		}
		afterStat, ok := after.Sys().(*syscall.Stat_t)
		if !ok || afterStat.Uid != uid {
			return nil, "", errResetExecutionEvidence
		}
		filesystems[id] = resetD101SpaceFilesystem{strconv.FormatUint(device, 10), *space.AvailableBytes, *space.AvailableInodes, at.UTC().Format(time.RFC3339Nano)}
	}
	budgetAfter, afterErr := readResetPrivateCustody(pins.BudgetDirectory, pins.OperationID, uid)
	if afterErr != nil || !bytes.Equal(budgetWire, budgetAfter) {
		return nil, "", errResetExecutionEvidence
	}
	for _, id := range resetD101SpaceSourceIDs {
		after, err := readResetPrivateCustody(pins.SourceDirectories[id], pins.OperationID, uid)
		if err != nil || !bytes.Equal(sources[id], after) {
			return nil, "", errResetExecutionEvidence
		}
	}
	completed := clock()
	required, requiredErr := resetRequiredSpace(budget.SpaceBudget)
	if requiredErr != nil || completed.Before(started) || completed.Sub(started) >= resetPreflightMaxAge || time.Since(startedMonotonic) >= resetPreflightMaxAge || bounded.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	value := resetD101SpaceInventoryReceipt{1, "D101_SPACE_INVENTORY_V1", budget.OperationID, budget.TargetFingerprint, budget.AppSourceSHA, budget.DockerSourceSHA, budget.OldImageDigests, budget.NewImageDigests, "BEFORE_ADMISSION", pins.BudgetSHA, budget.SpaceBudget, pins.FilesystemPaths, filesystems, required.Bytes, required.Inodes, completed.UTC().Format(time.RFC3339Nano), pins.ProducerIdentity, "HOST_STATFS_ONLY"}
	wire, marshalErr := json.Marshal(value)
	sha := resetD101OriginalSHA(wire)
	if marshalErr != nil {
		return nil, "", errResetExecutionEvidence
	}
	if _, err := decodeResetD101SpaceInventoryReceipt(wire, sha, pins, budget, completed); err != nil {
		return nil, "", errResetExecutionEvidence
	}
	return wire, sha, nil
}
