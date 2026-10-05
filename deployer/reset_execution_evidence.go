package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const resetEvidenceMaxBytes = 64 * 1024
const resetPreflightMaxAge = 30 * time.Second

var resetEvidenceSHA = regexp.MustCompile("^[a-f0-9]{64}$")
var errResetExecutionEvidence = errors.New("reset execution evidence is unavailable")

// Private local custody does not attest upstream CI, human approval or drain.
// Only the exact approved host issuing procedure can supply those proofs.
type resetApprovalPlan struct {
	Version                    int                  `json:"version"`
	ServerID                   string               `json:"serverId"`
	WorldID                    int                  `json:"worldId"`
	OperationID                string               `json:"operationId"`
	TargetFingerprint          string               `json:"targetFingerprint"`
	AppSourceSHA               string               `json:"appSourceSha"`
	Target                     resetLifecycleTarget `json:"target"`
	OldImageDigests            map[string]string    `json:"oldImageDigests"`
	NewImageDigests            map[string]string    `json:"newImageDigests"`
	WindowOpensAtUnix          int64                `json:"windowOpensAtUnix"`
	DestructiveCutoffUnix      int64                `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix       int64                `json:"recoveryDeadlineUnix"`
	ApprovalReceiptSHA         string               `json:"approvalReceiptSha256"`
	CombinedCIReceiptSHA       string               `json:"combinedCiReceiptSha256"`
	SelectedSourceReceiptSHA   string               `json:"selectedSourceReceiptSha256"`
	IsolatedSeedTickReceiptSHA string               `json:"isolatedSeedTickReceiptSha256"`
	WriterFreezeReceiptSHA     string               `json:"writerFreezeReceiptSha256"`
	SpaceInventoryReceiptSHA   string               `json:"spaceInventoryReceiptSha256"`
	SpaceBudget                resetSpaceBudget     `json:"spaceBudget"`
}

type resetPreflightReceipt struct {
	Version                  int               `json:"version"`
	ServerID                 string            `json:"serverId"`
	WorldID                  int               `json:"worldId"`
	OperationID              string            `json:"operationId"`
	TargetFingerprint        string            `json:"targetFingerprint"`
	ApprovalPlanSHA          string            `json:"approvalPlanSha256"`
	AppSourceSHA             string            `json:"appSourceSha"`
	NewImageDigests          map[string]string `json:"newImageDigests"`
	OldImageDigests          map[string]string `json:"oldImageDigests"`
	ObservedAtUnix           int64             `json:"observedAtUnix"`
	ExpiresAtUnix            int64             `json:"expiresAtUnix"`
	PublicationState         string            `json:"publicationState"`
	PublicationRevision      string            `json:"publicationRevision"`
	WriterFreezeReceiptSHA   string            `json:"writerFreezeReceiptSha256"`
	DrainReceiptSHA          string            `json:"drainReceiptSha256"`
	BackupManifestSHA        string            `json:"backupManifestSha256"`
	BackupRetainUntilUnix    int64             `json:"backupRetainUntilUnix"`
	RestoreVerified          *bool             `json:"restoreVerified"`
	FilesystemDevice         *uint64           `json:"filesystemDevice"`
	AvailableBytes           *uint64           `json:"availableBytes"`
	AvailableInodes          *uint64           `json:"availableInodes"`
	UnfinishedTemporaryBytes *uint64           `json:"unfinishedTemporaryBytes"`
	RemainingNewFileCount    *uint64           `json:"remainingNewFileCount"`
	StoppedContainerIDs      map[string]string `json:"stoppedContainerIds"`
	DatabaseClientCount      *uint64           `json:"databaseClientCount"`
}

func validResetFiveImageDigests(pins map[string]string) bool {
	if len(pins) != 5 {
		return false
	}
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		if !resetManifestDigest.MatchString(pins[service]) {
			return false
		}
	}
	return true
}

func validateResetApprovalPlan(plan resetApprovalPlan, op string, target resetLifecycleTarget, now time.Time) error {
	normalizedOp, err := normalizeLifecycleOperationID(op)
	if err != nil || normalizedOp == "" || normalizedOp != op || plan.Version != 1 || plan.ServerID != "pep" || plan.WorldID != 1 ||
		plan.OperationID != op || !gitSHA40.MatchString(plan.AppSourceSHA) ||
		plan.TargetFingerprint != resetRequestFingerprint("pep", target) || !reflect.DeepEqual(plan.Target, target) ||
		plan.Target.Updates["IMAGE_TAG"] != plan.AppSourceSHA || plan.Target.Updates["WEB_GAME_TAG"] != plan.AppSourceSHA ||
		!validResetFiveImageDigests(plan.OldImageDigests) || !validResetFiveImageDigests(plan.NewImageDigests) {
		return errResetExecutionEvidence
	}
	for _, service := range resetImageServices {
		if target.ImageDigests[service] != plan.NewImageDigests[service] {
			return errResetExecutionEvidence
		}
	}
	if target.ScenarioCode != "scenario_3190" || target.Generation != 0 || !target.ScenarioSeedEnabled ||
		len(target.StorageImageDigests) != 2 {
		return errResetExecutionEvidence
	}
	settings := map[string]string{"SERVER_NAME": "빼섭", "RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate", "SCENARIO_LOOKUP_DIR": "", "RESET_TURNTERM": "60", "RESET_EXTEND": "1", "RESET_BLOCK_GENERAL_CREATE": "1", "RESET_NPCMODE": "0", "RESET_SHOW_IMG_LEVEL": "3"}
	for key, want := range settings {
		actual, explicit := target.Updates[key]
		if !explicit || actual != want {
			return errResetExecutionEvidence
		}
	}
	for _, service := range resetStorageServices {
		if target.StorageImageDigests[service] != plan.NewImageDigests[service] {
			return errResetExecutionEvidence
		}
	}
	for _, proof := range []string{plan.ApprovalReceiptSHA, plan.CombinedCIReceiptSHA, plan.SelectedSourceReceiptSHA,
		plan.IsolatedSeedTickReceiptSHA, plan.WriterFreezeReceiptSHA, plan.SpaceInventoryReceiptSHA} {
		if !resetEvidenceSHA.MatchString(proof) {
			return errResetExecutionEvidence
		}
	}
	if plan.WindowOpensAtUnix <= 0 || plan.WindowOpensAtUnix >= plan.DestructiveCutoffUnix ||
		plan.DestructiveCutoffUnix >= plan.RecoveryDeadlineUnix || now.Before(time.Unix(plan.WindowOpensAtUnix, 0)) ||
		!now.Before(time.Unix(plan.DestructiveCutoffUnix, 0)) {
		return errResetExecutionEvidence
	}
	if _, err := resetRequiredSpace(plan.SpaceBudget); err != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func validateResetPreflight(receipt resetPreflightReceipt, plan resetApprovalPlan, planSHA string, now time.Time) error {
	revision, revisionErr := strconv.ParseInt(receipt.PublicationRevision, 10, 64)
	if receipt.Version != 1 || receipt.ServerID != plan.ServerID || receipt.WorldID != plan.WorldID ||
		receipt.OperationID != plan.OperationID || receipt.TargetFingerprint != plan.TargetFingerprint ||
		!resetEvidenceSHA.MatchString(planSHA) || receipt.ApprovalPlanSHA != planSHA || receipt.AppSourceSHA != plan.AppSourceSHA ||
		!reflect.DeepEqual(receipt.NewImageDigests, plan.NewImageDigests) || !reflect.DeepEqual(receipt.OldImageDigests, plan.OldImageDigests) ||
		receipt.PublicationState != "VERIFYING" || revisionErr != nil || revision <= 0 || strconv.FormatInt(revision, 10) != receipt.PublicationRevision ||
		receipt.WriterFreezeReceiptSHA != plan.WriterFreezeReceiptSHA || !resetEvidenceSHA.MatchString(receipt.DrainReceiptSHA) ||
		!resetEvidenceSHA.MatchString(receipt.BackupManifestSHA) || receipt.RestoreVerified == nil || *receipt.RestoreVerified ||
		receipt.FilesystemDevice == nil || receipt.DatabaseClientCount == nil || *receipt.DatabaseClientCount != 0 {
		return errResetExecutionEvidence
	}
	// Host and container share the Unix clock. Future observations fail closed.
	observed, expiry := time.Unix(receipt.ObservedAtUnix, 0), time.Unix(receipt.ExpiresAtUnix, 0)
	if receipt.ObservedAtUnix < plan.WindowOpensAtUnix || observed.After(now) || now.Sub(observed) >= resetPreflightMaxAge ||
		!expiry.After(observed) || expiry.Sub(observed) > resetPreflightMaxAge || !now.Before(expiry) ||
		receipt.ExpiresAtUnix > plan.DestructiveCutoffUnix || receipt.BackupRetainUntilUnix < receipt.ObservedAtUnix+7*24*60*60 {
		return errResetExecutionEvidence
	}
	if len(receipt.StoppedContainerIDs) != 5 {
		return errResetExecutionEvidence
	}
	ids := make(map[string]bool)
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		id := receipt.StoppedContainerIDs[service]
		if !resetEvidenceSHA.MatchString(id) || ids[id] {
			return errResetExecutionEvidence
		}
		ids[id] = true
	}
	if receipt.UnfinishedTemporaryBytes == nil || receipt.RemainingNewFileCount == nil ||
		plan.SpaceBudget.TemporaryBytes == nil || plan.SpaceBudget.NewFileCount == nil ||
		*receipt.UnfinishedTemporaryBytes > *plan.SpaceBudget.TemporaryBytes ||
		*receipt.RemainingNewFileCount > *plan.SpaceBudget.NewFileCount {
		return errResetExecutionEvidence
	}
	if err := verifyResetRemainingSpace(plan.SpaceBudget.RecoveryBytes, receipt.UnfinishedTemporaryBytes,
		receipt.RemainingNewFileCount, plan.SpaceBudget.InodeReserve,
		resetSpaceObservation{AvailableBytes: receipt.AvailableBytes, AvailableInodes: receipt.AvailableInodes}); err != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// The production caller fixes uid=0. Tests supply their current UID.
// Root is the trusted issuer. This reader cannot attest a compromised root.
func readResetPrivateEvidence(directory, operationID, expectedSHA string, uid uint32, into any) error {
	if !resetEvidenceSHA.MatchString(expectedSHA) {
		return errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(directory, operationID, uid)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != expectedSHA {
		return errResetExecutionEvidence
	}
	return decodeResetPrivateJSON(wire, into)
}

func readResetPrivateCustody(directory, operationID string, uid uint32) ([]byte, error) {
	op, opErr := normalizeLifecycleOperationID(operationID)
	if !filepath.IsAbs(directory) || opErr != nil || op == "" || op != operationID {
		return nil, errResetExecutionEvidence
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != filepath.Clean(directory) {
		return nil, errResetExecutionEvidence
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return nil, errResetExecutionEvidence
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || dirStat.Uid != uid {
		return nil, errResetExecutionEvidence
	}
	path := filepath.Join(directory, operationID+".json")
	// O_NOFOLLOW closes the leaf symlink race. Parent custody is root-only.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() <= 0 || info.Size() > resetEvidenceMaxBytes {
		return nil, errResetExecutionEvidence
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Nlink != 1 {
		return nil, errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(file, resetEvidenceMaxBytes+1))
	if err != nil || len(wire) > resetEvidenceMaxBytes {
		return nil, errResetExecutionEvidence
	}
	after, err := file.Stat()
	dirAfter, dirErr := os.Lstat(directory)
	if err != nil || dirErr != nil || !os.SameFile(info, after) || info.Size() != after.Size() ||
		!info.ModTime().Equal(after.ModTime()) || !os.SameFile(dirInfo, dirAfter) {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}

func decodeResetPrivateJSON(wire []byte, into any) error {
	if rejectResetDuplicateJSONKeys(wire) != nil {
		return errResetExecutionEvidence
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(into) != nil {
		return errResetExecutionEvidence
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errResetExecutionEvidence
	}
	return nil
}

func rejectResetDuplicateJSONKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		if delimiter != '{' && delimiter != '[' {
			return errResetExecutionEvidence
		}
		keys := make(map[string]bool)
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return errResetExecutionEvidence
				}
				keys[name] = true
			}
			if err := readValue(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := readValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errResetExecutionEvidence
	}
	return nil
}
