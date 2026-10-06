package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// All fields are non-secret immutable proof references/observations. No token,
// private path, environment, arbitrary URL or response projection is returned.
type resetPublicationReceipt struct {
	Version                    int                   `json:"version"`
	ServerID                   string                `json:"serverId"`
	WorldID                    int                   `json:"worldId"`
	OperationID                string                `json:"operationId"`
	Generation                 *int                  `json:"generation"`
	ScenarioCode               string                `json:"scenarioCode"`
	TargetFingerprint          string                `json:"targetFingerprint"`
	PublicationRevision        string                `json:"publicationRevision"`
	AppSourceSHA               string                `json:"appSourceSha"`
	ImageDigests               map[string]string     `json:"imageDigests"`
	SelectedSourceReceiptSHA   string                `json:"selectedSourceReceiptSha256"`
	IsolatedSeedTickReceiptSHA string                `json:"isolatedSeedTickReceiptSha256"`
	ActualRuntimeReceiptSHA    string                `json:"actualRuntimeReceiptSha256"`
	FirstTickReceiptSHA        string                `json:"firstTickReceiptSha256"`
	RoleValidationReceiptSHA   string                `json:"roleValidationReceiptSha256"`
	BackupManifestSHA          string                `json:"backupManifestSha256"`
	IssuedAtUnix               int64                 `json:"issuedAtUnix"`
	ExpiresAtUnix              int64                 `json:"expiresAtUnix"`
	Execution                  resetExecutionJournal `json:"execution"`
}

var resetPublicationReceiptReadSlots = make(chan struct{}, 2)

func validateResetPublicationReceipt(receipt resetPublicationReceipt, evidence resetExecutionEvidence, record durableOperationRecord, now time.Time) error {
	plan, preflight := evidence.Plan, evidence.Preflight
	if receipt.Version != 1 || receipt.ServerID != "pep" || receipt.WorldID != 1 || receipt.OperationID != plan.OperationID ||
		record.OperationID != plan.OperationID || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobSucceeded ||
		receipt.Generation == nil || *receipt.Generation != 0 || receipt.ScenarioCode != "scenario_3190" || receipt.TargetFingerprint != plan.TargetFingerprint ||
		receipt.PublicationRevision != preflight.PublicationRevision || receipt.AppSourceSHA != plan.AppSourceSHA ||
		receipt.SelectedSourceReceiptSHA != plan.SelectedSourceReceiptSHA || receipt.IsolatedSeedTickReceiptSHA != plan.IsolatedSeedTickReceiptSHA ||
		receipt.BackupManifestSHA != preflight.BackupManifestSHA || !validResetFiveImageDigests(receipt.ImageDigests) ||
		receipt.Execution.AcceptedAtUnix != record.CreatedAt.Unix() || receipt.Execution.RequestFingerprint != record.RequestFingerprint ||
		len(receipt.Execution.Attestations) != 3 || validateResetExecutionJournal(receipt.Execution, plan.OperationID, plan.Target) != nil {
		return errResetExecutionEvidence
	}
	for service, pin := range plan.NewImageDigests {
		if receipt.ImageDigests[service] != pin {
			return errResetExecutionEvidence
		}
	}
	for _, proof := range []string{receipt.ActualRuntimeReceiptSHA, receipt.FirstTickReceiptSHA, receipt.RoleValidationReceiptSHA} {
		if !resetEvidenceSHA.MatchString(proof) {
			return errResetExecutionEvidence
		}
	}
	issued := time.Unix(receipt.IssuedAtUnix, 0)
	last := receipt.Execution.Attestations[2]
	if last.Snapshot.PublicationRevision != preflight.PublicationRevision || last.Snapshot.WriterFreezeReceiptSHA != plan.WriterFreezeReceiptSHA ||
		last.CompletedAt.Unix() >= plan.DestructiveCutoffUnix || issued.Before(last.CompletedAt) || issued.After(now) ||
		receipt.ExpiresAtUnix <= receipt.IssuedAtUnix || receipt.ExpiresAtUnix-receipt.IssuedAtUnix > 30 ||
		receipt.ExpiresAtUnix > plan.RecoveryDeadlineUnix || now.Unix() >= receipt.ExpiresAtUnix {
		return errResetExecutionEvidence
	}
	return nil
}

// Root custody is only one part of trust. The approved issuer that checks raw,
// physical pins, source bytes, real tick and roles remains a separate missing
// gate. This reader is not an issuer and cannot manufacture proof documents.
func (c config) readResetPublicationReceipt(operationID, expectedSHA string, now time.Time) ([]byte, error) {
	return c.readResetPublicationReceiptWithCustodyUID(operationID, expectedSHA, now, 0)
}

// The UID parameter is for isolated custody fixtures; production fixes it to 0.
func (c config) readResetPublicationReceiptWithCustodyUID(operationID, expectedSHA string, now time.Time, uid uint32) ([]byte, error) {
	if !lifecycleJobIDRe.MatchString(operationID) || !resetEvidenceSHA.MatchString(expectedSHA) || c.lifecycleOperationStore == nil {
		return nil, errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(operationID)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.Status != lifecycleJobSucceeded {
		return nil, errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-publication-receipts"), operationID, uid)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != expectedSHA {
		return nil, errResetExecutionEvidence
	}
	var receipt resetPublicationReceipt
	if decodeResetPrivateJSON(wire, &receipt) != nil {
		return nil, errResetExecutionEvidence
	}
	var plan resetApprovalPlan
	if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), operationID,
		receipt.Execution.Evidence.ApprovalPlanSHA, uid, &plan) != nil {
		return nil, errResetExecutionEvidence
	}
	var preflight resetPreflightReceipt
	if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-preflights"), operationID,
		receipt.Execution.Evidence.ExecutionReceiptSHA, uid, &preflight) != nil ||
		validateResetApprovalPlan(plan, operationID, plan.Target, record.CreatedAt) != nil ||
		validateResetPreflight(preflight, plan, receipt.Execution.Evidence.ApprovalPlanSHA, record.CreatedAt) != nil ||
		validateResetPublicationReceipt(receipt, resetExecutionEvidence{plan, preflight}, record, now) != nil {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}

func (c config) handleResetPublicationReceipt(w http.ResponseWriter, r *http.Request, parts []string) {
	serveResetPublicationReceipt(w, r, parts, c.readResetPublicationReceipt)
}

func serveResetPublicationReceipt(w http.ResponseWriter, r *http.Request, parts []string, read func(string, string, time.Time) ([]byte, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if len(parts) != 3 || !lifecycleJobIDRe.MatchString(parts[0]) || parts[1] != "validation-receipt" || !resetEvidenceSHA.MatchString(parts[2]) ||
		r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid receipt identity"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	select {
	case resetPublicationReceiptReadSlots <- struct{}{}:
		defer func() { <-resetPublicationReceiptReadSlots }()
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "validation receipt unavailable"})
		return
	}
	if read == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "validation receipt unavailable"})
		return
	}
	wire, err := read(parts[0], parts[2], time.Now())
	sum := sha256.Sum256(wire)
	if err != nil || len(wire) == 0 || len(wire) > resetEvidenceMaxBytes ||
		hex.EncodeToString(sum[:]) != parts[2] || r.Context().Err() != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "validation receipt unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wire)
}

func isResetPublicationReceiptPath(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) >= 2 && parts[1] == "validation-receipt"
}
