package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

// Retained durable identity validation. Existing native reset journals remain
// readable and cannot be automatically replayed by ordinary maintenance repair.
type resetExecutionJournal struct {
	Version            int                         `json:"version"`
	AcceptedAtUnix     int64                       `json:"acceptedAtUnix"`
	Evidence           resetExecutionEvidenceRefs  `json:"evidence"`
	TargetFingerprint  string                      `json:"targetFingerprint"`
	RequestFingerprint string                      `json:"requestFingerprint"`
	Attestations       []resetExecutionAttestation `json:"attestations"`
}

type resetExecutionSpaceSnapshot struct {
	Device          uint64 `json:"device"`
	AvailableBytes  uint64 `json:"availableBytes"`
	AvailableInodes uint64 `json:"availableInodes"`
}

func (s *resetExecutionSpaceSnapshot) UnmarshalJSON(wire []byte) error {
	var observed struct {
		Device          *uint64 `json:"device"`
		AvailableBytes  *uint64 `json:"availableBytes"`
		AvailableInodes *uint64 `json:"availableInodes"`
	}
	if decodeResetPrivateJSON(wire, &observed) != nil || observed.Device == nil ||
		observed.AvailableBytes == nil || observed.AvailableInodes == nil {
		return errResetExecutionEvidence
	}
	*s = resetExecutionSpaceSnapshot{*observed.Device, *observed.AvailableBytes, *observed.AvailableInodes}
	return nil
}

type resetExecutionAttestation struct {
	Phase       string                      `json:"phase"`
	PreviousSHA string                      `json:"previousSha256,omitempty"`
	StartedAt   time.Time                   `json:"startedAt"`
	CompletedAt time.Time                   `json:"completedAt"`
	Snapshot    resetExecutionPhaseSnapshot `json:"snapshot"`
	Space       resetExecutionSpaceSnapshot `json:"space"`
	SHA         string                      `json:"sha256"`
}

func resetExecutionAttestationSHA(record resetExecutionJournal, attestation resetExecutionAttestation) string {
	attestation.SHA = ""
	wire, _ := json.Marshal(struct {
		AcceptedAtUnix     int64                      `json:"acceptedAtUnix"`
		Evidence           resetExecutionEvidenceRefs `json:"evidence"`
		TargetFingerprint  string                     `json:"targetFingerprint"`
		RequestFingerprint string                     `json:"requestFingerprint"`
		Attestation        resetExecutionAttestation  `json:"attestation"`
	}{record.AcceptedAtUnix, record.Evidence, record.TargetFingerprint, record.RequestFingerprint, attestation})
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func validateResetExecutionJournal(record resetExecutionJournal, operationID string, target resetLifecycleTarget) error {
	if record.Version != 1 || record.AcceptedAtUnix <= 0 || !lifecycleJobIDRe.MatchString(operationID) ||
		record.Evidence.ApprovalPlanSHA == "" || record.Evidence.ExecutionReceiptSHA == "" ||
		record.TargetFingerprint != resetRequestFingerprint("pep", target) {
		return errResetExecutionEvidence
	}
	fp, err := resetExecutionRequestFingerprint("pep", target, record.Evidence)
	if err != nil || record.RequestFingerprint != fp || len(record.Attestations) == 0 || len(record.Attestations) > 3 {
		return errResetExecutionEvidence
	}
	phases := []string{"prepared", "before-journal", "before-down"}
	previous := ""
	previousCompletion := time.Unix(record.AcceptedAtUnix, 0)
	revision, freeze := "", ""
	for i, a := range record.Attestations {
		s := a.Snapshot
		parsedRevision, parseErr := strconv.ParseInt(s.PublicationRevision, 10, 64)
		if a.Phase != phases[i] || a.PreviousSHA != previous || a.StartedAt.Before(previousCompletion) ||
			a.CompletedAt.Before(a.StartedAt) || s.ObservedAt.Before(a.StartedAt) || s.ObservedAt.After(a.CompletedAt) ||
			a.CompletedAt.Sub(a.StartedAt) >= resetPreflightMaxAge ||
			s.ServerID != "pep" || s.OperationID != operationID || s.TargetFingerprint != record.TargetFingerprint ||
			s.PublicationState != "VERIFYING" || parseErr != nil || parsedRevision <= 0 ||
			strconv.FormatInt(parsedRevision, 10) != s.PublicationRevision || !s.WriterFreezeHeld ||
			!resetEvidenceSHA.MatchString(s.WriterFreezeReceiptSHA) ||
			a.Space.AvailableBytes < resetDiskReserveBytes || a.Space.AvailableInodes == 0 ||
			(i > 0 && (s.PublicationRevision != revision || s.WriterFreezeReceiptSHA != freeze)) ||
			!resetEvidenceSHA.MatchString(a.SHA) || a.SHA != resetExecutionAttestationSHA(record, a) {
			return errResetExecutionEvidence
		}
		previous, previousCompletion = a.SHA, a.CompletedAt
		revision, freeze = s.PublicationRevision, s.WriterFreezeReceiptSHA
	}
	return nil
}

func validateLifecycleResetExecution(journal lifecycleJournal) error {
	if journal.ResetExecution == nil {
		return nil
	}
	if journal.Operation != "reset" || journal.OperationKind != lifecycleKindReset || journal.ServerID != "pep" ||
		journal.ResetTarget == nil || journal.ResetTarget.ScenarioCode != "scenario_3190" ||
		len(journal.ResetExecution.Attestations) < 2 {
		return errResetExecutionEvidence
	}
	if journal.Stage == lifecycleJournalStageDown && len(journal.ResetExecution.Attestations) != 3 {
		return errResetExecutionEvidence
	}
	return validateResetExecutionJournal(*journal.ResetExecution, journal.OperationID, *journal.ResetTarget)
}

// Reservation CreatedAt is the first durable admission time; neither a retry
// nor a new preflight may replace it after a long candidate pull.
func (c config) validateResetExecutionOperation(record resetExecutionJournal, operationID string) error {
	if c.lifecycleOperationStore == nil {
		return errResetExecutionEvidence
	}
	op, found := c.lifecycleOperationStore.Lookup(operationID)
	if !found || op.Kind != lifecycleKindReset || op.SubjectID != "pep" ||
		op.RequestFingerprint != record.RequestFingerprint || op.CreatedAt.Unix() != record.AcceptedAtUnix {
		return errResetExecutionEvidence
	}
	return nil
}

// Ordinary operations can settle; retained native execution journals cannot
// be cleared without the removed, uninstalled issuer. Leave recovery closed.
func (c config) settleSucceededLifecycleJournal(_ context.Context, _ string) error {
	journal, exists, err := c.readLifecycleJournal()
	if err != nil {
		return err
	}
	if exists && journal.ResetExecution != nil {
		return errResetExecutionEvidence
	}
	return c.clearLifecycleJournal()
}
