package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"time"
)

// This is durable identity and a bounded observation chain, not an approval
// issuer. The worker remains closed until its real phase source is connected.
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

func newResetExecutionJournal(binding resetExecutionPhaseBinding, attestation resetExecutionAttestation) (resetExecutionJournal, error) {
	record := resetExecutionJournal{Version: 1, AcceptedAtUnix: binding.AcceptedAtUnix, Evidence: binding.Evidence,
		TargetFingerprint: resetRequestFingerprint("pep", binding.Target)}
	var err error
	record.RequestFingerprint, err = resetExecutionRequestFingerprint("pep", binding.Target, binding.Evidence)
	if err != nil || binding.Phase != "prepared" || binding.PreviousAttestationSHA != "" ||
		attestation.Phase != binding.Phase || attestation.PreviousSHA != "" {
		return resetExecutionJournal{}, errResetExecutionEvidence
	}
	attestation.SHA = resetExecutionAttestationSHA(record, attestation)
	record.Attestations = []resetExecutionAttestation{attestation}
	if validateResetExecutionJournal(record, binding.OperationID, binding.Target) != nil {
		return resetExecutionJournal{}, errResetExecutionEvidence
	}
	return record, nil
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

func (c config) writeResetExecutionLifecycleJournal(target serverTarget, resetTarget resetLifecycleTarget, operationID string, record resetExecutionJournal) error {
	if stateFilePresent(c.lifecycleJournalFile) || c.lifecycleJournalFile == "" || target.ID != "pep" ||
		c.validateResetExecutionOperation(record, operationID) != nil {
		return errResetExecutionEvidence
	}
	journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", OperationID: operationID,
		OperationKind: lifecycleKindReset, Stage: lifecycleJournalStagePrepared, ServerID: target.ID,
		Project: target.Project, ResetTarget: &resetTarget, ResetExecution: &record}
	if err := c.writeLifecycleJournalRecord(journal); err != nil {
		return err
	}
	if c.operations != nil {
		c.operations.markLifecycleJournalPending()
	}
	return nil
}

func (c config) appendResetExecutionPhaseToJournal(ctx context.Context, binding resetExecutionPhaseBinding, source resetExecutionPhaseSource) error {
	journal, exists, err := c.readLifecycleJournal()
	if err != nil || !exists || journal.ResetExecution == nil || journal.ResetTarget == nil ||
		journal.OperationID != binding.OperationID || !reflect.DeepEqual(*journal.ResetTarget, binding.Target) ||
		c.validateResetExecutionOperation(*journal.ResetExecution, binding.OperationID) != nil {
		return errResetExecutionEvidence
	}
	a, err := c.observeResetExecutionPhase(ctx, binding, source)
	if err != nil {
		return err
	}
	next, err := appendResetExecutionAttestation(*journal.ResetExecution, binding, a)
	if err != nil {
		return err
	}
	journal.ResetExecution = &next
	return c.writeLifecycleJournalRecord(journal)
}

func appendResetExecutionAttestation(record resetExecutionJournal, binding resetExecutionPhaseBinding, attestation resetExecutionAttestation) (resetExecutionJournal, error) {
	if validateResetExecutionJournal(record, binding.OperationID, binding.Target) != nil ||
		record.AcceptedAtUnix != binding.AcceptedAtUnix || !reflect.DeepEqual(record.Evidence, binding.Evidence) ||
		len(record.Attestations) >= 3 || binding.PreviousAttestationSHA != record.Attestations[len(record.Attestations)-1].SHA ||
		attestation.Phase != binding.Phase || attestation.PreviousSHA != binding.PreviousAttestationSHA {
		return resetExecutionJournal{}, errResetExecutionEvidence
	}
	attestation.SHA = resetExecutionAttestationSHA(record, attestation)
	// Never mutate the prior chain when a later observation is refused.
	record.Attestations = append(append([]resetExecutionAttestation(nil), record.Attestations...), attestation)
	if validateResetExecutionJournal(record, binding.OperationID, binding.Target) != nil {
		return resetExecutionJournal{}, errResetExecutionEvidence
	}
	return record, nil
}
