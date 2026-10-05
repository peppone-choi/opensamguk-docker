package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func normalizeResetExecutionEvidenceRefs(refs resetExecutionEvidenceRefs) (resetExecutionEvidenceRefs, error) {
	if refs.ApprovalPlanSHA == "" && refs.ExecutionReceiptSHA == "" {
		return refs, nil
	}
	if !resetEvidenceSHA.MatchString(refs.ApprovalPlanSHA) || !resetEvidenceSHA.MatchString(refs.ExecutionReceiptSHA) {
		return resetExecutionEvidenceRefs{}, errResetExecutionEvidence
	}
	return refs, nil
}

// The typed target hash excludes proof hashes, avoiding a plan/receipt hash cycle.
// The durable request includes BOTH immutable evidence hashes. Legacy nil proof
// requests keep their exact existing fingerprint representation.
func resetExecutionRequestFingerprint(id string, target resetLifecycleTarget, refs resetExecutionEvidenceRefs) (string, error) {
	refs, err := normalizeResetExecutionEvidenceRefs(refs)
	if err != nil {
		return "", err
	}
	if refs.ApprovalPlanSHA == "" {
		return resetRequestFingerprint(id, target), nil
	}
	wire, err := json.Marshal(struct {
		ID                  string               `json:"id"`
		Target              resetLifecycleTarget `json:"target"`
		ApprovalPlanSHA     string               `json:"approvalPlanSha256"`
		ExecutionReceiptSHA string               `json:"executionReceiptSha256"`
	}{id, target, refs.ApprovalPlanSHA, refs.ExecutionReceiptSHA})
	if err != nil {
		return "", errResetExecutionEvidence
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}
