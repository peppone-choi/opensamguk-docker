package main

import (
	"reflect"
	"unicode/utf8"
)

// An immutable execution-plan artifact, not an approval/provenance issuer.
// Its referenced original config/commands/recovery/readers/evidence/review
// basis must separately be supplied and verified by the actual host producer.
// In particular, successful decoding cannot instantiate purpose authority.
type resetD101DeploymentCard struct {
	SchemaVersion      int               `json:"schemaVersion"`
	Kind               string            `json:"kind"`
	OperationID        string            `json:"operationId"`
	ApprovalIntentSHA  string            `json:"approvalIntentSha256"`
	AppSourceSHA       string            `json:"appSourceSha"`
	DockerSourceSHA    string            `json:"dockerSourceSha"`
	OldImageDigests    map[string]string `json:"oldImageDigests"`
	NewImageDigests    map[string]string `json:"newImageDigests"`
	ConfigInventorySHA string            `json:"configInventorySha256"`
	CommandPlanSHA     string            `json:"commandPlanSha256"`
	RecoveryPlanSHA    string            `json:"recoveryPlanSha256"`
	ReaderBindingsSHA  string            `json:"readerBindingsSha256"`
	EvidenceCatalogSHA string            `json:"evidenceCatalogSha256"`
	ReviewBasisSHA     string            `json:"reviewBasisSha256"`
}

// Future card signatures use this distinct domain followed by original bytes.
// The raw SHA is SHA256(original bytes), without domain/normalization. No card
// signer, key installer or success provider is connected by this codec.
const resetD101DeploymentCardDomain = "OPENSAMGUK-D101-DEPLOYMENT-CARD-V1\n"

type resetDecodedDeploymentCard struct {
	Card     resetD101DeploymentCard
	SHA      string
	original []byte
}

func (card resetDecodedDeploymentCard) originalBytes() []byte {
	return append([]byte(nil), card.original...)
}

func decodeResetD101DeploymentCard(wire []byte, expectedSHA string, approved resetDecodedApprovalIntent) (resetDecodedDeploymentCard, error) {
	closed := resetDecodedDeploymentCard{}
	original := append([]byte(nil), wire...)
	intent, err := decodeResetApprovalIntent(approved.originalBytes(), approved.SHA)
	if err != nil || !resetEvidenceSHA.MatchString(expectedSHA) || len(original) == 0 || len(original) > 32*1024 || !utf8.Valid(original) || resetD101OriginalSHA(original) != expectedSHA ||
		requireResetIntentShape(original, reflect.TypeOf(resetD101DeploymentCard{})) != nil {
		return closed, errResetExecutionEvidence
	}
	var card resetD101DeploymentCard
	if decodeResetPrivateJSON(original, &card) != nil || card.SchemaVersion != 1 || card.Kind != "D101_PEP_EXECUTION_CARD" || card.OperationID != intent.Intent.OperationID ||
		card.ApprovalIntentSHA != intent.SHA || card.AppSourceSHA != intent.Intent.AppSourceSHA || !gitSHA40.MatchString(card.DockerSourceSHA) ||
		!validResetFiveImageDigests(card.OldImageDigests) || !validResetFiveImageDigests(card.NewImageDigests) ||
		!reflect.DeepEqual(card.OldImageDigests, intent.Intent.OldImageDigests) || !reflect.DeepEqual(card.NewImageDigests, intent.Intent.NewImageDigests) {
		return closed, errResetExecutionEvidence
	}
	for _, hash := range []string{card.ConfigInventorySHA, card.CommandPlanSHA, card.RecoveryPlanSHA, card.ReaderBindingsSHA, card.EvidenceCatalogSHA, card.ReviewBasisSHA} {
		if !resetEvidenceSHA.MatchString(hash) {
			return closed, errResetExecutionEvidence
		}
	}
	return resetDecodedDeploymentCard{Card: card, SHA: expectedSHA, original: original}, nil
}
