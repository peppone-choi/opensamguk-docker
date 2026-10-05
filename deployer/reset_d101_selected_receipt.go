package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"
	"unicode/utf8"
)

const resetD101SelectedSourceDomain = "OPENSAMGUK-D101-SELECTED-SOURCE-V1\n"

type resetD101SelectedOriginalPin struct {
	LogicalArtifactID string `json:"logicalArtifactId"`
	RawSHA            string `json:"rawSha256"`
	ByteLength        uint64 `json:"byteLength"`
}

// Exact App producer/consumer wire contract. The signature binds originals;
// validation here does not substitute for the actual source semantic verifier.
type resetD101SelectedReceipt struct {
	SchemaVersion         int                                     `json:"schemaVersion"`
	Kind                  string                                  `json:"kind"`
	SelectionStatus       string                                  `json:"selectionStatus"`
	OriginalOp            string                                  `json:"originalOp"`
	TargetFingerprint     string                                  `json:"typedTargetFingerprint"`
	AppSourceSHA          string                                  `json:"appSourceSha"`
	ImagePins             map[string]string                       `json:"imagePins"`
	ScenarioOrigin        string                                  `json:"scenarioOrigin"`
	ScenarioLogicalID     string                                  `json:"scenarioLogicalId"`
	ClasspathLogicalID    string                                  `json:"classpathLogicalId"`
	OriginalPins          map[string]resetD101SelectedOriginalPin `json:"originalPins"`
	ArtifactSetID         string                                  `json:"artifactSetId"`
	Variant               string                                  `json:"variant"`
	TopologyRevision      string                                  `json:"topologyRevision"`
	TopologyContentHash   string                                  `json:"topologyContentHash"`
	TopologyProvenanceSHA string                                  `json:"topologyContentHashProvenanceSha256"`
	EffectiveOptions      map[string]string                       `json:"effectiveOptions"`
	OptionProvenance      map[string]string                       `json:"optionProvenance"`
	ConfigurationSHA      string                                  `json:"configurationSha256"`
	ParserBytecodeSHA     string                                  `json:"parserBytecodeSha256"`
	ResolverDecisionSHA   string                                  `json:"resolverDecisionReceiptSha256"`
	CapturedAtUTC         string                                  `json:"capturedAtUtc"`
	ProducerIdentity      string                                  `json:"trustedProducerIdentity"`
}
type resetD101VerifiedSelectedReceipt struct {
	original []byte
	sha      string
	value    resetD101SelectedReceipt
}

func decodeResetD101SelectedReceipt(envelope []byte, spki []byte, spkiSHA, producer string, intent resetDecodedApprovalIntent, now time.Time) (resetD101VerifiedSelectedReceipt, error) {
	closed := resetD101VerifiedSelectedReceipt{}
	fresh, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	intent = fresh
	public, err := resetD101PinnedPublicKey(spki, spkiSHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	wire, err := decodeResetD101SignedHostOriginal(envelope, resetD101SelectedSourceDomain, public)
	var receipt resetD101SelectedReceipt
	if err != nil || len(wire) > 64*1024 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(receipt)) != nil || decodeResetPrivateJSON(wire, &receipt) != nil ||
		receipt.SchemaVersion != 1 || receipt.Kind != "D101_FINAL_SELECTED_SOURCE_V1" || receipt.SelectionStatus != "FINAL_SELECTED" ||
		resetD101OriginalSHA(wire) != intent.Intent.SelectedSourceReceiptSHA || receipt.OriginalOp != intent.Intent.OperationID || receipt.TargetFingerprint != intent.Intent.TargetFingerprint || receipt.AppSourceSHA != intent.Intent.AppSourceSHA ||
		!reflect.DeepEqual(receipt.ImagePins, intent.Intent.NewImageDigests) || receipt.ProducerIdentity != producer || !resetD101KeyID.MatchString(producer) ||
		(receipt.ScenarioOrigin != "CLASSPATH" && receipt.ScenarioOrigin != "EXTERNAL") || receipt.ScenarioLogicalID == "" || receipt.ClasspathLogicalID == "" || receipt.ArtifactSetID == "" || receipt.Variant == "" || receipt.TopologyRevision == "" {
		return closed, errResetExecutionEvidence
	}
	for _, sha := range []string{receipt.TopologyContentHash, receipt.TopologyProvenanceSHA, receipt.ConfigurationSHA, receipt.ParserBytecodeSHA, receipt.ResolverDecisionSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return closed, errResetExecutionEvidence
		}
	}
	keys := []string{"SERVER_NAME", "SERVER_GENERATION", "SCENARIO_CODE", "SCENARIO_SEED_ENABLED", "SCENARIO_LOOKUP_DIR", "RESET_MAXGENERAL", "RESET_FIRST_TURN", "RESET_EXTEND", "RESET_TURNTERM", "RESET_BLOCK_GENERAL_CREATE", "RESET_NPCMODE", "RESET_SHOW_IMG_LEVEL"}
	required := map[string]bool{}
	for _, key := range keys {
		required[key] = true
	}
	if len(receipt.EffectiveOptions) != len(receipt.OptionProvenance) || (len(receipt.EffectiveOptions) != len(keys) && len(receipt.EffectiveOptions) != len(keys)+1) {
		return closed, errResetExecutionEvidence
	}
	for key, value := range receipt.EffectiveOptions {
		if !required[key] && key != "RESET_FICTION" || intent.Target.Updates[key] != value || !resetEvidenceSHA.MatchString(receipt.OptionProvenance[key]) {
			return closed, errResetExecutionEvidence
		}
	}
	for _, key := range keys {
		if _, ok := receipt.EffectiveOptions[key]; !ok {
			return closed, errResetExecutionEvidence
		}
	}
	if receipt.EffectiveOptions["SERVER_GENERATION"] != "0" || len(receipt.OriginalPins) != 5 {
		return closed, errResetExecutionEvidence
	}
	for _, id := range []string{"tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"} {
		pin, ok := receipt.OriginalPins[id]
		if !ok || pin.LogicalArtifactID != id || !resetEvidenceSHA.MatchString(pin.RawSHA) || pin.ByteLength == 0 || pin.ByteLength > resetD101SelectedByteLimit {
			return closed, errResetExecutionEvidence
		}
	}
	captured, err := resetD101RecoveryUTC(receipt.CapturedAtUTC)
	if err != nil || captured.After(now) {
		return closed, errResetExecutionEvidence
	}
	return resetD101VerifiedSelectedReceipt{append([]byte(nil), wire...), resetD101OriginalSHA(wire), receipt}, nil
}

// Sign only an original already generated and verified by the actual selected
// producer. The producer installer owns proof verification; this is a key primitive.
func encodeResetD101SelectedEnvelope(key *resetD101SigningKey, original []byte) ([]byte, error) {
	signature, err := key.sign(resetD101SelectedSourceDomain, original)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errResetExecutionEvidence
	}
	return marshalResetD101SignedOriginal(original, signature)
}
func marshalResetD101SignedOriginal(original, signature []byte) ([]byte, error) {
	// The common envelope codec uses canonical unpadded URL base64 and exact3.
	return json.Marshal(resetD101SignedHostOriginal{1, base64.RawURLEncoding.EncodeToString(original), base64.RawURLEncoding.EncodeToString(signature)})
}
