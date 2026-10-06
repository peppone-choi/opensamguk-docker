package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"opensamguk-deployer/internal/d101custody"
)

// Static installation pins from the existing independently approved host
// installation. No HTTP input/env switch selects a key, capture file or image.
// Signing is unavailable until the actual capture child and all native originals
// exist. The source installer does not issue approval, create keys or run a child.
type resetD101SelectedProducerPins struct {
	OperationID           string
	TargetFingerprint     string
	AppSourceSHA          string
	ImagePins             map[string]string
	ProducerContainerID   string
	ProducerImageID       string
	AppRepository         string
	FactsFile             string
	FactsSHA              string
	TargetFile            string
	ConfigurationFile     string
	ParserBytecodeFile    string
	ParserBytecodeSHA     string
	ResolverDecisionFile  string
	TopologyCanonicalFile string
	TopologyAlgorithmFile string
	TopologyAlgorithmSHA  string
	TopologyInputs        map[string]string
	RawOriginals          resetD101SelectedBytePins
	SigningKey            resetD101SigningKeyPins
	ReceiptDirectory      string
	EnvelopeDirectory     string
	capture               *resetD101PreIntentCaptureReception
}
type resetD101SelectedProducer struct{ pins resetD101SelectedProducerPins }

const resetD101PreIntentCaptureEntrypoint = "/app/d101-pre-intent-entrypoint"

func newResetD101SelectedProducer(p resetD101SelectedProducerPins) (*resetD101SelectedProducer, error) {
	if p.capture == nil || p.capture.requireProducerPins(p) != nil {
		return nil, errResetExecutionEvidence
	}
	if !lifecycleJobIDRe.MatchString(p.OperationID) || !resetEvidenceSHA.MatchString(p.TargetFingerprint) || !gitSHA40.MatchString(p.AppSourceSHA) || !validResetFiveImageDigests(p.ImagePins) ||
		!resetEvidenceSHA.MatchString(p.ProducerContainerID) || !resetManifestDigest.MatchString(p.ProducerImageID) || !resetRuntimeRepository.MatchString(p.AppRepository) || !resetEvidenceSHA.MatchString(p.FactsSHA) || !resetEvidenceSHA.MatchString(p.ParserBytecodeSHA) || !resetEvidenceSHA.MatchString(p.TopologyAlgorithmSHA) || len(p.TopologyInputs) == 0 || len(p.TopologyInputs) > 32 {
		return nil, errResetExecutionEvidence
	}
	for _, path := range append([]string{p.FactsFile, p.TargetFile, p.ConfigurationFile, p.ParserBytecodeFile, p.ResolverDecisionFile, p.TopologyCanonicalFile, p.TopologyAlgorithmFile, p.ReceiptDirectory, p.EnvelopeDirectory}, resetD101SelectedTopologyPaths(p.TopologyInputs)...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errResetExecutionEvidence
		}
	}
	p.ImagePins = cloneResetD101Strings(p.ImagePins)
	p.TopologyInputs = cloneResetD101Strings(p.TopologyInputs)
	rawPins := make(map[string]resetD101RawBytePin, len(p.RawOriginals.Pins))
	for id, pin := range p.RawOriginals.Pins {
		rawPins[id] = pin
	}
	p.RawOriginals.Pins = rawPins
	return &resetD101SelectedProducer{p}, nil
}
func resetD101SelectedTopologyPaths(values map[string]string) []string {
	result := []string{}
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
func (c config) issueResetD101SelectedSource(ctx context.Context, producer *resetD101SelectedProducer) (string, error) {
	if producer == nil || ctx == nil || ctx.Err() != nil || producer.pins.capture == nil {
		return "", errResetExecutionEvidence
	}
	p := producer.pins
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	started := time.Now()
	// Inspect the real retained capture-only child, not a facts JSON image label.
	before, err := c.observeResetD101SelectedCapture(bounded, p)
	if err != nil {
		return "", err
	}
	raw, err := p.capture.readRawFive()
	if err != nil {
		return "", errResetExecutionEvidence
	}
	originals := map[string]d101custody.Original{}
	read := func(id, path string, limit int64) ([]byte, error) {
		value, err := d101custody.ReadPrivate(path, limit)
		if err != nil {
			return nil, errResetExecutionEvidence
		}
		originals[id] = value
		return value.Bytes, nil
	}
	facts, err := read("facts", p.FactsFile, 64*1024)
	if err != nil || resetD101OriginalSHA(facts) != p.FactsSHA {
		return "", errResetExecutionEvidence
	}
	var receipt resetD101SelectedReceipt
	if requireResetIntentShape(facts, reflect.TypeOf(receipt)) != nil || decodeResetPrivateJSON(facts, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Kind != "D101_FINAL_SELECTED_SOURCE_V1" || receipt.SelectionStatus != "FINAL_SELECTED" || receipt.OriginalOp != p.OperationID || receipt.TargetFingerprint != p.TargetFingerprint || receipt.AppSourceSHA != p.AppSourceSHA || !reflect.DeepEqual(receipt.ImagePins, p.ImagePins) || receipt.ProducerIdentity != p.SigningKey.KeyID || len(receipt.OriginalPins) != 5 {
		return "", errResetExecutionEvidence
	}
	for leaf, pin := range raw.ObservedPins() {
		observed := receipt.OriginalPins[leaf]
		if observed.LogicalArtifactID != leaf || observed.RawSHA != pin.SHA256 || observed.ByteLength != pin.ByteLength {
			return "", errResetExecutionEvidence
		}
	}
	if receipt.ScenarioOrigin == "CLASSPATH" {
		if receipt.ScenarioLogicalID != receipt.ClasspathLogicalID || receipt.OriginalPins["selected-scenario.json"].RawSHA != receipt.OriginalPins["classpath-scenario.json"].RawSHA {
			return "", errResetExecutionEvidence
		}
	} else if receipt.ScenarioOrigin != "EXTERNAL" {
		return "", errResetExecutionEvidence
	}
	target, err := read("target", p.TargetFile, 16*1024)
	if err != nil || resetD101OriginalSHA(target) != p.TargetFingerprint {
		return "", errResetExecutionEvidence
	}
	var wrapper struct {
		ID     string               `json:"id"`
		Target resetLifecycleTarget `json:"target"`
	}
	if requireResetIntentShape(target, reflect.TypeOf(wrapper)) != nil || decodeResetPrivateJSON(target, &wrapper) != nil || wrapper.ID != "pep" || wrapper.Target.Generation != 0 || wrapper.Target.ScenarioCode != "scenario_3190" || !wrapper.Target.ScenarioSeedEnabled {
		return "", errResetExecutionEvidence
	}
	combined := cloneResetD101Strings(wrapper.Target.ImageDigests)
	for id, pin := range wrapper.Target.StorageImageDigests {
		combined[id] = pin
	}
	if !reflect.DeepEqual(combined, p.ImagePins) {
		return "", errResetExecutionEvidence
	}
	configuration, err := read("configuration", p.ConfigurationFile, 64*1024)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	parser, err := read("parser", p.ParserBytecodeFile, 2*1024*1024)
	if err != nil || resetD101OriginalSHA(parser) != p.ParserBytecodeSHA || receipt.ParserBytecodeSHA != p.ParserBytecodeSHA || receipt.ConfigurationSHA != resetD101OriginalSHA(configuration) {
		return "", errResetExecutionEvidence
	}
	if requireResetD101SelectedOptions(configuration, receipt, wrapper.Target.Updates) != nil {
		return "", errResetExecutionEvidence
	}
	decision, err := read("resolver", p.ResolverDecisionFile, 64*1024)
	if err != nil || resetD101OriginalSHA(decision) != receipt.ResolverDecisionSHA || requireResetD101SelectedDecision(decision, receipt) != nil {
		return "", errResetExecutionEvidence
	}
	canonical, err := read("canonical", p.TopologyCanonicalFile, 2*1024*1024)
	if err != nil || resetD101OriginalSHA(canonical) != receipt.TopologyContentHash {
		return "", errResetExecutionEvidence
	}
	algorithm, err := read("algorithm", p.TopologyAlgorithmFile, 2*1024*1024)
	if err != nil || resetD101OriginalSHA(algorithm) != p.TopologyAlgorithmSHA {
		return "", errResetExecutionEvidence
	}
	inputPins := map[string]resetD101SelectedOriginalPin{}
	worldLinked, tilesLinked := false, false
	for id, path := range p.TopologyInputs {
		wire, err := read("topology:"+id, path, 64*1024*1024)
		if err != nil || id == "" {
			return "", errResetExecutionEvidence
		}
		inputPins[id] = resetD101SelectedOriginalPin{id, resetD101OriginalSHA(wire), uint64(len(wire))}
		if id == "infra/src/main/resources/map/han-world-v3.json" {
			worldPin := receipt.OriginalPins["world.json"]
			worldLinked = worldPin.RawSHA == resetD101OriginalSHA(wire) && worldPin.ByteLength == uint64(len(wire))
		}
		if pin := receipt.OriginalPins["tiles.json"]; pin.RawSHA == resetD101OriginalSHA(wire) && pin.ByteLength == uint64(len(wire)) {
			tilesLinked = true
		}
	}
	if !worldLinked || !tilesLinked {
		return "", errResetExecutionEvidence
	}
	provenance, err := json.Marshal(struct {
		ArtifactSetID    string                                  `json:"artifactSetId"`
		Variant          string                                  `json:"variant"`
		TopologyRevision string                                  `json:"topologyRevision"`
		ContentHash      string                                  `json:"contentHash"`
		AlgorithmSHA     string                                  `json:"algorithmBytecodeSha256"`
		CanonicalSHA     string                                  `json:"canonicalInputSha256"`
		InputArtifacts   map[string]resetD101SelectedOriginalPin `json:"inputArtifacts"`
	}{receipt.ArtifactSetID, receipt.Variant, receipt.TopologyRevision, receipt.TopologyContentHash, p.TopologyAlgorithmSHA, resetD101OriginalSHA(canonical), inputPins})
	if err != nil || receipt.ArtifactSetID == "" || receipt.Variant == "" || receipt.TopologyRevision == "" || resetD101OriginalSHA(provenance) != receipt.TopologyProvenanceSHA {
		return "", errResetExecutionEvidence
	}
	captured, err := resetD101RecoveryUTC(receipt.CapturedAtUTC)
	if err != nil || captured.After(started) {
		return "", errResetExecutionEvidence
	}
	// Re-read all originals and actual child identity after observation. A changed
	// source set or uncertain signing/write never yields another implicit attempt.
	for id, value := range originals {
		path := map[string]string{"facts": p.FactsFile, "target": p.TargetFile, "configuration": p.ConfigurationFile, "parser": p.ParserBytecodeFile, "resolver": p.ResolverDecisionFile, "canonical": p.TopologyCanonicalFile, "algorithm": p.TopologyAlgorithmFile}[id]
		if strings.HasPrefix(id, "topology:") {
			path = p.TopologyInputs[strings.TrimPrefix(id, "topology:")]
		}
		after, err := d101custody.ReadPrivate(path, int64(len(value.Bytes)))
		if err != nil || after.SHA256 != value.SHA256 {
			return "", errResetExecutionEvidence
		}
	}
	rawAfter, err := p.capture.readRawFive()
	if err != nil || !reflect.DeepEqual(rawAfter.ObservedPins(), raw.ObservedPins()) {
		return "", errResetExecutionEvidence
	}
	after, err := c.observeResetD101SelectedCapture(bounded, p)
	if err != nil || !reflect.DeepEqual(before, after) || bounded.Err() != nil {
		return "", errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(p.SigningKey)
	if err != nil {
		return "", err
	}
	defer key.close()
	spki, err := x509.MarshalPKIXPublicKey(key.private.Public())
	if err != nil || resetD101OriginalSHA(spki) != p.SigningKey.PublicKeySpkiSHA {
		return "", errResetExecutionEvidence
	}
	envelope, err := encodeResetD101SelectedEnvelope(&key, facts)
	if err != nil || bounded.Err() != nil || time.Since(started) >= resetPreflightMaxAge {
		return "", errResetExecutionEvidence
	}
	// Both exact raw receipt and signed envelope have independent immutable files.
	if createResetImmutablePrivateBytes(p.ReceiptDirectory, p.OperationID, resetD101OriginalSHA(facts), facts, 0) != nil || createResetImmutablePrivateBytes(p.EnvelopeDirectory, p.OperationID, resetD101OriginalSHA(envelope), envelope, 0) != nil {
		return "", errResetExecutionEvidence
	}
	return resetD101OriginalSHA(facts), nil
}

type resetD101SelectedCaptureObservation struct {
	ID         string   `json:"id"`
	ImageID    string   `json:"imageId"`
	Status     string   `json:"status"`
	Running    *bool    `json:"running"`
	ExitCode   *int     `json:"exitCode"`
	Entrypoint []string `json:"entrypoint"`
	Command    []string `json:"command"`
}

func (c config) observeResetD101SelectedCapture(ctx context.Context, p resetD101SelectedProducerPins) (resetD101SelectedCaptureObservation, error) {
	if p.capture != nil && c.requireResetD101PreIntentRetainedChild(ctx, p.capture) != nil {
		return resetD101SelectedCaptureObservation{}, errResetExecutionEvidence
	}
	var value resetD101SelectedCaptureObservation
	call := func(args ...string) (string, error) {
		if p.capture != nil && (p.capture.beforeCommand == nil || p.capture.beforeCommand(ctx) != nil || p.capture.recheck() != nil) {
			return "", errResetExecutionEvidence
		}
		return c.runServerDockerContext(ctx, args...)
	}
	out, err := call("inspect", "--format", `{"id":{{json .Id}},"imageId":{{json .Image}},"status":{{json .State.Status}},"running":{{json .State.Running}},"exitCode":{{json .State.ExitCode}},"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}}}`, p.ProducerContainerID)
	if err != nil || len(out) > 16*1024 || requireResetIntentShape([]byte(out), reflect.TypeOf(value)) != nil || decodeResetPrivateJSON([]byte(out), &value) != nil || value.ID != p.ProducerContainerID || value.ImageID != p.ProducerImageID || value.Status != "exited" || value.Running == nil || *value.Running || value.ExitCode == nil || *value.ExitCode != 0 || !reflect.DeepEqual(value.Entrypoint, []string{resetD101PreIntentCaptureEntrypoint}) || len(value.Command) != 0 {
		return value, errResetExecutionEvidence
	}
	imageOut, err := call("image", "inspect", "--format", `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, value.ImageID)
	var image resetRuntimeImage
	if err != nil || len(imageOut) > 16*1024 || requireResetIntentShape([]byte(imageOut), reflect.TypeOf(image)) != nil || decodeResetPrivateJSON([]byte(imageOut), &image) != nil || image.OS != "linux" || image.Architecture != "amd64" || !resetRuntimePinMatches(image.RepoDigests, "game-engine", p.AppRepository, p.ImagePins["game-engine"]) {
		return value, errResetExecutionEvidence
	}
	return value, nil
}
func requireResetD101SelectedOptions(wire []byte, r resetD101SelectedReceipt, target map[string]string) error {
	var config struct {
		SchemaVersion     int               `json:"schemaVersion"`
		Kind              string            `json:"kind"`
		OriginalOp        string            `json:"originalOp"`
		TargetFingerprint string            `json:"typedTargetFingerprint"`
		AppSourceSHA      string            `json:"appSourceSha"`
		ImagePins         map[string]string `json:"imagePins"`
		RawInputs         map[string]string `json:"rawInputs"`
	}
	if requireResetIntentShape(wire, reflect.TypeOf(config)) != nil || decodeResetPrivateJSON(wire, &config) != nil || config.SchemaVersion != 1 || config.Kind != "D101_EFFECTIVE_SEED_INPUTS_V1" || config.OriginalOp != r.OriginalOp || config.TargetFingerprint != r.TargetFingerprint || config.AppSourceSHA != r.AppSourceSHA || !reflect.DeepEqual(config.ImagePins, r.ImagePins) || len(config.RawInputs) != len(r.EffectiveOptions) || len(r.OptionProvenance) != len(r.EffectiveOptions) {
		return errResetExecutionEvidence
	}
	required := []string{"SERVER_NAME", "SERVER_GENERATION", "SCENARIO_CODE", "SCENARIO_SEED_ENABLED", "SCENARIO_LOOKUP_DIR", "RESET_MAXGENERAL", "RESET_FIRST_TURN", "RESET_EXTEND", "RESET_TURNTERM", "RESET_BLOCK_GENERAL_CREATE", "RESET_NPCMODE", "RESET_SHOW_IMG_LEVEL"}
	allowed := map[string]bool{"RESET_FICTION": true}
	for _, key := range required {
		allowed[key] = true
		if _, ok := r.EffectiveOptions[key]; !ok {
			return errResetExecutionEvidence
		}
	}
	numeric := map[string]bool{"SERVER_GENERATION": true, "RESET_MAXGENERAL": true, "RESET_EXTEND": true, "RESET_TURNTERM": true, "RESET_BLOCK_GENERAL_CREATE": true, "RESET_NPCMODE": true, "RESET_SHOW_IMG_LEVEL": true, "RESET_FICTION": true}
	for key, value := range r.EffectiveOptions {
		raw, ok := config.RawInputs[key]
		if !ok || !allowed[key] || target[key] != value {
			return errResetExecutionEvidence
		}
		effective := raw
		if numeric[key] {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.IndexFunc(trimmed, func(ch rune) bool { return ch < '0' || ch > '9' }) >= 0 {
				return errResetExecutionEvidence
			}
			number, err := strconv.ParseUint(trimmed, 10, 31)
			if err != nil {
				return errResetExecutionEvidence
			}
			effective = strconv.FormatUint(number, 10)
		}
		if effective != value {
			return errResetExecutionEvidence
		}
		original, err := json.Marshal(struct {
			ConfigurationSHA string `json:"configurationSha256"`
			ParserSHA        string `json:"parserBytecodeSha256"`
			Option           string `json:"option"`
			RawInput         string `json:"rawInput"`
			EffectiveValue   string `json:"effectiveValue"`
		}{r.ConfigurationSHA, r.ParserBytecodeSHA, key, raw, value})
		if err != nil || resetD101OriginalSHA(original) != r.OptionProvenance[key] {
			return errResetExecutionEvidence
		}
	}
	fixed := map[string]string{"SERVER_NAME": "빼섭", "SERVER_GENERATION": "0", "SCENARIO_CODE": "scenario_3190", "SCENARIO_SEED_ENABLED": "true", "SCENARIO_LOOKUP_DIR": "", "RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate", "RESET_TURNTERM": "60", "RESET_BLOCK_GENERAL_CREATE": "1"}
	for key, value := range fixed {
		if r.EffectiveOptions[key] != value {
			return errResetExecutionEvidence
		}
	}
	for key, values := range map[string]map[string]bool{"RESET_EXTEND": {"0": true, "1": true}, "RESET_NPCMODE": {"0": true, "1": true, "2": true}, "RESET_SHOW_IMG_LEVEL": {"0": true, "1": true, "2": true, "3": true}} {
		if !values[r.EffectiveOptions[key]] {
			return errResetExecutionEvidence
		}
	}
	if value, ok := r.EffectiveOptions["RESET_FICTION"]; ok && value != "0" && value != "1" {
		return errResetExecutionEvidence
	}
	return nil
}
func requireResetD101SelectedDecision(wire []byte, r resetD101SelectedReceipt) error {
	var decision struct {
		SchemaVersion      int                                     `json:"schemaVersion"`
		Kind               string                                  `json:"kind"`
		OriginalOp         string                                  `json:"originalOp"`
		TargetFingerprint  string                                  `json:"typedTargetFingerprint"`
		AppSourceSHA       string                                  `json:"appSourceSha"`
		ImagePins          map[string]string                       `json:"imagePins"`
		SelectedOrigin     string                                  `json:"selectedOrigin"`
		SelectedLogicalID  string                                  `json:"selectedLogicalId"`
		ClasspathLogicalID string                                  `json:"classpathLogicalId"`
		OriginalPins       map[string]resetD101SelectedOriginalPin `json:"originalPins"`
	}
	if requireResetIntentShape(wire, reflect.TypeOf(decision)) != nil || decodeResetPrivateJSON(wire, &decision) != nil || decision.SchemaVersion != 1 || decision.Kind != "D101_RESOLVER_DECISION_V1" || decision.OriginalOp != r.OriginalOp || decision.TargetFingerprint != r.TargetFingerprint || decision.AppSourceSHA != r.AppSourceSHA || !reflect.DeepEqual(decision.ImagePins, r.ImagePins) || decision.SelectedOrigin != r.ScenarioOrigin || decision.SelectedLogicalID != r.ScenarioLogicalID || decision.ClasspathLogicalID != r.ClasspathLogicalID || !reflect.DeepEqual(decision.OriginalPins, r.OriginalPins) {
		return errResetExecutionEvidence
	}
	return nil
}
