package main

import (
	"bytes"
	"context"
	"opensamguk-deployer/internal/d101custody"
	"path/filepath"
	"reflect"
	"strings"

	"opensamguk-deployer/internal/d101selectedtransport"
)

func (r *resetD101PreIntentCaptureReception) readRawFive() (resetD101SelectedBytes, error) {
	if r == nil || r.recheck() != nil {
		return resetD101SelectedBytes{}, errResetExecutionEvidence
	}
	result := resetD101SelectedBytes{bytes: map[string][]byte{}, observed: map[string]resetD101RawBytePin{}}
	for _, id := range []string{"tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"} {
		original, ok := r.originals[id]
		if !ok {
			return resetD101SelectedBytes{}, errResetExecutionEvidence
		}
		result.bytes[id] = append([]byte(nil), original.Bytes...)
		result.observed[id] = resetD101RawBytePin{original.SHA256, uint64(len(original.Bytes))}
	}
	return result, nil
}

func (r *resetD101PreIntentCaptureReception) requireUnsignedSnapshot() error {
	if r == nil || r.recheck() != nil {
		return errResetExecutionEvidence
	}
	var facts resetD101SelectedReceipt
	wire := r.originals["captureFacts"].Bytes
	if requireResetIntentShape(wire, reflect.TypeOf(facts)) != nil || decodeResetPrivateJSON(wire, &facts) != nil || facts.OriginalOp != r.manifest.OriginalOp ||
		facts.TargetFingerprint != r.manifest.TargetFingerprint || facts.AppSourceSHA != r.manifest.AppSourceSHA || !reflect.DeepEqual(facts.ImagePins, r.manifest.ImagePins) ||
		facts.CapturedAtUTC != r.manifest.CapturedAtUTC || facts.ProducerIdentity != r.source.reviewed.ProducerIdentity || len(facts.EffectiveOptions) != 13 {
		return errResetExecutionEvidence
	}
	var world struct {
		ArtifactSetID        string `json:"artifactSetId"`
		Variant              string `json:"variant"`
		TopologyRevision     string `json:"topologyRevision"`
		TopologyContentHash  string `json:"topologyContentHash"`
		WorldID              int    `json:"worldId"`
		MapResourceLogicalID string `json:"mapResourceLogicalId"`
	}
	wire = r.originals["selectedWorld"].Bytes
	if requireResetIntentShape(wire, reflect.TypeOf(world)) != nil || decodeResetPrivateJSON(wire, &world) != nil || world.WorldID != 1 || world.MapResourceLogicalID != "map/han-world-v3.json" ||
		world.ArtifactSetID != facts.ArtifactSetID || world.Variant != facts.Variant || world.TopologyRevision != facts.TopologyRevision || world.TopologyContentHash != facts.TopologyContentHash {
		return errResetExecutionEvidence
	}
	var options struct {
		ParsedImporterOptions map[string]string `json:"parsedImporterOptions"`
		EffectiveOptions      map[string]string `json:"effectiveOptions"`
		EffectiveResetExtend  int               `json:"effectiveResetExtend"`
		ConfiguredResetExtend string            `json:"configuredResetExtend"`
	}
	wire = r.originals["parsedOptions"].Bytes
	importer := cloneResetD101Strings(facts.EffectiveOptions)
	delete(importer, "SERVER_NAME")
	delete(importer, "SERVER_GENERATION")
	if requireResetIntentShape(wire, reflect.TypeOf(options)) != nil || decodeResetPrivateJSON(wire, &options) != nil || len(importer) != 11 ||
		!reflect.DeepEqual(options.ParsedImporterOptions, importer) || !reflect.DeepEqual(options.EffectiveOptions, facts.EffectiveOptions) ||
		options.EffectiveResetExtend < 0 || options.EffectiveResetExtend > 1 || options.ConfiguredResetExtend != facts.EffectiveOptions["RESET_EXTEND"] ||
		options.ConfiguredResetExtend != []string{"0", "1"}[options.EffectiveResetExtend] {
		return errResetExecutionEvidence
	}
	for _, id := range []string{"parserClass", "topologyRootClass"} {
		wire = r.originals[id].Bytes
		if len(wire) < 4 || string(wire[:4]) != "\xca\xfe\xba\xbe" {
			return errResetExecutionEvidence
		}
	}
	return nil // Remaining config/parser/target/topology/provenance is the issuer's independent recomputation below.
}

func (r *resetD101PreIntentCaptureReception) requireProducerPins(p resetD101SelectedProducerPins) error {
	if r == nil || r.source == nil || p.capture != r || r.requireUnsignedSnapshot() != nil {
		return errResetExecutionEvidence
	}
	s := r.source.reviewed
	repository, _, ok := strings.Cut(r.child.ImageRef, "@")
	if !ok || p.OperationID != s.OperationID || p.TargetFingerprint != s.TargetFingerprint || p.AppSourceSHA != s.AppSourceSHA || !reflect.DeepEqual(p.ImagePins, s.ImagePins) ||
		p.ProducerContainerID != r.child.ID || p.ProducerImageID != r.child.ImageID || p.AppRepository != repository || p.SigningKey.KeyID != s.ProducerIdentity ||
		p.FactsSHA != r.originals["captureFacts"].SHA256 || p.ParserBytecodeSHA != r.originals["parserClass"].SHA256 || p.TopologyAlgorithmSHA != r.originals["topologyRootClass"].SHA256 {
		return errResetExecutionEvidence
	}
	paths := map[string]string{"captureFacts": p.FactsFile, "typedTarget": p.TargetFile, "configuration": p.ConfigurationFile, "parserClass": p.ParserBytecodeFile,
		"resolverDecision": p.ResolverDecisionFile, "topologyCanonical": p.TopologyCanonicalFile, "topologyRootClass": p.TopologyAlgorithmFile}
	for id, path := range paths {
		if path != resetD101PreIntentOriginalPath(r.source.outputLocal, id) {
			return errResetExecutionEvidence
		}
	}
	wanted := map[string]string{}
	for id := range r.originals {
		if strings.HasPrefix(id, "topology-input:") {
			wanted[strings.TrimPrefix(id, "topology-input:")] = resetD101PreIntentOriginalPath(r.source.outputLocal, id)
		}
	}
	if !reflect.DeepEqual(wanted, p.TopologyInputs) {
		return errResetExecutionEvidence
	}
	return nil
}

// The actual source call chain: reviewed native inputs -> isolated read-only
// child -> full native reception -> existing independent selected issuer.
// Caller must already own approval for this physical target and signing key.
// There is no HTTP/env/request enable, installer, key creation or fallback.
func (c config) captureAndIssueResetD101SelectedSource(ctx context.Context, s *resetD101PreIntentCaptureSource, key resetD101SigningKeyPins,
	receiptDirectory, envelopeDirectory string, beforeCommand func(context.Context) error) (*resetD101PreIntentCaptureReception, string, error) {
	if s == nil || beforeCommand == nil || key.KeyID != s.reviewed.ProducerIdentity || !filepath.IsAbs(receiptDirectory) || !filepath.IsAbs(envelopeDirectory) ||
		receiptDirectory == envelopeDirectory || requireResetD101PreIntentDirectory(receiptDirectory, false) != nil || requireResetD101PreIntentDirectory(envelopeDirectory, false) != nil {
		return nil, "", errResetExecutionEvidence
	}
	r, err := c.runResetD101PreIntentCapture(ctx, s, beforeCommand)
	if err != nil {
		return nil, "", err
	}
	if r.requireUnsignedSnapshot() != nil {
		return nil, "", errResetExecutionEvidence
	}
	repository, _, _ := strings.Cut(r.child.ImageRef, "@")
	path := func(id string) string { return resetD101PreIntentOriginalPath(s.outputLocal, id) }
	p := resetD101SelectedProducerPins{OperationID: s.reviewed.OperationID, TargetFingerprint: s.reviewed.TargetFingerprint, AppSourceSHA: s.reviewed.AppSourceSHA, ImagePins: cloneResetD101Strings(s.reviewed.ImagePins),
		ProducerContainerID: r.child.ID, ProducerImageID: r.child.ImageID, AppRepository: repository, FactsFile: path("captureFacts"), FactsSHA: r.originals["captureFacts"].SHA256,
		TargetFile: path("typedTarget"), ConfigurationFile: path("configuration"), ParserBytecodeFile: path("parserClass"), ParserBytecodeSHA: r.originals["parserClass"].SHA256,
		ResolverDecisionFile: path("resolverDecision"), TopologyCanonicalFile: path("topologyCanonical"), TopologyAlgorithmFile: path("topologyRootClass"), TopologyAlgorithmSHA: r.originals["topologyRootClass"].SHA256,
		TopologyInputs: map[string]string{}, SigningKey: key, ReceiptDirectory: receiptDirectory, EnvelopeDirectory: envelopeDirectory, capture: r}
	for id := range r.originals {
		if strings.HasPrefix(id, "topology-input:") && d101selectedtransport.ValidSourceID(id) {
			p.TopologyInputs[strings.TrimPrefix(id, "topology-input:")] = path(id)
		}
	}
	producer, err := newResetD101SelectedProducer(p)
	if err != nil {
		return nil, "", err
	}
	sha, err := c.issueResetD101SelectedSource(ctx, producer)
	if err != nil {
		return nil, "", err
	}
	receipt, err := d101custody.ReadPrivate(filepath.Join(receiptDirectory, s.reviewed.OperationID+".json"), 64<<10)
	if err != nil || receipt.SHA256 != sha || !bytes.Equal(receipt.Bytes, r.originals["captureFacts"].Bytes) {
		return nil, "", errResetExecutionEvidence
	}
	envelope, err := d101custody.ReadPrivate(filepath.Join(envelopeDirectory, s.reviewed.OperationID+".json"), 96<<10)
	if err != nil || r.recheck() != nil || c.requireResetD101PreIntentRetainedChild(ctx, r) != nil {
		return nil, "", errResetExecutionEvidence
	}
	r.issuedReceiptSHA = receipt.SHA256
	r.issuedEnvelopeSHA = envelope.SHA256
	r.issuedReceipt = append([]byte(nil), receipt.Bytes...)
	r.issuedEnvelope = append([]byte(nil), envelope.Bytes...)
	return r, sha, nil
}

func (c config) captureIssueAndPublishResetD101SelectedSource(ctx context.Context, s *resetD101PreIntentCaptureSource, key resetD101SigningKeyPins,
	receiptDirectory, envelopeDirectory string, beforeCommand func(context.Context) error) (string, string, error) {
	r, receiptSHA, err := c.captureAndIssueResetD101SelectedSource(ctx, s, key, receiptDirectory, envelopeDirectory, beforeCommand)
	if err != nil {
		return "", "", err
	}
	indexSHA, err := c.publishResetD101SelectedCaptureIndex(ctx, r)
	if err != nil {
		return "", "", err
	}
	return receiptSHA, indexSHA, nil
}
