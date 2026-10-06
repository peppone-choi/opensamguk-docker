package main

import (
	"bytes"
	"context"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Fixed host installation values only. These pins and directory mappings are
// never decoded from an HTTP request or an environment enable switch.
type resetD101HostAuthorityPins struct {
	OperationID           string
	ApprovalIntentSHA     string
	ManifestSHA           string
	RootPrivateOrigin     string
	ManifestDirectory     string
	ClockDirectory        string
	OriginalDirectories   map[string]string
	ApprovalAnchorSpki    []byte
	ApprovalAnchorSpkiSHA string
	SigningKey            resetD101SigningKeyPins
}

// Required separate producer verification: actual selected raw5/custody,
// effective option meaning/provenance, isolated C4 evidence, approval lineage,
// exact card's config/commands/recovery/readers/evidence/review originals and
// observed runtime source/image pins. Signature/hash success cannot replace it.
type resetD101HostEvidenceVerifier func(context.Context, *resetD101HostEvidence) error

type resetD101HostEvidence struct{ originals map[string][]byte }

func (e *resetD101HostEvidence) Original(id string) ([]byte, error) {
	wire, ok := e.originals[id]
	if !ok {
		return nil, errResetExecutionEvidence
	}
	return append([]byte(nil), wire...), nil
}

func newResetD101HostAuthority(pins resetD101HostAuthorityPins, verify resetD101HostEvidenceVerifier,
	clock func() time.Time) (resetD101PurposeAuthoritySource, error) {
	return newResetD101HostAuthorityWithUID(pins, verify, clock, 0)
}

// Non-root UID injection is confined to isolated file-custody tests.
func newResetD101HostAuthorityWithUID(pins resetD101HostAuthorityPins, verify resetD101HostEvidenceVerifier,
	clock func() time.Time, uid uint32) (resetD101PurposeAuthoritySource, error) {
	anchor, err := resetD101PinnedPublicKey(append([]byte(nil), pins.ApprovalAnchorSpki...), pins.ApprovalAnchorSpkiSHA)
	origin, uriErr := url.Parse(pins.RootPrivateOrigin)
	port := 0
	if uriErr == nil && origin != nil {
		port, _ = strconv.Atoi(origin.Port())
	}
	if err != nil || uriErr != nil || origin == nil || verify == nil || clock == nil ||
		!lifecycleJobIDRe.MatchString(pins.OperationID) || !resetEvidenceSHA.MatchString(pins.ApprovalIntentSHA) ||
		!resetEvidenceSHA.MatchString(pins.ManifestSHA) || origin.Scheme != "http" && origin.Scheme != "https" ||
		origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || strings.Contains(pins.RootPrivateOrigin, "#") ||
		origin.RawPath != "" || origin.Path != "" && origin.Path != "/" || port < 1 || port > 65535 ||
		!validResetD101PrivateHost(origin.Hostname()) ||
		!resetD101KeyID.MatchString(pins.SigningKey.KeyID) || !resetEvidenceSHA.MatchString(pins.SigningKey.EnvelopeSHA) ||
		!resetEvidenceSHA.MatchString(pins.SigningKey.PublicKeySpkiSHA) {
		return nil, errResetExecutionEvidence
	}
	// Use a value-only frozen installation, not the caller's mutable map/slice.
	directories := make(map[string]string, len(pins.OriginalDirectories))
	for id, dir := range pins.OriginalDirectories {
		directories[id] = dir
	}
	pins.OriginalDirectories = directories
	paths := []string{pins.ManifestDirectory, pins.ClockDirectory, pins.SigningKey.Directory}
	for _, dir := range directories {
		paths = append(paths, dir)
	}
	for _, dir := range paths {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return nil, errResetExecutionEvidence
		}
	}
	if len(directories) != len(resetD101HostOriginalIDs) {
		return nil, errResetExecutionEvidence
	}
	for _, id := range resetD101HostOriginalIDs {
		if directories[id] == "" {
			return nil, errResetExecutionEvidence
		}
	}
	return func(ctx context.Context, op, intentSHA string) (resetD101VerifiedPurposeAuthority, error) {
		closed := resetD101VerifiedPurposeAuthority{}
		if ctx == nil || ctx.Err() != nil || op != pins.OperationID || intentSHA != pins.ApprovalIntentSHA {
			return closed, errResetExecutionEvidence
		}
		ctx, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
		defer cancel()
		startedMonotonic := time.Now()
		started := clock()
		read := func(dir string) ([]byte, error) { return readResetPrivateCustody(dir, pins.OperationID, uid) }
		originals := make(map[string][]byte, len(directories)+2)
		for id, dir := range directories {
			wire, err := read(dir)
			if err != nil {
				return closed, errResetExecutionEvidence
			}
			originals[id] = wire
		}
		intent, err := decodeResetApprovalIntent(originals["approvalIntent"], pins.ApprovalIntentSHA)
		if err != nil || intent.Intent.OperationID != op {
			return closed, errResetExecutionEvidence
		}
		signed, err := read(pins.ManifestDirectory)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		manifestWire, err := decodeResetD101SignedHostOriginal(signed, resetD101HostTrustDomain, anchor)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		// Card SHA comes from the pinned, independently signed manifest; no
		// field may select a different local file or a different trust key.
		var preliminary resetD101HostTrustManifest
		if decodeResetPrivateJSON(manifestWire, &preliminary) != nil {
			return closed, errResetExecutionEvidence
		}
		card, err := decodeResetD101DeploymentCard(originals["deploymentCard"], preliminary.DeploymentCardSHA, intent)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		manifest, err := decodeResetD101HostTrust(manifestWire, pins.ManifestSHA, intent, card,
			pins.RootPrivateOrigin, pins.SigningKey)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		expected := map[string]string{
			"approvalIntent": intent.SHA, "deploymentCard": card.SHA,
			"approvalReceipt":         intent.Intent.ApprovalReceiptSHA,
			"combinedCiReceipt":       intent.Intent.CombinedCIReceiptSHA,
			"selectedSourceReceipt":   intent.Intent.SelectedSourceReceiptSHA,
			"isolatedSeedTickReceipt": intent.Intent.IsolatedSeedTickReceiptSHA,
			"spaceInventoryReceipt":   intent.Intent.SpaceInventoryReceiptSHA,
			"configInventory":         card.Card.ConfigInventorySHA, "commandPlan": card.Card.CommandPlanSHA,
			"recoveryPlan": card.Card.RecoveryPlanSHA, "readerBindings": card.Card.ReaderBindingsSHA,
			"evidenceCatalog": card.Card.EvidenceCatalogSHA, "reviewBasis": card.Card.ReviewBasisSHA,
			"approvedReceiptProvenance": manifest.ApprovedReceiptProvenanceSHA,
		}
		for id, sha := range expected {
			if resetD101OriginalSHA(originals[id]) != sha {
				return closed, errResetExecutionEvidence
			}
		}
		// Same-op plan semantics are mandatory before granting QUERY/PREPARE.
		// Native SHA/signature labels cannot replace the exact intent/command/
		// card binding. Actual backup/restore receipts remain separate checks.
		if _, err := requireResetD101RecoveryPlanCard(originals["recoveryPlan"], card, intent, originals["commandPlan"]); err != nil {
			return closed, errResetExecutionEvidence
		}
		signedClock, err := read(pins.ClockDirectory)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		clockWire, err := decodeResetD101SignedHostOriginal(signedClock, resetD101ClockAgreementDomain, anchor)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		if _, err := decodeResetD101ClockAgreement(clockWire, op, intentSHA, clock()); err != nil {
			return closed, errResetExecutionEvidence
		}
		// Verify the pinned actual signing envelope through native UID/mode/
		// no-follow/nlink custody, derive SPKI, and clear secret bytes. No signing.
		key, err := readResetD101SigningKeyWithUID(pins.SigningKey, uid)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		key.close()
		originals["trustManifest"] = manifestWire
		originals["clockAgreement"] = clockWire
		producerInput := &resetD101HostEvidence{originals: make(map[string][]byte, len(originals))}
		for id, wire := range originals {
			producerInput.originals[id] = append([]byte(nil), wire...)
		}
		if verify(ctx, producerInput) != nil || ctx.Err() != nil {
			return closed, errResetExecutionEvidence
		}
		// Re-read the installed same-operation originals after the separate
		// semantic producer. A changed native capture/plan cannot inherit the
		// earlier labels or callback result.
		for id, directory := range directories {
			after, err := read(directory)
			if err != nil || !bytes.Equal(after, originals[id]) {
				return closed, errResetExecutionEvidence
			}
		}
		completed := clock()
		observed, err := decodeResetD101ClockAgreement(clockWire, op, intentSHA, completed)
		if err != nil || ctx.Err() != nil || time.Since(startedMonotonic) >= resetPreflightMaxAge ||
			started.Unix() <= 0 || completed.Before(started) ||
			completed.Sub(started) >= resetPreflightMaxAge {
			return closed, errResetExecutionEvidence
		}
		// Re-decode our originals so a producer cannot mutate returned authority.
		intent, err = decodeResetApprovalIntent(originals["approvalIntent"], pins.ApprovalIntentSHA)
		if err != nil {
			return closed, errResetExecutionEvidence
		}
		return resetD101VerifiedPurposeAuthority{intent, pins.SigningKey, card.SHA,
			manifest.ApprovedReceiptProvenanceSHA, resetD101OriginalSHA(clockWire), observed}, nil
	}, nil
}

func validResetD101PrivateHost(host string) bool {
	switch host {
	case "deployer", "opensamguk-deployer", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

var resetD101HostOriginalIDs = []string{
	"approvalIntent", "deploymentCard", "approvalReceipt", "combinedCiReceipt",
	"selectedSourceReceipt", "isolatedSeedTickReceipt", "spaceInventoryReceipt",
	"configInventory", "commandPlan", "recoveryPlan", "readerBindings",
	"evidenceCatalog", "reviewBasis", "approvedReceiptProvenance",
}
