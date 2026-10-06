package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101operatorauth"
)

type resetD101BootstrapUnavailableFixture struct{ calls *int }

func (p *resetD101BootstrapUnavailableFixture) BuildVerified(context.Context, resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error) {
	(*p.calls)++
	return nil, errors.New("actual issuer not installed")
}

type resetD101TechnicalInstallationUnavailableFixture struct{ calls *int }

func (p *resetD101TechnicalInstallationUnavailableFixture) BuildFromTechnicalIssuance(context.Context, d101operatorauth.TechnicalIssuance, resetD101BootstrapNativeOriginals) (*resetD101FixedInstallation, error) {
	(*p.calls)++
	return nil, errors.New("actual installation not supplied")
}

func newResetD101TechnicalBootstrapScopeFixture(t *testing.T) (resetD101BootstrapNativeOriginals, d101operatorauth.ReviewedPolicy, d101operatorauth.IssuanceEvent) {
	t.Helper()
	op := strings.Repeat("a", 32)
	manifest := resetD101HostTrustManifest{SchemaVersion: 1, Kind: "D101_HOST_TRUST_V1", OperationID: op,
		AppSourceSHA: strings.Repeat("b", 40), DockerSourceSHA: strings.Repeat("c", 40),
		DeploymentCardSHA: strings.Repeat("d", 64), PublicKeySpkiSHA: strings.Repeat("e", 64)}
	wire, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	scope := d101operatorauth.TechnicalScope{OperationID: op, AppSourceSHA: manifest.AppSourceSHA, DockerSourceSHA: manifest.DockerSourceSHA,
		FinalCard: d101operatorauth.Reference{LogicalID: "raw:synthetic-card", SHA256: manifest.DeploymentCardSHA, ByteLength: 10, MediaType: "application/json"}}
	return resetD101BootstrapNativeOriginals{operationID: op, manifestBody: wire},
		d101operatorauth.ReviewedPolicy{Scope: scope, RootPurposeSPKISHA256: manifest.PublicKeySpkiSHA, OpensAtUnix: time.Now().Unix() - 1, CutoffUnix: time.Now().Unix() + 30},
		d101operatorauth.IssuanceEvent{ScopeDecisionOriginal: scope.FinalCard}
}

func TestInstalledBootstrapTechnicalProviderRequiresActualInputs(t *testing.T) {
	native, policy, event := newResetD101TechnicalBootstrapScopeFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *resetD101TechnicalInstallationUnavailableFixture
	for _, name := range []string{"nil-producer", "cancelled", "missing-policy-authenticator", "missing-installation", "typed-nil-installation", "relative-jwt-path", "scope-drift", "authenticated-policy-denied", "already-attempted"} {
		t.Run(name, func(t *testing.T) {
			authCalls, installationCalls := 0, 0
			p := &resetD101TechnicalBootstrapProducer{policy: policy, event: event, jwtPath: "/independent/current-jwt",
				authenticate: func(context.Context, d101operatorauth.ReviewedPolicy, d101operatorauth.IssuanceEvent, resetD101BootstrapNativeOriginals) error {
					authCalls++
					return errors.New("actual independently authenticated policy not supplied")
				}, installation: &resetD101TechnicalInstallationUnavailableFixture{&installationCalls}}
			ctx, expectedAuth := context.Background(), 0
			switch name {
			case "nil-producer":
				p = nil
			case "cancelled":
				ctx = cancelled
			case "missing-policy-authenticator":
				p.authenticate = nil
			case "missing-installation":
				p.installation = nil
			case "typed-nil-installation":
				p.installation = typedNil
			case "relative-jwt-path":
				p.jwtPath = "relative"
			case "scope-drift":
				p.policy.Scope.DockerSourceSHA = strings.Repeat("f", 40)
			case "authenticated-policy-denied":
				expectedAuth = 1
			case "already-attempted":
				p.attempted = true
			}
			got, err := p.BuildVerified(ctx, native)
			if err == nil || got != nil || installationCalls != 0 || authCalls != expectedAuth {
				t.Fatal("unavailable technical input read JWT or reached installation provider")
			}
		})
	}
}

func TestInstalledBootstrapTechnicalScopeRejectsCrossOperation(t *testing.T) {
	for _, name := range []string{"matching-data-only", "operation", "app-source", "docker-source", "card-sha", "card-media", "event-card", "root-purpose-key", "malformed", "trailing-value"} {
		t.Run(name, func(t *testing.T) {
			native, policy, event := newResetD101TechnicalBootstrapScopeFixture(t)
			switch name {
			case "operation":
				policy.Scope.OperationID = strings.Repeat("f", 32)
			case "app-source":
				policy.Scope.AppSourceSHA = strings.Repeat("f", 40)
			case "docker-source":
				policy.Scope.DockerSourceSHA = strings.Repeat("f", 40)
			case "card-sha":
				policy.Scope.FinalCard.SHA256 = strings.Repeat("f", 64)
			case "card-media":
				policy.Scope.FinalCard.MediaType = "text/plain"
			case "event-card":
				event.ScopeDecisionOriginal.LogicalID = "raw:other-card"
			case "root-purpose-key":
				policy.RootPurposeSPKISHA256 = strings.Repeat("f", 64)
			case "malformed":
				native.manifestBody = []byte("{}")
			case "trailing-value":
				native.manifestBody = append(native.manifestBody, []byte(" {}")...)
			}
			if err := requireResetD101TechnicalBootstrapScope(native, policy, event); (err == nil) != (name == "matching-data-only") {
				t.Fatal("technical scope did not bind the exact signed manifest/card data")
			}
		})
	}
}

func TestInstalledBootstrapTechnicalZeroProofNeverBecomesInstallation(t *testing.T) {
	if requireResetD101TechnicalInstalledBinding(d101operatorauth.TechnicalIssuance{}, d101operatorauth.ReviewedPolicy{}, &resetD101FixedInstallation{}) == nil {
		t.Fatal("zero opaque technical proof became installation evidence")
	}
}

func TestInstalledBootstrapMissingActualPolicyNeverReadsOrActivates(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *resetD101BootstrapUnavailableFixture
	calls := 0
	producer := &resetD101BootstrapUnavailableFixture{&calls}
	for _, test := range []struct {
		name   string
		ctx    context.Context
		policy *resetD101InstalledBootstrap
	}{
		{"nil-context", nil, nil},
		{"cancelled", cancelled, nil},
		{"nil-policy", context.Background(), nil},
		{"nil-producer", context.Background(), &resetD101InstalledBootstrap{manifestDir: "/independent/manifest"}},
		{"typed-nil", context.Background(), &resetD101InstalledBootstrap{manifestDir: "/independent/manifest", producer: typedNil}},
		{"relative-directory", context.Background(), &resetD101InstalledBootstrap{manifestDir: "relative", producer: producer}},
		{"missing-anchor", context.Background(), &resetD101InstalledBootstrap{manifestDir: "/independent/manifest", producer: producer}},
		{"malformed-anchor", context.Background(), &resetD101InstalledBootstrap{manifestDir: "/independent/manifest", producer: producer, anchorDER: []byte("not an independently approved DER"), anchorSHA: "self-claim"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := loadResetD101ReviewedInstallation(test.ctx, config{}, test.policy)
			if err == nil || got.d101FixedInstallation != nil || got.d101PurposeAuthority != nil || got.d101CandidatePipeline != nil || calls != 0 {
				t.Fatal("missing bootstrap policy read/activated native inputs")
			}
		})
	}
}
