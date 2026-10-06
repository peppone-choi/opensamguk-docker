package main

import (
	"context"
	"net/http/httptest"
	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101native"
	"strings"
	"testing"
)

type native9AbsentInstallerSource struct{}

func (*native9AbsentInstallerSource) AuthenticateInstallation(context.Context, string, string) error {
	return nil
}
func (*native9AbsentInstallerSource) RecheckInstallation(context.Context, string, string) error {
	return nil
}
func TestNative9PhaseScopedInstallerNoFutureReceiptCycle(t *testing.T) {
	v := &resetD101NativeAuthorityInstaller{operationID: strings.Repeat("a", 32), installation: &native9AbsentInstallerSource{}}
	used := false
	if v.consumePhase(context.Background(), nil, v.operationID, 11, func(*d101native.VerifiedCurrent) error { used = true; return nil }) == nil || used {
		t.Fatal("missing actual current source authorized issuer")
	}
	if _, err := v.hostIssuer(context.Background(), nil, v.operationID); err == nil {
		t.Fatal("missing issuer originals filled")
	}
	if _, err := v.hostOperation(context.Background(), nil, v.operationID); err == nil {
		t.Fatal("missing physical originals filled")
	}
	if _, err := v.overallCompletion(context.Background()); err == nil {
		t.Fatal("physical fact became overall completion")
	}
}
func TestNative9AllEightAndRequiredConsumers(t *testing.T) {
	v := &resetD101NativeAuthorityInstaller{}
	for _, name := range []string{"entry", "main-bootstrap", "physical", "issuer", "relay", "signing", "runtime-certificate", "completion"} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "entry":
				old := resetD101ReviewedNativeEntryFactory
				resetD101ReviewedNativeEntryFactory = nil
				defer func() { resetD101ReviewedNativeEntryFactory = old }()
				if _, e := actualResetD101NativeEntry(context.Background(), "keeper", ""); e == nil {
					t.Fatal("missing entry accepted")
				}
			case "main-bootstrap":
				if _, e := v.fixedForMain(context.Background(), config{}, d101custody.Original{}, d101custody.NativeFilePin{}); e == nil {
					t.Fatal("empty bootstrap accepted")
				}
			case "physical":
				if _, e := v.hostOperation(context.Background(), nil, ""); e == nil {
					t.Fatal("physical accepted")
				}
			case "issuer":
				if _, e := v.hostIssuer(context.Background(), nil, ""); e == nil {
					t.Fatal("issuer accepted")
				}
			case "relay":
				if _, e := v.relayInstallation(context.Background()); e == nil {
					t.Fatal("relay accepted")
				}
			case "signing":
				if _, e := v.signStage(context.Background(), nil, &d101native.Acquired{}); e == nil {
					t.Fatal("signing accepted")
				}
			case "runtime-certificate":
				if _, e := v.signRuntimeCertificate(context.Background(), nil, d101native.RelaySessionBinding{}, resetD101RelayPeerObservation{}); e == nil {
					t.Fatal("public accepted")
				}
			case "completion":
				w := httptest.NewRecorder()
				v.completionHandler()(w, httptest.NewRequest("GET", "/d101/native/completion", nil))
				if w.Code != 503 || strings.Contains(w.Body.String(), `"complete":true`) {
					t.Fatal("missing actual release declared complete")
				}
			}
		})
	}
	c := native9RootDataFixture(t)
	closed, err := assembleResetD101InstalledSourcesWithReader(context.Background(), c, func(context.Context, config) (resetD101InstalledSources, error) {
		return resetD101InstalledSources{}, nil
	})
	if err == nil || closed.d101PurposeAuthority != nil || closed.d101PhaseSource != nil || closed.d101PreStopNativeInstallation != nil || closed.d101RecoveryClosureReader != nil || closed.d101RecoveryVerifier != nil || closed.d101RecoveryDatabaseSource != nil || closed.d101SeedMaterialInputs != nil || closed.d101CandidatePipeline != nil {
		t.Fatal("partial all8 installation published")
	}
}
