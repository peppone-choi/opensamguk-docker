package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101operatorauth"
)

type productionTechnicalInstallationTrap struct{ calls int }

// Synthetic approval source for the existing claim-only regression. Its held
// file and parent are actual disposable custody. This type exists only in the
// test binary and supplies no management, human, barrier or physical authority.
type productionRecoveryClaimInstallationFixture struct {
	op string
	originals *resetD101ProductionOriginals
}

func (p *productionRecoveryClaimInstallationFixture) AuthenticateInstallation(ctx context.Context, op, entry string) error {
	if p == nil || op != p.op || entry != "recovery" {
		return errResetD101InstallationNotSupplied
	}
	return p.originals.recheck(ctx)
}

func (p *productionRecoveryClaimInstallationFixture) RecheckInstallation(ctx context.Context, op, entry string) error {
	return p.AuthenticateInstallation(ctx, op, entry)
}

func productionRecoveryClaimFixture(t *testing.T, op, intentSHA, cardSHA string, intent resetDecodedApprovalIntent, purpose resetD101PurposeAuthoritySource) *resetD101ProductionRecoveryInstallation {
	t.Helper()
	path, pin, uid := nativeInstallInputFixture(t)
	h, err := openResetD101NativeInputWithAncestors(context.Background(), path, pin, 0400, uid, func(string, uint32) error { return nil })
	if err != nil {
		t.Fatal("disposable recovery custody", err)
	}
	originals := &resetD101ProductionOriginals{custodyUID: uid,
		refs: []resetD101Key3OriginalRef{{Path: path, Bytes: uint64(len(h.wire)), SHA256: pin.SHA256}},
		held: map[string]*resetD101NativeHeldInput{path: h}}
	t.Cleanup(originals.close)
	p := &resetD101ProductionRecoveryInstallation{operationID: op, intentSHA: intentSHA, cardSHA: cardSHA,
		deadline: time.Unix(intent.Intent.RecoveryDeadlineUnix, 0), originals: originals, purpose: purpose,
		installation: &productionRecoveryClaimInstallationFixture{op: op, originals: originals}, producer: installationMapperDenyRecovery{}}
	if p.RecheckInstallation(context.Background()) != nil {
		t.Fatal("dedicated synthetic recovery source refused")
	}
	return p
}

func (p *productionTechnicalInstallationTrap) AuthenticateInstallation(context.Context, string, string) error {
	p.calls++
	return errResetD101InstallationNotSupplied
}

func (p *productionTechnicalInstallationTrap) RecheckInstallation(context.Context, string, string) error {
	p.calls++
	return errResetD101InstallationNotSupplied
}

// The capability has no exported proof fields. Supplying all caller-visible
// bootstrap bytes cannot create it or reach an installation source.
func TestNativeProductionTechnicalOpaqueIssuanceRejectsBeforeSources(t *testing.T) {
	trap := &productionTechnicalInstallationTrap{}
	p := &resetD101ProductionTechnicalBuilder{installation: trap, originals: &resetD101ProductionOriginals{}}
	native := resetD101BootstrapNativeOriginals{operationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", manifest: []byte("untrusted manifest"), manifestBody: []byte("untrusted body")}
	if installed, err := p.BuildFromTechnicalIssuance(context.Background(), d101operatorauth.TechnicalIssuance{}, native); err == nil || installed != nil {
		t.Fatal("absent opaque proof produced a fixed installation")
	}
	if trap.calls != 0 {
		t.Fatal("absent opaque proof reached the installation source")
	}
}

func TestNativeProductionTechnicalMissingInputDoesNotAuthenticate(t *testing.T) {
	trap := &productionTechnicalInstallationTrap{}
	policy := d101operatorauth.ReviewedPolicy{Scope: d101operatorauth.TechnicalScope{OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	fixed := resetD101FixedInstallation{authority: resetD101HostAuthorityPins{OperationID: policy.Scope.OperationID}}
	if installed, err := newResetD101ProductionTechnicalBuilder(context.Background(), trap, &resetD101ProductionOriginals{}, policy, d101operatorauth.IssuanceEvent{}, fixed); err == nil || installed != nil {
		t.Fatal("missing historical/current/recovery sources produced an installation")
	}
	if trap.calls != 0 {
		t.Fatal("partial bundle reached the installation source")
	}
}

func TestNativeProductionRecoveryRejectsDestructiveActionsBeforeSource(t *testing.T) {
	trap := &productionTechnicalInstallationTrap{}
	purposeCalls := 0
	op, intent := strings.Repeat("a", 32), strings.Repeat("b", 64)
	p := &resetD101ProductionRecoveryInstallation{installation: trap, operationID: op, intentSHA: intent,
		purpose: func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
			purposeCalls++
			return resetD101VerifiedPurposeAuthority{}, errResetExecutionEvidence
		}}
	for _, action := range []string{"PREPARE", "DISPATCH_INTENT", "SETTLE_REGISTRY", "RECOVERY_BEGIN", "unknown"} {
		if _, err := p.Authority(context.Background(), op, intent, action); err == nil {
			t.Fatalf("recovery installation accepted %s", action)
		}
	}
	if trap.calls != 0 || purposeCalls != 0 {
		t.Fatal("destructive action touched a recovery source")
	}
}

func TestNativeProductionRecoveryDoesNotAdoptGenericAuthority(t *testing.T) {
	calls := 0
	c := config{d101PurposeAuthority: func(context.Context, string, string) (resetD101VerifiedPurposeAuthority, error) {
		calls++
		return resetD101VerifiedPurposeAuthority{}, errResetExecutionEvidence
	}}
	op, intent := strings.Repeat("a", 32), strings.Repeat("b", 64)
	if _, err := c.resetD101RecoveryAuthority(context.Background(), op, intent, "QUERY"); err == nil {
		t.Fatal("generic purpose source supplied missing recovery installation")
	}
	if _, err := c.issueResetD101RecoveryQueryGrant(context.Background(), resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: intent, Action: "PREPARE"}); err == nil {
		t.Fatal("recovery query adapter issued destructive grant")
	}
	if calls != 0 {
		t.Fatal("missing dedicated installation fell back to generic authority")
	}
}

func TestNativeProductionRecoveryExpiredDeadlineBeforeSource(t *testing.T) {
	trap := &productionTechnicalInstallationTrap{}
	p := &resetD101ProductionRecoveryInstallation{installation: trap, originals: &resetD101ProductionOriginals{},
		operationID: strings.Repeat("a", 32), intentSHA: strings.Repeat("b", 64), cardSHA: strings.Repeat("c", 64),
		deadline: time.Now().Add(-time.Second), producer: installationMapperDenyRecovery{}}
	if p.RecheckInstallation(context.Background()) == nil || trap.calls != 0 {
		t.Fatal("expired original recovery deadline reached authentication")
	}
}

func TestNativeProductionRetainedReaderMissingSourceNeverCallsDocker(t *testing.T) {
	calls := 0
	c := config{dockerRunner: func(...string) (string, error) { calls++; return "unexpected", nil }}
	if p, err := newResetD101ProductionRetainedJobReader(context.Background(), c, nil, nil, resetD101SucceededRestore{}); err == nil || p != nil {
		t.Fatal("missing actual source constructed a retained reader")
	}
	p := &resetD101ProductionRetainedJobReader{c: c}
	if p.VerifyArchive(context.Background()) == nil {
		t.Fatal("missing source supplied archive verification")
	}
	if calls != 0 {
		t.Fatal("missing source reached a physical command")
	}
}

func TestNativeProductionRetainedExecutionRejectsReplayedAndUnknownJobs(t *testing.T) {
	// Data codec only. Even the valid observation authenticates no installer,
	// approval, execution authority, retained lease or old-world settlement.
	start, end := time.Now().Add(-3*time.Second), time.Now().Add(-time.Second)
	id, image := strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	name := "/d101-restore-list-"+strings.Repeat("c", 32)
	base := map[string]any{"id": id, "image": image, "name": name,
		"startedAt": start.Add(100*time.Millisecond).UTC().Format(time.RFC3339Nano),
		"finishedAt": end.Add(-100*time.Millisecond).UTC().Format(time.RFC3339Nano),
		"pid": 0, "restartCount": 0, "oomKilled": false, "error": "", "dead": false, "paused": false, "restarting": false, "autoRemove": false}
	wire, err := json.Marshal(base)
	if err != nil || requireResetD101ProductionRetainedExecution(wire, id, image, name, start, end) != nil {
		t.Fatal("valid observation codec refused")
	}
	for _, tc := range []struct {
		name, field string
		value any
	}{
		{"different-id", "id", strings.Repeat("d", 64)},
		{"different-image", "image", "sha256:"+strings.Repeat("d", 64)},
		{"different-name", "name", name+"-2"},
		{"earlier-start", "startedAt", start.Add(-time.Second).UTC().Format(time.RFC3339Nano)},
		{"later-finish", "finishedAt", end.Add(time.Second).UTC().Format(time.RFC3339Nano)},
		{"finish-before-start", "finishedAt", start.UTC().Format(time.RFC3339Nano)},
		{"invalid-clock", "startedAt", "unknown"},
		{"live-pid", "pid", 17},
		{"unknown-pid", "pid", nil},
		{"restart", "restartCount", 1},
		{"unknown-restart", "restartCount", nil},
		{"oom", "oomKilled", true},
		{"unknown-oom", "oomKilled", nil},
		{"execution-error", "error", "error"},
		{"unknown-error", "error", nil},
		{"dead", "dead", true},
		{"paused", "paused", true},
		{"restarting", "restarting", true},
		{"auto-removed", "autoRemove", true},
		{"unknown-field", "unreviewed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := make(map[string]any, len(base)+1)
			for key, value := range base { changed[key] = value }
			changed[tc.field] = tc.value
			wire, err := json.Marshal(changed)
			if err != nil || requireResetD101ProductionRetainedExecution(wire, id, image, name, start, end) == nil {
				t.Fatal("changed job observation accepted")
			}
		})
	}
}

func TestNativeProductionRetainedDatabaseScopeRefusalBeforeSources(t *testing.T) {
	trap := &productionTechnicalInstallationTrap{}
	op, wire := strings.Repeat("a", 32), []byte("unverified")
	sha := resetD101OriginalSHA(wire)
	p := &resetD101ProductionRetainedJobReader{installation: trap,
		attempt: resetD101SucceededRestore{binding: resetD101RecoveryBinding{operation: durableOperationRecord{OperationID: op}}}}
	input := resetD101RestoredDatabaseInputs{PostgresContainerID: strings.Repeat("b", 64), Project: "project", Network: "network", Database: "game", User: "game"}
	observed := resetD101RestoredDatabaseObservation{original: wire, sha: sha, postgresID: input.PostgresContainerID, jobID: strings.Repeat("c", 64)}
	for _, tc := range []struct{ op, sha string }{{strings.Repeat("d", 32), sha}, {op, ""}, {op, strings.Repeat("d", 64)}} {
		if v, err := p.ReadDatabase(context.Background(), tc.op, tc.sha, input, observed); err == nil || len(v.original) != 0 {
			t.Fatal("wrong operation/original scope returned a database observation")
		}
	}
	if trap.calls != 0 {
		t.Fatal("scope refusal reached installation authentication")
	}
}
