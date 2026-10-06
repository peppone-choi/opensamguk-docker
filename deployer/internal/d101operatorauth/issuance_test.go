package d101operatorauth

import (
	"strings"
	"testing"
)

func eventFixture(op CurrentOperator) IssuanceEvent {
	p := op.proof
	return IssuanceEvent{ActorID: p.claims.actor, RunID: p.claims.run, JTI: p.claims.jti, WorkflowSHA: p.claims.workflow, RunAttempt: p.claims.attempt,
		AuthenticationOriginal: p.auth, ScopeDecisionOriginal: p.policy.Scope.FinalCard}
}

func TestTechnicalIssuanceRejectsValidAuthenticationForOtherScope(t *testing.T) {
	f := newOperatorFixture(t)
	scopes := []func(*TechnicalScope){func(s *TechnicalScope) { s.OperationID = strings.Repeat("2", 32) }, func(s *TechnicalScope) { s.AppSourceSHA = strings.Repeat("e", 40) },
		func(s *TechnicalScope) { s.DockerSourceSHA = strings.Repeat("e", 40) }, func(s *TechnicalScope) { s.FinalCard.SHA256 = strings.Repeat("e", 64) },
		func(s *TechnicalScope) { s.ScopeOriginal.SHA256 = strings.Repeat("e", 64) }, func(s *TechnicalScope) { s.DecisionParents[0].SHA256 = strings.Repeat("e", 64) },
		func(s *TechnicalScope) { s.DecisionSlicesSHA256 = strings.Repeat("e", 64) }}
	for _, mutate := range scopes {
		op := f.operator(t)
		scope := f.policy.Scope
		mutate(&scope)
		event := eventFixture(op)
		event.ScopeDecisionOriginal = scope.FinalCard
		if _, err := NewTechnicalIssuance(op, event, scope); err == nil {
			t.Fatal("authenticated actor was accepted for another technical scope")
		}
	}
	events := []func(*IssuanceEvent){func(e *IssuanceEvent) { e.ActorID = "105" }, func(e *IssuanceEvent) { e.RunID = "105" }, func(e *IssuanceEvent) { e.RunAttempt = 2 },
		func(e *IssuanceEvent) { e.JTI = "synthetic-other-event" }, func(e *IssuanceEvent) { e.WorkflowSHA = strings.Repeat("e", 40) }, func(e *IssuanceEvent) { e.AuthenticationOriginal.SHA256 = strings.Repeat("e", 64) }}
	for _, mutate := range events {
		op := f.operator(t)
		event := eventFixture(op)
		mutate(&event)
		if _, err := NewTechnicalIssuance(op, event, f.policy.Scope); err == nil {
			t.Fatal("provider event drift accepted")
		}
	}
	if _, err := NewTechnicalIssuance(CurrentOperator{}, IssuanceEvent{}, f.policy.Scope); err == nil {
		t.Fatal("metadata created a current operator")
	}
}

func TestTechnicalIssuanceOneUseAndDefensiveIssuerPins(t *testing.T) {
	f := newOperatorFixture(t)
	op := f.operator(t)
	event := eventFixture(op)
	issued, err := NewTechnicalIssuance(op, event, f.policy.Scope)
	if err != nil {
		t.Fatal("valid current technical issuance denied")
	}
	scope, err := issued.Scope()
	if err != nil || scope != f.policy.Scope {
		t.Fatal("scope changed")
	}
	actual, err := issued.Event()
	if err != nil || actual != event {
		t.Fatal("event changed")
	}
	if _, err := issued.IssuedAtUTC(); err != nil {
		t.Fatal("current issuance time absent")
	}
	for _, role := range []string{ApprovalIssuerRole, ApprovedReceiptIssuerRole} {
		pins, err := issued.Issuer(role)
		if err != nil || pins.Role != role {
			t.Fatal("issuer role changed")
		}
		pins.PublicKeySPKI[0] ^= 1
		again, err := issued.Issuer(role)
		if err != nil || hash(again.PublicKeySPKI) != again.PublicKeySPKISHA256 {
			t.Fatal("issuer pins alias caller")
		}
	}
	if ApprovalOriginDomain == ReceiptAttestationDomain {
		t.Fatal("issuer domains merged")
	}
	if _, err := issued.Issuer("ROOT_PURPOSE"); err == nil {
		t.Fatal("root execution key role returned")
	}
	if _, err := NewTechnicalIssuance(op, event, f.policy.Scope); err == nil {
		t.Fatal("same verified issuance event consumed twice")
	}
	if _, err := (TechnicalIssuance{}).Scope(); err == nil {
		t.Fatal("zero value promoted metadata")
	}
}
