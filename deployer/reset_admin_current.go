package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"time"
)

// A root-issued operation credential is not part of request identity. Replacing
// it never replaces approval/evidence or renews the operation's deadline.
// The game API, not this file, verifies signature, audience, expiry and ADMIN.
type resetAdminCredential struct {
	Version           int    `json:"version"`
	ServerID          string `json:"serverId"`
	WorldID           int    `json:"worldId"`
	OperationID       string `json:"operationId"`
	TargetFingerprint string `json:"targetFingerprint"`
	ApprovalPlanSHA   string `json:"approvalPlanSha256"`
	ExpiresAtUnix     int64  `json:"expiresAtUnix"`
	AccessToken       string `json:"accessToken"`
}

var resetAdminJWTShape = regexp.MustCompile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$")

func readResetAdminCredential(directory string, binding resetExecutionPhaseBinding, now time.Time, uid uint32) (string, error) {
	wire, err := readResetPrivateCustody(directory, binding.OperationID, uid)
	if err != nil {
		return "", errResetExecutionEvidence
	}
	var credential resetAdminCredential
	if decodeResetPrivateJSON(wire, &credential) != nil || credential.Version != 1 || credential.ServerID != "pep" ||
		credential.WorldID != 1 || credential.OperationID != binding.OperationID ||
		credential.TargetFingerprint != resetRequestFingerprint("pep", binding.Target) ||
		credential.ApprovalPlanSHA != binding.Evidence.ApprovalPlanSHA || !resetEvidenceSHA.MatchString(credential.ApprovalPlanSHA) ||
		credential.ExpiresAtUnix <= now.Unix() || len(credential.AccessToken) > 8192 || !resetAdminJWTShape.MatchString(credential.AccessToken) {
		return "", errResetExecutionEvidence
	}
	return credential.AccessToken, nil
}

type resetAdminCurrent struct {
	WorldID            *int    `json:"worldId"`
	Generation         *string `json:"generation"`
	ScenarioCode       *string `json:"scenarioCode"`
	Year               *int    `json:"year"`
	Month              *int    `json:"month"`
	Phase              *int    `json:"phase"`
	Status             *string `json:"status"`
	TurnTerm           *int    `json:"turnTerm"`
	StartTime          *string `json:"startTime"`
	MaxGeneral         *int    `json:"maxGeneral"`
	BlockGeneralCreate *int    `json:"blockGeneralCreate"`
	FirstTurn          *string `json:"firstTurn"`
}

type resetAdminCurrentObservation struct {
	ObservedAt time.Time
	Current    resetAdminCurrent
}

// This only diagnoses raw settings. It cannot prove source bytes, five image
// pins, seeded people/cities, actual first tick, flush or restart persistence.
func validateResetD101AdminCurrent(current resetAdminCurrent) error {
	if current.WorldID == nil || *current.WorldID != 1 || current.Generation == nil || *current.Generation != "0" ||
		current.ScenarioCode == nil || *current.ScenarioCode != "scenario_3190" ||
		current.TurnTerm == nil || *current.TurnTerm != 60 || current.MaxGeneral == nil || *current.MaxGeneral != 50 ||
		current.BlockGeneralCreate == nil || *current.BlockGeneralCreate != 1 ||
		current.FirstTurn == nil || *current.FirstTurn != "immediate" || current.StartTime == nil {
		return errResetExecutionEvidence
	}
	if _, err := time.Parse(time.RFC3339Nano, *current.StartTime); err != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func getResetAdminCurrent(ctx context.Context, endpoint, accessToken string) (resetAdminCurrentObservation, error) {
	if len(accessToken) > 8192 || !resetAdminJWTShape.MatchString(accessToken) {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	deadline, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(deadline, http.MethodGet, endpoint, nil)
	if err != nil {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Cache-Control", "no-store")
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext,
		DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(wire) > 16*1024 {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	var current resetAdminCurrent
	if decodeResetPrivateJSON(wire, &current) != nil || validateResetD101AdminCurrent(current) != nil || deadline.Err() != nil {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	return resetAdminCurrentObservation{ObservedAt: time.Now(), Current: current}, nil
}

// No caller can select a URL or supply a bearer in a reset body. Production reads
// only the root-private credential and the server's canonical internal origin.
// This remains unconnected to the closed D101 worker.
func (c config) observeResetD101AdminCurrent(ctx context.Context, binding resetExecutionPhaseBinding) (resetAdminCurrentObservation, error) {
	if binding.OperationID == "" || binding.Target.ScenarioCode != "scenario_3190" ||
		binding.Target.Generation != 0 {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	token, err := readResetAdminCredential(filepath.Join(c.serversDir, ".deployer-reset-admin"), binding, time.Now(), 0)
	if err != nil {
		return resetAdminCurrentObservation{}, errResetExecutionEvidence
	}
	return getResetAdminCurrent(ctx, c.gameAPIURLFor("pep")+"/api/admin/reset-current", token)
}
