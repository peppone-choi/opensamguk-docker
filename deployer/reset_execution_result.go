package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const resetD101ResultMaxBytes = 16 * 1024

var resetD101ResultReadSlots = make(chan struct{}, 2)

// Root physical outcome only. Canonical gateway settlement and final PUBLIC
// tick/role validation occur later; this record cannot substitute for either.
type resetD101ExecutionResult struct {
	SchemaVersion           int               `json:"schemaVersion"`
	ServerID                string            `json:"serverId"`
	WorldID                 int               `json:"worldId"`
	OperationID             string            `json:"operationId"`
	Kind                    string            `json:"kind"`
	Status                  string            `json:"status"`
	Generation              int               `json:"generation"`
	ScenarioCode            string            `json:"scenarioCode"`
	ServerName              string            `json:"serverName"`
	ApprovalIntentSHA       string            `json:"approvalIntentSha256"`
	ApprovalPlanSHA         string            `json:"approvalPlanSha256"`
	ExecutionReceiptSHA     string            `json:"executionReceiptSha256"`
	TargetFingerprint       string            `json:"targetFingerprint"`
	RootRequestFingerprint  string            `json:"rootRequestFingerprint"`
	GatewayPayloadSHA       string            `json:"gatewayPayloadSha256"`
	VerifyingRevision       string            `json:"verifyingRevision"`
	AppSourceSHA            string            `json:"appSourceSha"`
	ImageDigests            map[string]string `json:"imageDigests"`
	AcceptedAtUTC           string            `json:"acceptedAtUtc"`
	CompletedAtUTC          string            `json:"completedAtUtc"`
	ExecutionJournalSHA     *string           `json:"executionJournalSha256"`
	ActualRuntimeReceiptSHA *string           `json:"actualRuntimeReceiptSha256"`
	FailureCode             *string           `json:"failureCode"`
}

func decodeResetD101ExecutionResult(wire []byte, expectedSHA string) (resetD101ExecutionResult, error) {
	empty := resetD101ExecutionResult{}
	sum := sha256.Sum256(wire)
	if len(wire) == 0 || len(wire) > resetD101ResultMaxBytes || !resetEvidenceSHA.MatchString(expectedSHA) ||
		hex.EncodeToString(sum[:]) != expectedSHA {
		return empty, errResetExecutionEvidence
	}
	var fields map[string]json.RawMessage
	shape := reflect.TypeOf(empty)
	if json.Unmarshal(wire, &fields) != nil || len(fields) != shape.NumField() {
		return empty, errResetExecutionEvidence
	}
	nullable := map[string]bool{"executionJournalSha256": true, "actualRuntimeReceiptSha256": true, "failureCode": true}
	for n := 0; n < shape.NumField(); n++ {
		f := shape.Field(n)
		value, ok := fields[f.Tag.Get("json")]
		if !ok || (!nullable[f.Tag.Get("json")] && requireResetIntentShape(value, f.Type) != nil) {
			return empty, errResetExecutionEvidence
		}
	}
	var result resetD101ExecutionResult
	if decodeResetPrivateJSON(wire, &result) != nil || result.SchemaVersion != 1 || result.ServerID != "pep" || result.WorldID != 1 ||
		!lifecycleJobIDRe.MatchString(result.OperationID) || result.Kind != "reset" || result.Generation != 0 ||
		result.ScenarioCode != "scenario_3190" || result.ServerName != "빼섭" || !gitSHA40.MatchString(result.AppSourceSHA) ||
		!validResetFiveImageDigests(result.ImageDigests) {
		return empty, errResetExecutionEvidence
	}
	for _, sha := range []string{result.ApprovalIntentSHA, result.ApprovalPlanSHA, result.ExecutionReceiptSHA,
		result.TargetFingerprint, result.RootRequestFingerprint, result.GatewayPayloadSHA} {
		if !resetEvidenceSHA.MatchString(sha) {
			return empty, errResetExecutionEvidence
		}
	}
	for _, sha := range []*string{result.ExecutionJournalSHA, result.ActualRuntimeReceiptSHA} {
		if sha != nil && !resetEvidenceSHA.MatchString(*sha) {
			return empty, errResetExecutionEvidence
		}
	}
	revision, err := strconv.ParseInt(result.VerifyingRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != result.VerifyingRevision {
		return empty, errResetExecutionEvidence
	}
	switch lifecycleJobStatus(result.Status) {
	case lifecycleJobSucceeded:
		if result.ExecutionJournalSHA == nil || result.ActualRuntimeReceiptSHA == nil || result.FailureCode != nil {
			return empty, errResetExecutionEvidence
		}
	case lifecycleJobFailed, lifecycleJobCancelled, lifecycleJobRecoveryRequired:
		if result.FailureCode == nil {
			return empty, errResetExecutionEvidence
		}
		switch *result.FailureCode {
		case "ADMISSION_REJECTED", "PHASE_FAILED", "WORKER_FAILED", "CANCELLED", "SOURCE_UNAVAILABLE", "CLOCK_UNAVAILABLE", "CUSTODY_UNAVAILABLE", "UNKNOWN_STAGE":
		default:
			return empty, errResetExecutionEvidence
		}
	default:
		return empty, errResetExecutionEvidence
	}
	accepted, err := resetC4UTC(result.AcceptedAtUTC)
	completed, completedErr := resetC4UTC(result.CompletedAtUTC)
	if err != nil || completedErr != nil || completed.Before(accepted) {
		return empty, errResetExecutionEvidence
	}
	return result, nil
}

func requireResetD101ResultBinding(result resetD101ExecutionResult, intent resetDecodedApprovalIntent, plan resetApprovalPlan, preflight resetPreflightReceipt, record durableOperationRecord, now time.Time) error {
	accepted, err := resetC4UTC(result.AcceptedAtUTC)
	completed, completedErr := resetC4UTC(result.CompletedAtUTC)
	fingerprint, fpErr := resetExecutionRequestFingerprint("pep", plan.Target, resetExecutionEvidenceRefs{result.ApprovalPlanSHA, result.ExecutionReceiptSHA})
	revision, revisionErr := strconv.ParseInt(result.VerifyingRevision, 10, 64)
	initial, initialErr := strconv.ParseInt(intent.Intent.InitialPublicRevision, 10, 64)
	if err != nil || completedErr != nil || fpErr != nil || revisionErr != nil || initialErr != nil || revision <= initial ||
		(record.D101IntentSHA != "" && record.D101IntentSHA != intent.SHA) ||
		completed.After(now) || !accepted.Equal(record.CreatedAt) || !completed.Equal(record.UpdatedAt) ||
		record.OperationID != result.OperationID || record.Kind != lifecycleKindReset || record.SubjectID != "pep" ||
		string(record.Status) != result.Status || record.RequestFingerprint != result.RootRequestFingerprint || fingerprint != record.RequestFingerprint ||
		requireResetIntentPlan(intent, plan) != nil || result.ApprovalIntentSHA != intent.SHA || result.OperationID != plan.OperationID ||
		result.TargetFingerprint != plan.TargetFingerprint || result.AppSourceSHA != plan.AppSourceSHA ||
		!reflect.DeepEqual(result.ImageDigests, plan.NewImageDigests) || result.VerifyingRevision != preflight.PublicationRevision ||
		preflight.ApprovalPlanSHA != result.ApprovalPlanSHA || preflight.OperationID != result.OperationID ||
		preflight.TargetFingerprint != result.TargetFingerprint || preflight.AppSourceSHA != result.AppSourceSHA {
		return errResetExecutionEvidence
	}
	return nil
}

// Always re-read the current durable record. A retained file for a missing,
// pruned, reused, running or changed operation never establishes completion.
// Missing actual authority source means 503 even when all files are readable.
func (c config) readResetD101ExecutionResult(ctx context.Context, op, expectedSHA string) ([]byte, string, error) {
	if c.d101PurposeAuthority == nil || c.lifecycleOperationStore == nil || !lifecycleJobIDRe.MatchString(op) ||
		!resetEvidenceSHA.MatchString(expectedSHA) || ctx.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	record, found := c.lifecycleOperationStore.Lookup(op)
	if !found || record.Kind != lifecycleKindReset || record.SubjectID != "pep" || record.D101IntentSHA == "" {
		return nil, "", errResetExecutionEvidence
	}
	wire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-results"), op, 0)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	result, err := decodeResetD101ExecutionResult(wire, expectedSHA)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	authority, err := c.d101PurposeAuthority(ctx, op, result.ApprovalIntentSHA)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	request := resetD101PurposeGrantRequest{OperationID: op, ApprovalIntentSHA: result.ApprovalIntentSHA, GatewayPayloadSHA: result.GatewayPayloadSHA, Action: "QUERY"}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	var plan resetApprovalPlan
	var preflight resetPreflightReceipt
	if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-approvals"), op, result.ApprovalPlanSHA, 0, &plan) != nil ||
		readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-preflights"), op, result.ExecutionReceiptSHA, 0, &preflight) != nil ||
		requireResetD101ResultBinding(result, intent, plan, preflight, record, time.Now()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	prepare, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	if err != nil || requireResetD101PrepareBody(prepare, intent, result.GatewayPayloadSHA) != nil {
		return nil, "", errResetExecutionEvidence
	}
	if err := c.requireResetD101ResultProofs(result, plan, preflight, record); err != nil {
		return nil, "", errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(authority.KeyPins)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer key.close()
	signature, err := key.sign("OPENSAMGUK-D101-RESULT-V1\n", wire)
	current, currentFound := c.lifecycleOperationStore.Lookup(op)
	if err != nil || !currentFound || current != record || ctx.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	if _, err := requireResetD101Authority(authority, request, time.Now()); err != nil {
		return nil, "", errResetExecutionEvidence
	}
	return wire, key.keyID + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func isResetD101ResultPath(path string) bool { return strings.Contains(path, "/execution-result/") }
func (c config) requireResetD101ResultProofs(result resetD101ExecutionResult, plan resetApprovalPlan, preflight resetPreflightReceipt, record durableOperationRecord) error {
	return c.requireResetD101ResultProofsWithCustodyUID(result, plan, preflight, record, 0)
}

// UID injection is restricted to isolated custody fixtures.
func (c config) requireResetD101ResultProofsWithCustodyUID(result resetD101ExecutionResult, plan resetApprovalPlan, preflight resetPreflightReceipt, record durableOperationRecord, uid uint32) error {
	if result.ExecutionJournalSHA != nil {
		var journal resetExecutionJournal
		if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-execution-journals"), result.OperationID, *result.ExecutionJournalSHA, uid, &journal) != nil ||
			validateResetExecutionJournal(journal, result.OperationID, plan.Target) != nil || journal.AcceptedAtUnix != record.CreatedAt.Unix() ||
			journal.RequestFingerprint != record.RequestFingerprint || journal.Evidence != (resetExecutionEvidenceRefs{result.ApprovalPlanSHA, result.ExecutionReceiptSHA}) {
			return errResetExecutionEvidence
		}
		for _, phase := range journal.Attestations {
			if phase.Snapshot.PublicationRevision != preflight.PublicationRevision || phase.Snapshot.WriterFreezeReceiptSHA != plan.WriterFreezeReceiptSHA ||
				preflight.FilesystemDevice == nil || phase.Space.Device != *preflight.FilesystemDevice {
				return errResetExecutionEvidence
			}
		}
		if result.Status == "succeeded" && (len(journal.Attestations) != 3 || journal.Attestations[2].Snapshot.PublicationRevision != result.VerifyingRevision ||
			journal.Attestations[2].CompletedAt.Unix() >= plan.DestructiveCutoffUnix || journal.Attestations[2].CompletedAt.After(record.UpdatedAt)) {
			return errResetExecutionEvidence
		}
	}
	if result.ActualRuntimeReceiptSHA != nil {
		promotion, err := c.readResetD101CandidatePromotion(result.OperationID, uid)
		if err != nil || promotion.AppSourceSHA != result.AppSourceSHA || promotion.ApprovalIntentSHA != record.D101IntentSHA || promotion.TargetFingerprint != result.TargetFingerprint || promotion.SelectedSourceReceiptSHA != plan.SelectedSourceReceiptSHA {
			return errResetExecutionEvidence
		}
		var runtime resetRuntimeObservation
		if readResetPrivateEvidence(filepath.Join(c.serversDir, ".deployer-reset-runtime"), result.OperationID, *result.ActualRuntimeReceiptSHA, uid, &runtime) != nil ||
			runtime.Version != 1 || runtime.ServerID != "pep" || runtime.WorldID != 1 || runtime.OperationID != result.OperationID ||
			runtime.TargetFingerprint != result.TargetFingerprint || runtime.AppSourceSHA != result.AppSourceSHA ||
			runtime.Evidence != (resetExecutionEvidenceRefs{result.ApprovalPlanSHA, result.ExecutionReceiptSHA}) ||
			!reflect.DeepEqual(runtime.ImageDigests, result.ImageDigests) || len(runtime.Containers) != 5 ||
			runtime.StartedAt.Before(record.CreatedAt) || runtime.CompletedAt.Before(runtime.StartedAt) ||
			runtime.CompletedAt.Sub(runtime.StartedAt) >= resetPreflightMaxAge || runtime.CompletedAt.After(record.UpdatedAt) ||
			runtime.Raw.ObservedAt.Before(runtime.StartedAt) || runtime.Raw.ObservedAt.After(runtime.CompletedAt) ||
			validateResetD101AdminCurrent(runtime.Raw.Current) != nil {
			return errResetExecutionEvidence
		}
		ids := map[string]bool{}
		for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
			container, ok := runtime.Containers[service]
			if !ok || !resetEvidenceSHA.MatchString(container.ID) || ids[container.ID] || container.ID == preflight.StoppedContainerIDs[service] ||
				container.Name != "/spep-"+service || container.Service != service || container.Project != resetD101RuntimeProject(service, promotion.Resources.Project) ||
				!resetManifestDigest.MatchString(container.ImageID) || container.Running == nil || !*container.Running || container.Status != "running" {
				return errResetExecutionEvidence
			}
			if (service == "game-postgres" && container.ID != promotion.PostgresContainerID) || (service == "game-redis" && container.ID != promotion.RedisContainerID) {
				return errResetExecutionEvidence
			}
			ids[container.ID] = true
			if (service == "game-api" || len(container.ServerIDs) > 0) && (len(container.ServerIDs) != 1 || container.ServerIDs[0] != "SERVER_ID=pep") {
				return errResetExecutionEvidence
			}
			selected := []*string{}
			for key, value := range container.SeedSettings {
				entry := key + "=" + value
				selected = append(selected, &entry)
			}
			selected = append(selected, nil)
			if _, err := resetRuntimeSeedSettings(service, selected); err != nil {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}

func (c config) handleResetD101ExecutionResult(w http.ResponseWriter, r *http.Request, parts []string) {
	serveResetD101ExecutionResult(w, r, parts, c.readResetD101ExecutionResult)
}
func serveResetD101ExecutionResult(w http.ResponseWriter, r *http.Request, parts []string, read func(context.Context, string, string) ([]byte, string, error)) {
	w.Header().Set("Cache-Control", "no-store")
	if len(parts) != 3 || !lifecycleJobIDRe.MatchString(parts[0]) || parts[1] != "execution-result" || !resetEvidenceSHA.MatchString(parts[2]) ||
		r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Path != "/operations/"+strings.Join(parts, "/") || r.ContentLength != 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid result identity"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "GET only"})
		return
	}
	select {
	case resetD101ResultReadSlots <- struct{}{}:
	default:
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "execution result unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	type observation struct {
		wire  []byte
		proof string
		err   error
	}
	completed := make(chan observation, 1)
	// If a source ignores cancellation, it keeps its slot until it exits. A
	// timed-out HTTP caller cannot start an unbounded number of background reads.
	go func() {
		defer func() { <-resetD101ResultReadSlots }()
		if read == nil {
			completed <- observation{err: errResetExecutionEvidence}
			return
		}
		wire, proof, err := read(ctx, parts[0], parts[2])
		completed <- observation{wire, proof, err}
	}()
	var observed observation
	select {
	case observed = <-completed:
	case <-ctx.Done():
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "execution result unavailable"})
		return
	}
	sum := sha256.Sum256(observed.wire)
	proofParts := strings.Split(observed.proof, ".")
	proofValid := len(proofParts) == 2 && resetD101KeyID.MatchString(proofParts[0])
	if proofValid {
		signature, err := base64.RawURLEncoding.Strict().DecodeString(proofParts[1])
		proofValid = err == nil && len(signature) == 64 && base64.RawURLEncoding.EncodeToString(signature) == proofParts[1]
	}
	if observed.err != nil || ctx.Err() != nil || len(observed.wire) == 0 || len(observed.wire) > resetD101ResultMaxBytes ||
		hex.EncodeToString(sum[:]) != parts[2] || !proofValid {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "execution result unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-D101-Result-Proof", observed.proof)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(observed.wire)
}

func resetD101RuntimeProject(service, candidateProject string) string {
	if service == "game-postgres" || service == "game-redis" {
		return candidateProject
	}
	return "opensamguk-spep"
}
