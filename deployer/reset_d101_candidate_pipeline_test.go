package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCandidatePipelineMissingInstallationStopsBeforeAnyPhysicalCommand(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if err := c.runResetD101CandidateThenPromote(context.Background(), resetD101CandidateAdmission{}, nil, func(context.Context) error { return nil }); err == nil || calls != 0 {
		t.Fatal("missing installation reached physical stage")
	}
	if _, err := c.runResetD101PhysicalWorker(nil, serverTarget{}, resetExecutionPhaseBinding{}, func(context.Context, resetExecutionPhaseBinding) (resetExecutionPhaseSnapshot, error) {
		return resetExecutionPhaseSnapshot{}, nil
	}); err == nil || calls != 0 {
		t.Fatal("legacy full-up fallback")
	}
}
func candidatePipelineSeedFixture(t *testing.T) (*resetD101CandidatePipeline, resetD101CandidateAdmission, resetD101CandidateSeedEvidence) {
	t.Helper()
	intent, evidence, binding, server := candidateAdmissionFixture(t)
	a, err := newResetD101CandidateAdmission(intent, evidence, binding, server)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a.cutoff = now.Add(time.Hour)
	options := map[string]string{}
	for _, key := range []string{"SERVER_NAME", "SERVER_GENERATION", "SCENARIO_CODE", "SCENARIO_SEED_ENABLED", "SCENARIO_LOOKUP_DIR", "RESET_MAXGENERAL", "RESET_FIRST_TURN", "RESET_EXTEND", "RESET_TURNTERM", "RESET_BLOCK_GENERAL_CREATE", "RESET_NPCMODE", "RESET_SHOW_IMG_LEVEL"} {
		options[key] = a.Target().Updates[key]
	}
	provenance := map[string]string{}
	for key := range options {
		provenance[key] = strings.Repeat("a", 64)
	}
	selected := resetD101VerifiedSelectedReceipt{sha: a.SelectedSourceReceiptSHA(), value: resetD101SelectedReceipt{EffectiveOptions: options, OptionProvenance: provenance, OriginalPins: map[string]resetD101SelectedOriginalPin{"selected-scenario.json": {"selected-scenario.json", strings.Repeat("c", 64), 100}}}}
	p := &resetD101CandidatePipeline{selected: selected}
	generation := 0
	value := resetD101CandidateSeedReceipt{SchemaVersion: 1, Kind: "D101_SEED_ONLY_RESULT_V1", OriginalOp: a.OperationID(), TargetFingerprint: a.TargetFingerprint(), AppSourceSHA: a.AppSourceSHA(), ImagePins: a.ImagePins(), SelectedSourceReceiptSHA: selected.sha, ScenarioRawSHA: strings.Repeat("c", 64), ScenarioRawLength: 100, EffectiveOptions: options, OptionProvenance: provenance, ActiveGeneralRows: 384, ActiveRetainerRows: 10, ConfigMaxGeneral: 50, GameEnvMaxGeneral: 50, ConfigOriginalSHA: strings.Repeat("d", 64), MetaOriginalSHA: strings.Repeat("e", 64), GameEnvOriginalSHA: strings.Repeat("f", 64), ObservedGeneration: &generation, ObservedAtUTC: now.Format(time.RFC3339Nano)}
	wire, _ := json.Marshal(value)
	seed := resetD101CandidateSeedEvidence{WorkerContainerID: strings.Repeat("1", 64), PostgresContainerID: strings.Repeat("2", 64), RedisContainerID: strings.Repeat("3", 64), WorkerImageID: "sha256:" + strings.Repeat("4", 64), SelectedSourceReceiptSHA: selected.sha, GenerationProvenanceSHA: provenance["SERVER_GENERATION"], ActualGeneration: "0", StartedAt: now.Add(-time.Second), CompletedAt: now, Original: wire}
	return p, a, seed
}
func TestCandidatePipelineConsumesActualCli20AndRefusesUnknownGenerationOrSelectedOptionDrift(t *testing.T) {
	p, a, seed := candidatePipelineSeedFixture(t)
	if p.requireSeed(a, seed, nil) != nil {
		t.Fatal("synthetic CLI20 refused")
	}
	for _, mode := range []string{"null-generation", "string-generation", "generation-one", "wrong-selected", "option-drift", "provenance-drift", "old-cid", "duplicate-cid", "unknown-key", "duplicate-key"} {
		changed := seed
		changed.Original = append([]byte(nil), seed.Original...)
		var tree map[string]any
		if json.Unmarshal(changed.Original, &tree) != nil {
			t.Fatal("fixture")
		}
		old := map[string]string{}
		switch mode {
		case "null-generation":
			tree["observedGeneration"] = nil
		case "string-generation":
			tree["observedGeneration"] = "0"
		case "generation-one":
			tree["observedGeneration"] = 1
		case "wrong-selected":
			tree["selectedSourceReceiptSha256"] = strings.Repeat("0", 64)
		case "option-drift":
			tree["effectiveOptions"].(map[string]any)["RESET_EXTEND"] = "0"
		case "provenance-drift":
			tree["optionProvenance"].(map[string]any)["SERVER_GENERATION"] = strings.Repeat("0", 64)
		case "old-cid":
			old["game-postgres"] = seed.PostgresContainerID
		case "duplicate-cid":
			changed.RedisContainerID = seed.PostgresContainerID
		case "unknown-key":
			tree["approved"] = true
		}
		changed.Original, _ = json.Marshal(tree)
		if mode == "duplicate-key" {
			changed.Original = append(append([]byte(nil), changed.Original[:len(changed.Original)-1]...), []byte(`,"observedGeneration":0}`)...)
		}
		if p.requireSeed(a, changed, old) == nil {
			t.Fatal("accepted " + mode)
		}
	}
}
