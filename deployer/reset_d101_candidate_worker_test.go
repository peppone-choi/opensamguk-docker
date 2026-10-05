package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func workerAdmissionFixture(t *testing.T) resetD101CandidateAdmission {
	t.Helper()
	intent, evidence, binding, server := candidateAdmissionFixture(t)
	admission, err := newResetD101CandidateAdmission(intent, evidence, binding, server)
	if err != nil {
		t.Fatal(err)
	}
	admission.cutoff = time.Now().Add(time.Hour)
	return admission
}

func TestResetD101CandidateEveryPhysicalCommandRequiresFreshGuard(t *testing.T) {
	admission := workerAdmissionFixture(t)
	var calls []string
	guard := func(context.Context) error {
		calls = append(calls, "guard")
		return nil
	}
	command := func(context.Context) (string, error) {
		calls = append(calls, "command")
		return "observed", nil
	}
	for range 2 {
		out, err := runResetD101CandidateCommand(context.Background(), admission, guard, command)
		if err != nil || out != "observed" {
			t.Fatalf("guarded command: out=%q err=%v", out, err)
		}
	}
	if strings.Join(calls, ",") != "guard,command,guard,command" {
		t.Fatalf("physical order=%v", calls)
	}
}

func TestResetD101CandidateUnknownOrExpiredAuthorityExecutesNoCommand(t *testing.T) {
	for _, mode := range []string{"nil-guard", "rejected-guard", "guard-cancelled", "expired", "nil-command", "cancelled", "zero-admission", "mutated-target", "mutated-pin"} {
		t.Run(mode, func(t *testing.T) {
			admission := workerAdmissionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			guardCalls, commandCalls := 0, 0
			guard := func(context.Context) error { guardCalls++; return nil }
			command := func(context.Context) (string, error) { commandCalls++; return "unexpected", nil }
			switch mode {
			case "nil-guard":
				guard = nil
			case "rejected-guard":
				guard = func(context.Context) error { guardCalls++; return errors.New("unknown") }
			case "guard-cancelled":
				guard = func(context.Context) error { guardCalls++; cancel(); return nil }
			case "expired":
				admission.cutoff = time.Now().Add(-time.Second)
			case "nil-command":
				command = nil
			case "cancelled":
				cancel()
			case "zero-admission":
				admission = resetD101CandidateAdmission{}
			case "mutated-target":
				admission.target.Updates["RESET_MAXGENERAL"] = "51"
			case "mutated-pin":
				admission.imagePins["game-engine"] = "unknown"
			}
			out, err := runResetD101CandidateCommand(ctx, admission, guard, command)
			if err == nil || out != "" || commandCalls != 0 {
				t.Fatalf("unsafe call: out=%q err=%v commandCalls=%d", out, err, commandCalls)
			}
			if mode == "rejected-guard" && guardCalls != 1 {
				t.Fatalf("rejection guard calls=%d", guardCalls)
			}
		})
	}
}

func TestResetD101CandidateEvidenceEnvelopeIsOnlyStructural(t *testing.T) {
	admission := workerAdmissionFixture(t)
	valid := resetD101CandidateSeedEvidence{
		WorkerContainerID:        strings.Repeat("a", 64),
		PostgresContainerID:      strings.Repeat("b", 64),
		RedisContainerID:         strings.Repeat("c", 64),
		WorkerImageID:            "sha256:" + strings.Repeat("d", 64),
		WorkerRepoDigest:         "ghcr.io/owner/opensamguk@" + admission.ImagePins()["game-engine"],
		SelectedSourceReceiptSHA: admission.SelectedSourceReceiptSHA(),
		// The CLI does not issue a separate effective-options receipt SHA.
		EffectiveOptionsReceiptSHA: "",
		GenerationProvenanceSHA:    strings.Repeat("f", 64),
		ActualGeneration:           "0",
		StartedAt:                  time.Now().Add(-time.Minute),
		CompletedAt:                time.Now(),
		Original:                   []byte("unparsed original"),
	}
	if err := requireResetD101CandidateEvidenceEnvelope(admission, valid); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	for _, mode := range []string{"config-digest-as-repo", "wrong-selected", "missing-generation", "duplicate-container", "expired", "missing-original"} {
		t.Run(mode, func(t *testing.T) {
			changed := valid
			switch mode {
			case "config-digest-as-repo":
				changed.WorkerRepoDigest = changed.WorkerImageID
			case "wrong-selected":
				changed.SelectedSourceReceiptSHA = strings.Repeat("0", 64)
			case "missing-generation":
				changed.ActualGeneration = ""
			case "duplicate-container":
				changed.RedisContainerID = changed.PostgresContainerID
			case "expired":
				changed.CompletedAt = admission.Cutoff()
			case "missing-original":
				changed.Original = nil
			}
			if err := requireResetD101CandidateEvidenceEnvelope(admission, changed); err == nil {
				t.Fatal("invalid outer evidence accepted")
			}
		})
	}
}

func TestResetD101CandidateStoragePlanIncludesOnlyCandidatePostgresAndRedis(t *testing.T) {
	admission := workerAdmissionFixture(t)
	r := resetD101CandidateResourceNames(admission.OperationID())
	r.CandidateComposeFile = "/private/candidate.json"
	r.LiveComposeFile = "/private/live.json"
	r.CandidateComposeSHA = strings.Repeat("a", 64)
	r.LiveComposeSHA = strings.Repeat("b", 64)
	r.CapsReaderFile = "/private/caps-reader.json"
	admission = admission.withCandidateResources(r)
	if !validResetD101CandidateResources(admission.CandidateResources(), admission.OperationID()) {
		t.Fatal("candidate resources")
	}
	missingCapsReader := r
	missingCapsReader.CapsReaderFile = ""
	if validResetD101CandidateResources(missingCapsReader, admission.OperationID()) {
		t.Fatal("missing fixed caps reader accepted")
	}
	want := []string{"compose", "-p", r.Project, "--env-file", admission.Server().EnvFile,
		"-f", r.CandidateComposeFile, "up", "-d", "--wait", "--no-deps", "game-postgres", "game-redis"}
	if got := resetD101CandidateStorageUpArgs(admission); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate storage command: %v", got)
	}
}

func TestResetD101CandidateStorageMissingNativeOriginalExecutesNoDocker(t *testing.T) {
	admission := workerAdmissionFixture(t)
	r := resetD101CandidateResourceNames(admission.OperationID())
	r.CandidateComposeFile = "/missing/d101-candidate.json"
	r.LiveComposeFile = "/missing/d101-live.json"
	r.CandidateComposeSHA = strings.Repeat("a", 64)
	r.LiveComposeSHA = strings.Repeat("b", 64)
	r.CapsReaderFile = "/missing/d101-caps-reader.json"
	admission = admission.withCandidateResources(r)
	commands := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) {
		commands++
		return "", nil
	}}
	_, _, err := c.prepareResetD101CandidateStorage(context.Background(), admission, func(context.Context) error { return nil })
	if err == nil || commands != 0 {
		t.Fatalf("missing native plan reached Docker: err=%v commands=%d", err, commands)
	}
}
