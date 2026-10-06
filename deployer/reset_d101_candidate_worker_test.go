package main

import (
	"context"
	"encoding/json"
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

func seedChildFixture(t *testing.T) (resetD101CandidateAdmission, resetD101SeedChildMaterial, string, string) {
	t.Helper()
	a := workerAdmissionFixture(t)
	r := resetD101CandidateResourceNames(a.OperationID())
	r.CandidateComposeFile, r.LiveComposeFile, r.CapsReaderFile = "/private/candidate.json", "/private/live.json", "/private/caps.json"
	r.CandidateComposeSHA, r.LiveComposeSHA = strings.Repeat("a", 64), strings.Repeat("b", 64)
	a = a.withCandidateResources(r)
	pg, redis := strings.Repeat("b", 64), strings.Repeat("c", 64)
	material := resetD101SeedChildMaterial{InstallationSHA: strings.Repeat("a", 64), PostgresContainerID: pg, DatabaseAddress: "172.20.0.3"}
	for child := range resetD101SeedChildFiles {
		leaf := strings.TrimPrefix(child, "/run/d101/")
		material.bindings = append(material.bindings, resetD101SeedReadOnlyBinding{
			LocalPath: "/private/" + leaf, HostPath: "/host/" + leaf, ChildPath: child, SHA: strings.Repeat("a", 64)})
	}
	return a, material, pg, redis
}

func seedChildInspectFixture(t *testing.T, a resetD101CandidateAdmission, material resetD101SeedChildMaterial,
	id, imageID, imageRef, status string, exitCode int, writable bool) string {
	t.Helper()
	mounts := []any{}
	for _, binding := range material.Bindings() {
		mounts = append(mounts, map[string]any{"type": "bind", "source": binding.HostPath,
			"destination": binding.ChildPath, "rw": writable})
	}
	mounts = append(mounts, nil)
	value := map[string]any{"id": id, "name": "/" + resetD101SeedChildName(a.OperationID()),
		"imageId": imageID, "imageRef": imageRef, "status": status, "running": false,
		"exitCode": exitCode, "network": a.CandidateResources().Network, "user": "0:0",
		"entrypoint": []string{resetD101SeedChildEntrypoint}, "cmd": []string{},
		"readOnly": true, "privileged": false, "capDrop": []string{"ALL"},
		"securityOptions": []string{"no-new-privileges"}, "mounts": mounts}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func seedChildOutputFixture(t *testing.T, a resetD101CandidateAdmission) string {
	t.Helper()
	zero := 0
	value := resetD101CandidateSeedReceipt{SchemaVersion: 1, Kind: "D101_SEED_ONLY_RESULT_V1",
		ApprovalIntentSHA: a.ApprovalIntentSHA(), OriginalOp: a.OperationID(),
		TargetFingerprint: a.TargetFingerprint(), AppSourceSHA: a.AppSourceSHA(), ImagePins: a.ImagePins(),
		SelectedSourceReceiptSHA: a.SelectedSourceReceiptSHA(), ScenarioRawSHA: strings.Repeat("a", 64),
		ScenarioRawLength: 1024, EffectiveOptions: map[string]string{"SERVER_GENERATION": "0"},
		OptionProvenance:  map[string]string{"SERVER_GENERATION": strings.Repeat("f", 64)},
		ActiveGeneralRows: 384, ConfigMaxGeneral: 50, GameEnvMaxGeneral: 50,
		ConfigOriginalSHA: strings.Repeat("a", 64), MetaOriginalSHA: strings.Repeat("b", 64),
		GameEnvOriginalSHA: strings.Repeat("c", 64), ObservedGeneration: &zero,
		ObservedAtUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return resetD101CandidateSeedOutputPrefix + string(wire) + "\n"
}

func TestResetD101RetainedSeedChildUsesFixedCLIAndFreshGuardForEveryCommand(t *testing.T) {
	a, material, pg, redis := seedChildFixture(t)
	id, imageID := strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)
	imageRef := "ghcr.io/owner/opensamguk@" + a.ImagePins()["game-engine"]
	output := seedChildOutputFixture(t, a)
	var calls []string
	inspectCount, guardCount, verifyCount := 0, 0, 0
	c := config{ghcrOwner: "owner", dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args[0])
		switch args[0] {
		case "create":
			if !reflect.DeepEqual(args[len(args)-3:], []string{"--entrypoint", resetD101SeedChildEntrypoint, imageRef}) ||
				strings.Contains(strings.Join(args, " "), "--d101-seed-only-v1") {
				t.Fatal("unreviewed child command")
			}
			mounts := map[string]bool{}
			for n := 0; n < len(args)-1; n++ {
				if args[n] == "--env" || args[n] == "--rm" {
					t.Fatal("unexpected child environment or cleanup")
				}
				if args[n] == "--mount" {
					mounts[args[n+1]] = true
				}
			}
			if len(mounts) != len(resetD101SeedChildFiles) {
				t.Fatal("child8 read-only bindings missing", mounts)
			}
			for _, binding := range material.Bindings() {
				if !mounts["type=bind,src="+binding.HostPath+",dst="+binding.ChildPath+",readonly"] {
					t.Fatal("unreviewed child mount", binding.ChildPath)
				}
			}
			return id, nil
		case "inspect":
			inspectCount++
			status := "created"
			if inspectCount > 1 {
				status = "exited"
			}
			return seedChildInspectFixture(t, a, material, id, imageID, imageRef, status, 0, false), nil
		case "image":
			return `{"repoDigests":["` + imageRef + `"],"os":"linux","architecture":"amd64"}`, nil
		case "start":
			return id, nil
		case "wait":
			return "0\n", nil
		case "logs":
			return output, nil
		}
		return "", errors.New("unexpected Docker command")
	}}
	evidence, err := c.runResetD101CandidateSeedChildWithVerifier(context.Background(), a, material, pg, redis,
		func(context.Context) error { guardCount++; return nil }, func() error { verifyCount++; return nil })
	if err != nil || evidence.WorkerContainerID != id || evidence.WorkerImageID != imageID ||
		evidence.WorkerRepoDigest != imageRef || evidence.PostgresContainerID != pg || evidence.RedisContainerID != redis ||
		string(evidence.Original) != strings.TrimSuffix(strings.TrimPrefix(output, resetD101CandidateSeedOutputPrefix), "\n") {
		t.Fatal("actual child evidence not preserved", err)
	}
	if strings.Join(calls, ",") != "create,inspect,image,start,wait,inspect,logs,inspect" || guardCount != len(calls) || verifyCount < len(calls) {
		t.Fatal("physical commands missed independent guard", calls, guardCount, verifyCount)
	}
}

func TestResetD101RetainedSeedChildClosesOnMissingMaterialAndUnknownExit(t *testing.T) {
	a, material, pg, redis := seedChildFixture(t)
	for _, mode := range []string{"nil-guard", "missing-installation", "rejected-verifier", "nonzero-exit", "duplicate-output", "writeable-mount"} {
		t.Run(mode, func(t *testing.T) {
			id, imageID := strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)
			imageRef := "ghcr.io/owner/opensamguk@" + a.ImagePins()["game-engine"]
			local := material
			if mode == "missing-installation" {
				local.InstallationSHA = ""
			}
			calls, inspectCount := 0, 0
			c := config{ghcrOwner: "owner", dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
				calls++
				switch args[0] {
				case "create":
					return id, nil
				case "inspect":
					inspectCount++
					status := "created"
					if inspectCount > 1 {
						status = "exited"
					}
					return seedChildInspectFixture(t, a, local, id, imageID, imageRef, status, 0, mode == "writeable-mount"), nil
				case "image":
					return `{"repoDigests":["` + imageRef + `"],"os":"linux","architecture":"amd64"}`, nil
				case "start":
					return id, nil
				case "wait":
					if mode == "nonzero-exit" {
						return "78\n", nil
					}
					return "0\n", nil
				case "logs":
					out := seedChildOutputFixture(t, a)
					if mode == "duplicate-output" {
						out += out
					}
					return out, nil
				}
				return "", errors.New("unexpected command")
			}}
			guard := func(context.Context) error { return nil }
			if mode == "nil-guard" {
				guard = nil
			}
			verify := func() error { return nil }
			if mode == "rejected-verifier" {
				verify = func() error { return errors.New("unavailable") }
			}
			result, err := c.runResetD101CandidateSeedChildWithVerifier(context.Background(), a, local, pg, redis, guard, verify)
			if err == nil || result.WorkerContainerID != "" {
				t.Fatal("uncertain child promoted")
			}
			if (mode == "nil-guard" || mode == "missing-installation" || mode == "rejected-verifier") && calls != 0 {
				t.Fatal("missing authority invoked Docker", calls)
			}
		})
	}
}

func TestResetD101RetainedSeedChildMissingInstalledInputsCallsNoDocker(t *testing.T) {
	a := workerAdmissionFixture(t)
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) {
		calls++
		return "unexpected", nil
	}}
	evidence, err := c.runResetD101CandidateSeed(context.Background(), a, func(context.Context) error { return nil })
	if err == nil || calls != 0 || evidence.WorkerContainerID != "" {
		t.Fatal("missing fixed native seed installation started Docker")
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
