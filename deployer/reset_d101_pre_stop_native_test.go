package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Synthetic protocol data only; no native issuer/authentication/SQL execution.
func r2PreStopNativeFixture(t *testing.T, base time.Time) (resetD101PreStopNativeBody, resetDecodedApprovalIntent, resetApprovalPlan, string, string, string) {
	t.Helper()
	query, _, evidence, _, gatewaySHA := resetD101GatewayDispatchFixture(t)
	plan := evidence.Plan
	var intentValue resetApprovalIntent
	intentOriginal, _, _ := resetIntentFixture(t)
	_ = json.Unmarshal(intentOriginal, &intentValue)
	intentValue.WindowOpensAtUnix = base.Add(-time.Minute).Unix()
	intentValue.DestructiveCutoffUnix = base.Add(5 * time.Minute).Unix()
	intentValue.RecoveryDeadlineUnix = base.Add(10 * time.Minute).Unix()
	intentOriginal, _ = json.Marshal(intentValue)
	intent, err := decodeResetApprovalIntent(intentOriginal, resetD101OriginalSHA(intentOriginal))
	if err != nil {
		t.Fatal(err)
	}
	plan.ApprovalIntentSHA = intent.SHA
	plan.WindowOpensAtUnix, plan.DestructiveCutoffUnix, plan.RecoveryDeadlineUnix = intentValue.WindowOpensAtUnix, intentValue.DestructiveCutoffUnix, intentValue.RecoveryDeadlineUnix
	planWire, _ := json.Marshal(plan)
	planSHA := resetD101OriginalSHA(planWire)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(query, &fields)
	var encoded string
	_ = json.Unmarshal(fields["preResetOriginalsBytesBase64url"], &encoded)
	canonicalWire, _ := base64.RawURLEncoding.DecodeString(encoded)
	var canonical resetD101PreResetOriginal
	_ = json.Unmarshal(canonicalWire, &canonical)
	canonical.ApprovalIntentSHA = intent.SHA
	canonicalWire, _ = json.Marshal(canonical)
	fields["preResetOriginalsBytesBase64url"], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(canonicalWire))
	fields["preResetOriginalsSha256"], _ = json.Marshal(resetD101OriginalSHA(canonicalWire))
	fields["approvalIntentSha256"], _ = json.Marshal(intent.SHA)
	fields["state"], _ = json.Marshal("PREPARED")
	fields["rootRequestFingerprint"] = json.RawMessage("null")
	fields["createdAtUtc"], _ = json.Marshal(base.Add(-time.Second).UTC().Format(time.RFC3339Nano))
	fields["updatedAtUtc"], _ = json.Marshal(base.Add(-500 * time.Millisecond).UTC().Format(time.RFC3339Nano))
	query, _ = json.Marshal(fields)
	old, _, _ := oldWorldCaptureFixture()
	old.ObservedAtUTC = base.Add(time.Second + 804*time.Millisecond).UTC().Format(time.RFC3339Nano)
	oldWire, _ := json.Marshal(old)
	sourceSHA := strings.Repeat("f", 40)
	body := resetD101PreStopNativeBody{SchemaVersion: 1, OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA, ApprovalPlanSHA: planSHA, GatewayPayloadSHA: gatewaySHA,
		VerifyingRevision: "2", PreResetOriginalsBase64url: base64.RawURLEncoding.EncodeToString(canonicalWire), PreResetOriginalsSHA: resetD101OriginalSHA(canonicalWire),
		PostgresContainerID: strings.Repeat("a", 64), PostgresImageID: "sha256:" + strings.Repeat("b", 64), JobContainerID: strings.Repeat("c", 64), JobImageID: "sha256:" + strings.Repeat("b", 64),
		CollectorStartedAtUTC: base.Add(time.Second).UTC().Format(time.RFC3339Nano), CollectorCompletedAtUTC: base.Add(4 * time.Second).UTC().Format(time.RFC3339Nano),
		OldWorldBytesBase64url: base64.RawURLEncoding.EncodeToString(oldWire), OldWorldSHA: resetD101OriginalSHA(oldWire), CommandEvidence: resetD101PreStopNativeCommandEvidence{SQLSHA: resetD101OriginalSHA([]byte(resetD101OldWorldSQL)), ProducerSourceSHA: sourceSHA}}
	zero := 0
	publication := resetAdminPublication{"pep", "KNOWN", "VERIFYING", "2", body.OperationID, &zero, "scenario_3190", plan.TargetFingerprint}
	pubWire, _ := json.Marshal(publication)
	for i := 0; i < 17; i++ {
		at := base.Add(time.Duration(i)*100*time.Millisecond + time.Second)
		if i == 0 {
			at = base
		}
		if i >= 15 {
			at = base.Add(4*time.Second + time.Duration(i-14)*10*time.Millisecond)
		}
		frame := resetD101PreStopNativeFrame{StartedAtUTC: at.UTC().Format(time.RFC3339Nano), CompletedAtUTC: at.Add(2 * time.Millisecond).UTC().Format(time.RFC3339Nano), GatewayQueryBase64: base64.RawURLEncoding.EncodeToString(query),
			Publication: resetD101PreStopNativePublication{at.Add(time.Millisecond).UTC().Format(time.RFC3339Nano), resetD101OriginalSHA(pubWire), publication, base64.RawURLEncoding.EncodeToString(pubWire)},
			Snapshot:    resetD101PreStopNativeSnapshot{at.Add(time.Millisecond).UTC().Format(time.RFC3339Nano), "pep", body.OperationID, plan.TargetFingerprint, "VERIFYING", "2", plan.WriterFreezeReceiptSHA, true}}
		if i >= 1 && i <= 14 {
			verb := "inspect"
			if i == 8 {
				verb = "start"
			}
			frame.Invocation = &resetD101PreStopNativeInvocation{CommandID: "docker:" + verb + ":" + strconv.Itoa(i), ArgvSHA: strings.Repeat("d", 64), StartedAtUTC: at.Add(3 * time.Millisecond).UTC().Format(time.RFC3339Nano), CompletedAtUTC: at.Add(5 * time.Millisecond).UTC().Format(time.RFC3339Nano), GuardObservationIndex: i}
			body.CommandEvidence.Invocations = append(body.CommandEvidence.Invocations, *frame.Invocation)
		}
		body.Observations = append(body.Observations, frame)
	}
	return body, intent, plan, planSHA, gatewaySHA, sourceSHA
}

func TestR2PreStopNativeHistoricalOriginalAndNullCanonicalRemainData(t *testing.T) {
	body, intent, plan, planSHA, gatewaySHA, sourceSHA := r2PreStopNativeFixture(t, time.Unix(1791162000, 0).UTC())
	wire, _ := json.Marshal(body)
	value, err := decodeResetD101PreStopNative(wire, resetD101OriginalSHA(wire), intent, plan, planSHA, gatewaySHA, sourceSHA)
	if err != nil || value.canonical.registry.Generation != nil || value.canonical.registry.ScenarioCode != nil || value.old.GenerationRaw != "9" || value.old.ScenarioCode != "scenario_990002" {
		t.Fatal("historical capture/null canonical data refused", err)
	}
	clone := value.Original()
	clone[0] = '!'
	if !bytes.Equal(value.Original(), wire) {
		t.Fatal("original can be changed through caller slice")
	}
	// Data shape does not substitute for actual producer/native installation.
	if _, err := (config{}).readResetD101PreStopNativeProof(context.Background(), intent, plan, planSHA, gatewaySHA, value.sha, 0); err == nil {
		t.Fatal("data became installed producer authority")
	}
}

func TestR2PreStopNativeRejectsScopeTraceOriginalAndSummarySubstitution(t *testing.T) {
	for _, mode := range []string{"operation", "plan", "prepare", "source", "sql", "old-sha", "publication-bytes", "publication-current", "index", "summary", "command-null", "initial-command", "missing-frame", "guard-cache", "command-before-guard", "command-after-interval", "generation", "sql-outside-command", "sql-command-id", "future-collector", "unknown", "duplicate", "alias", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			body, intent, plan, planSHA, gatewaySHA, sourceSHA := r2PreStopNativeFixture(t, time.Unix(1791162000, 0).UTC())
			switch mode {
			case "operation":
				body.OperationID = strings.Repeat("f", 32)
			case "plan":
				body.ApprovalPlanSHA = strings.Repeat("f", 64)
			case "prepare":
				body.GatewayPayloadSHA = strings.Repeat("f", 64)
			case "source":
				body.CommandEvidence.ProducerSourceSHA = strings.Repeat("a", 40)
			case "sql":
				body.CommandEvidence.SQLSHA = strings.Repeat("a", 64)
			case "old-sha":
				body.OldWorldSHA = strings.Repeat("f", 64)
			case "publication-bytes":
				body.Observations[1].Publication.BodyBase64 = base64.RawURLEncoding.EncodeToString([]byte("{}"))
			case "publication-current":
				body.Observations[1].Publication.Current.Revision = "3"
			case "index":
				body.Observations[1].Invocation.GuardObservationIndex = 2
			case "summary":
				body.CommandEvidence.Invocations[0].ArgvSHA = strings.Repeat("a", 64)
			case "command-null":
				body.Observations[1].Invocation = nil
			case "initial-command":
				body.Observations[0].Invocation = body.Observations[1].Invocation
			case "missing-frame":
				body.Observations = body.Observations[:16]
			case "guard-cache":
				body.Observations[1].Snapshot.ObservedAtUTC = body.Observations[0].Snapshot.ObservedAtUTC
			case "command-before-guard":
				body.Observations[1].Invocation.StartedAtUTC = body.Observations[0].StartedAtUTC
				body.CommandEvidence.Invocations[0] = *body.Observations[1].Invocation
			case "command-after-interval":
				body.Observations[14].Invocation.CompletedAtUTC = body.Observations[16].CompletedAtUTC
				body.CommandEvidence.Invocations[13] = *body.Observations[14].Invocation
			case "generation":
				raw, _ := base64.RawURLEncoding.DecodeString(body.OldWorldBytesBase64url)
				raw = []byte(strings.Replace(string(raw), `"generationRaw":"9"`, `"generationRaw":"09"`, 1))
				body.OldWorldBytesBase64url = base64.RawURLEncoding.EncodeToString(raw)
				body.OldWorldSHA = resetD101OriginalSHA(raw)
			case "sql-outside-command":
				raw, _ := base64.RawURLEncoding.DecodeString(body.OldWorldBytesBase64url)
				var old resetD101OldWorldOriginal
				_ = json.Unmarshal(raw, &old)
				old.ObservedAtUTC = body.Observations[8].CompletedAtUTC
				raw, _ = json.Marshal(old)
				body.OldWorldBytesBase64url = base64.RawURLEncoding.EncodeToString(raw)
				body.OldWorldSHA = resetD101OriginalSHA(raw)
			case "sql-command-id":
				body.Observations[8].Invocation.CommandID = "docker:inspect:8"
				body.CommandEvidence.Invocations[7] = *body.Observations[8].Invocation
			case "future-collector":
				body.CollectorCompletedAtUTC = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
			}
			wire, _ := json.Marshal(body)
			switch mode {
			case "unknown":
				wire = append(wire[:len(wire)-1], []byte(`,"authority":true}`)...)
			case "duplicate":
				wire = []byte(strings.Replace(string(wire), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1))
			case "alias":
				wire = []byte(strings.Replace(string(wire), `"operationId":`, `"OperationID":`, 1))
			case "trailing":
				wire = append(wire, []byte(`{}`)...)
			}
			if _, err := decodeResetD101PreStopNative(wire, resetD101OriginalSHA(wire), intent, plan, planSHA, gatewaySHA, sourceSHA); err == nil {
				t.Fatal("changed subject/trace accepted")
			}
		})
	}
}

func r2FixtureLeafOpener(dir *os.File, op string, flags int, mode uint32) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir.Name(), op+".json"), flags, os.FileMode(mode))
}

func r2FixtureDirectory(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "native")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func r2FixtureFrameNow(frame resetD101PreStopNativeFrame) resetD101PreStopNativeFrame {
	at := time.Now().UTC().Add(-2 * time.Millisecond)
	frame.StartedAtUTC = at.Format(time.RFC3339Nano)
	frame.CompletedAtUTC = at.Add(time.Millisecond).Format(time.RFC3339Nano)
	frame.Publication.ObservedAtUTC = frame.CompletedAtUTC
	frame.Snapshot.ObservedAtUTC = frame.CompletedAtUTC
	frame.Invocation = nil
	return frame
}

func TestR2PreStopNativeStreamFsyncsActualArgvBeforeRunnerAndSummaryFromFile(t *testing.T) {
	body, _, _, _, _, _ := r2PreStopNativeFixture(t, time.Now().UTC().Add(-time.Second))
	directory := r2FixtureDirectory(t)
	uid := uint32(os.Getuid())
	stream, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uid, r2FixtureLeafOpener)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.ClosePreservingPartial()
	if stream.AppendNonCommand(r2FixtureFrameNow(body.Observations[0])) != nil {
		t.Fatal("initial frame")
	}
	ctx := context.WithValue(context.Background(), resetD101PreStopStreamContextKey{}, stream)
	ctx = context.WithValue(ctx, resetD101OldWorldPhysicalContextKey{}, true)
	calls := 0
	cfg := config{dockerRunnerContext: func(ctx context.Context, args ...string) (string, error) {
		calls++
		prefix, _, err := readResetD101PreStopNativeFileWithLeafOpener(directory, body.OperationID, uid, r2FixtureLeafOpener)
		argv, _ := json.Marshal(append([]string{"docker"}, args...))
		last := bytes.LastIndex(prefix, []byte(`"invocation":`))
		if err != nil || last < 0 || json.Valid(prefix) || !bytes.Contains(prefix[last:], []byte(resetD101OriginalSHA(argv))) || bytes.Contains(prefix[last:], []byte(`"completedAtUtc"`)) {
			t.Fatal("runner preceded native command start fsync")
		}
		return "isolated runner fixture", nil
	}}
	for i := 1; i <= 14; i++ {
		if stream.QueueGuard(r2FixtureFrameNow(body.Observations[i])) != nil {
			t.Fatal("fresh guard")
		}
		if _, err := cfg.runServerDockerContext(ctx, "inspect", strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 15; i <= 16; i++ {
		if stream.AppendNonCommand(r2FixtureFrameNow(body.Observations[i])) != nil {
			t.Fatal("final native frame")
		}
	}
	if stream.Finish(body) != nil {
		t.Fatal("finish native stream")
	}
	stream.ClosePreservingPartial()
	wire, _, err := readResetD101PreStopNativeFileWithLeafOpener(directory, body.OperationID, uid, r2FixtureLeafOpener)
	var native resetD101PreStopNativeBody
	if err != nil || requireResetD101PreStopNativeShape(wire) != nil || decodeResetPrivateJSON(wire, &native) != nil || calls != 14 || len(native.CommandEvidence.Invocations) != 14 {
		t.Fatal("complete shape/native summary")
	}
	for i, invocation := range native.CommandEvidence.Invocations {
		if native.Observations[i+1].Invocation == nil || *native.Observations[i+1].Invocation != invocation {
			t.Fatal("summary differs from native frame")
		}
	}
	if _, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uid, r2FixtureLeafOpener); err == nil {
		t.Fatal("completed original retried/overwritten")
	}
}

func TestR2PreStopNativeFailureRetainsPrefixAndRefusesNewAttempt(t *testing.T) {
	body, _, _, _, _, _ := r2PreStopNativeFixture(t, time.Now().UTC().Add(-time.Second))
	directory := r2FixtureDirectory(t)
	uid := uint32(os.Getuid())
	stream, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uid, r2FixtureLeafOpener)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.AppendNonCommand(r2FixtureFrameNow(body.Observations[0]))
	_ = stream.QueueGuard(r2FixtureFrameNow(body.Observations[1]))
	ctx := context.WithValue(context.Background(), resetD101PreStopStreamContextKey{}, stream)
	ctx = context.WithValue(ctx, resetD101OldWorldPhysicalContextKey{}, true)
	cfg := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { return "", errors.New("isolated failure") }}
	if _, err := cfg.runServerDockerContext(ctx, "start", "--attach", strings.Repeat("a", 64)); err == nil {
		t.Fatal("failed command accepted")
	}
	stream.ClosePreservingPartial()
	wire, _, err := readResetD101PreStopNativeFileWithLeafOpener(directory, body.OperationID, uid, r2FixtureLeafOpener)
	if err != nil || json.Valid(wire) || !bytes.Contains(wire, []byte(`"argvSha256"`)) || !bytes.Contains(wire, []byte(`"completedAtUtc"`)) {
		t.Fatal("failure trace removed/finished")
	}
	if _, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uid, r2FixtureLeafOpener); err == nil {
		t.Fatal("partial native attempt retried")
	}
}

func TestR2PreStopNativeAbsentGuardAndIssuerDenyBeforeRunner(t *testing.T) {
	body, intent, plan, planSHA, gatewaySHA, _ := r2PreStopNativeFixture(t, time.Now().UTC())
	directory := r2FixtureDirectory(t)
	stream, err := openResetD101PreStopNativeStreamWithLeafOpener(directory, body.OperationID, body, uint32(os.Getuid()), r2FixtureLeafOpener)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.ClosePreservingPartial()
	ctx := context.WithValue(context.Background(), resetD101PreStopStreamContextKey{}, stream)
	ctx = context.WithValue(ctx, resetD101OldWorldPhysicalContextKey{}, true)
	calls := 0
	cfg := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if _, err := cfg.runServerDockerContext(ctx, "inspect", strings.Repeat("a", 64)); err == nil || calls != 0 {
		t.Fatal("command without fresh guard reached runner")
	}
	if _, err := cfg.readResetD101PreStopNativeProof(context.Background(), intent, plan, planSHA, gatewaySHA, strings.Repeat("f", 64), 0); err == nil {
		t.Fatal("native data substitutes for installed issuer")
	}
}
