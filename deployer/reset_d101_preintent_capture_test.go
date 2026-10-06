package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func preIntentReviewedFixture() (resetD101PreIntentReviewedPins, resetD101PreIntentProfile) {
	p := resetD101PreIntentReviewedPins{OperationID: strings.Repeat("a", 32), TargetFingerprint: strings.Repeat("b", 64), AppSourceSHA: strings.Repeat("c", 40), ImagePins: map[string]string{},
		InputBindingsSHA: strings.Repeat("d", 64), HelperSHA: strings.Repeat("e", 64), ProducerIdentity: "fixture-root-producer"}
	for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		p.ImagePins[id] = "sha256:" + strings.Repeat("f", 64)
	}
	profile := resetD101PreIntentProfile{1, "D101_PRE_INTENT_SOURCE_PINS_V1", p.OperationID, p.TargetFingerprint, p.AppSourceSHA, cloneResetD101Strings(p.ImagePins), "/app", p.InputBindingsSHA, resetD101PreIntentHelperPath, p.HelperSHA, p.ProducerIdentity}
	wire, _ := json.Marshal(profile)
	p.ProfileSHA = resetD101OriginalSHA(wire)
	return p, profile
}
func TestPreIntentProfileRequiresIndependentExactBindings(t *testing.T) {
	p, profile := preIntentReviewedFixture()
	wire, _ := json.Marshal(profile)
	if _, err := decodeResetD101PreIntentProfile(wire, p); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		alter func(map[string]any)
	}{
		{"caller-helper", func(v map[string]any) { v["nativeHelperPath"] = "/caller/helper" }},
		{"caller-artifacts", func(v map[string]any) { v["artifactsRoot"] = "/caller/artifacts" }},
		{"wrong-op", func(v map[string]any) { v["originalOp"] = strings.Repeat("b", 32) }},
		{"wrong-target", func(v map[string]any) { v["typedTargetFingerprint"] = strings.Repeat("c", 64) }},
		{"wrong-input-sha", func(v map[string]any) { v["preIntentInstallationSha256"] = strings.Repeat("f", 64) }},
		{"wrong-helper-sha", func(v map[string]any) { v["nativeHelperSha256"] = strings.Repeat("f", 64) }},
		{"wrong-producer", func(v map[string]any) { v["producerIdentity"] = "another-producer" }},
		{"missing-field", func(v map[string]any) { delete(v, "nativeHelperPath") }},
		{"future-field", func(v map[string]any) { v["approvalIntentSha256"] = strings.Repeat("b", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			json.Unmarshal(wire, &value)
			test.alter(value)
			changed, _ := json.Marshal(value)
			expected := p
			expected.ProfileSHA = resetD101OriginalSHA(changed)
			if _, err := decodeResetD101PreIntentProfile(changed, expected); err == nil {
				t.Fatal("unbound profile accepted")
			}
		})
	}
	p.ProfileSHA = strings.Repeat("a", 64)
	if _, err := decodeResetD101PreIntentProfile(wire, p); err == nil {
		t.Fatal("profile selected own expected SHA")
	}
}

func TestPreIntentChildRequiresExactIsolationAndArguments(t *testing.T) {
	p, _ := preIntentReviewedFixture()
	s := &resetD101PreIntentCaptureSource{reviewed: p, inputHost: "/host/input", outputHost: "/host/output"}
	imageRef := "ghcr.io/owner/opensamguk@" + p.ImagePins["game-engine"]
	id := strings.Repeat("a", 64)
	for _, test := range []struct {
		name  string
		alter func(*resetD101PreIntentChild)
		valid bool
	}{
		{"valid", func(*resetD101PreIntentChild) {}, true},
		{"rw-input", func(v *resetD101PreIntentChild) { v.Mounts[0].RW = true }, false},
		{"wrong-host-input", func(v *resetD101PreIntentChild) { v.Mounts[0].Source = "/caller/input" }, false},
		{"duplicate-mount", func(v *resetD101PreIntentChild) { v.Mounts[1] = v.Mounts[0] }, false},
		{"extra-mount", func(v *resetD101PreIntentChild) {
			v.Mounts = append(v.Mounts[:2], &resetD101CapsMount{Source: "/var/run/docker.sock"}, nil)
		}, false},
		{"network", func(v *resetD101PreIntentChild) { v.Network = "bridge" }, false},
		{"old-wrapper", func(v *resetD101PreIntentChild) { v.Entrypoint = []string{"/app/d101-selected-capture"} }, false},
		{"caller-args", func(v *resetD101PreIntentChild) { v.Cmd = []string{"--capture"} }, false},
		{"privileged", func(v *resetD101PreIntentChild) { yes := true; v.Privileged = &yes }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			no, yes, exit := false, true, 0
			child := resetD101PreIntentChild{ID: id, Name: "/d101-pre-intent-" + p.OperationID, ImageID: "sha256:" + strings.Repeat("c", 64), ImageRef: imageRef, Status: "exited", Running: &no, ExitCode: &exit,
				Network: "none", User: "0:0", Entrypoint: []string{resetD101PreIntentCaptureEntrypoint}, Cmd: []string{}, ReadOnly: &yes, Privileged: &no, CapDrop: []string{"ALL"}, SecurityOptions: []string{"no-new-privileges"},
				Mounts: []*resetD101CapsMount{{Type: "bind", Source: s.inputHost, Destination: resetD101PreIntentNamespace}, {Type: "bind", Source: s.outputHost, Destination: resetD101PreIntentOutputPath, RW: true}, nil}}
			test.alter(&child)
			wire, _ := json.Marshal(child)
			_, err := decodeResetD101PreIntentChild(string(wire), id, imageRef, s)
			if (err == nil) != test.valid {
				t.Fatalf("accepted=%v", err == nil)
			}
		})
	}
	c := config{ghcrOwner: "owner"}
	args, err := c.resetD101PreIntentCreateArgs(s)
	if err != nil || args[len(args)-1] != imageRef || args[len(args)-2] != resetD101PreIntentCaptureEntrypoint {
		t.Fatal("create args lack pinned wrapper/image")
	}
	for _, arg := range args {
		if arg == "--rm" || arg == "--env" || arg == "--env-file" {
			t.Fatal("extra authority in argv")
		}
	}
}

func TestPreIntentManifestRequiresWholeOriginalSetAndExactWire(t *testing.T) {
	p, _ := preIntentReviewedFixture()
	s := &resetD101PreIntentCaptureSource{reviewed: p}
	now := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name  string
		alter func(*resetD101PreIntentCaptureManifest)
		valid bool
	}{
		{"valid", func(*resetD101PreIntentCaptureManifest) {}, true},
		{"missing-raw", func(v *resetD101PreIntentCaptureManifest) { delete(v.Originals, "world.json") }, false},
		{"missing-topology", func(v *resetD101PreIntentCaptureManifest) {
			delete(v.Originals, "topology-input:dryLandProjectionPolicy")
		}, false},
		{"caller-id", func(v *resetD101PreIntentCaptureManifest) {
			v.Originals["../../key"] = resetD101PreIntentOriginalRef{strings.Repeat("a", 64), 1, "application/json"}
		}, false},
		{"canonical-media", func(v *resetD101PreIntentCaptureManifest) {
			v.Originals["topologyCanonical"] = resetD101PreIntentOriginalRef{strings.Repeat("a", 64), 1, "text/plain"}
		}, false},
		{"target-cap", func(v *resetD101PreIntentCaptureManifest) {
			v.Originals["typedTarget"] = resetD101PreIntentOriginalRef{strings.Repeat("a", 64), 16<<10 + 1, "application/json"}
		}, false},
		{"wrong-input-bindings", func(v *resetD101PreIntentCaptureManifest) { v.InputBindingsSHA = strings.Repeat("a", 64) }, false},
		{"future-capture", func(v *resetD101PreIntentCaptureManifest) {
			v.CapturedAtUTC = now.Add(time.Second).Format(time.RFC3339Nano)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := resetD101PreIntentCaptureManifest{1, "D101_PRE_INTENT_CAPTURE_V1", p.OperationID, p.TargetFingerprint, p.AppSourceSHA, cloneResetD101Strings(p.ImagePins), p.InputBindingsSHA, now.Format(time.RFC3339Nano), map[string]resetD101PreIntentOriginalRef{}}
			for _, id := range append([]string{"captureFacts"}, append(d101PreIntentRequiredIDs(), "topology-input:dryLandProjectionPolicy")...) {
				m.Originals[id] = resetD101PreIntentOriginalRef{strings.Repeat("a", 64), 1, resetD101PreIntentMedia(id)}
			}
			test.alter(&m)
			wire, _ := json.Marshal(m)
			_, err := decodeResetD101PreIntentManifest(wire, s, now)
			if (err == nil) != test.valid {
				t.Fatalf("accepted=%v", err == nil)
			}
		})
	}
}
func d101PreIntentRequiredIDs() []string {
	return []string{"typedTarget", "configuration", "parserClass", "resolverDecision", "topologyRootClass", "topologyCanonical", "selectedWorld", "parsedOptions", "tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"}
}

func TestPreIntentMissingNativeSourceDoesNotRunChildOrReadKey(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if _, err := c.runResetD101PreIntentCapture(context.Background(), nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("nil source ran")
	}
	if _, err := c.runResetD101PreIntentCapture(context.Background(), &resetD101PreIntentCaptureSource{}, nil); err == nil {
		t.Fatal("nil guard ran")
	}
	if _, _, err := c.captureAndIssueResetD101SelectedSource(context.Background(), nil, resetD101SigningKeyPins{}, "/receipt", "/envelope", nil); err == nil {
		t.Fatal("missing source issued")
	}
	if calls != 0 {
		t.Fatalf("physical calls=%d", calls)
	}
}

func TestPreIntentUnsignedReceptionCannotPublishCompleteIndex(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	for _, r := range []*resetD101PreIntentCaptureReception{nil, {}, {issuedReceiptSHA: strings.Repeat("a", 64), issuedEnvelopeSHA: strings.Repeat("b", 64), issuedReceipt: []byte("self-reported"), issuedEnvelope: []byte("unsigned")}} {
		if _, err := c.publishResetD101SelectedCaptureIndex(context.Background(), r); err == nil {
			t.Fatal("unsigned or self-reported capture published index")
		}
	}
	if calls != 0 {
		t.Fatalf("missing issuer performed %d physical operations", calls)
	}
}
