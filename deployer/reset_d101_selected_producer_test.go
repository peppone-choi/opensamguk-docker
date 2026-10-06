package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSelectedProducerRequiresPreIntentWrapperAndActualChildIdentity(t *testing.T) {
	p := resetD101SelectedProducerPins{ProducerContainerID: strings.Repeat("d", 64), ProducerImageID: "sha256:" + strings.Repeat("e", 64), AppRepository: "ghcr.io/owner/opensamguk", ImagePins: map[string]string{"game-engine": "sha256:" + strings.Repeat("a", 64)}}
	for _, test := range []struct {
		name      string
		change    func(*resetD101SelectedCaptureObservation, *resetRuntimeImage)
		wantOK    bool
		wantCalls int
	}{
		{"fixed-wrapper", func(*resetD101SelectedCaptureObservation, *resetRuntimeImage) {}, true, 2},
		{"old-wrapper", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) {
			o.Entrypoint = []string{"/app/d101-selected-capture"}
		}, false, 1},
		{"extra-command", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) {
			o.Command = []string{"--d101-pre-intent-capture-v1"}
		}, false, 1},
		{"wrong-container", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) { o.ID = strings.Repeat("f", 64) }, false, 1},
		{"wrong-image", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) {
			o.ImageID = "sha256:" + strings.Repeat("f", 64)
		}, false, 1},
		{"running", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) {
			running := true
			o.Running = &running
		}, false, 1},
		{"failed-exit", func(o *resetD101SelectedCaptureObservation, _ *resetRuntimeImage) { exit := 78; o.ExitCode = &exit }, false, 1},
		{"wrong-repository-digest", func(_ *resetD101SelectedCaptureObservation, i *resetRuntimeImage) {
			i.RepoDigests = []string{p.AppRepository + "@sha256:" + strings.Repeat("f", 64)}
		}, false, 2},
		{"wrong-platform", func(_ *resetD101SelectedCaptureObservation, i *resetRuntimeImage) { i.Architecture = "arm64" }, false, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			running, exit := false, 0
			observation := resetD101SelectedCaptureObservation{ID: p.ProducerContainerID, ImageID: p.ProducerImageID, Status: "exited", Running: &running, ExitCode: &exit, Entrypoint: []string{resetD101PreIntentCaptureEntrypoint}, Command: []string{}}
			image := resetRuntimeImage{RepoDigests: []string{p.AppRepository + "@" + p.ImagePins["game-engine"]}, OS: "linux", Architecture: "amd64"}
			test.change(&observation, &image)
			calls := 0
			c := config{dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
				calls++
				var value any
				if calls == 1 && len(args) == 4 && args[0] == "inspect" && args[3] == p.ProducerContainerID {
					value = observation
				} else if calls == 2 && len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[4] == p.ProducerImageID {
					value = image
				} else {
					t.Fatalf("unexpected physical call %d: %v", calls, args)
				}
				wire, err := json.Marshal(value)
				return string(wire), err
			}}
			_, err := c.observeResetD101SelectedCapture(context.Background(), p)
			if (err == nil) != test.wantOK || calls != test.wantCalls {
				t.Fatalf("accepted=%v calls=%d; want accepted=%v calls=%d", err == nil, calls, test.wantOK, test.wantCalls)
			}
		})
	}
}

func TestSelectedProducerDoesNotSignOrReadKeyWithoutActualCaptureSource(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	if _, err := c.issueResetD101SelectedSource(context.Background(), nil); err == nil || calls != 0 {
		t.Fatal("nil source signed")
	}
	p := resetD101SelectedProducerPins{OperationID: strings.Repeat("a", 32), TargetFingerprint: strings.Repeat("b", 64), AppSourceSHA: strings.Repeat("c", 40), ImagePins: map[string]string{}, ProducerContainerID: strings.Repeat("d", 64), ProducerImageID: "sha256:" + strings.Repeat("e", 64), AppRepository: "ghcr.io/owner/opensamguk"}
	if _, err := newResetD101SelectedProducer(p); err == nil {
		t.Fatal("uninstalled originals accepted")
	}
}
func TestSelectedProducerRecomputesActualRawOptionDecisionsAndProvenance(t *testing.T) {
	options := map[string]string{"SERVER_NAME": "빼섭", "SERVER_GENERATION": "0", "SCENARIO_CODE": "scenario_3190", "SCENARIO_SEED_ENABLED": "true", "SCENARIO_LOOKUP_DIR": "", "RESET_MAXGENERAL": "50", "RESET_FIRST_TURN": "immediate", "RESET_EXTEND": "1", "RESET_TURNTERM": "60", "RESET_BLOCK_GENERAL_CREATE": "1", "RESET_NPCMODE": "0", "RESET_SHOW_IMG_LEVEL": "3"}
	raw := cloneResetD101Strings(options)
	raw["RESET_MAXGENERAL"] = " 050 "
	imagePins := map[string]string{}
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		imagePins[service] = "sha256:" + strings.Repeat("a", 64)
	}
	wire, _ := json.Marshal(map[string]any{"schemaVersion": 1, "kind": "D101_EFFECTIVE_SEED_INPUTS_V1", "originalOp": strings.Repeat("b", 32), "typedTargetFingerprint": strings.Repeat("c", 64), "appSourceSha": strings.Repeat("d", 40), "imagePins": imagePins, "rawInputs": raw})
	r := resetD101SelectedReceipt{OriginalOp: strings.Repeat("b", 32), TargetFingerprint: strings.Repeat("c", 64), AppSourceSHA: strings.Repeat("d", 40), ImagePins: imagePins, ConfigurationSHA: resetD101OriginalSHA(wire), ParserBytecodeSHA: strings.Repeat("e", 64), EffectiveOptions: options, OptionProvenance: map[string]string{}}
	for key, value := range options {
		original, _ := json.Marshal(struct {
			ConfigurationSHA string `json:"configurationSha256"`
			ParserSHA        string `json:"parserBytecodeSha256"`
			Option           string `json:"option"`
			RawInput         string `json:"rawInput"`
			EffectiveValue   string `json:"effectiveValue"`
		}{r.ConfigurationSHA, r.ParserBytecodeSHA, key, raw[key], value})
		r.OptionProvenance[key] = resetD101OriginalSHA(original)
	}
	if requireResetD101SelectedOptions(wire, r, options) != nil {
		t.Fatal("actual normalized source refused")
	}
	r.OptionProvenance["RESET_MAXGENERAL"] = strings.Repeat("f", 64)
	if requireResetD101SelectedOptions(wire, r, options) == nil {
		t.Fatal("self-reported option SHA accepted")
	}
	r.OptionProvenance = map[string]string{}
	if requireResetD101SelectedOptions(wire, r, options) == nil {
		t.Fatal("missing actual provenance accepted")
	}
}
