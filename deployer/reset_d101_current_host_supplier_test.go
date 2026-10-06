package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101hostlaunch"
)

func TestCurrentHostSupplierRetainedNamesRequireNewInvocation(t *testing.T) {
	op, nonce := strings.Repeat("a", 32), strings.Repeat("b", 32)
	name := "current-freeze-" + op + "-" + nonce + ".original"
	for _, test := range []struct {
		name          string
		before, after []string
		want          int
		deny          bool
	}{
		{"new", nil, []string{name}, 1, false},
		{"replay", []string{name}, []string{name}, 0, false},
		{"temporary-not-original", nil, []string{strings.TrimSuffix(name, ".original") + ".tmp"}, 0, false},
		{"other-operation", nil, []string{strings.Replace(name, op, strings.Repeat("c", 32), 1)}, 0, false},
		{"bad-nonce", nil, []string{"current-freeze-" + op + "-bad.original"}, 0, true},
		{"path-escape", nil, []string{"current-freeze-" + op + "-../" + nonce + ".original"}, 0, true},
		{"duplicate", nil, []string{name, name}, 0, true},
		{"bound", nil, make([]string, 1025), 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resetD101NewRetainedCaptureNames(op, test.before, test.after)
			if (err != nil) != test.deny || !test.deny && len(got) != test.want {
				t.Fatalf("retained names count=%d error=%v", len(got), err)
			}
		})
	}
}

func TestCurrentHostSupplierUnavailableBeforeNativeRead(t *testing.T) {
	if source, err := newResetD101CurrentHostSupplier(nil, d101hostlaunch.Pins{}, resetD101CurrentFreezePins{}, nil); err == nil || source != nil {
		t.Fatal("missing host keeper/authenticator installed")
	}
	var source *resetD101CurrentHostSupplier
	if _, err := source.CaptureAfter(context.Background(), resetExecutionPhaseBinding{}, time.Now()); err == nil {
		t.Fatal("nil host source accepted")
	}
	if _, err := (&resetD101CurrentHostSupplier{}).CaptureAfter(context.Background(), resetExecutionPhaseBinding{}, time.Now()); err == nil {
		t.Fatal("missing actual authenticator accepted")
	}
}
