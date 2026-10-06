package main

import (
	"context"
	"strings"
	"testing"
)

func TestPreStopOldWorldMissingCurrentSourceNeverInvokesPhysicalCollector(t *testing.T) {
	for _, mode := range []string{"missing-source", "nil-context", "cancelled-context", "nil-preparation"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			if mode == "nil-context" {
				ctx = nil
			}
			if mode == "cancelled-context" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			c, s := preStopLeaseFixture(t)
			if mode == "nil-preparation" {
				s = nil
			}
			commands := 0
			c.dockerRunner = func(args ...string) (string, error) { commands++; return "", nil }
			captured, err := c.captureResetD101PreStopOldWorld(ctx, s, strings.Repeat("a", 64), resetD101OldWorldCaptureInputs{})
			if err == nil || captured.preparation != nil || len(captured.oldWorld.original) != 0 || commands != 0 {
				t.Fatal("missing actual current source invoked physical collection")
			}
		})
	}
}
