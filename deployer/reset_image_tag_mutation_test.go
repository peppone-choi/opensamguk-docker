package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the requested service-latest mutation only in a temporary source copy.
// A build/fixture failure is not accepted as proof that the tag assertion works.
func TestResetImageTagMutationIsRejectedByCandidateRegression(t *testing.T) {
	original, err := os.ReadFile("reset_image_pins.go")
	if err != nil {
		t.Fatal(err)
	}
	const approved = `reference := repository + ":" + service + "-" + target.Updates["IMAGE_TAG"]`
	const mutated = `reference := repository + ":" + service + "-latest"`
	if bytes.Count(original, []byte(approved)) != 1 {
		t.Fatal("image tag mutation point changed; update the behavioral probe")
	}
	scratch := t.TempDir()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources = append(sources, "go.mod")
	for _, file := range sources {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if file == "reset_image_pins.go" {
			contents = bytes.Replace(contents, []byte(approved), []byte(mutated), 1)
		}
		if err := os.WriteFile(filepath.Join(scratch, file), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", "^TestResetCandidatePinsExactServiceTagsForInspectAndPull$", ".")
	command.Dir = scratch
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("image tag mutation probe exceeded its deadline: %v", ctx.Err())
	}
	if err == nil {
		t.Fatal("service-latest mutation passed the candidate tag regression")
	}
	if !strings.Contains(string(output), "inspection did not use exact approved tag: ghcr.io/owner/opensamguk:game-api-latest") {
		t.Fatalf("mutation failed without the required behavior assertion: %s", output)
	}
	after, err := os.ReadFile("reset_image_pins.go")
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("mutation probe changed the original source")
	}
	t.Log("service-latest mutation rejected by the exact candidate tag assertion; original source preserved")
}
