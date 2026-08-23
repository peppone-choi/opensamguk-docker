package main

import "testing"

// TestCICanaryPasses exists only to force a real diff under deployer/**
// so the deployer-ci workflow's path filter fires a fresh run, and to
// prove the CI job is green when tests pass (OPENSAM-31 verification).
// Removed in the follow-up commit on this same PR.
func TestCICanaryPasses(t *testing.T) {}
