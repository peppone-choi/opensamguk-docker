package main

import "testing"

// TestCICanaryDeliberateFailure exists only to prove the CI job in
// .github/workflows/deployer-ci.yml actually turns red on a failing test
// (OPENSAM-31 verification). It is removed in the follow-up commit on this
// same PR once the red run is observed.
func TestCICanaryDeliberateFailure(t *testing.T) {
	t.Fatal("intentional failure to verify CI catches red test runs")
}
