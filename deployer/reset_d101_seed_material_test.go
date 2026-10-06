package main

import (
	"context"
	"strings"
	"testing"
)

func TestSeedMaterialMissingFixedInputsClosesBeforeDockerOrGrant(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	guardCalls := 0
	guard := func(context.Context) error { guardCalls++; return nil }
	if material, err := c.prepareResetD101SeedChildMaterial(context.Background(), resetD101CandidateAdmission{}, strings.Repeat("a", 64), guard); err == nil || material.InstallationSHA != "" || len(material.Bindings()) != 0 || calls != 0 || guardCalls != 0 {
		t.Fatal("missing native installation released material")
	}
}
func TestSeedMaterialHostBindUsesHostRootAndRejectsEscapingOrInterpolatedPaths(t *testing.T) {
	c := config{composeDir: "/workspace", serversDir: "/workspace/servers", composeHostDir: "/srv/opensamguk"}
	observed, err := resetD101SeedHostPath(c, "/workspace/servers/.deployer-reset-seed-root-pins/"+strings.Repeat("a", 32)+".json")
	if err != nil || observed != "/srv/opensamguk/servers/.deployer-reset-seed-root-pins/"+strings.Repeat("a", 32)+".json" {
		t.Fatal("container path used as host bind source", err)
	}
	for _, local := range []string{"/workspace/servers", "/workspace/servers/../key.json", "/workspace/foreign/key.json", "/workspace/servers/a,key.json", "relative.json"} {
		if _, err := resetD101SeedHostPath(c, local); err == nil {
			t.Fatal("invalid host bind source accepted", local)
		}
	}
	c.composeHostDir = "/srv/a,b"
	if _, err := resetD101SeedHostPath(c, "/workspace/servers/key.json"); err == nil {
		t.Fatal("bind syntax interpolation accepted")
	}
}
