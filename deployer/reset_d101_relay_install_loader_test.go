package main

import (
	"context"
	"testing"
)

func TestRelayInstallMissingIndependentPublicAuthorityRemainsNil(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		p, err := readResetD101RelayInstallNegative(ctx)
		if p != nil || err == nil {
			t.Fatal("public shape registered relay authority")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if fixedResetD101HostRelayInstallation(ctx) != nil {
		t.Fatal("canceled missing installer")
	}
}
