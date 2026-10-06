package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestHostNativeInstallerMissingInputsNeverRegistersSuppliers(t *testing.T) {
	op := strings.Repeat("a", 32)
	if installer, err := newResetD101NativeHostInstaller(nil); err == nil || installer != nil {
		t.Fatal("nil installation registered")
	}
	if value, err := resetD101InstalledHostOperationSupplier(context.Background(), nil, op); err == nil || value != nil {
		t.Fatal("unsupplied native operation factory registered")
	}
	if value, err := resetD101InstalledHostIssuerSupplier(context.Background(), nil, op); err == nil || value != nil {
		t.Fatal("unsupplied native issuer factory registered")
	}
}

func TestHostNativeInstallerNativeLabelsDoNotReachAuthority(t *testing.T) {
	calls := 0
	authority := func(context.Context, *os.File, string, string) error { calls++; return nil }
	for _, name := range []string{"nil-context", "no-fd9", "wrong-selector", "unstamped-source"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "nil-context" {
				ctx = nil
			}
			installer := &resetD101NativeHostInstaller{inputs: resetD101HostInstallerInputs{authenticate: authority}}
			if installer.authenticate(ctx, nil, strings.Repeat("a", 32), "fixture") == nil || calls != 0 {
				t.Fatal("labels reached independent authority without native prerequisites")
			}
		})
	}
}
