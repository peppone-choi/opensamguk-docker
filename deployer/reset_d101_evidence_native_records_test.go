package main

import (
	"context"
	"testing"
)

func TestNativeOriginRecordsMissingFixedInstallationCannotCaptureOrGrantAuthority(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "no-fixed-role", "no-origin-key"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			var installed resetD101NativeRecordInstallation
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "no-origin-key":
				f := newNativeOriginSourceFixture(t)
				installed.Evidence = f.pins
				installed.Expected.Role = "APPROVAL_ISSUER"
			}
			result, err := captureResetD101NativeUnverifiedRecords(ctx, installed)
			if err == nil || result != nil {
				t.Fatal("missing fixed native installation produced reception")
			}
		})
	}
}
