package main

import (
	"context"
	"opensamguk-deployer/internal/d101custody"
	"os"
	"runtime"
)

const resetD101RelayPublicPinsPath = "/etc/opensamguk/d101/relay-public-pins.json"

// Independent build/issuer input, not a decoder adopting expected values from
// public file bytes. Delivery and dynamic keeper issuer remain unverified.
type resetD101RelayPublicExpected struct{ pin d101custody.NativeFilePin }

var resetD101ReviewedRelayPublicExpected *resetD101RelayPublicExpected

func readResetD101RelayInstallNegative(ctx context.Context) (*resetD101HostRelayInstallation, error) {
	p := resetD101ReviewedRelayPublicExpected
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "linux" || os.Geteuid() != 0 || p == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	h, err := openResetD101NativeInput(ctx, resetD101RelayPublicPinsPath, p.pin, 0444, 0)
	if err != nil {
		return nil, err
	}
	defer h.close()
	if h.recheck(ctx, 0) != nil {
		return nil, errResetExecutionEvidence
	}
	// No public codec/session issuer/independent connected-peer authority exists.
	return nil, errResetD101InstallationNotSupplied
}
func fixedResetD101HostRelayInstallation(ctx context.Context) *resetD101HostRelayInstallation {
	if resetD101ReviewedHostRelay != nil {
		return resetD101ReviewedHostRelay
	}
	p, _ := readResetD101RelayInstallNegative(ctx)
	return p
}
