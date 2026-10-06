package main

import (
	"context"
	"os"

	"opensamguk-deployer/internal/d101native"
)

// The installed source owns every credential, original, deadline and stream.
// A missing handoff exits before touching stdio or starting a native child.
func run(ctx context.Context) error {
	// The authenticated native last-use/terminal owner is not supplied.
	// Opening and closing a transport cannot perform that consumer handoff.
	return d101native.ErrUnavailable
}

func main() {
	if run(context.Background()) != nil { os.Exit(1) }
}
