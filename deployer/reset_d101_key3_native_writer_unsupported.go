//go:build !linux || !amd64

package main

import "context"

func initializeResetD101Key3Native(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected, resetD101Key3NativeInitializationBinding, resetD101Key3NativeInitializationSource) resetD101Key3NativeInitializationOutcome {
	return resetD101Key3NativeInitializationOutcome{err: errResetD101InstallationNotSupplied}
}
