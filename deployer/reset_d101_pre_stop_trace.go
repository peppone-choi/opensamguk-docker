package main

import (
	"context"
	"encoding/base64"
	"time"
)

// Private context values are set only by the owning capture and the collector
// command wrapper. QUERY/current source observations never carry the execution
// marker. No HTTP parameter/env/runner switch can enable this native trace.
type resetD101PreStopStreamContextKey struct{}
type resetD101OldWorldPhysicalContextKey struct{}

func resetD101PreStopStreamFromContext(ctx context.Context) *resetD101PreStopNativeStream {
	if ctx == nil {
		return nil
	}
	value, _ := ctx.Value(resetD101PreStopStreamContextKey{}).(*resetD101PreStopNativeStream)
	return value
}

func resetD101TraceActualDocker(ctx context.Context, args []string) (func() error, error) {
	if ctx == nil {
		return nil, errResetExecutionEvidence
	}
	physical, _ := ctx.Value(resetD101OldWorldPhysicalContextKey{}).(bool)
	stream := resetD101PreStopStreamFromContext(ctx)
	if !physical || stream == nil {
		return func() error { return nil }, nil
	}
	return stream.BeginInvocation(ctx, args)
}

func resetD101PreStopNativeFrameFromObservation(value resetD101PreStopCommandObservation) (resetD101PreStopNativeFrame, error) {
	closed := resetD101PreStopNativeFrame{}
	p, s := value.gateway.publication, value.freeze
	if value.started.IsZero() || value.completed.Before(value.started) || value.completed.Sub(value.started) >= resetPreflightMaxAge ||
		p.ObservedAt.Before(value.started) || p.ObservedAt.After(value.completed) || s.ObservedAt.Before(value.started) || s.ObservedAt.After(value.completed) || len(p.Original()) == 0 || len(value.gateway.gateway.Original()) == 0 {
		return closed, errResetExecutionEvidence
	}
	return resetD101PreStopNativeFrame{
		StartedAtUTC: value.started.UTC().Format(time.RFC3339Nano), CompletedAtUTC: value.completed.UTC().Format(time.RFC3339Nano), GatewayQueryBase64: base64.RawURLEncoding.EncodeToString(value.gateway.gateway.Original()),
		Publication: resetD101PreStopNativePublication{p.ObservedAt.UTC().Format(time.RFC3339Nano), p.BodySHA256, p.Current, base64.RawURLEncoding.EncodeToString(p.Original())},
		Snapshot:    resetD101PreStopNativeSnapshot{s.ObservedAt.UTC().Format(time.RFC3339Nano), s.ServerID, s.OperationID, s.TargetFingerprint, s.PublicationState, s.PublicationRevision, s.WriterFreezeReceiptSHA, s.WriterFreezeHeld},
	}, nil
}
