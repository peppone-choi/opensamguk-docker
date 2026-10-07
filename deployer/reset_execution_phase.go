package main

import "time"

// Observation shape retained for strict validation of existing durable journals.
type resetExecutionPhaseSnapshot struct {
	ObservedAt             time.Time
	ServerID               string
	OperationID            string
	TargetFingerprint      string
	PublicationState       string
	PublicationRevision    string
	WriterFreezeReceiptSHA string
	WriterFreezeHeld       bool
}
