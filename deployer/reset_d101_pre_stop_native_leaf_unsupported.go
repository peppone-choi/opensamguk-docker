//go:build !linux

package main

import "os"

// Production native issuance/custody requires the approved Linux namespace.
// Portable fixtures inject only their isolated data-file opener, not authority.
func resetD101OpenNativeLeaf(directory *os.File, op string, flags int, mode uint32) (*os.File, error) {
	return nil, errResetExecutionEvidence
}
