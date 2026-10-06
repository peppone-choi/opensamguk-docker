package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// Anchor the reserved/read leaf to the independently verified actual parent
// FD. Parent pathname replacement cannot create an issuing attempt elsewhere.
func resetD101OpenNativeLeaf(directory *os.File, op string, flags int, mode uint32) (*os.File, error) {
	if directory == nil || !lifecycleJobIDRe.MatchString(op) {
		return nil, errResetExecutionEvidence
	}
	fd, err := syscall.Openat(int(directory.Fd()), op+".json", flags, mode)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	return os.NewFile(uintptr(fd), filepath.Join(directory.Name(), op+".json")), nil
}
