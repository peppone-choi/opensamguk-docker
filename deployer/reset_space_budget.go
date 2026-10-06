package main

import (
	"errors"
	"math"
)

const resetDiskReserveBytes uint64 = 10 * 1024 * 1024 * 1024

// The workflow must obtain these upper bounds from the approved source/pin and
// backup inventory. A missing observation is not a zero-byte allocation. This
// calculation alone does not attest the origin or freshness of an observation.
type resetSpaceBudget struct {
	CandidateUnpackedBytes *uint64
	BackupBytes            *uint64
	RecoveryBytes          *uint64
	TemporaryBytes         *uint64
	NewFileCount           *uint64
	InodeReserve           *uint64
}

type resetSpaceObservation struct {
	AvailableBytes  *uint64
	AvailableInodes *uint64
}

type resetSpaceRequirement struct {
	Bytes  uint64
	Inodes uint64
}

func checkedResetSpaceSum(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, errors.New("reset space budget exceeds supported range")
		}
		total += value
	}
	return total, nil
}

func resetRequiredSpace(budget resetSpaceBudget) (resetSpaceRequirement, error) {
	if budget.CandidateUnpackedBytes == nil || budget.BackupBytes == nil || budget.RecoveryBytes == nil || budget.TemporaryBytes == nil || budget.NewFileCount == nil || budget.InodeReserve == nil {
		return resetSpaceRequirement{}, errors.New("reset space budget is incomplete")
	}
	bytes, err := checkedResetSpaceSum(*budget.CandidateUnpackedBytes, *budget.BackupBytes, *budget.RecoveryBytes, *budget.TemporaryBytes, resetDiskReserveBytes)
	if err != nil {
		return resetSpaceRequirement{}, err
	}
	inodes, err := checkedResetSpaceSum(*budget.NewFileCount, *budget.InodeReserve)
	if err != nil {
		return resetSpaceRequirement{}, err
	}
	return resetSpaceRequirement{Bytes: bytes, Inodes: inodes}, nil
}

func verifyResetSpaceBudget(budget resetSpaceBudget, observed resetSpaceObservation) error {
	required, err := resetRequiredSpace(budget)
	if err != nil {
		return err
	}
	if observed.AvailableBytes == nil || observed.AvailableInodes == nil {
		return errors.New("reset space observation is incomplete")
	}
	if *observed.AvailableBytes < required.Bytes {
		return errors.New("reset disk space is insufficient")
	}
	if *observed.AvailableInodes < required.Inodes {
		return errors.New("reset inode space is insufficient")
	}
	return nil
}

// After backup/pull, recovery and unfinished temporary work still need space.
// Merely retaining 10 GiB is insufficient when those allocations are outstanding.
func verifyResetRemainingSpace(recoveryBytes, unfinishedTemporaryBytes, newFileCount, inodeReserve *uint64, observed resetSpaceObservation) error {
	zero := uint64(0)
	return verifyResetSpaceBudget(resetSpaceBudget{CandidateUnpackedBytes: &zero, BackupBytes: &zero, RecoveryBytes: recoveryBytes, TemporaryBytes: unfinishedTemporaryBytes, NewFileCount: newFileCount, InodeReserve: inodeReserve}, observed)
}
