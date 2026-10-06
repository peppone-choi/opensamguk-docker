package main

import (
	"math"
	"testing"
)

func resetBudgetNumber(value uint64) *uint64 { return &value }

func TestResetSpaceBudgetProtectsAllAllocationsAndInodes(t *testing.T) {
	budget := resetSpaceBudget{resetBudgetNumber(100), resetBudgetNumber(200), resetBudgetNumber(300), resetBudgetNumber(400), resetBudgetNumber(50), resetBudgetNumber(10)}
	required, err := resetRequiredSpace(budget)
	if err != nil || required.Bytes != resetDiskReserveBytes+1000 || required.Inodes != 60 {
		t.Fatalf("incorrect required allocation: %#v %v", required, err)
	}
	for _, test := range []struct {
		name          string
		bytes, inodes uint64
		wantError     bool
	}{
		{"exact", required.Bytes, required.Inodes, false},
		{"one-byte-short", required.Bytes - 1, required.Inodes, true},
		{"one-inode-short", required.Bytes, required.Inodes - 1, true},
		{"ten-gib-alone", resetDiskReserveBytes, required.Inodes, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyResetSpaceBudget(budget, resetSpaceObservation{&test.bytes, &test.inodes})
			if (err != nil) != test.wantError {
				t.Fatalf("budget admission mismatch: %v", err)
			}
		})
	}
}

func TestResetSpaceBudgetRejectsEveryUnknownAndOverflow(t *testing.T) {
	complete := resetSpaceBudget{resetBudgetNumber(100), resetBudgetNumber(200), resetBudgetNumber(300), resetBudgetNumber(400), resetBudgetNumber(50), resetBudgetNumber(10)}
	for i := 0; i < 6; i++ {
		budget := complete
		fields := []**uint64{&budget.CandidateUnpackedBytes, &budget.BackupBytes, &budget.RecoveryBytes, &budget.TemporaryBytes, &budget.NewFileCount, &budget.InodeReserve}
		*fields[i] = nil
		if _, err := resetRequiredSpace(budget); err == nil {
			t.Fatalf("unknown field %d accepted", i)
		}
	}
	for _, observed := range []resetSpaceObservation{{nil, resetBudgetNumber(100)}, {resetBudgetNumber(math.MaxUint64), nil}} {
		if err := verifyResetSpaceBudget(complete, observed); err == nil {
			t.Fatal("unknown observation accepted")
		}
	}
	for _, budget := range []resetSpaceBudget{
		{resetBudgetNumber(math.MaxUint64), resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(0)},
		{resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(0), resetBudgetNumber(math.MaxUint64), resetBudgetNumber(1)},
	} {
		if _, err := resetRequiredSpace(budget); err == nil {
			t.Fatal("overflow wrapped into an admissible budget")
		}
	}
}

func TestResetRemainingSpaceRetainsRecoveryReserveAfterBackupAndPull(t *testing.T) {
	recovery, temp, files, reserve := resetBudgetNumber(300), resetBudgetNumber(100), resetBudgetNumber(50), resetBudgetNumber(10)
	for _, observed := range []resetSpaceObservation{
		{resetBudgetNumber(resetDiskReserveBytes), resetBudgetNumber(60)},
		{resetBudgetNumber(resetDiskReserveBytes + 400), resetBudgetNumber(59)},
	} {
		if err := verifyResetRemainingSpace(recovery, temp, files, reserve, observed); err == nil {
			t.Fatal("unfinished recovery allocation was not reserved")
		}
	}
	if err := verifyResetRemainingSpace(recovery, temp, files, reserve, resetSpaceObservation{resetBudgetNumber(resetDiskReserveBytes + 400), resetBudgetNumber(60)}); err != nil {
		t.Fatal(err)
	}
}
