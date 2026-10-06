package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Disposable filesystem and command-recording fixtures only. A passing legacy
// regression supplies no D101 execution, management authentication or live ops.
func effectiveTargetFixture(t *testing.T, scenario string) (config, serverTarget) {
	t.Helper()
	c := configuredResetOperationTest(t)
	target, err := c.serverTargetForID("pep")
	if err != nil {
		t.Fatal(err)
	}
	writeEnv(t, target.EnvFile, "SERVER_ID=pep\nSERVER_GENERATION=1\nSCENARIO_CODE="+scenario+"\nSCENARIO_SEED_ENABLED=true\n")
	return c, target
}

func effectiveTargetFiles(t *testing.T, c config) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(c.serversDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		wire := []byte(nil)
		if !entry.IsDir() {
			wire, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		files[path] = fmt.Sprintf("%v:%d:%s", info.Mode(), info.ModTime().UnixNano(), wire)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(c.sharedEnvFile())
	if err != nil {
		t.Fatal(err)
	}
	files[c.sharedEnvFile()] = fmt.Sprintf("%v:%d:%s", info.Mode(), info.ModTime().UnixNano(), readFile(t, c.sharedEnvFile()))
	return files
}

func TestD101EffectiveTargetResetRefusesBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		includeScenario bool
		operationID string
	}{
		{name: "inherited", current: "scenario_3190"},
		{name: "empty", current: "scenario_3190", includeScenario: true},
		{name: "normalized-inherited", current: " scenario_3190 "},
		{name: "durable-request", current: "scenario_3190", operationID: "0123456789abcdef0123456789abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := effectiveTargetFixture(t, tc.current)
			calls := &dockerCallRecorder{}
			c.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
			body := map[string]string{"id": "pep", "confirm": "RESET pep", "generation": "0"}
			if tc.includeScenario {
				body["scenarioCode"] = ""
			}
			if tc.operationID != "" {
				body["operationId"] = tc.operationID
			}
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			before := effectiveTargetFiles(t, c)
			response := envRequest(t, c.withAuth(c.handleServerReset), http.MethodPost, "/servers/reset", string(wire))
			var value createServerResponse
			if json.Unmarshal(response.Body.Bytes(), &value) != nil || response.Code != http.StatusBadRequest || value.OK || value.JobID != "" || !strings.Contains(value.Detail, "3190 리셋은") || calls.count() != 0 {
				t.Fatal("protected effective target reached admission or a command")
			}
			if !reflect.DeepEqual(before, effectiveTargetFiles(t, c)) || c.operations.active != nil || c.operations.preparing != nil {
				t.Fatal("refusal changed lifecycle files or reserved work")
			}
			if _, exists := c.lifecycleOperationStore.Lookup(tc.operationID); exists {
				t.Fatal("refusal created a durable operation")
			}
			c.lifecycleJobs.mu.Lock()
			jobs := len(c.lifecycleJobs.jobs)
			c.lifecycleJobs.mu.Unlock()
			if jobs != 0 {
				t.Fatal("refusal reserved a lifecycle job")
			}
		})
	}
}

func TestD101EffectiveTargetRecoveryRefusesBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, stage string
		explicit bool
	}{
		{name: "legacy-env", stage: lifecycleJournalStageEnv},
		{name: "legacy-registry", stage: lifecycleJournalStageRegistry},
		{name: "legacy-down", stage: lifecycleJournalStageDown},
		{name: "missing-prepared", stage: lifecycleJournalStagePrepared},
		{name: "explicit-prepared", stage: lifecycleJournalStagePrepared, explicit: true},
		{name: "explicit-down", stage: lifecycleJournalStageDown, explicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, target := effectiveTargetFixture(t, "scenario_3190")
			journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", Stage: tc.stage, ServerID: "pep", Project: target.Project}
			if tc.explicit {
				resolved, err := resetLifecycleTargetForEnv(target.EnvFile, nil)
				if err != nil {
					t.Fatal(err)
				}
				journal.ResetTarget = &resolved
			}
			if err := c.writeLifecycleJournalRecord(journal); err != nil {
				t.Fatal(err)
			}
			read, exists, err := c.readLifecycleJournal()
			if err != nil || !exists || read.ResetExecution != nil || (read.ResetTarget != nil) != tc.explicit {
				t.Fatal("legacy fixture was not readable before admission")
			}
			c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, c.lifecycleJobs)
			calls := &dockerCallRecorder{}
			c.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
			before := effectiveTargetFiles(t, c)
			repairErr := c.repairLifecycleJournal()
			if repairErr == nil || calls.count() != 0 {
				t.Fatal("protected or absent effective target reached recovery commands")
			}
			if tc.name != "missing-prepared" && !strings.Contains(repairErr.Error(), "D101 reset recovery") {
				t.Fatal("fixture refused before the effective-target guard")
			}
			if !reflect.DeepEqual(before, effectiveTargetFiles(t, c)) || !c.operations.closed || !c.operations.journalPending || c.operations.active != nil {
				t.Fatal("refusal altered original files or lost recovery barrier")
			}
		})
	}
}

func TestD101EffectiveTargetLegacyResetRemainsAvailable(t *testing.T) {
	for _, scenario := range []string{"scenario_1010", "scenario_3190"} {
		t.Run(scenario, func(t *testing.T) {
			c, target := effectiveTargetFixture(t, scenario)
			calls := &dockerCallRecorder{}
			c.dockerRunner = func(args ...string) (string, error) {
				if dockerPreflightProbe(args) {
					return "29.0.0\n", nil
				}
				calls.record(args...)
				return "fixture-ok\n", nil
			}
			response := envRequest(t, c.withAuth(c.handleServerReset), http.MethodPost, "/servers/reset", `{"id":"pep","confirm":"RESET pep","scenarioCode":"scenario_1002","generation":"2"}`)
			var value createServerResponse
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.JobID == "" {
				t.Fatal("ordinary effective target was refused")
			}
			if result := waitForLifecycleJob(t, c.lifecycleJobs, value.JobID, lifecycleJobSucceeded); result.Status != lifecycleJobSucceeded {
				t.Fatal("ordinary reset did not complete")
			}
			if countDockerCallsContaining(calls.snapshot(), "down --volumes --remove-orphans") != 1 || stateFilePresent(c.lifecycleJournalFile) || !strings.Contains(readFile(t, target.EnvFile), "SCENARIO_CODE=scenario_1002\n") {
				t.Fatal("ordinary reset changed its once execution or final target")
			}
		})
	}
}

func TestD101EffectiveTargetLegacyRecoveryRemainsAvailable(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			c, target := effectiveTargetFixture(t, "scenario_1002")
			journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", Stage: lifecycleJournalStageDown, ServerID: "pep", Project: target.Project}
			if explicit {
				resolved, err := resetLifecycleTargetForEnv(target.EnvFile, nil)
				if err != nil {
					t.Fatal(err)
				}
				journal.ResetTarget = &resolved
				journal.Stage = lifecycleJournalStagePrepared
			}
			if err := c.writeLifecycleJournalRecord(journal); err != nil {
				t.Fatal(err)
			}
			c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, c.lifecycleJobs)
			calls := &dockerCallRecorder{}
			c.dockerRunner = func(args ...string) (string, error) {
				if dockerPreflightProbe(args) {
					return "29.0.0\n", nil
				}
				calls.record(args...)
				if strings.Contains(strings.Join(args, " "), "down --volumes") {
					read, exists, err := c.readLifecycleJournal()
					if err != nil || !exists || (read.ResetTarget != nil) != explicit || read.ResetExecution != nil {
						return "", fmt.Errorf("legacy journal shape changed")
					}
				}
				return "fixture-ok\n", nil
			}
			if err := c.repairLifecycleJournal(); err != nil {
				t.Fatal("ordinary recovery refused", err)
			}
			if countDockerCallsContaining(calls.snapshot(), "down --volumes --remove-orphans") != 1 || stateFilePresent(c.lifecycleJournalFile) || c.operations.journalPending {
				t.Fatal("ordinary recovery did not preserve once execution/cleanup")
			}
		})
	}
}

func TestD101EffectiveTargetBoundSucceededCleanupStaysReadOnly(t *testing.T) {
	for _, mode := range []string{"succeeded", "wrong-fingerprint", "postcondition-failure"} {
		t.Run(mode, func(t *testing.T) {
			c, target := effectiveTargetFixture(t, "scenario_3190")
			resolved, err := resetLifecycleTargetForEnv(target.EnvFile, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.reconcileServerRegistry(target); err != nil {
				t.Fatal(err)
			}
			op := "0123456789abcdef0123456789abcdef"
			fingerprint := resetRequestFingerprint("pep", resolved)
			if mode == "wrong-fingerprint" {
				fingerprint = strings.Repeat("f", 64)
			}
			mustReserveOperation(t, c.lifecycleOperationStore, durableOperationRecord{OperationID: op, Kind: lifecycleKindReset, SubjectID: "pep", RequestFingerprint: fingerprint, Status: lifecycleJobRunning})
			mustTransitionOperation(t, c.lifecycleOperationStore, op, lifecycleJobSucceeded, http.StatusOK, durableOperationSuccessMessage(lifecycleKindReset))
			journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", OperationID: op, OperationKind: lifecycleKindReset, Stage: lifecycleJournalStageDown, ServerID: "pep", Project: target.Project, ResetTarget: &resolved}
			if err := c.writeLifecycleJournalRecord(journal); err != nil {
				t.Fatal(err)
			}
			c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, c.lifecycleJobs)
			if mode == "postcondition-failure" {
				c.httpGet = func(context.Context, string) (int, []byte, error) { return http.StatusServiceUnavailable, nil, fmt.Errorf("fixture unavailable") }
				c.resetVerifyTimeout = 10 * time.Millisecond
				c.resetVerifyPollInterval = time.Millisecond
			}
			calls := &dockerCallRecorder{}
			c.dockerRunner = func(args ...string) (string, error) { calls.record(args...); return "unexpected", nil }
			envBefore, sharedBefore, journalBefore := readFile(t, target.EnvFile), readFile(t, c.sharedEnvFile()), readFile(t, c.lifecycleJournalFile)
			recordBefore, _ := c.lifecycleOperationStore.Lookup(op)
			err = c.repairLifecycleJournal()
			if mode == "succeeded" {
				if err != nil || stateFilePresent(c.lifecycleJournalFile) {
					t.Fatal("bound completed cleanup was refused", err)
				}
			} else if err == nil || readFile(t, c.lifecycleJournalFile) != journalBefore || !c.operations.closed || !c.operations.journalPending {
				t.Fatal("invalid completed cleanup lost its journal/barrier")
			}
			recordAfter, _ := c.lifecycleOperationStore.Lookup(op)
			if calls.count() != 0 || readFile(t, target.EnvFile) != envBefore || readFile(t, c.sharedEnvFile()) != sharedBefore || recordBefore != recordAfter {
				t.Fatal("completed cleanup replayed mutation or rewrote terminal state")
			}
		})
	}
}

func TestD101EffectiveTargetRecoveryKeepsResolvedTargetThroughPreflight(t *testing.T) {
	c, target := effectiveTargetFixture(t, "scenario_1002")
	journal := lifecycleJournal{Version: lifecycleJournalVersion, Operation: "reset", Stage: lifecycleJournalStageDown, ServerID: "pep", Project: target.Project}
	if err := c.writeLifecycleJournalRecord(journal); err != nil {
		t.Fatal(err)
	}
	c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, c.lifecycleJobs)
	calls := &dockerCallRecorder{}
	changed := false
	c.dockerRunner = func(args ...string) (string, error) {
		if dockerPreflightProbe(args) {
			if !changed {
				// Disposable external-change fixture. The production preparation
				// must consume the already checked target, not resolve this again.
				writeEnv(t, target.EnvFile, "SERVER_ID=pep\nSERVER_GENERATION=1\nSCENARIO_CODE=scenario_3190\nSCENARIO_SEED_ENABLED=true\n")
				changed = true
			}
			return "29.0.0\n", nil
		}
		calls.record(args...)
		if strings.Contains(strings.Join(args, " "), "down --volumes") && !strings.Contains(readFile(t, target.EnvFile), "SCENARIO_CODE=scenario_1002\n") {
			return "", fmt.Errorf("preparation did not consume the checked target")
		}
		return "fixture-ok\n", nil
	}
	if err := c.repairLifecycleJournal(); err != nil || !changed || countDockerCallsContaining(calls.snapshot(), "down --volumes --remove-orphans") != 1 || stateFilePresent(c.lifecycleJournalFile) {
		t.Fatal("resolved target was lost before preparation", err)
	}
}
