package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const resetAdminCurrentFixture = `{"worldId":1,"generation":"0","scenarioCode":"scenario_3190","year":190,"month":1,"phase":1,"status":"READY","turnTerm":60,"startTime":"2026-10-05T10:00:00Z","maxGeneral":50,"blockGeneralCreate":1,"firstTurn":"immediate"}`

func TestResetD101AdminCurrentPreservesRawAndRejectsUnknownSettings(t *testing.T) {
	var valid resetAdminCurrent
	if decodeResetPrivateJSON([]byte(resetAdminCurrentFixture), &valid) != nil || validateResetD101AdminCurrent(valid) != nil {
		t.Fatal("valid fixture refused")
	}
	cases := map[string]string{
		"world":                   strings.Replace(resetAdminCurrentFixture, `"worldId":1`, `"worldId":2`, 1),
		"generation-null":         strings.Replace(resetAdminCurrentFixture, `"generation":"0"`, `"generation":null`, 1),
		"generation-number":       strings.Replace(resetAdminCurrentFixture, `"generation":"0"`, `"generation":0`, 1),
		"generation-leading-zero": strings.Replace(resetAdminCurrentFixture, `"generation":"0"`, `"generation":"00"`, 1),
		"scenario-alias":          strings.Replace(resetAdminCurrentFixture, "scenario_3190", "3190", 1),
		"term-seconds":            strings.Replace(resetAdminCurrentFixture, `"turnTerm":60`, `"turnTerm":3600`, 1),
		"cap":                     strings.Replace(resetAdminCurrentFixture, `"maxGeneral":50`, `"maxGeneral":null`, 1),
		"block":                   strings.Replace(resetAdminCurrentFixture, `"blockGeneralCreate":1`, `"blockGeneralCreate":0`, 1),
		"scheduled":               strings.Replace(resetAdminCurrentFixture, "immediate", "scheduled", 1),
		"start-null":              strings.Replace(resetAdminCurrentFixture, `"startTime":"2026-10-05T10:00:00Z"`, `"startTime":null`, 1),
		"duplicate":               strings.Replace(resetAdminCurrentFixture, `"worldId":1`, `"worldId":2,"worldId":1`, 1),
		"trailing":                resetAdminCurrentFixture + " {}",
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			var current resetAdminCurrent
			if decodeResetPrivateJSON([]byte(wire), &current) == nil && validateResetD101AdminCurrent(current) == nil {
				t.Fatal("unknown/wrong setting accepted")
			}
		})
	}
	// Diagnostic zero/null are retained; raw does not prove initial seed date.
	wire := strings.Replace(resetAdminCurrentFixture, `"year":190`, `"year":0`, 1)
	wire = strings.Replace(wire, `"status":"READY"`, `"status":null`, 1)
	var zero resetAdminCurrent
	if decodeResetPrivateJSON([]byte(wire), &zero) != nil || validateResetD101AdminCurrent(zero) != nil ||
		zero.Year == nil || *zero.Year != 0 || zero.Status != nil {
		t.Fatal("raw diagnostics were defaulted")
	}
}

func TestResetAdminCredentialIsPrivateOperationBoundAndNeverAnApproval(t *testing.T) {
	plan, binding, _ := resetExecutionChainFixture(t, 2)
	now := time.Unix(plan.WindowOpensAtUnix+60, 0)
	directory := filepath.Join(t.TempDir(), "private")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("fixture directory")
	}
	path := filepath.Join(directory, plan.OperationID+".json")
	token := "header.payload.signature"
	credential := resetAdminCredential{Version: 1, ServerID: "pep", WorldID: 1, OperationID: plan.OperationID,
		TargetFingerprint: plan.TargetFingerprint, ApprovalPlanSHA: binding.Evidence.ApprovalPlanSHA, ExpiresAtUnix: now.Unix() + 60, AccessToken: token}
	write := func(test *testing.T, value resetAdminCredential) {
		test.Helper()
		wire, _ := json.Marshal(value)
		temporary := path + ".next"
		if os.WriteFile(temporary, wire, 0600) != nil || os.Chmod(temporary, 0400) != nil || os.Rename(temporary, path) != nil {
			test.Fatal("fixture file")
		}
	}
	write(t, credential)
	value, err := readResetAdminCredential(directory, binding, now, uint32(os.Getuid()))
	if err != nil || value != token {
		t.Fatal("private fixture credential refused")
	}
	cases := map[string]func(*resetAdminCredential){
		"other-world":      func(c *resetAdminCredential) { c.WorldID = 2 },
		"other-op":         func(c *resetAdminCredential) { c.OperationID = strings.Repeat("e", 32) },
		"other-target":     func(c *resetAdminCredential) { c.TargetFingerprint = strings.Repeat("e", 64) },
		"other-plan":       func(c *resetAdminCredential) { c.ApprovalPlanSHA = strings.Repeat("e", 64) },
		"expired":          func(c *resetAdminCredential) { c.ExpiresAtUnix = now.Unix() },
		"header-injection": func(c *resetAdminCredential) { c.AccessToken = token + "\r\nInjected:value" },
		"unknown-token":    func(c *resetAdminCredential) { c.AccessToken = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := credential
			change(&bad)
			write(t, bad)
			got, err := readResetAdminCredential(directory, binding, now, uint32(os.Getuid()))
			if err == nil || got != "" || strings.Contains(err.Error(), token) {
				t.Fatal("invalid credential accepted or disclosed")
			}
		})
	}
	write(t, credential)
	if os.Chmod(path, 0600) != nil {
		t.Fatal("fixture chmod")
	}
	if _, err := readResetAdminCredential(directory, binding, now, uint32(os.Getuid())); err == nil {
		t.Fatal("writable leaf accepted")
	}
}

func TestResetAdminCurrentReadsOnlyExactAuthorizedRouteAndRefusesFallback(t *testing.T) {
	for _, mode := range []string{"valid", "401", "403", "503", "redirect", "oversize", "bad-json"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/api/admin/reset-current" ||
					r.Header.Get("Authorization") != "Bearer header.payload.signature" || r.Header.Get("Cache-Control") != "no-store" {
					t.Error("wrong authorized request")
				}
				switch mode {
				case "401":
					w.WriteHeader(401)
				case "403":
					w.WriteHeader(403)
				case "503":
					w.WriteHeader(503)
				case "redirect":
					w.Header().Set("Location", "/api/front-info")
					w.WriteHeader(302)
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", 16*1024+1)))
				case "bad-json":
					_, _ = w.Write([]byte("{}"))
				default:
					_, _ = w.Write([]byte(resetAdminCurrentFixture))
				}
			}))
			defer server.Close()
			observed, err := getResetAdminCurrent(context.Background(), server.URL+"/api/admin/reset-current", "header.payload.signature")
			if mode == "valid" {
				if err != nil || observed.ObservedAt.IsZero() {
					t.Fatal("valid fixture refused")
				}
			} else if !errors.Is(err, errResetExecutionEvidence) {
				t.Fatal("failed source became successful")
			}
			if calls != 1 {
				t.Fatal("redirect, retry or alternate readiness reached")
			}
		})
	}
}

func TestResetAdminCurrentBoundsBodyCompletionByCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := getResetAdminCurrent(ctx, server.URL+"/api/admin/reset-current", "header.payload.signature"); err == nil ||
		time.Since(start) > time.Second {
		t.Fatal("incomplete body escaped caller deadline")
	}
}
