package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHostOperationMissingNativeInputsNeverStartsSupplier(t *testing.T) {
	calls := 0
	supplier := func(context.Context, *os.File, string) (*resetD101HostOperationInstallation, error) {
		calls++
		return nil, nil
	}
	if status := runResetD101HostOperation(context.Background(), nil, strings.Repeat("a", 32), supplier); status != 2 || calls != 0 {
		t.Fatal("missing host FD9 reached installed supplier or admission")
	}
	if status := runResetD101HostOperation(nil, nil, strings.Repeat("a", 32), supplier); status != 2 || calls != 0 {
		t.Fatal("missing context reached operation")
	}
}

func TestHostOperationStorePreservesUnknownAndPreviousOperation(t *testing.T) {
	op := strings.Repeat("a", 32)
	for _, name := range []string{"empty", "same-op-terminal", "other-op-pending", "deferred-transition", "other-op-terminal"} {
		t.Run(name, func(t *testing.T) {
			store := &durableOperationStore{operations: map[string]durableOperationRecord{}, deferredTransitions: map[string]durableOperationRecord{}}
			switch name {
			case "same-op-terminal":
				store.operations[op] = durableOperationRecord{OperationID: op, Status: lifecycleJobSucceeded}
			case "other-op-pending":
				store.operations["other"] = durableOperationRecord{Status: lifecycleJobPending}
			case "deferred-transition":
				store.deferredTransitions[op] = durableOperationRecord{Status: lifecycleJobRunning}
			case "other-op-terminal":
				store.operations["other"] = durableOperationRecord{Status: lifecycleJobSucceeded}
			}
			beforeOperations, beforeDeferred := len(store.operations), len(store.deferredTransitions)
			want := name != "empty" && name != "other-op-terminal"
			if resetD101HostStoreRequiresHold(store, op) != want || len(store.operations) != beforeOperations || len(store.deferredTransitions) != beforeDeferred {
				t.Fatal("unknown/staged state was recovered, overwritten or readmitted")
			}
		})
	}
}

func TestHostOperationSelectorDoesNotAdoptAuthorityOrIssuerInput(t *testing.T) {
	for _, args := range [][]string{{"deployer", "--d101-host-operation"}, {"deployer", "--d101-host-operation", "--operation-id", "not-an-operation"}, {"deployer", "--d101-host-operation", "--operation-id", strings.Repeat("a", 32), "caller-policy"}, {"deployer", "--d101-host-operation", "--operation-id", strings.Repeat("a", 32)}} {
		var output, errOutput bytes.Buffer
		handled, status := earlyResetD101HostCommand(args, func(string) string { return "" }, &output, &errOutput)
		if !handled || status != 2 || output.Len() != 0 {
			t.Fatal("selector/argv acquired runtime authority without native source")
		}
	}
	var output, errOutput bytes.Buffer
	if handled, status := earlyResetD101HostCommand([]string{"deployer", "--d101-issue-current-receipt"}, nil, &output, &errOutput); !handled || status != 2 || output.Len() != 0 {
		t.Fatal("malformed issuer-only request fell through to ordinary/full operation")
	}
}

func TestHostPreparedSessionRejectsAmbiguousAuthAndCanonicalRedirect(t *testing.T) {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	path := "/operations/" + op + "/prepared-proof/" + sha + "/" + sha
	for _, name := range []string{"duplicate-auth", "missing-auth", "duplicate-slash", "dot-segment", "encoded-path", "chunked-body"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			handler := resetD101HostSessionHandler("synthetic-transport-token", func(context.Context, string, string, string) ([]byte, string, error) {
				calls++
				return nil, "", errResetExecutionEvidence
			})
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer synthetic-transport-token")
			switch name {
			case "duplicate-auth":
				request.Header.Add("Authorization", "Bearer synthetic-transport-token")
			case "missing-auth":
				request.Header.Del("Authorization")
			case "duplicate-slash":
				request.URL.Path = "/operations//" + op + "/prepared-proof/" + sha + "/" + sha
			case "dot-segment":
				request.URL.Path = "/operations/../" + op + "/prepared-proof/" + sha + "/" + sha
			case "encoded-path":
				request.URL.RawPath = "/operations/%61" + op[1:] + "/prepared-proof/" + sha + "/" + sha
			case "chunked-body":
				request.TransferEncoding = []string{"chunked"}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if calls != 0 || response.Code < 400 || response.Header().Get("Location") != "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("ambiguous request reached getter, redirected or allowed caching")
			}
		})
	}
}

func TestHostIssuerMissingInputsNeverWritesReadyOrStartsSupplier(t *testing.T) {
	calls := 0
	supplier := func(context.Context, *os.File, string) (*resetD101HostIssuerInstallation, error) {
		calls++
		return nil, nil
	}
	for _, name := range []string{"nil-context", "nil-fd", "nil-supplier", "bad-selector"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			op := strings.Repeat("a", 32)
			supplied := supplier
			if name == "nil-context" {
				ctx = nil
			}
			if name == "nil-supplier" {
				supplied = nil
			}
			if name == "bad-selector" {
				op = "caller"
			}
			if runResetD101HostIssuer(ctx, nil, op, nil, nil, supplied) != 2 || calls != 0 {
				t.Fatal("issuer reached supplier or READY without native preconditions")
			}
		})
	}
}

func TestHostIssuerJWTDeadlineAndExactEOF(t *testing.T) {
	for _, name := range []string{"exact-eof", "empty", "trailing-lf", "two-tokens", "oversize", "old-ready-chunk", "missing-eof", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			wire := []byte("header.payload.signature")
			switch name {
			case "empty":
				wire = nil
			case "trailing-lf":
				wire = append(wire, '\n')
			case "two-tokens":
				wire = append(wire, append([]byte(" "), wire...)...)
			case "oversize":
				wire = bytes.Repeat([]byte{'a'}, (64<<10)+1)
			case "old-ready-chunk":
				start = start.Add(-2 * time.Second)
			case "cancelled":
				cancel()
			case "missing-eof":
				start = start.Add(-1900 * time.Millisecond)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = write.Write(wire)
				if name != "missing-eof" {
					_ = write.Close()
				}
			}()
			got, err := readResetD101IssuerJWT(ctx, read, start)
			_ = read.Close()
			_ = write.Close()
			<-done
			if name == "exact-eof" {
				if err != nil || !bytes.Equal(got, wire) {
					t.Fatal("exact pipe bytes plus EOF were changed")
				}
			} else if err == nil || got != nil {
				t.Fatal("invalid/late JWT input was accepted or deadline renewed")
			}
		})
	}
}

func TestHostIssuerTransportRequiresAnonymousPipe(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	wantPipe := runtime.GOOS == "linux"
	if resetD101AnonymousPipe(read) != wantPipe || resetD101AnonymousPipe(write) != wantPipe || resetD101AnonymousPipe(regular) || resetD101AnonymousPipe(nil) {
		t.Fatal("private pipe transport accepted ordinary file or rejected pipe")
	}
}

func TestHostCaptureWitnessUnavailableDoesNotInventNativeAuthority(t *testing.T) {
	var supplier *resetD101CurrentHostSupplier
	if _, witness, err := supplier.captureAuthenticatedWitness(context.Background(), resetExecutionPhaseBinding{}, time.Now()); err == nil || witness != nil {
		t.Fatal("missing native supplier returned witness")
	}
	if err := (*resetD101AuthenticatedCaptureWitness)(nil).recheckNative(); err == nil {
		t.Fatal("missing capture witness accepted")
	}
}

func TestPreparedNativeCustodyTupleDigestFramesBodyAndHeader(t *testing.T) {
	if resetD101SignedResponseTupleSHA([]byte("ab"), []byte("c")) == resetD101SignedResponseTupleSHA([]byte("a"), []byte("bc")) {
		t.Fatal("tuple boundaries were lost")
	}
	if resetD101SignedResponseTupleSHA([]byte("body"), []byte("proof")) != resetD101SignedResponseTupleSHA([]byte("body"), []byte("proof")) {
		t.Fatal("same immutable response cannot have different tuple digests")
	}
}

func TestPreparedNativeCustodyMissingInputsNeverRegistersOrRetains(t *testing.T) {
	if custody, err := newResetD101HostPreparedCustody(resetD101HostPreparedCustodyPins{}); err == nil || custody != nil {
		t.Fatal("unsupplied audit custody registered")
	}
	var custody *resetD101HostPreparedCustody
	if _, err := custody.retain(context.Background(), nil, resetExecutionPhaseBinding{}, time.Time{}, time.Time{}, nil, nil, ""); err == nil {
		t.Fatal("missing authority retained a successful response")
	}
}

func TestPreparedNativeTwoStepRetentionBindsOriginalDescriptors(t *testing.T) {
	for _, name := range []string{"success", "body-existing", "record-existing", "commit-existing", "cancelled", "record-replaced", "commit-replaced", "directory-replaced", "expired-original"} {
		t.Run(name, func(t *testing.T) {
			// Isolated temporary UID fixture only, never native host authority.
			root := t.TempDir()
			path := filepath.Join(root, "private")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			op, nonce := strings.Repeat("a", 32), strings.Repeat("b", 32)
			stem := "get-" + op + "-" + nonce
			body, header := []byte("synthetic exact response"), []byte("synthetic-key.synthetic-proof")
			record := resetD101PreparedPrivateRecord{Version: 1, OperationID: op, CaptureNonce: nonce, RequestSequence: 1,
				ResponseBodyWholeSHA: resetD101OriginalSHA(body), ResponseProofHeaderWholeSHA: resetD101OriginalSHA(header), SignedResponseWholeSHA: resetD101SignedResponseTupleSHA(body, header)}
			if strings.HasSuffix(name, "-existing") {
				suffix := strings.TrimSuffix(name, "-existing")
				if err := os.WriteFile(filepath.Join(path, stem+"."+suffix), []byte("preserved original"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if name == "cancelled" {
				cancel()
			}
			started := time.Now()
			receipt, err := retainResetD101PreparedNativeRecord(ctx, dir, stem, record, body, header, uint32(os.Geteuid()))
			if name == "cancelled" || strings.HasSuffix(name, "-existing") {
				if err == nil || receipt != nil {
					t.Fatal("uncertain or existing originals accepted")
				}
				if name != "cancelled" {
					wire, err := os.ReadFile(filepath.Join(path, stem+"."+strings.TrimSuffix(name, "-existing")))
					if err != nil || string(wire) != "preserved original" {
						t.Fatal("existing original changed")
					}
				}
				return
			}
			if err != nil || receipt == nil {
				t.Fatal("two step retention", err)
			}
			defer receipt.close()
			var commit resetD101PreparedPrivateCommit
			if json.Unmarshal(receipt.commitWire, &commit) != nil || commit.CommittedRecordWholeSHA != resetD101OriginalSHA(receipt.recordWire) {
				t.Fatal("record link")
			}
			observed, err := resetC4UTC(commit.RecordCommittedAtUTC)
			if err != nil || observed.Before(started) || time.Now().Before(observed) {
				t.Fatal("actual post-record observation")
			}
			var recordKeys map[string]json.RawMessage
			if json.Unmarshal(receipt.recordWire, &recordKeys) != nil || recordKeys["recordCommittedAtUTC"] != nil {
				t.Fatal("record claimed its own future completion")
			}
			if name == "expired-original" {
				receipt.validUntil = started.Add(-time.Nanosecond)
				if receipt.recheck(ctx) == nil {
					t.Fatal("original cutoff extended")
				}
				return
			}
			if strings.HasSuffix(name, "-replaced") {
				if name == "directory-replaced" {
					if err := os.Rename(path, path+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					suffix := strings.TrimSuffix(name, "-replaced")
					file := filepath.Join(path, stem+"."+suffix)
					wire, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(file, file+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(file, wire, 0400); err != nil {
						t.Fatal(err)
					}
				}
				if receipt.recheck(ctx) == nil {
					t.Fatal("same-byte native replacement accepted")
				}
			} else if receipt.recheck(ctx) != nil {
				t.Fatal("unchanged original descriptors rejected")
			}
		})
	}
}

func TestNative9PhysicalStageFactDoesNotDependOnReleaseCompletion(t *testing.T) {
	c := native9RootDataFixture(t)
	op := strings.Repeat("a", 32)
	job := strings.Repeat("b", 32)
	body := json.RawMessage(`{"stage":"physical-result","success":true}`)
	c.lifecycleJobs.jobs[job] = lifecycleJob{id: job, operationID: op, status: lifecycleJobSucceeded, httpStatus: 200, result: body}
	c.lifecycleJobs.operationJobs[op] = job
	response, ok := c.lifecycleJobs.lookupOperation(op)
	if !ok || response.Status != lifecycleJobSucceeded || response.HTTPStatus != 200 {
		t.Fatal("physical stage success became release dependent")
	}
	v := &resetD101NativeAuthorityInstaller{operationID: op}
	if _, err := v.overallCompletion(context.Background()); err == nil {
		t.Fatal("physical stage result forged overall completion")
	}
	if c.lifecycleJobs.jobs[job].status != lifecycleJobSucceeded || !bytes.Equal(c.lifecycleJobs.jobs[job].result, body) {
		t.Fatal("completion HOLD overwrote physical fact")
	}
}
