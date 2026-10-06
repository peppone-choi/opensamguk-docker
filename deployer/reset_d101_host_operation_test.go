package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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
