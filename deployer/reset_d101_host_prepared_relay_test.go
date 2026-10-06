package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resetD101RelayFixtureTransport func(*http.Request) (*http.Response, error)

func (f resetD101RelayFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHostRelayAdmissionLatchDoesNotLearnRejectedCandidate(t *testing.T) {
	for _, name := range []string{"bad-signature", "auth-after-denied", "future", "noncanonical", "static-pin-mismatch"} {
		t.Run(name, func(t *testing.T) {
			relay, wire, header, private := newResetD101RelayFixture(t)
			relay.policy.expected.AcceptedAtUTC = ""
			proof, err := decodeResetD101PreparedProof(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "bad-signature":
				header = "synthetic-root." + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "auth-after-denied":
				calls := 0
				relay.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error {
					calls++
					if calls == 2 {
						return errResetExecutionEvidence
					}
					return nil
				}
			case "future":
				proof.AcceptedAtUTC = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
			case "noncanonical":
				proof.AcceptedAtUTC = time.Now().Add(-time.Second).UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z")
			case "static-pin-mismatch":
				proof.TargetFingerprint = strings.Repeat("f", 64)
			}
			if name != "bad-signature" {
				wire, err = json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				header = "synthetic-root." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(resetD101PreparedDomain), wire...)))
			}
			relay.client.Transport = resetD101RelayFixtureTransport(func(*http.Request) (*http.Response, error) { return resetD101RelayFixtureResponse(wire, header), nil })
			if body, _, err := readResetD101RelayFixture(relay, context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA); err == nil || body != nil || relay.acceptedAtUTC != "" {
				t.Fatal("rejected candidate changed first admission latch")
			}
		})
	}
}

func TestHostRelayAdmissionLatchUsesSingleCASUnderConcurrentSlots(t *testing.T) {
	for _, name := range []string{"same-admission", "changed-admission", "concurrent-change"} {
		t.Run(name, func(t *testing.T) {
			relay, first, firstHeader, private := newResetD101RelayFixture(t)
			relay.policy.expected.AcceptedAtUTC = ""
			proof, err := decodeResetD101PreparedProof(first)
			if err != nil {
				t.Fatal(err)
			}
			accepted, _ := resetC4UTC(proof.AcceptedAtUTC)
			proof.AcceptedAtUTC = accepted.Add(-time.Nanosecond).Format(time.RFC3339Nano)
			second, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			secondHeader := "synthetic-root." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(resetD101PreparedDomain), second...)))
			if name == "same-admission" {
				second, secondHeader = first, firstHeader
			}
			var requests atomic.Int32
			barrier := make(chan struct{})
			ready := make(chan struct{}, 2)
			relay.client.Transport = resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
				n := requests.Add(1)
				if name == "concurrent-change" {
					ready <- struct{}{}
					select {
					case <-barrier:
					case <-request.Context().Done():
						return nil, request.Context().Err()
					}
				}
				if n == 1 {
					return resetD101RelayFixtureResponse(first, firstHeader), nil
				}
				return resetD101RelayFixtureResponse(second, secondHeader), nil
			})
			read := func() error {
				_, _, err := readResetD101RelayFixture(relay, context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA)
				return err
			}
			if name == "concurrent-change" {
				results := make(chan error, 2)
				go func() { results <- read() }()
				go func() { results <- read() }()
				for i := 0; i < 2; i++ {
					select {
					case <-ready:
					case <-time.After(2 * time.Second):
						close(barrier)
						t.Fatal("concurrent readers did not reach transport")
					}
				}
				close(barrier)
				one, two := <-results, <-results
				if (one == nil) == (two == nil) || relay.acceptedAtUTC == "" {
					t.Fatal("concurrent admissions both accepted or neither latched")
				}
			} else {
				if read() != nil {
					t.Fatal("first authenticated admission")
				}
				secondErr := read()
				if (secondErr == nil) != (name == "same-admission") {
					t.Fatal("changed admission was adopted or same admission rejected")
				}
			}
		})
	}
}

func newResetD101RelayFixture(t *testing.T) (*resetD101HostPreparedRelay, []byte, string, ed25519.PrivateKey) {
	t.Helper()
	// Synthetic deterministic test key only; never an installed issuer/purpose key.
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hash := strings.Repeat("b", 64)
	images := map[string]string{}
	for _, service := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
		images[service] = "sha256:" + hash
	}
	proof := resetD101PreparedProof{SchemaVersion: 1, ServerID: "pep", WorldID: 1, OperationID: strings.Repeat("a", 32), Phase: "prepared",
		ApprovalIntentSHA: hash, ApprovalPlanSHA: hash, ExecutionReceiptSHA: hash, TargetFingerprint: hash, RootRequestFingerprint: hash,
		GatewayPayloadSHA: hash, InitialPublicRevision: "1", VerifyingRevision: "2", AppSourceSHA: strings.Repeat("c", 40), ImageDigests: images,
		AcceptedAtUTC: now.Add(-time.Second).Format(time.RFC3339Nano), PreparedAtUTC: now.Add(-time.Millisecond).Format(time.RFC3339Nano), PreparedJournalSHA: hash,
		DestructiveCutoffUnix: now.Unix() + 30, RecoveryDeadlineUnix: now.Unix() + 60}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	header := "synthetic-root." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(resetD101PreparedDomain), wire...)))
	policy := &resetD101HostRelayInstallation{expected: proof, keyID: "synthetic-root", publicSPKI: spki, publicSPKISHA: resetD101OriginalSHA(spki),
		authenticate: func(context.Context, string, string, string, resetD101RelayPeerObservation) error { return nil }}
	relay, err := newResetD101HostPreparedRelay(policy, "synthetic-transport-token")
	if err != nil {
		t.Fatal(err)
	}
	relay.client = &http.Client{}
	return relay, wire, header, private
}

func resetD101RelayFixtureResponse(wire []byte, header string) *http.Response {
	return &http.Response{StatusCode: 200, ContentLength: int64(len(wire)), Body: io.NopCloser(bytes.NewReader(wire)), Header: http.Header{
		"Cache-Control": []string{"no-store"}, "Content-Type": []string{"application/json"},
		"X-D101-Prepared-Proof": []string{header}, "X-D101-Prepared-Sha256": []string{resetD101OriginalSHA(wire)},
	}}
}

func TestHostPreparedRelayPreservesOriginalAndChecksLiveTwice(t *testing.T) {
	relay, wire, header, _ := newResetD101RelayFixture(t)
	authCalls, requests := 0, 0
	relay.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error {
		authCalls++
		return nil
	}
	relay.client.Transport = resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		want := "http://d101-host/operations/" + relay.policy.expected.OperationID + "/prepared-proof/" + relay.policy.expected.ApprovalPlanSHA + "/" + relay.policy.expected.ExecutionReceiptSHA
		if request.Method != "GET" || request.URL.String() != want || request.Header.Get("Authorization") != "Bearer synthetic-transport-token" {
			t.Fatal("relay changed exact request")
		}
		return resetD101RelayFixtureResponse(wire, header), nil
	})
	got, signature, err := readResetD101RelayFixture(relay, context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA)
	if err != nil || !bytes.Equal(got, wire) || signature != header || requests != 1 || authCalls != 4 {
		t.Fatal("relay did not preserve original or verify live authority before wire and under CAS")
	}
}

func TestHostPreparedRelayRejectsSignedStaleOrUnboundResponse(t *testing.T) {
	for _, name := range []string{"wrong-op", "wrong-plan", "wrong-receipt", "wrong-target", "wrong-source", "wrong-cutoff", "stale", "future", "wrong-domain", "wrong-key-id", "extra-field", "duplicate-sha", "cache", "redirect", "host-error", "nil-authenticator", "lost-live-authority"} {
		t.Run(name, func(t *testing.T) {
			relay, wire, header, private := newResetD101RelayFixture(t)
			proof := relay.policy.expected
			mutated := true
			switch name {
			case "wrong-op":
				proof.OperationID = strings.Repeat("d", 32)
			case "wrong-plan":
				proof.ApprovalPlanSHA = strings.Repeat("d", 64)
			case "wrong-receipt":
				proof.ExecutionReceiptSHA = strings.Repeat("d", 64)
			case "wrong-target":
				proof.TargetFingerprint = strings.Repeat("d", 64)
			case "wrong-source":
				proof.AppSourceSHA = strings.Repeat("d", 40)
			case "wrong-cutoff":
				proof.DestructiveCutoffUnix--
			case "stale":
				proof.AcceptedAtUTC = time.Now().Add(-40 * time.Second).UTC().Format(time.RFC3339Nano)
				proof.PreparedAtUTC = time.Now().Add(-31 * time.Second).UTC().Format(time.RFC3339Nano)
				relay.policy.expected.AcceptedAtUTC = proof.AcceptedAtUTC
			case "future":
				proof.PreparedAtUTC = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
			default:
				mutated = false
			}
			if mutated {
				var err error
				wire, err = json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				header = "synthetic-root." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(resetD101PreparedDomain), wire...)))
			}
			switch name {
			case "wrong-domain":
				header = "synthetic-root." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(resetD101HostTrustDomain), wire...)))
			case "wrong-key-id":
				header = strings.Replace(header, "synthetic-root.", "other-root.", 1)
			case "extra-field":
				wire = append(wire[:len(wire)-1], []byte(",\"collectorStarted\":1}")...)
			case "nil-authenticator":
				relay.policy.authenticate = nil
			case "lost-live-authority":
				calls := 0
				relay.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error {
					calls++
					if calls > 1 {
						return errors.New("keeper/lease lost")
					}
					return nil
				}
			}
			relay.client.Transport = resetD101RelayFixtureTransport(func(*http.Request) (*http.Response, error) {
				r := resetD101RelayFixtureResponse(wire, header)
				switch name {
				case "duplicate-sha":
					r.Header.Add("X-D101-Prepared-Sha256", resetD101OriginalSHA(wire))
				case "cache":
					r.Header.Set("Cache-Control", "public")
				case "redirect":
					r.StatusCode = 302
				case "host-error":
					return nil, errors.New("host unavailable")
				}
				return r, nil
			})
			got, signature, err := readResetD101RelayFixture(relay, context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA)
			if err == nil || len(got) != 0 || signature != "" {
				t.Fatal("unbound/stale/non-live response acquired relay authority")
			}
		})
	}
}

func TestHostPreparedRelayModeHasNoOrdinaryWriterOrFallback(t *testing.T) {
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	for _, path := range []string{"/operations/" + op + "/prepared-proof/" + sha + "/" + sha, "/deploy", "/maintenance", "/servers/create", "/healthz"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer synthetic-transport-token")
			response := httptest.NewRecorder()
			resetD101PreparedRelayHandler("synthetic-transport-token", nil).ServeHTTP(response, request)
			if response.Code != 503 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing relay source reached ordinary mode/fallback")
			}
		})
	}
}

// Isolated wire/latch fixtures use a synthetic native witness explicitly. The
// production Read entry always captures Linux actual connected descriptor data.
func readResetD101RelayFixture(r *resetD101HostPreparedRelay, ctx context.Context, op, plan, receipt string) ([]byte, string, error) {
	return r.readWithCallTransport(ctx, op, plan, receipt, func(call *resetD101RelayCall) http.RoundTripper {
		call.witness = &resetD101RelayPeerWitness{}
		call.checkNative = func(ctx context.Context) error { return ctx.Err() }
		return resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
			if call.authenticate(r.policy, op, plan, receipt) != nil {
				return nil, errResetExecutionEvidence
			}
			return r.client.Transport.RoundTrip(request)
		})
	})
}

func TestHostRelayCallRetainsOwnHandlesThroughEOFAndFinalAuthentication(t *testing.T) {
	r, wire, header, _ := newResetD101RelayFixture(t)
	file, err := os.CreateTemp(t.TempDir(), "held-witness-")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	checks := 0
	auth := 0
	eof := false
	closedBody := false
	r.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error {
		auth++
		if _, err := file.Stat(); err != nil {
			t.Error("witness closed before authentication")
		}
		return nil
	}
	body := &resetD101RelayEOFBody{Reader: bytes.NewReader(wire), onEOF: func() { eof = true }, onClose: func() {
		closedBody = true
		if _, err := file.Stat(); err != nil {
			t.Error("closed before body cleanup")
		}
	}}
	got, signature, err := r.readWithCallTransport(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
		call.conn = left
		call.witness = &resetD101RelayPeerWitness{socket: file}
		call.checkNative = func(ctx context.Context) error {
			checks++
			_, err := file.Stat()
			if err != nil {
				return err
			}
			return ctx.Err()
		}
		return resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
			if call.authenticate(r.policy, call.op, call.plan, call.receipt) != nil {
				return nil, errResetExecutionEvidence
			}
			response := resetD101RelayFixtureResponse(wire, header)
			response.Body = body
			return response, nil
		})
	})
	if err != nil || !bytes.Equal(got, wire) || signature != header || !eof || !closedBody || auth != 4 || checks < 6 {
		t.Fatal("call did not retain EOF/final witness", err, checks, auth)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("owner did not close own witness")
	}
}

type resetD101RelayEOFBody struct {
	io.Reader
	onEOF, onClose func()
}

func (b *resetD101RelayEOFBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.onEOF != nil {
		b.onEOF()
	}
	return n, err
}
func (b *resetD101RelayEOFBody) Close() error {
	if b.onClose != nil {
		b.onClose()
	}
	return nil
}

func TestHostRelayNativeLossCannotCommitAdmissionCAS(t *testing.T) {
	for _, phase := range []string{"before-cas", "after-cas", "cancel", "partial"} {
		t.Run(phase, func(t *testing.T) {
			r, wire, header, _ := newResetD101RelayFixture(t)
			r.policy.expected.AcceptedAtUTC = ""
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			got, signature, err := r.readWithCallTransport(ctx, r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
				call.witness = &resetD101RelayPeerWitness{}
				call.checkNative = func(ctx context.Context) error {
					checks++
					if phase == "before-cas" && checks == 6 || phase == "after-cas" && checks == 8 {
						return errResetExecutionEvidence
					}
					return ctx.Err()
				}
				return resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
					if call.authenticate(r.policy, call.op, call.plan, call.receipt) != nil {
						return nil, errResetExecutionEvidence
					}
					if phase == "cancel" {
						cancel()
					}
					if phase == "partial" {
						return nil, io.ErrUnexpectedEOF
					}
					return resetD101RelayFixtureResponse(wire, header), nil
				})
			})
			if err == nil || got != nil || signature != "" || r.acceptedAtUTC != "" {
				t.Fatal("failed call changed first admission")
			}
		})
	}
}
func TestHostRelaySlotsUseIndependentWitnessesAndCloseOnlyOwnCall(t *testing.T) {
	r, wire, header, _ := newResetD101RelayFixture(t)
	ready := make(chan *resetD101RelayCall, 2)
	release := make(chan struct{})
	done := make(chan error, 2)
	var mu sync.Mutex
	calls := map[*resetD101RelayCall]*os.File{}
	read := func() {
		_, _, err := r.readWithCallTransport(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
			f, err := os.CreateTemp(t.TempDir(), "slot-")
			if err != nil {
				t.Error(err)
				return nil
			}
			call.witness = &resetD101RelayPeerWitness{socket: f}
			call.checkNative = func(ctx context.Context) error {
				_, err := f.Stat()
				if err != nil {
					return err
				}
				return ctx.Err()
			}
			mu.Lock()
			calls[call] = f
			mu.Unlock()
			return resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
				if call.authenticate(r.policy, call.op, call.plan, call.receipt) != nil {
					return nil, errResetExecutionEvidence
				}
				ready <- call
				select {
				case <-release:
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
				return resetD101RelayFixtureResponse(wire, header), nil
			})
		})
		done <- err
	}
	go read()
	go read()
	var one, two *resetD101RelayCall
	select {
	case one = <-ready:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first slot")
	}
	select {
	case two = <-ready:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("second slot")
	}
	if one == two || one.witness == two.witness || one.witness.socket == two.witness.socket {
		close(release)
		t.Fatal("shared slot witness")
	}
	if got, _, err := r.Read(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA); err == nil || got != nil {
		close(release)
		t.Fatal("third slot admitted")
	}
	close(release)
	if <-done != nil || <-done != nil {
		t.Fatal("independent slots failed")
	}
	for _, file := range calls {
		if _, err := file.Stat(); err == nil {
			t.Fatal("call witness leaked")
		}
	}
}
func TestHostRelayTransportCloseRetainsDialDescriptorUntilOwnerRelease(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	call := &resetD101RelayCall{conn: left}
	wrapped := &resetD101RelayHeldConn{left}
	if wrapped.Close() != nil {
		t.Fatal("close deadline")
	}
	// Clearing the deadline proves transport Close did not close the connection.
	if left.SetDeadline(time.Time{}) != nil {
		t.Fatal("transport closed actual dial FD")
	}
	call.close()
	if left.SetDeadline(time.Time{}) == nil {
		t.Fatal("owner did not close dial connection")
	}
}
func TestHostRelayMissingNativeWitnessOrProcessIdentityDenies(t *testing.T) {
	r, wire, header, _ := newResetD101RelayFixture(t)
	got, _, err := r.readWithCallTransport(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
		return resetD101RelayFixtureTransport(func(*http.Request) (*http.Response, error) { return resetD101RelayFixtureResponse(wire, header), nil })
	})
	if err == nil || got != nil || r.acceptedAtUTC != "" {
		t.Fatal("absent native witness accepted")
	}
	if _, _, err := resetD101RelayReadProcess(nil, 123); err == nil {
		t.Fatal("missing process FD")
	}
	if _, err := resetD101RelayPeerCredentials(nil); err == nil {
		t.Fatal("missing connected FD")
	}
}

func TestHostRelayTransportRejectsRedialAndAlternateDestination(t *testing.T) {
	for _, mode := range []string{"redial", "closed", "alternate"} {
		t.Run(mode, func(t *testing.T) {
			call := &resetD101RelayCall{ctx: context.Background()}
			address := "d101-host:80"
			switch mode {
			case "redial":
				call.dialed = true
			case "closed":
				call.closed = true
			case "alternate":
				address = "other-host:80"
			}
			conn, err := call.transport().DialContext(context.Background(), "tcp", address)
			if conn != nil || err == nil || call.conn != nil || call.witness != nil {
				t.Fatal("alternate dial acquired witness")
			}
		})
	}
}

func TestHostRelayCASRechecksIndependentAuthorityAfterWaiting(t *testing.T) {
	for _, phase := range []string{"before-write", "after-write"} {
		t.Run(phase, func(t *testing.T) {
			r, wire, header, _ := newResetD101RelayFixture(t)
			r.policy.expected.AcceptedAtUTC = ""
			beforeCAS := make(chan struct{})
			var calls atomic.Int32
			var denied atomic.Bool
			r.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error {
				n := calls.Add(1)
				if n == 2 {
					close(beforeCAS)
				}
				if denied.Load() && (phase == "before-write" && n == 3 || phase == "after-write" && n == 4) {
					return errResetExecutionEvidence
				}
				return nil
			}
			r.admissionMu.Lock()
			locked := true
			defer func() {
				if locked {
					r.admissionMu.Unlock()
				}
			}()
			result := make(chan bool, 1)
			go func() {
				body, signature, err := r.readWithCallTransport(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
					call.witness = &resetD101RelayPeerWitness{}
					call.checkNative = func(ctx context.Context) error { return ctx.Err() }
					return resetD101RelayFixtureTransport(func(*http.Request) (*http.Response, error) {
						if call.authenticate(r.policy, call.op, call.plan, call.receipt) != nil {
							return nil, errResetExecutionEvidence
						}
						return resetD101RelayFixtureResponse(wire, header), nil
					})
				})
				result <- err != nil && body == nil && signature == ""
			}()
			select {
			case <-beforeCAS:
			case <-time.After(time.Second):
				t.Fatal("reader did not reach held CAS mutex")
			}
			denied.Store(true)
			r.admissionMu.Unlock()
			locked = false
			select {
			case rejected := <-result:
				if !rejected || r.acceptedAtUTC != "" {
					t.Fatal("native-stable denied authority committed admission")
				}
			case <-time.After(time.Second):
				t.Fatal("CAS reader stuck")
			}
		})
	}
}
func TestHostRelayCASRechecksOriginalCutoffAfterWaiting(t *testing.T) {
	r, wire, header, _ := newResetD101RelayFixture(t)
	r.policy.expected.AcceptedAtUTC = ""
	proof, err := decodeResetD101PreparedProof(wire)
	if err != nil {
		t.Fatal(err)
	}
	originalNow := time.Now()
	beforeCAS := make(chan struct{})
	var bindingCalls atomic.Int32
	var elapsed atomic.Bool
	r.policy.authenticate = func(context.Context, string, string, string, resetD101RelayPeerObservation) error { return nil }
	r.admissionMu.Lock()
	locked := true
	defer func() {
		if locked {
			r.admissionMu.Unlock()
		}
	}()
	result := make(chan bool, 1)
	go func() {
		body, signature, err := r.readWithCallTransportClock(context.Background(), r.policy.expected.OperationID, r.policy.expected.ApprovalPlanSHA, r.policy.expected.ExecutionReceiptSHA, func(call *resetD101RelayCall) http.RoundTripper {
			call.witness = &resetD101RelayPeerWitness{}
			call.checkNative = func(ctx context.Context) error { return ctx.Err() }
			return resetD101RelayFixtureTransport(func(*http.Request) (*http.Response, error) {
				if call.authenticate(r.policy, call.op, call.plan, call.receipt) != nil {
					return nil, errResetExecutionEvidence
				}
				return resetD101RelayFixtureResponse(wire, header), nil
			})
		}, func() time.Time {
			// Freeze the second outer binding's valid timestamp BEFORE notifying
			// the thread holding admissionMu. Only the following in-mutex
			// binding can observe the deliberately advanced cutoff clock.
			n := bindingCalls.Add(1)
			if n == 2 {
				close(beforeCAS)
				return originalNow
			}
			if elapsed.Load() {
				return time.Unix(proof.DestructiveCutoffUnix, 0)
			}
			return originalNow
		})
		result <- err != nil && body == nil && signature == ""
	}()
	select {
	case <-beforeCAS:
	case <-time.After(time.Second):
		t.Fatal("reader did not reach CAS boundary")
	}
	elapsed.Store(true)
	r.admissionMu.Unlock()
	locked = false
	select {
	case rejected := <-result:
		if !rejected || r.acceptedAtUTC != "" {
			t.Fatal("expired proof committed admission")
		}
	case <-time.After(time.Second):
		t.Fatal("CAS reader stuck")
	}
}
