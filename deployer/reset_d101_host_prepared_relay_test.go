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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type resetD101RelayFixtureTransport func(*http.Request) (*http.Response, error)

func (f resetD101RelayFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
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
		authenticate: func(context.Context, string, string, string) error { return nil }}
	relay, err := newResetD101HostPreparedRelay(policy, "synthetic-transport-token")
	if err != nil {
		t.Fatal(err)
	}
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
	relay.policy.authenticate = func(context.Context, string, string, string) error { authCalls++; return nil }
	relay.client.Transport = resetD101RelayFixtureTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		want := "http://d101-host/operations/" + relay.policy.expected.OperationID + "/prepared-proof/" + relay.policy.expected.ApprovalPlanSHA + "/" + relay.policy.expected.ExecutionReceiptSHA
		if request.Method != "GET" || request.URL.String() != want || request.Header.Get("Authorization") != "Bearer synthetic-transport-token" {
			t.Fatal("relay changed exact request")
		}
		return resetD101RelayFixtureResponse(wire, header), nil
	})
	got, signature, err := relay.Read(context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA)
	if err != nil || !bytes.Equal(got, wire) || signature != header || requests != 1 || authCalls != 2 {
		t.Fatal("relay did not preserve original or verify current live authority twice")
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
				relay.policy.authenticate = func(context.Context, string, string, string) error {
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
			got, signature, err := relay.Read(context.Background(), relay.policy.expected.OperationID, relay.policy.expected.ApprovalPlanSHA, relay.policy.expected.ExecutionReceiptSHA)
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
