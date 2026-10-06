package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

const resetD101HostSessionSocket = "/etc/opensamguk/d101/host-session.sock"
const resetD101PreparedDomain = "OPENSAMGUK-D101-PREPARED-V1\n"

// Independent installed public verification and live authority only. No key is
// learned from the socket response; private signing keys never enter relay mode.
// Socket/UID/PID/inode facts are transport observations, not this authenticator.
type resetD101LiveSessionAuthenticator func(context.Context, string, string, string) error
type resetD101HostRelayInstallation struct {
	expected      resetD101PreparedProof
	keyID         string
	publicSPKI    []byte
	publicSPKISHA string
	authenticate  resetD101LiveSessionAuthenticator
}

var resetD101ReviewedHostRelay *resetD101HostRelayInstallation

type resetD101HostPreparedRelay struct {
	policy        resetD101HostRelayInstallation
	publicKey     ed25519.PublicKey
	credential    string
	client        *http.Client
	slots         chan struct{}
	admissionMu   sync.Mutex
	acceptedAtUTC string
}

func newResetD101HostPreparedRelay(p *resetD101HostRelayInstallation, credential string) (*resetD101HostPreparedRelay, error) {
	if p == nil || p.authenticate == nil || !validResetD101ServiceToken(credential) || !resetD101KeyID.MatchString(p.keyID) {
		return nil, errResetD101InstallationNotSupplied
	}
	key, err := resetD101PinnedPublicKey(p.publicSPKI, p.publicSPKISHA)
	if err != nil || !lifecycleJobIDRe.MatchString(p.expected.OperationID) ||
		!resetEvidenceSHA.MatchString(p.expected.ApprovalPlanSHA) || !resetEvidenceSHA.MatchString(p.expected.ExecutionReceiptSHA) {
		return nil, errResetExecutionEvidence
	}
	policy := *p
	policy.publicSPKI = bytes.Clone(p.publicSPKI)
	policy.expected.ImageDigests = cloneResetD101Strings(p.expected.ImageDigests)
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "d101-host:80" {
				return nil, errResetExecutionEvidence
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", resetD101HostSessionSocket)
		}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &resetD101HostPreparedRelay{policy: policy, publicKey: key, credential: credential, client: client, slots: make(chan struct{}, 2)}, nil
}

// Existing getter ABI, original body/signature bytes, and original deadline.
// There is no container getter, stale original, redirect, proxy or cache fallback.
func (r *resetD101HostPreparedRelay) Read(ctx context.Context, op, planSHA, receiptSHA string) ([]byte, string, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.policy.authenticate == nil || r.client == nil ||
		op != r.policy.expected.OperationID || planSHA != r.policy.expected.ApprovalPlanSHA || receiptSHA != r.policy.expected.ExecutionReceiptSHA {
		return nil, "", errResetExecutionEvidence
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return nil, "", errResetExecutionEvidence
	}
	defer func() { <-r.slots }()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if r.policy.authenticate(bounded, op, planSHA, receiptSHA) != nil || bounded.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	request, err := http.NewRequestWithContext(bounded, http.MethodGet,
		"http://d101-host/operations/"+op+"/prepared-proof/"+planSHA+"/"+receiptSHA, nil)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	request.Header.Set("Authorization", "Bearer "+r.credential)
	request.Header.Set("Accept", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, "", errResetExecutionEvidence
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > resetD101ResultMaxBytes {
		return nil, "", errResetExecutionEvidence
	}
	for _, field := range []string{"Cache-Control", "Content-Type", "X-D101-Prepared-Proof", "X-D101-Prepared-Sha256"} {
		if len(response.Header.Values(field)) != 1 {
			return nil, "", errResetExecutionEvidence
		}
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" {
		return nil, "", errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, resetD101ResultMaxBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > resetD101ResultMaxBytes || bounded.Err() != nil ||
		response.Header.Get("X-D101-Prepared-Sha256") != resetD101OriginalSHA(wire) {
		return nil, "", errResetExecutionEvidence
	}
	proof, err := decodeResetD101PreparedProof(wire)
	header := response.Header.Get("X-D101-Prepared-Proof")
	parts := strings.Split(header, ".")
	if err != nil || len(parts) != 2 || parts[0] != r.policy.keyID || requireResetD101RelayPreparedBinding(proof, r.policy.expected, time.Now()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != parts[1] ||
		!ed25519.Verify(r.publicKey, append([]byte(resetD101PreparedDomain), wire...), signature) ||
		r.policy.authenticate(bounded, op, planSHA, receiptSHA) != nil || bounded.Err() != nil ||
		requireResetD101RelayPreparedBinding(proof, r.policy.expected, time.Now()) != nil {
		return nil, "", errResetExecutionEvidence
	}
	// Only authenticated, signed, canonical admission values reach this CAS.
	// Restart loses memory but never renews the immutable proof's time/cutoff;
	// mandatory actual host admission authentication must succeed again.
	r.admissionMu.Lock()
	if r.acceptedAtUTC == "" {
		r.acceptedAtUTC = proof.AcceptedAtUTC
	}
	matched := r.acceptedAtUTC == proof.AcceptedAtUTC
	r.admissionMu.Unlock()
	if !matched || bounded.Err() != nil {
		return nil, "", errResetExecutionEvidence
	}
	return wire, header, nil
}

func requireResetD101RelayPreparedBinding(proof, expected resetD101PreparedProof, now time.Time) error {
	prepared, e1 := resetC4UTC(proof.PreparedAtUTC)
	accepted, e2 := resetC4UTC(proof.AcceptedAtUTC)
	if e1 != nil || e2 != nil || accepted.UTC().Format(time.RFC3339Nano) != proof.AcceptedAtUTC || prepared.UTC().Format(time.RFC3339Nano) != proof.PreparedAtUTC || now.Before(prepared) || now.Sub(prepared) >= resetPreflightMaxAge || accepted.After(prepared) ||
		now.Unix() >= proof.DestructiveCutoffUnix {
		return errResetExecutionEvidence
	}
	// These two values arise from this preparation's actual native journal.
	// Signature plus mandatory live host authentication bind them; all remaining
	// fields, including first admission and original cutoff, match installed pins.
	proof.PreparedAtUTC, expected.PreparedAtUTC = "", ""
	proof.PreparedJournalSHA, expected.PreparedJournalSHA = "", ""
	if expected.AcceptedAtUTC == "" {
		proof.AcceptedAtUTC = ""
	}
	if !reflect.DeepEqual(proof, expected) {
		return errResetExecutionEvidence
	}
	return nil
}

// No loadConfig, operation-store open/Recover, coordinator or signing factory.
func resetD101PreparedRelayHandler(credential string, installation *resetD101HostRelayInstallation) http.Handler {
	relay, _ := newResetD101HostPreparedRelay(installation, credential)
	prepared := resetD101HostSessionHandler(credential, relay.Read)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if request.URL.Path != "/healthz" {
			prepared.ServeHTTP(w, request)
			return
		}
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid health request"})
			return
		}
		if relay == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "host relay unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "relay"})
	})
}
