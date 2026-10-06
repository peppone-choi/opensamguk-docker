package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"opensamguk-deployer/internal/d101operatorauth"
)

// Independent controlled build stamp; an empty source is always unavailable.
// This value alone does not authenticate the artifact/installer/actual host.
var rootBuiltSourceSHA string

type resetD101HostOperationInstallation struct {
	operationID, sourceSHA, binarySHA, storePath string
	configuration                                config
	bootstrap                                    *resetD101InstalledBootstrap
	target                                       resetLifecycleTarget
	evidence                                     resetExecutionEvidenceRefs
	authenticate                                 func(context.Context, *os.File, string, string) error
	preparedCustody                              *resetD101HostPreparedCustody
}
type resetD101HostOperationSupplier func(context.Context, *os.File, string) (*resetD101HostOperationInstallation, error)

var resetD101ReviewedHostOperationSupplier resetD101HostOperationSupplier

func earlyResetD101HostCommand(args []string, getenv func(string) string, output, errOutput io.Writer) (bool, int) {
	if len(args) < 2 {
		return false, 0
	}
	switch args[1] {
	case "--d101-initialize-key3":
		if len(args) != 4 || args[2] != "--ceremony-card-sha256" || !resetEvidenceSHA.MatchString(args[3]) ||
			runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
			return true, 2
		}
		return true, runResetD101Key3Initialization(context.Background(), args[3])
	case "--d101-prepared-relay":
		if len(args) != 2 || getenv == nil || !validResetD101ServiceToken(getenv("DEPLOYER_TOKEN")) {
			return true, 2
		}
		srv := &http.Server{Addr: ":9000", Handler: resetD101PreparedRelayHandler(getenv("DEPLOYER_TOKEN"), fixedResetD101HostRelayInstallation(context.Background())), ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
		if srv.ListenAndServe() != nil {
			return true, 2
		}
		return true, 0
	case "--d101-host-operation", "--d101-issue-current-receipt":
		if len(args) != 4 || args[2] != "--operation-id" || !lifecycleJobIDRe.MatchString(args[3]) {
			return true, 2
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		// FD9 is borrowed; it is never closed/reopened/unlocked by this process.
		descriptor := os.NewFile(9, "existing-host-keeper-fd9")
		status := 2
		if args[1] == "--d101-issue-current-receipt" {
			supplier := resetD101ReviewedHostIssuerSupplier
			if supplier == nil {
				supplier = resetD101InstalledHostIssuerSupplier
			}
			status = runResetD101HostIssuer(ctx, descriptor, args[3], os.Stdin, os.Stdout, supplier)
		} else {
			supplier := resetD101ReviewedHostOperationSupplier
			if supplier == nil {
				supplier = resetD101InstalledHostOperationSupplier
			}
			status = runResetD101HostOperation(ctx, descriptor, args[3], supplier)
		}
		runtime.KeepAlive(descriptor)
		if status == 3 {
			if errOutput != nil {
				_, _ = io.WriteString(errOutput, "D101 same operation HOLD; explicit recovery required\n")
			}
			// Keep the process, keeper FD and cancellation barrier alive. A
			// runner timeout is not permission to release or start another op.
			for {
				time.Sleep(time.Second)
				runtime.KeepAlive(descriptor)
			}
		}
		return true, status
	default:
		return false, 0
	}
}

// This entry is physical operation only. The current receipt issuer's private
// JWT pipe/READY protocol is a separate entry and must never invoke this body.
// Status2 is a definite pre-admission denial; status3 is same-op HOLD after any
// possibly committed admission. No general loadConfig/Recover or retry occurs.
func runResetD101HostOperation(ctx context.Context, descriptor *os.File, selector string, supplier resetD101HostOperationSupplier) int {
	if ctx == nil || ctx.Err() != nil || descriptor == nil || descriptor.Fd() != 9 || supplier == nil ||
		runtime.GOOS != "linux" || os.Geteuid() != 0 || !lifecycleJobIDRe.MatchString(selector) || !gitSHA40.MatchString(rootBuiltSourceSHA) {
		return 2
	}
	p, err := supplier(ctx, descriptor, selector)
	if err != nil || p == nil || p.authenticate == nil || p.bootstrap == nil || p.operationID != selector ||
		p.sourceSHA != rootBuiltSourceSHA || !resetEvidenceSHA.MatchString(p.binarySHA) ||
		!filepath.IsAbs(p.storePath) || filepath.Clean(p.storePath) != p.storePath ||
		!resetEvidenceSHA.MatchString(p.evidence.ApprovalPlanSHA) || !resetEvidenceSHA.MatchString(p.evidence.ExecutionReceiptSHA) ||
		p.configuration.operations != nil || p.configuration.lifecycleOperationStore != nil || p.configuration.lifecycleJobs != nil ||
		!validResetD101ServiceToken(p.configuration.token) || p.authenticate(ctx, descriptor, selector, "preinstall") != nil {
		return 2
	}
	// All eight actual suppliers must assemble before the operation store or any
	// maintenance/admission writer starts. Source/policy callbacks remain mandatory.
	c, err := loadResetD101ReviewedInstallation(ctx, p.configuration, p.bootstrap)
	if err != nil || p.authenticate(ctx, descriptor, selector, "installed") != nil || ctx.Err() != nil {
		return 2
	}
	if c.d101FixedInstallation == nil || c.d101PurposeAuthority == nil || p.preparedCustody == nil {
		return 2
	}
	currentSupplier, ok := c.d101FixedInstallation.current.supplier.(*resetD101CurrentHostSupplier)
	if !ok || currentSupplier == nil || p.preparedCustody.pins.operationID != selector ||
		p.preparedCustody.pins.purposeKeyID != c.d101FixedInstallation.authority.SigningKey.KeyID || p.preparedCustody.pins.purposeSPKISHA != c.d101FixedInstallation.authority.SigningKey.PublicKeySpkiSHA {
		return 2
	}
	intentSHA := c.d101FixedInstallation.authority.ApprovalIntentSHA
	authority, err := c.d101PurposeAuthority(ctx, selector, intentSHA)
	intent, intentErr := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: selector, ApprovalIntentSHA: intentSHA, Action: "QUERY"}, time.Now())
	if err != nil || intentErr != nil || resetRequestFingerprint("pep", p.target) != intent.Intent.TargetFingerprint || ctx.Err() != nil {
		return 2
	}
	store, err := openDurableOperationStore(p.storePath, durableOperationMaxEntries, durableOperationTerminalRetention)
	if err != nil || resetD101HostStoreRequiresHold(store, selector) {
		return 3
	}
	c.lifecycleOperationStore = store
	c.lifecycleJobs = newLifecycleJobManager()
	c.operations = newOperationCoordinator(c.maintenanceFile, c.lifecycleJournalFile, c.lifecycleJobs)
	if p.authenticate(ctx, descriptor, selector, "before-admission") != nil || ctx.Err() != nil {
		return 2
	}
	// An existing maintenance/journal/unknown state is not reconstructed as a new
	// lease. Only a newly acquired idle admission can enter this operation.
	_, token, err := c.operations.enterMaintenanceIfIdle()
	if err != nil {
		return 3
	}
	fingerprint, err := resetExecutionRequestFingerprint("pep", p.target, p.evidence)
	if err != nil {
		c.operations.markPreparationSettlementPending()
		return 3
	}
	preparation, err := c.operations.prepare(lifecycleKindReset, selector, "pep", fingerprint, token)
	if err != nil || preparation == nil || preparation.admissionErr != nil {
		c.operations.markPreparationSettlementPending()
		return 3
	}
	stopCancellation := context.AfterFunc(ctx, preparation.cancel)
	defer stopCancellation()
	failed := true
	defer func() {
		if failed {
			preparation.complete(false)
		}
	}()
	if p.authenticate(ctx, descriptor, selector, "gateway-prepare") != nil || c.postResetD101HostGatewayPhase(ctx, selector, "PREPARE", nil) != nil {
		return 3
	}
	binding, _, err := c.prepareResetD101Execution(preparation, p.target, p.evidence, c.d101PhaseSource)
	if err != nil {
		return 3
	}
	getter := func(readCtx context.Context, op, plan, receipt string) ([]byte, string, error) {
		if readCtx == nil {
			return nil, "", errResetExecutionEvidence
		}
		bounded, cancel := context.WithTimeout(readCtx, 2*time.Second)
		defer cancel()
		requestStarted := time.Now()
		if op != selector || plan != binding.Evidence.ApprovalPlanSHA || receipt != binding.Evidence.ExecutionReceiptSHA ||
			p.authenticate(bounded, descriptor, selector, "prepared-get-before") != nil || bounded.Err() != nil {
			return nil, "", errResetExecutionEvidence
		}
		returned := false
		defer func() {
			if !returned {
				p.preparedCustody.hold()
			}
		}()
		record, found := c.lifecycleOperationStore.Lookup(op)
		if !found || record.CreatedAt.Unix() != binding.AcceptedAtUnix || c.requireResetD101Preparation(record) != nil {
			return nil, "", errResetExecutionEvidence
		}
		_, witness, err := currentSupplier.captureAuthenticatedWitness(bounded, binding, requestStarted)
		if err != nil || witness == nil || bounded.Err() != nil {
			if witness != nil && witness.release != nil {
				witness.release()
			}
			return nil, "", errResetExecutionEvidence
		}
		defer witness.release()
		wire, header, err := c.readResetD101PreparedProof(bounded, op, plan, receipt)
		if err != nil {
			return nil, "", errResetExecutionEvidence
		}
		retained, err := p.preparedCustody.retain(bounded, descriptor, binding, record.CreatedAt, requestStarted, witness, wire, header)
		if err != nil || retained == nil {
			return nil, "", errResetExecutionEvidence
		}
		defer retained.close()
		if c.requireResetD101Preparation(record) != nil || retained.recheck(bounded) != nil || witness.recheckNative() != nil ||
			p.authenticate(bounded, descriptor, selector, "prepared-get-after") != nil || retained.recheck(bounded) != nil || witness.recheckNative() != nil || bounded.Err() != nil {
			return nil, "", errResetExecutionEvidence
		}
		if retained.complete == nil || retained.complete() != nil || bounded.Err() != nil {
			return nil, "", errResetExecutionEvidence
		}
		returned = true
		return wire, header, nil
	}
	if p.authenticate(ctx, descriptor, selector, "socket-parent-before") != nil || ctx.Err() != nil {
		return 3
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: resetD101HostSessionSocket, Net: "unix"})
	if err != nil {
		return 3
	}
	// Close never removes/replaces even our socket. Exact native installation and
	// rollback/recovery card own any later cleanup; unowned stale paths are denied.
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	socketBefore, statErr := os.Lstat(resetD101HostSessionSocket)
	if statErr != nil || socketBefore.Mode()&os.ModeSocket == 0 || os.Chmod(resetD101HostSessionSocket, 0600) != nil {
		return 3
	}
	socketAfter, statErr := os.Lstat(resetD101HostSessionSocket)
	if statErr != nil || !os.SameFile(socketBefore, socketAfter) || socketAfter.Mode().Perm() != 0600 ||
		p.authenticate(ctx, descriptor, selector, "socket-installed") != nil || ctx.Err() != nil {
		return 3
	}
	session := &http.Server{Handler: resetD101HostSessionHandler(c.token, getter), ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
	defer session.Close()
	serverFailure := make(chan error, 1)
	go func() { serverFailure <- session.Serve(listener) }()
	proofWire, _, err := getter(ctx, selector, binding.Evidence.ApprovalPlanSHA, binding.Evidence.ExecutionReceiptSHA)
	proof, decodeErr := decodeResetD101PreparedProof(proofWire)
	if err != nil || decodeErr != nil || p.authenticate(ctx, descriptor, selector, "before-dispatch") != nil ||
		c.postResetD101HostGatewayPhase(ctx, selector, "DISPATCH_INTENT", &proof) != nil {
		return 3
	}
	// This actual worker start observes signed Gateway QUERY and promotes the
	// same coordinator's unconsumed lease. No alternate physical worker is called.
	jobID, err := c.startResetD101PreparedWorker(preparation, binding, c.d101PhaseSource)
	if err != nil {
		return 3
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 3
		case <-serverFailure:
			return 3
		case <-ticker.C:
			if p.authenticate(ctx, descriptor, selector, "worker-lifetime") != nil {
				preparation.cancel()
				return 3
			}
			job, found := c.lifecycleJobs.lookup(jobID)
			if !found {
				return 3
			}
			if !isTerminalLifecycleJob(job.Status) {
				continue
			}
			c.operations.mu.Lock()
			settlementPending := c.operations.preparationSettlementPending
			ended := c.operations.active == nil && !settlementPending
			c.operations.mu.Unlock()
			if job.Status != lifecycleJobSucceeded || settlementPending {
				return 3
			}
			if !ended {
				continue
			}
			if p.authenticate(ctx, descriptor, selector, "release") != nil {
				return 3
			}
			failed = false
			return 0
		}
	}
}

func resetD101HostStoreRequiresHold(store *durableOperationStore, op string) bool {
	if store == nil {
		return true
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.operations[op]; exists {
		return true
	}
	if len(store.deferredTransitions) != 0 {
		return true
	}
	for _, record := range store.operations {
		if !isTerminalLifecycleJob(record.Status) {
			return true
		}
	}
	return false
}

func resetD101HostSessionHandler(token string, read func(context.Context, string, string, string) ([]byte, string, error)) http.Handler {
	// Manual dispatch preserves the exact path. ServeMux canonical redirects
	// would otherwise precede the existing prepared-proof identity checks.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !strings.HasPrefix(r.URL.Path, "/operations/") {
			writeJSON(w, 503, errorResponse{Error: "host prepared session only"})
			return
		}
		if !validResetD101ServiceToken(token) || len(r.Header.Values("Authorization")) != 1 || !secureEqual(r.Header.Get("Authorization"), "Bearer "+token) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid prepared credential"})
			return
		}
		if len(r.TransferEncoding) != 0 {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid prepared body"})
			return
		}
		serveResetD101PreparedProof(w, r, strings.Split(strings.TrimPrefix(r.URL.Path, "/operations/"), "/"), read)
	})
}

// Issuer-only native custody is separate from the execution store/all8 mapper.
// Implementations must independently authenticate the approved installation,
// reserve the operation durably before READY, retain the exact JWT with native
// O_EXCL0400/nlink1/fsync custody, and atomically claim authenticated issuer/JTI/
// scope before native signing. There is no default implementation or bool PASS.
type resetD101HostIssuerCustody interface {
	Authenticate(context.Context, *os.File, string, string) error
	ReserveOperation(context.Context, *os.File, d101operatorauth.ReviewedPolicy) error
	RetainJWT(context.Context, *os.File, []byte, d101operatorauth.Reference) error
	ClaimAuthenticatedIssuance(context.Context, *os.File, d101operatorauth.TechnicalIssuance) error
	IssueAndRetainOriginals(context.Context, *os.File, d101operatorauth.TechnicalIssuance) error
}
type resetD101HostIssuerInstallation struct {
	operationID, sourceSHA, binarySHA, jwtLogicalID string
	policy                                          d101operatorauth.ReviewedPolicy
	custody                                         resetD101HostIssuerCustody
}
type resetD101HostIssuerSupplier func(context.Context, *os.File, string) (*resetD101HostIssuerInstallation, error)

var resetD101ReviewedHostIssuerSupplier resetD101HostIssuerSupplier

func runResetD101HostIssuer(ctx context.Context, fd *os.File, op string, input, ready *os.File, supplier resetD101HostIssuerSupplier) int {
	if ctx == nil || ctx.Err() != nil || fd == nil || fd.Fd() != 9 || supplier == nil || runtime.GOOS != "linux" ||
		os.Geteuid() != 0 || !gitSHA40.MatchString(rootBuiltSourceSHA) || !lifecycleJobIDRe.MatchString(op) ||
		!resetD101AnonymousPipe(input) || !resetD101AnonymousPipe(ready) {
		return 2
	}
	// The initial bound is never renewed by policy, token chunks or JWKS IO.
	initial, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	p, err := supplier(initial, fd, op)
	if err != nil || p == nil || p.custody == nil || (reflect.ValueOf(p.custody).Kind() == reflect.Pointer && reflect.ValueOf(p.custody).IsNil()) ||
		p.operationID != op || p.sourceSHA != rootBuiltSourceSHA || !resetEvidenceSHA.MatchString(p.binarySHA) ||
		p.policy.Scope.OperationID != op || p.policy.Scope.DockerSourceSHA != rootBuiltSourceSHA ||
		!strings.HasPrefix(p.jwtLogicalID, "raw:") || p.custody.Authenticate(initial, fd, op, "issuer-pre-ready") != nil || initial.Err() != nil {
		return 2
	}
	policy := cloneResetD101TechnicalPolicy(p.policy)
	verifier, err := d101operatorauth.NewVerifier(policy)
	if err != nil {
		return 2
	}
	bounded, stop := context.WithDeadline(initial, time.Unix(policy.CutoffUnix, 0))
	defer stop()
	deadline, _ := bounded.Deadline()
	// Unsupported pipe deadlines deny before any reservation or R write.
	if bounded.Err() != nil || input.SetReadDeadline(deadline) != nil || ready.SetWriteDeadline(deadline) != nil {
		return 2
	}
	if p.custody.ReserveOperation(bounded, fd, policy) != nil || bounded.Err() != nil {
		return 3
	}
	if p.custody.Authenticate(bounded, fd, op, "issuer-reserved") != nil || bounded.Err() != nil {
		return 3
	}
	// This process observes successful R write and uses its own monotonic clock.
	// Producer observation time is never evidence of this host deadline.
	// Capture conservatively before Write: scheduling after its successful return
	// cannot move the deadline later than the actual R-success-write + two seconds.
	started := time.Now()
	if n, err := ready.Write([]byte{'R'}); err != nil || n != 1 {
		return 3
	}
	jwt, err := readResetD101IssuerJWT(bounded, input, started)
	if err != nil {
		return 3
	}
	auth := d101operatorauth.Reference{LogicalID: p.jwtLogicalID, SHA256: resetD101OriginalSHA(jwt), ByteLength: uint64(len(jwt)), MediaType: "text/plain"}
	if p.custody.RetainJWT(bounded, fd, bytes.Clone(jwt), auth) != nil ||
		p.custody.Authenticate(bounded, fd, op, "issuer-token-retained") != nil || bounded.Err() != nil {
		return 3
	}
	operator, err := verifier.Verify(bounded, jwt, auth)
	if err != nil {
		return 3
	}
	// Read JTI only after actual signature/claims verification. NewTechnicalIssuance
	// binds it again to the unforgeable CurrentOperator; no pre-token JTI exists.
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return 3
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var claims struct {
		JTI string `json:"jti"`
	}
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return 3
	}
	event := d101operatorauth.IssuanceEvent{ActorID: policy.ActorID, RunID: policy.RunID, RunAttempt: 1, JTI: claims.JTI,
		WorkflowSHA: policy.WorkflowSHA, AuthenticationOriginal: auth, ScopeDecisionOriginal: policy.Scope.FinalCard}
	issuance, err := d101operatorauth.NewTechnicalIssuance(operator, event, policy.Scope)
	if err != nil || bounded.Err() != nil {
		return 3
	}
	if p.custody.ClaimAuthenticatedIssuance(bounded, fd, issuance) != nil || bounded.Err() != nil {
		return 3
	}
	if p.custody.Authenticate(bounded, fd, op, "issuer-before-native-issue") != nil ||
		p.custody.IssueAndRetainOriginals(bounded, fd, issuance) != nil || bounded.Err() != nil ||
		p.custody.Authenticate(bounded, fd, op, "issuer-release") != nil || bounded.Err() != nil {
		return 3
	}
	runtime.KeepAlive(fd)
	return 0
}

func resetD101AnonymousPipe(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	// Named FIFOs are not an approved private transport, even with the same mode.
	link, err := os.Readlink("/proc/self/fd/" + fmt.Sprint(file.Fd()))
	return err == nil && strings.HasPrefix(link, "pipe:[") && strings.HasSuffix(link, "]")
}

func readResetD101IssuerJWT(ctx context.Context, input *os.File, readyWrittenAt time.Time) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || input == nil || readyWrittenAt.IsZero() {
		return nil, errResetExecutionEvidence
	}
	deadline := readyWrittenAt.Add(2 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if input.SetReadDeadline(deadline) != nil {
		return nil, errResetExecutionEvidence
	}
	stop := context.AfterFunc(ctx, func() { _ = input.SetReadDeadline(time.Now()) })
	defer stop()
	wire, err := io.ReadAll(io.LimitReader(input, (64<<10)+1))
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) || len(wire) == 0 || len(wire) > 64<<10 ||
		bytes.ContainsAny(wire, "\r\n\t ") {
		return nil, errResetExecutionEvidence
	}
	return wire, nil
}

// Existing Gateway PREPARE/DISPATCH wire only; each POST is attempted once.
// A successful HTTP response is followed by the existing authenticated QUERY
// in startResetD101PreparedWorker, never treated as native execution authority.
func (c config) postResetD101HostGatewayPhase(ctx context.Context, op, action string, proof *resetD101PreparedProof) error {
	if ctx == nil || ctx.Err() != nil || c.d101PurposeAuthority == nil {
		return errResetExecutionEvidence
	}
	request := resetD101PurposeGrantRequest{OperationID: op, Action: action}
	// Intent is independently installed; the local durable row is not consulted
	// to learn approval before the first PREPARE reservation.
	if c.d101FixedInstallation == nil {
		return errResetExecutionEvidence
	}
	request.ApprovalIntentSHA = c.d101FixedInstallation.authority.ApprovalIntentSHA
	authority, err := c.d101PurposeAuthority(ctx, op, request.ApprovalIntentSHA)
	if err != nil {
		return errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, request, time.Now())
	if err != nil {
		return errResetExecutionEvidence
	}
	body, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-prepare-bodies"), op, 0)
	if err != nil || requireResetD101PrepareBody(body, intent, resetD101OriginalSHA(body)) != nil {
		return errResetExecutionEvidence
	}
	request.GatewayPayloadSHA = resetD101OriginalSHA(body)
	suffix := "/prepare"
	if action == "DISPATCH_INTENT" {
		if proof == nil || proof.OperationID != op || proof.ApprovalIntentSHA != intent.SHA {
			return errResetExecutionEvidence
		}
		body, err = json.Marshal(struct {
			SchemaVersion          int    `json:"schemaVersion"`
			VerifyingRevision      string `json:"verifyingRevision"`
			ApprovalPlanSHA        string `json:"approvalPlanSha256"`
			ExecutionReceiptSHA    string `json:"executionReceiptSha256"`
			RootRequestFingerprint string `json:"rootRequestFingerprint"`
		}{1, proof.VerifyingRevision, proof.ApprovalPlanSHA, proof.ExecutionReceiptSHA, proof.RootRequestFingerprint})
		suffix = "/dispatch-intent"
	} else if action != "PREPARE" {
		return errResetExecutionEvidence
	}
	if err != nil {
		return errResetExecutionEvidence
	}
	request.Body = bytes.Clone(body)
	credentialWire, err := readResetPrivateCustody(filepath.Join(c.serversDir, ".deployer-reset-gateway"), op, 0)
	var credential resetD101GatewayCredential
	if err != nil || requireResetIntentShape(credentialWire, reflect.TypeOf(credential)) != nil || decodeResetPrivateJSON(credentialWire, &credential) != nil ||
		credential.Version != 1 || credential.OperationID != op || credential.ApprovalIntentSHA != intent.SHA || credential.TargetFingerprint != intent.Intent.TargetFingerprint ||
		credential.ExpiresAtUnix <= time.Now().Unix() || !validResetD101ServiceToken(credential.ServiceToken) {
		return errResetExecutionEvidence
	}
	grant, err := c.issueResetD101PurposeGrant(ctx, request)
	origin, originErr := url.Parse(c.defaultGatewayAPIURL())
	if err != nil || originErr != nil || origin == nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" ||
		origin.ForceQuery || origin.Fragment != "" || origin.RawPath != "" || (origin.Path != "" && origin.Path != "/") || !resetPrivateGatewayHost(origin.Hostname()) {
		return errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, strings.TrimRight(origin.String(), "/")+"/internal/d101/servers/pep/operations/"+op+suffix, bytes.NewReader(body))
	if err != nil {
		return errResetExecutionEvidence
	}
	req.Header.Set("Authorization", "Bearer "+credential.ServiceToken)
	req.Header.Set("X-D101-Grant", grant)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return errResetExecutionEvidence
	}
	defer response.Body.Close()
	if (response.StatusCode != 200 && response.StatusCode != 201) || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return errResetExecutionEvidence
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
	value, decodeErr := decodeResetD101GatewayExecution(wire)
	state := "PREPARED"
	if action == "DISPATCH_INTENT" {
		state = "DISPATCH_INTENT"
	}
	if err != nil || len(wire) > 16<<10 || decodeErr != nil || value.SchemaVersion != 1 || value.ServerID != "pep" || value.OperationID != op || value.State != state ||
		value.ApprovalIntentSHA != intent.SHA || value.TargetFingerprint != intent.Intent.TargetFingerprint || value.GatewayPayloadSHA != request.GatewayPayloadSHA ||
		bounded.Err() != nil || credential.ExpiresAtUnix <= time.Now().Unix() {
		return errResetExecutionEvidence
	}
	return nil
}
