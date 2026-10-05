package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
)

// Static native inputs supplied only by the approved fixed installation. They
// are not env/request parameters, signing keys or a new approval receipt.
type resetD101SeedMaterialInputs struct {
	ConfigurationFile     string
	TargetFile            string
	ResolverFile          string
	ParserClassFile       string
	TopologyRootClassFile string
	TopologyRootClassSHA  string
	PasswordFile          string
	PasswordSHA           string
}
type resetD101SeedFileReference struct {
	FilePath string `json:"filePath"`
	SHA      string `json:"sha256"`
}
type resetD101SeedRootTrust struct {
	KeyID   string `json:"keyId"`
	SPKI    string `json:"publicKeySpkiBase64url"`
	SPKISHA string `json:"publicKeySpkiSha256"`
}
type resetD101SeedClassReference struct {
	BinaryName string `json:"binaryName"`
	SHA        string `json:"sha256"`
}
type resetD101SeedRuntimeClasses struct {
	Parser   resetD101SeedClassReference `json:"parser"`
	Topology resetD101SeedClassReference `json:"topology"`
}
type resetD101SeedDatabase struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Name         string `json:"databaseName"`
	User         string `json:"databaseUser"`
	PasswordFile string `json:"passwordFile"`
}
type resetD101SeedInstallation struct {
	SchemaVersion         int                         `json:"schemaVersion"`
	Kind                  string                      `json:"kind"`
	OriginalOp            string                      `json:"originalOp"`
	ApprovalIntentSHA     string                      `json:"approvalIntentSha256"`
	TargetFingerprint     string                      `json:"typedTargetFingerprint"`
	AppSourceSHA          string                      `json:"appSourceSha"`
	ImagePins             map[string]string           `json:"imagePins"`
	ProducerIdentity      string                      `json:"producerIdentity"`
	RootTrust             resetD101SeedRootTrust      `json:"rootTrust"`
	ApprovedMaterial      resetD101SeedFileReference  `json:"approvedMaterial"`
	SelectedEnvelope      resetD101SeedFileReference  `json:"selectedEnvelope"`
	ConfigurationOriginal resetD101SeedFileReference  `json:"configurationOriginal"`
	ResolverDecision      resetD101SeedFileReference  `json:"resolverDecision"`
	TypedTargetOriginal   resetD101SeedFileReference  `json:"typedTargetOriginal"`
	RuntimeClasses        resetD101SeedRuntimeClasses `json:"runtimeClasses"`
	ArtifactsRoot         string                      `json:"artifactsRoot"`
	Database              resetD101SeedDatabase       `json:"database"`
}
type resetD101SeedRootPins struct {
	SchemaVersion int               `json:"schemaVersion"`
	Kind          string            `json:"kind"`
	KeyID         string            `json:"keyId"`
	SPKI          string            `json:"publicKeySpkiBase64url"`
	SPKISHA       string            `json:"publicKeySpkiSha256"`
	ImagePins     map[string]string `json:"imagePins"`
}

// Bind only the complete checked native original; C7 verifies actual Docker
// mounts match HostPath/ChildPath and are RO. LocalPath is never a Docker bind.
type resetD101SeedReadOnlyBinding struct {
	LocalPath string
	HostPath  string
	ChildPath string
	SHA       string
}
type resetD101SeedChildMaterial struct {
	InstallationSHA     string
	PostgresContainerID string
	DatabaseAddress     string
	bindings            []resetD101SeedReadOnlyBinding
}

func (m resetD101SeedChildMaterial) Bindings() []resetD101SeedReadOnlyBinding {
	return append([]resetD101SeedReadOnlyBinding(nil), m.bindings...)
}

func resetD101SeedHostPath(c config, local string) (string, error) {
	if !filepath.IsAbs(c.composeDir) || filepath.Clean(c.composeDir) != c.composeDir || !filepath.IsAbs(c.composeHostDir) || filepath.Clean(c.composeHostDir) != c.composeHostDir || c.serversDir != filepath.Join(c.composeDir, "servers") || !filepath.IsAbs(local) || filepath.Clean(local) != local {
		return "", errResetExecutionEvidence
	}
	rel, err := filepath.Rel(c.serversDir, local)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errResetExecutionEvidence
	}
	host := filepath.Join(c.composeHostDir, "servers", rel)
	if strings.ContainsAny(host, ",\r\n") {
		return "", errResetExecutionEvidence
	}
	return host, nil
}

// Read and hash every fixed input before the physical worker pulls or downs.
// Native custody and expected source SHA remain mandatory on the later child
// material production path too; this never creates installation readiness.
func (c config) requireResetD101SeedMaterialInputs(a resetD101CandidateAdmission) error {
	if c.d101SeedMaterialInputs == nil || c.d101CandidatePipeline == nil || c.d101CandidatePipeline.selectedEnvelopeDirectory == "" || c.requireResetD101SeedOutputDirectories(a.OperationID()) != nil {
		return errResetExecutionEvidence
	}
	p := *c.d101SeedMaterialInputs
	selected := c.d101CandidatePipeline.selected.value
	selectedFile := filepath.Join(c.d101CandidatePipeline.selectedEnvelopeDirectory, a.OperationID()+".json")
	items := []struct {
		path, sha string
		limit     int64
	}{
		{p.ConfigurationFile, selected.ConfigurationSHA, 64 * 1024}, {p.TargetFile, a.TargetFingerprint(), 16 * 1024},
		{p.ResolverFile, selected.ResolverDecisionSHA, 64 * 1024}, {p.ParserClassFile, selected.ParserBytecodeSHA, 2 * 1024 * 1024},
		{p.TopologyRootClassFile, p.TopologyRootClassSHA, 2 * 1024 * 1024}, {p.PasswordFile, p.PasswordSHA, 4096},
		{selectedFile, c.d101CandidatePipeline.plan.SelectedEnvelopeSHA, 96 * 1024},
	}
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item.path] {
			return errResetExecutionEvidence
		}
		seen[item.path] = true
		if _, err := resetD101SeedHostPath(c, item.path); err != nil {
			return errResetExecutionEvidence
		}
		original, err := d101custody.ReadPrivate(item.path, item.limit)
		if err != nil || !resetEvidenceSHA.MatchString(item.sha) || original.SHA256 != item.sha {
			return errResetExecutionEvidence
		}
		if item.path == p.PasswordFile {
			valid := utf8.Valid(original.Bytes) && !bytes.ContainsAny(original.Bytes, "\x00\r\n")
			clear(original.Bytes)
			if !valid {
				return errResetExecutionEvidence
			}
		}
	}
	return nil
}

func (c config) requireResetD101SeedOutputDirectories(op string) error {
	if !lifecycleJobIDRe.MatchString(op) {
		return errResetExecutionEvidence
	}
	for _, leaf := range []string{".deployer-reset-seed-root-pins", ".deployer-reset-seed-approval", ".deployer-reset-seed-installation"} {
		directory := filepath.Join(c.serversDir, leaf)
		actual, err := filepath.EvalSymlinks(directory)
		info, statErr := os.Lstat(directory)
		stat, ok := resetPrivateFileStat(info)
		if err != nil || statErr != nil || actual != directory || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || stat.Uid != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errResetExecutionEvidence
		}
		if _, err := os.Lstat(filepath.Join(directory, op+".json")); !os.IsNotExist(err) {
			return errResetExecutionEvidence
		}
	}
	return nil
}

// Actual current lease/dispatch/cutoff issuance and exclusive native custody.
// No directory/key/image installation is performed here. All directories and
// fixed inputs must already be installed; missing inputs fail before child use.
func (c config) prepareResetD101SeedChildMaterial(ctx context.Context, a resetD101CandidateAdmission, postgresID string, guard func(context.Context) error) (resetD101SeedChildMaterial, error) {
	closed := resetD101SeedChildMaterial{}
	if ctx == nil || ctx.Err() != nil || guard == nil || c.d101SeedMaterialInputs == nil || c.d101CandidatePipeline == nil || c.d101PurposeAuthority == nil || c.d101CandidatePipeline.caps == nil || c.requireResetD101SeedMaterialInputs(a) != nil || !resetEvidenceSHA.MatchString(postgresID) || guard(ctx) != nil {
		return closed, errResetExecutionEvidence
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	authority, err := c.d101PurposeAuthority(bounded, a.OperationID(), a.ApprovalIntentSHA())
	intent, scopeErr := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: a.OperationID(), ApprovalIntentSHA: a.ApprovalIntentSHA(), Action: "DISPATCH_INTENT"}, time.Now())
	if err != nil || scopeErr != nil || c.d101CandidatePipeline.requireAdmission(a, authority) != nil {
		return closed, errResetExecutionEvidence
	}
	input := *c.d101SeedMaterialInputs
	selected := c.d101CandidatePipeline.selected.value
	selectedFile := filepath.Join(c.d101CandidatePipeline.selectedEnvelopeDirectory, a.OperationID()+".json")
	originals := map[string]d101custody.Original{}
	bindings := []resetD101SeedReadOnlyBinding{}
	read := func(local, child, sha string, limit int64) ([]byte, error) {
		host, err := resetD101SeedHostPath(c, local)
		value, readErr := d101custody.ReadPrivate(local, limit)
		if err != nil || readErr != nil || !resetEvidenceSHA.MatchString(sha) || value.SHA256 != sha {
			return nil, errResetExecutionEvidence
		}
		originals[local] = value
		if child != "" {
			bindings = append(bindings, resetD101SeedReadOnlyBinding{local, host, child, sha})
		}
		return value.Bytes, nil
	}
	target, err := read(input.TargetFile, "/run/d101/typed-target.json", a.TargetFingerprint(), 16*1024)
	if err != nil || !bytes.Equal(target, intent.targetBytes()) {
		return closed, errResetExecutionEvidence
	}
	if _, err = read(input.ConfigurationFile, "/run/d101/configuration.json", selected.ConfigurationSHA, 64*1024); err != nil {
		return closed, errResetExecutionEvidence
	}
	if _, err = read(input.ResolverFile, "/run/d101/resolver-decision.json", selected.ResolverDecisionSHA, 64*1024); err != nil {
		return closed, errResetExecutionEvidence
	}
	parser, err := read(input.ParserClassFile, "", selected.ParserBytecodeSHA, 2*1024*1024)
	if err != nil || len(parser) < 4 || !bytes.Equal(parser[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return closed, errResetExecutionEvidence
	}
	topology, err := read(input.TopologyRootClassFile, "", input.TopologyRootClassSHA, 2*1024*1024)
	if err != nil || len(topology) < 4 || !bytes.Equal(topology[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return closed, errResetExecutionEvidence
	}
	if _, err = read(selectedFile, "/run/d101/selected-envelope.json", c.d101CandidatePipeline.plan.SelectedEnvelopeSHA, 96*1024); err != nil {
		return closed, errResetExecutionEvidence
	}
	password, err := read(input.PasswordFile, "/run/d101/password", input.PasswordSHA, 4096)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	defer clear(password)
	if !utf8.Valid(password) || bytes.ContainsAny(password, "\x00\r\n") {
		return closed, errResetExecutionEvidence
	}
	if guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	pg, err := c.observeResetRuntimeContainerProject(bounded, "game-postgres", a.CandidateResources().Project)
	if err != nil || pg.ID != postgresID || guard(bounded) != nil || c.requireResetD101CapsImage(bounded, pg.ImageID, a.ImagePins()["game-postgres"]) != nil || guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	address, err := c.observeResetD101CapsAddress(bounded, postgresID, a.CandidateResources().Network)
	if err != nil || net.ParseIP(address) == nil {
		return closed, errResetExecutionEvidence
	}
	key, err := readResetD101SigningKey(authority.KeyPins)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	spki, keyErr := x509.MarshalPKIXPublicKey(key.private.Public())
	key.close()
	if keyErr != nil || resetD101OriginalSHA(spki) != authority.KeyPins.PublicKeySpkiSHA || authority.KeyPins.KeyID != selected.ProducerIdentity {
		return closed, errResetExecutionEvidence
	}
	publish := func(directory, child string, wire []byte) (resetD101SeedFileReference, error) {
		local := filepath.Join(c.serversDir, directory, a.OperationID()+".json")
		host, err := resetD101SeedHostPath(c, local)
		sha := resetD101OriginalSHA(wire)
		if err != nil || guard(bounded) != nil || createResetImmutablePrivateBytes(filepath.Dir(local), a.OperationID(), sha, wire, 0) != nil {
			return resetD101SeedFileReference{}, errResetExecutionEvidence
		}
		originals[local] = d101custody.Original{Bytes: append([]byte(nil), wire...), SHA256: sha}
		bindings = append(bindings, resetD101SeedReadOnlyBinding{local, host, child, sha})
		return resetD101SeedFileReference{child, sha}, nil
	}
	// This independent key mount is created from current installed native key
	// pins, not from the child manifest's candidate rootTrust values.
	pins := resetD101SeedRootPins{1, "D101_SEED_ROOT_PINS_V1", authority.KeyPins.KeyID, base64.RawURLEncoding.EncodeToString(spki), authority.KeyPins.PublicKeySpkiSHA, a.ImagePins()}
	pinsWire, err := json.Marshal(pins)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	if _, err = publish(".deployer-reset-seed-root-pins", "/run/d101/root-pins.json", pinsWire); err != nil {
		return closed, errResetExecutionEvidence
	}
	approval, err := c.readResetD101SeedApproval(bounded, a.OperationID(), a.ApprovalIntentSHA())
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	approvalRef, err := publish(".deployer-reset-seed-approval", "/run/d101/seed-approval.json", approval)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	caps := c.d101CandidatePipeline.caps.pins
	manifest := resetD101SeedInstallation{1, "D101_SEED_INSTALLATION_V1", a.OperationID(), a.ApprovalIntentSHA(), a.TargetFingerprint(), a.AppSourceSHA(), a.ImagePins(), authority.KeyPins.KeyID,
		resetD101SeedRootTrust{authority.KeyPins.KeyID, pins.SPKI, pins.SPKISHA}, approvalRef,
		resetD101SeedFileReference{"/run/d101/selected-envelope.json", c.d101CandidatePipeline.plan.SelectedEnvelopeSHA},
		resetD101SeedFileReference{"/run/d101/configuration.json", selected.ConfigurationSHA},
		resetD101SeedFileReference{"/run/d101/resolver-decision.json", selected.ResolverDecisionSHA},
		resetD101SeedFileReference{"/run/d101/typed-target.json", a.TargetFingerprint()},
		resetD101SeedRuntimeClasses{resetD101SeedClassReference{"opensamguk.engine.boot.SeedBootstrap", selected.ParserBytecodeSHA}, resetD101SeedClassReference{"opensamguk.logic.world.StrategicTopologySnapshot", input.TopologyRootClassSHA}},
		"/app", resetD101SeedDatabase{address, 5432, caps.DatabaseName, caps.DatabaseUser, "/run/d101/password"}}
	wire, err := json.Marshal(manifest)
	if err != nil || requireResetIntentShape(wire, reflect.TypeOf(manifest)) != nil {
		return closed, errResetExecutionEvidence
	}
	manifestRef, err := publish(".deployer-reset-seed-installation", "/run/d101/installation.json", wire)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	for local, before := range originals {
		after, err := d101custody.ReadPrivate(local, int64(len(before.Bytes)))
		if local == input.PasswordFile && err == nil {
			defer clear(after.Bytes)
		}
		if err != nil || after.SHA256 != before.SHA256 || !bytes.Equal(after.Bytes, before.Bytes) {
			return closed, errResetExecutionEvidence
		}
	}
	if guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	pgAfter, err := c.observeResetRuntimeContainerProject(bounded, "game-postgres", a.CandidateResources().Project)
	if err != nil || !reflect.DeepEqual(pg, pgAfter) || guard(bounded) != nil {
		return closed, errResetExecutionEvidence
	}
	addressAfter, err := c.observeResetD101CapsAddress(bounded, postgresID, a.CandidateResources().Network)
	if err != nil || addressAfter != address || bounded.Err() != nil || !time.Now().Before(a.Cutoff()) {
		return closed, errResetExecutionEvidence
	}
	return resetD101SeedChildMaterial{manifestRef.SHA, postgresID, address, bindings}, nil
}
