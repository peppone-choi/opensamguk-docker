package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101selectedtransport"
)

type resetD101PreIntentCaptureManifest struct {
	SchemaVersion     int                                      `json:"schemaVersion"`
	Kind              string                                   `json:"kind"`
	OriginalOp        string                                   `json:"originalOp"`
	TargetFingerprint string                                   `json:"typedTargetFingerprint"`
	AppSourceSHA      string                                   `json:"appSourceSha"`
	ImagePins         map[string]string                        `json:"imagePins"`
	InputBindingsSHA  string                                   `json:"preIntentInstallationSha256"`
	CapturedAtUTC     string                                   `json:"capturedAtUtc"`
	Originals         map[string]resetD101PreIntentOriginalRef `json:"originals"`
}
type resetD101PreIntentOriginalRef struct {
	RawSHA     string `json:"rawSha256"`
	ByteLength uint64 `json:"byteLength"`
	MediaType  string `json:"mediaType"`
}

// Created only after actual retained child and whole native sink reception.
// This type is byte custody, not a selected signature or database approval.
type resetD101PreIntentCaptureReception struct {
	source                              *resetD101PreIntentCaptureSource
	child                               resetD101PreIntentChild
	manifest                            resetD101PreIntentCaptureManifest
	manifestOriginal                    []byte
	originals                           map[string]d101custody.Original
	snapshots                           map[string]d101custody.PrivateSnapshot
	manifestSnapshot                    d101custody.PrivateSnapshot
	beforeCommand                       func(context.Context) error
	issuedReceiptSHA, issuedEnvelopeSHA string
	issuedReceipt, issuedEnvelope       []byte
	indexAttempted                      atomic.Bool
}
type resetD101PreIntentChild struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	ImageID         string                `json:"imageId"`
	ImageRef        string                `json:"imageRef"`
	Status          string                `json:"status"`
	Running         *bool                 `json:"running"`
	ExitCode        *int                  `json:"exitCode"`
	Network         string                `json:"network"`
	User            string                `json:"user"`
	Entrypoint      []string              `json:"entrypoint"`
	Cmd             []string              `json:"cmd"`
	ReadOnly        *bool                 `json:"readOnly"`
	Privileged      *bool                 `json:"privileged"`
	CapDrop         []string              `json:"capDrop"`
	CapAdd          []string              `json:"capAdd"`
	SecurityOptions []string              `json:"securityOptions"`
	Mounts          []*resetD101CapsMount `json:"mounts"`
}

var resetD101PreIntentChildInspectFormat = strings.Replace(resetD101SeedChildInspectFormat, `"capDrop":`, `"capAdd":{{json .HostConfig.CapAdd}},"capDrop":`, 1)

func decodeResetD101PreIntentChild(wire, id, imageRef string, s *resetD101PreIntentCaptureSource) (resetD101PreIntentChild, error) {
	var child resetD101PreIntentChild
	if s == nil || len(wire) == 0 || len(wire) > 16<<10 || !utf8.ValidString(wire) {
		return child, errResetExecutionEvidence
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(wire), &fields) != nil || len(fields) != reflect.TypeOf(child).NumField() {
		return child, errResetExecutionEvidence
	}
	shape := reflect.TypeOf(child)
	for i := 0; i < shape.NumField(); i++ {
		if _, ok := fields[shape.Field(i).Tag.Get("json")]; !ok {
			return child, errResetExecutionEvidence
		}
	}
	if s == nil || len(wire) == 0 || len(wire) > 16<<10 || !utf8.ValidString(wire) || decodeResetPrivateJSON([]byte(wire), &child) != nil ||
		child.ID != id || !resetEvidenceSHA.MatchString(id) || child.Name != "/d101-pre-intent-"+s.reviewed.OperationID || !resetManifestDigest.MatchString(child.ImageID) || child.ImageRef != imageRef ||
		child.Running == nil || child.ExitCode == nil || child.Network != "none" || child.User != "0:0" || child.ReadOnly == nil || !*child.ReadOnly || child.Privileged == nil || *child.Privileged ||
		!reflect.DeepEqual(child.Entrypoint, []string{resetD101PreIntentCaptureEntrypoint}) || len(child.Cmd) != 0 || len(child.CapAdd) != 0 || !reflect.DeepEqual(child.CapDrop, []string{"ALL"}) ||
		len(child.SecurityOptions) != 1 || child.SecurityOptions[0] != "no-new-privileges" && child.SecurityOptions[0] != "no-new-privileges=true" || len(child.Mounts) != 3 || child.Mounts[2] != nil {
		return resetD101PreIntentChild{}, errResetExecutionEvidence
	}
	wanted := map[string]resetD101CapsMount{
		resetD101PreIntentNamespace:  {Type: "bind", Source: s.inputHost, Destination: resetD101PreIntentNamespace, RW: false},
		resetD101PreIntentOutputPath: {Type: "bind", Source: s.outputHost, Destination: resetD101PreIntentOutputPath, RW: true},
	}
	for _, mount := range child.Mounts[:2] {
		if mount == nil || wanted[mount.Destination] != *mount {
			return resetD101PreIntentChild{}, errResetExecutionEvidence
		}
		delete(wanted, mount.Destination)
	}
	if len(wanted) != 0 {
		return resetD101PreIntentChild{}, errResetExecutionEvidence
	}
	return child, nil
}

func (c config) resetD101PreIntentCreateArgs(s *resetD101PreIntentCaptureSource) ([]string, error) {
	if s == nil || !resetRuntimeRepository.MatchString("ghcr.io/"+c.ghcrOwner+"/opensamguk") || !validResetFiveImageDigests(s.reviewed.ImagePins) || !lifecycleJobIDRe.MatchString(s.reviewed.OperationID) ||
		strings.ContainsAny(s.inputHost+s.outputHost, ",\r\n") || !filepath.IsAbs(s.inputHost) || !filepath.IsAbs(s.outputHost) {
		return nil, errResetExecutionEvidence
	}
	return []string{"create", "--name", "d101-pre-intent-" + s.reviewed.OperationID, "--pull", "never", "--network", "none", "--user", "0:0", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--mount", "type=bind,src=" + s.inputHost + ",dst=" + resetD101PreIntentNamespace + ",readonly",
		"--mount", "type=bind,src=" + s.outputHost + ",dst=" + resetD101PreIntentOutputPath,
		"--entrypoint", resetD101PreIntentCaptureEntrypoint, "ghcr.io/" + c.ghcrOwner + "/opensamguk@" + s.reviewed.ImagePins["game-engine"]}, nil
}

func (c config) runResetD101PreIntentCapture(ctx context.Context, s *resetD101PreIntentCaptureSource, beforeCommand func(context.Context) error) (*resetD101PreIntentCaptureReception, error) {
	if ctx == nil || ctx.Err() != nil || beforeCommand == nil || s == nil || s.verifyInputs() != nil || requireResetD101PreIntentDirectory(s.outputLocal, true) != nil || !s.attempted.CompareAndSwap(false, true) {
		return nil, errResetExecutionEvidence
	}
	args, err := c.resetD101PreIntentCreateArgs(s)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, resetPreflightMaxAge)
	defer cancel()
	call := func(args ...string) (string, error) {
		actual, statErr := os.Lstat(s.outputLocal)
		if bounded.Err() != nil || beforeCommand(bounded) != nil || s.verifyInputs() != nil || requireResetD101PreIntentDirectory(s.outputLocal, false) != nil || statErr != nil || s.outputIdentity == nil || !os.SameFile(s.outputIdentity, actual) {
			return "", errResetExecutionEvidence
		}
		out, err := c.runServerDockerContext(bounded, args...)
		if err != nil || bounded.Err() != nil || s.verifyInputs() != nil {
			return "", errResetExecutionEvidence
		}
		return out, nil
	}
	out, err := call(args...)
	id := strings.TrimSpace(out)
	if err != nil || !resetEvidenceSHA.MatchString(id) {
		return nil, errResetExecutionEvidence
	}
	imageRef := args[len(args)-1]
	inspect := func() (resetD101PreIntentChild, error) {
		out, err := call("inspect", "--format", resetD101PreIntentChildInspectFormat, id)
		if err != nil {
			return resetD101PreIntentChild{}, err
		}
		return decodeResetD101PreIntentChild(out, id, imageRef, s)
	}
	created, err := inspect()
	if err != nil || created.Status != "created" || *created.Running {
		return nil, errResetExecutionEvidence
	}
	imageOut, err := call("image", "inspect", "--format", `{"repoDigests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}`, created.ImageID)
	var image resetRuntimeImage
	if err != nil || len(imageOut) > 16<<10 || requireResetIntentShape([]byte(imageOut), reflect.TypeOf(image)) != nil || decodeResetPrivateJSON([]byte(imageOut), &image) != nil || image.OS != "linux" || image.Architecture != "amd64" ||
		!resetRuntimePinMatches(image.RepoDigests, "game-engine", "ghcr.io/"+c.ghcrOwner+"/opensamguk", s.reviewed.ImagePins["game-engine"]) {
		return nil, errResetExecutionEvidence
	}
	started := time.Now()
	if _, err = call("start", id); err != nil {
		return nil, err
	}
	waited, err := call("wait", id)
	if err != nil || strings.TrimSpace(waited) != "0" {
		return nil, errResetExecutionEvidence
	}
	finished, err := inspect()
	if err != nil || finished.Status != "exited" || *finished.Running || *finished.ExitCode != 0 || finished.ImageID != created.ImageID {
		return nil, errResetExecutionEvidence
	}
	reception, err := readResetD101PreIntentReception(s, finished, time.Now())
	if err != nil {
		return nil, err
	}
	captured, err := resetD101RecoveryUTC(reception.manifest.CapturedAtUTC)
	if err != nil || captured.Before(started) || captured.After(time.Now()) {
		return nil, errResetExecutionEvidence
	}
	again, err := inspect()
	if err != nil || !reflect.DeepEqual(finished, again) || reception.recheck() != nil || bounded.Err() != nil {
		return nil, errResetExecutionEvidence
	}
	reception.beforeCommand = beforeCommand
	return reception, nil // Failed/uncertain children and partial outputs stay retained.
}

// The issuer continues to check full mounts/security/native originals, rather
// than reducing the retained child to its self-reported facts/exit labels.
func (c config) requireResetD101PreIntentRetainedChild(ctx context.Context, r *resetD101PreIntentCaptureReception) error {
	if ctx == nil || ctx.Err() != nil || r == nil || r.beforeCommand == nil || r.beforeCommand(ctx) != nil || r.recheck() != nil {
		return errResetExecutionEvidence
	}
	out, err := c.runServerDockerContext(ctx, "inspect", "--format", resetD101PreIntentChildInspectFormat, r.child.ID)
	if err != nil {
		return errResetExecutionEvidence
	}
	actual, err := decodeResetD101PreIntentChild(out, r.child.ID, r.child.ImageRef, r.source)
	if err != nil || !reflect.DeepEqual(actual, r.child) || r.recheck() != nil {
		return errResetExecutionEvidence
	}
	return nil
}

func resetD101PreIntentOriginalPath(directory, id string) string {
	return filepath.Join(directory, resetD101OriginalSHA([]byte(id))+".bin")
}
func resetD101PreIntentOriginalLimit(id string) int64 {
	switch id {
	case "typedTarget":
		return 16 << 10
	case "captureFacts", "configuration", "resolverDecision", "selectedWorld", "parsedOptions":
		return 64 << 10
	case "parserClass", "topologyRootClass":
		return 2 << 20
	case "selected-scenario.json", "classpath-scenario.json":
		return 16 << 20
	case "tiles.json", "world.json", "roads.json", "topologyCanonical":
		return 64 << 20
	}
	if strings.HasPrefix(id, "topology-input:") && d101selectedtransport.ValidSourceID(id) {
		return 64 << 20
	}
	return 0
}
func resetD101PreIntentMedia(id string) string {
	if id == "parserClass" || id == "topologyRootClass" || id == "topologyCanonical" || id == "topology-input:dryLandProjectionPolicy" {
		return "application/octet-stream"
	}
	return "application/json"
}

func decodeResetD101PreIntentManifest(wire []byte, s *resetD101PreIntentCaptureSource, now time.Time) (resetD101PreIntentCaptureManifest, error) {
	var m resetD101PreIntentCaptureManifest
	if s == nil || len(wire) == 0 || len(wire) > 64<<10 || !utf8.Valid(wire) || requireResetIntentShape(wire, reflect.TypeOf(m)) != nil || decodeResetPrivateJSON(wire, &m) != nil ||
		m.SchemaVersion != 1 || m.Kind != "D101_PRE_INTENT_CAPTURE_V1" || m.OriginalOp != s.reviewed.OperationID || m.TargetFingerprint != s.reviewed.TargetFingerprint || m.AppSourceSHA != s.reviewed.AppSourceSHA ||
		!reflect.DeepEqual(m.ImagePins, s.reviewed.ImagePins) || m.InputBindingsSHA != s.reviewed.InputBindingsSHA || len(m.Originals) < 15 || len(m.Originals) > 14+32 {
		return resetD101PreIntentCaptureManifest{}, errResetExecutionEvidence
	}
	required := []string{"captureFacts", "typedTarget", "configuration", "parserClass", "resolverDecision", "topologyRootClass", "topologyCanonical", "selectedWorld", "parsedOptions", "tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"}
	for _, id := range required {
		if _, ok := m.Originals[id]; !ok {
			return resetD101PreIntentCaptureManifest{}, errResetExecutionEvidence
		}
	}
	for id, ref := range m.Originals {
		limit := resetD101PreIntentOriginalLimit(id)
		if limit == 0 || !resetEvidenceSHA.MatchString(ref.RawSHA) || ref.ByteLength == 0 || ref.ByteLength > uint64(limit) || ref.MediaType != resetD101PreIntentMedia(id) {
			return resetD101PreIntentCaptureManifest{}, errResetExecutionEvidence
		}
	}
	t, err := resetD101RecoveryUTC(m.CapturedAtUTC)
	if err != nil || t.After(now) {
		return resetD101PreIntentCaptureManifest{}, errResetExecutionEvidence
	}
	return m, nil
}

func readResetD101PreIntentReception(s *resetD101PreIntentCaptureSource, child resetD101PreIntentChild, now time.Time) (*resetD101PreIntentCaptureReception, error) {
	if s == nil || s.verifyInputs() != nil || requireResetD101PreIntentDirectory(s.outputLocal, false) != nil {
		return nil, errResetExecutionEvidence
	}
	raw, manifestSnapshot, err := d101custody.CapturePrivateOriginal(filepath.Join(s.outputLocal, "capture-manifest.json"), 64<<10)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	m, err := decodeResetD101PreIntentManifest(raw.Bytes, s, now)
	if err != nil {
		return nil, err
	}
	reception := &resetD101PreIntentCaptureReception{source: s, child: child, manifest: m, manifestOriginal: append([]byte(nil), raw.Bytes...), originals: map[string]d101custody.Original{}, snapshots: map[string]d101custody.PrivateSnapshot{}, manifestSnapshot: manifestSnapshot}
	for id, ref := range m.Originals {
		original, snapshot, err := d101custody.CapturePrivateOriginal(resetD101PreIntentOriginalPath(s.outputLocal, id), resetD101PreIntentOriginalLimit(id))
		if err != nil || original.SHA256 != ref.RawSHA || uint64(len(original.Bytes)) != ref.ByteLength {
			return nil, errResetExecutionEvidence
		}
		reception.originals[id] = original
		reception.snapshots[id] = snapshot
	}
	if !bytes.Equal(reception.originals["configuration"].Bytes, s.inputOriginals["configuration"].Bytes) || !bytes.Equal(reception.originals["typedTarget"].Bytes, s.inputOriginals["typed-target"].Bytes) || reception.recheck() != nil {
		return nil, errResetExecutionEvidence
	}
	return reception, nil
}
func (r *resetD101PreIntentCaptureReception) recheck() error {
	if r == nil || r.source == nil || r.source.verifyInputs() != nil {
		return errResetExecutionEvidence
	}
	actual, statErr := os.Lstat(r.source.outputLocal)
	if statErr != nil || r.source.outputIdentity == nil || !os.SameFile(r.source.outputIdentity, actual) {
		return errResetExecutionEvidence
	}
	raw, err := d101custody.ReadPrivate(filepath.Join(r.source.outputLocal, "capture-manifest.json"), 64<<10)
	if err != nil || !bytes.Equal(raw.Bytes, r.manifestOriginal) || d101custody.InspectPrivateSnapshot(filepath.Join(r.source.outputLocal, "capture-manifest.json"), r.manifestSnapshot) != nil {
		return errResetExecutionEvidence
	}
	wanted := map[string]bool{"capture-manifest.json": true}
	for id, original := range r.originals {
		path := resetD101PreIntentOriginalPath(r.source.outputLocal, id)
		wanted[filepath.Base(path)] = true
		after, err := d101custody.ReadPrivate(path, resetD101PreIntentOriginalLimit(id))
		if err != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) || d101custody.InspectPrivateSnapshot(path, r.snapshots[id]) != nil {
			return errResetExecutionEvidence
		}
	}
	return requireResetD101PreIntentOutputNames(r.source.outputLocal, wanted)
}

func requireResetD101PreIntentOutputNames(directory string, wanted map[string]bool) error {
	if requireResetD101PreIntentDirectory(directory, false) != nil {
		return errResetExecutionEvidence
	}
	before, err := os.Lstat(directory)
	if err != nil {
		return errResetExecutionEvidence
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), directory)
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return errResetExecutionEvidence
	}
	entries, err := file.Readdir(-1)
	if err != nil || len(entries) != len(wanted) {
		return errResetExecutionEvidence
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] || !entry.Mode().IsRegular() {
			return errResetExecutionEvidence
		}
	}
	after, err := os.Lstat(directory)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		return errResetExecutionEvidence
	}
	return requireResetD101PreIntentDirectory(directory, false)
}
