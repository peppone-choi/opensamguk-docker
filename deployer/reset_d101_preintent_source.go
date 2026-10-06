package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode/utf8"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101preinput"
)

const resetD101PreIntentNamespace = "/etc/opensamguk/d101"
const resetD101PreIntentProfilePath = resetD101PreIntentNamespace + "/pre-intent-source-pins.json"
const resetD101PreIntentHelperPath = resetD101PreIntentNamespace + "/native-helper/d101-host-reader"
const resetD101PreIntentOutputPath = "/run/d101/pre-intent-output"

type resetD101PreIntentProfile struct {
	SchemaVersion     int               `json:"schemaVersion"`
	Kind              string            `json:"kind"`
	OriginalOp        string            `json:"originalOp"`
	TargetFingerprint string            `json:"typedTargetFingerprint"`
	AppSourceSHA      string            `json:"appSourceSha"`
	ImagePins         map[string]string `json:"imagePins"`
	ArtifactsRoot     string            `json:"artifactsRoot"`
	InputBindingsSHA  string            `json:"preIntentInstallationSha256"`
	HelperPath        string            `json:"nativeHelperPath"`
	HelperSHA         string            `json:"nativeHelperSha256"`
	ProducerIdentity  string            `json:"producerIdentity"`
}

// Supplied only by independently reviewed installation source. Expected pins
// are never copied from the helper response or the on-disk profile itself.
type resetD101PreIntentReviewedPins struct {
	OperationID, TargetFingerprint, AppSourceSHA              string
	ImagePins                                                 map[string]string
	ProfileSHA, InputBindingsSHA, HelperSHA, ProducerIdentity string
}
type resetD101PreIntentCaptureSource struct {
	reviewed                                       resetD101PreIntentReviewedPins
	inputLocal, inputHost, outputLocal, outputHost string
	profile                                        resetD101PreIntentProfile
	profileOriginal, bindingsOriginal              []byte
	inputOriginals                                 map[string]d101custody.Original
	snapshots                                      map[string]d101custody.PrivateSnapshot
	inputIdentity, outputIdentity                  os.FileInfo
	attempted                                      atomic.Bool
}

func decodeResetD101PreIntentProfile(wire []byte, expected resetD101PreIntentReviewedPins) (resetD101PreIntentProfile, error) {
	var p resetD101PreIntentProfile
	if len(wire) == 0 || len(wire) > 16<<10 || !utf8.Valid(wire) || !lifecycleJobIDRe.MatchString(expected.OperationID) ||
		!resetEvidenceSHA.MatchString(expected.TargetFingerprint) || !gitSHA40.MatchString(expected.AppSourceSHA) || !validResetFiveImageDigests(expected.ImagePins) ||
		!resetEvidenceSHA.MatchString(expected.ProfileSHA) || !resetEvidenceSHA.MatchString(expected.InputBindingsSHA) || !resetEvidenceSHA.MatchString(expected.HelperSHA) || !resetD101KeyID.MatchString(expected.ProducerIdentity) ||
		resetD101OriginalSHA(wire) != expected.ProfileSHA || requireResetIntentShape(wire, reflect.TypeOf(p)) != nil || decodeResetPrivateJSON(wire, &p) != nil ||
		p.SchemaVersion != 1 || p.Kind != "D101_PRE_INTENT_SOURCE_PINS_V1" || p.OriginalOp != expected.OperationID || p.TargetFingerprint != expected.TargetFingerprint ||
		p.AppSourceSHA != expected.AppSourceSHA || !reflect.DeepEqual(p.ImagePins, expected.ImagePins) || p.ArtifactsRoot != "/app" || p.InputBindingsSHA != expected.InputBindingsSHA ||
		p.HelperPath != resetD101PreIntentHelperPath || p.HelperSHA != expected.HelperSHA || p.ProducerIdentity != expected.ProducerIdentity {
		return resetD101PreIntentProfile{}, errResetExecutionEvidence
	}
	return p, nil
}

func newResetD101PreIntentCaptureSource(c config, p resetD101PreIntentReviewedPins) (*resetD101PreIntentCaptureSource, error) {
	if !lifecycleJobIDRe.MatchString(p.OperationID) {
		return nil, errResetExecutionEvidence
	}
	p.ImagePins = cloneResetD101Strings(p.ImagePins)
	input := filepath.Join(c.serversDir, ".deployer-reset-preintent-inputs", p.OperationID)
	output := filepath.Join(c.serversDir, ".deployer-reset-preintent-output", p.OperationID)
	inputHost, err := resetD101SeedHostPath(c, input)
	if err != nil {
		return nil, err
	}
	outputHost, err := resetD101SeedHostPath(c, output)
	if err != nil {
		return nil, err
	}
	s := &resetD101PreIntentCaptureSource{reviewed: p, inputLocal: input, inputHost: inputHost, outputLocal: output, outputHost: outputHost}
	if s.verifyInputs() != nil || requireResetD101PreIntentDirectory(output, true) != nil {
		return nil, errResetExecutionEvidence
	}
	s.inputIdentity, err = os.Lstat(input)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	s.outputIdentity, err = os.Lstat(output)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	if s.verifyInputs() != nil {
		return nil, errResetExecutionEvidence
	}
	return s, nil
}

func (s *resetD101PreIntentCaptureSource) verifyInputs() error {
	if s == nil {
		return errResetExecutionEvidence
	}
	if s.inputIdentity != nil {
		actual, err := os.Lstat(s.inputLocal)
		if err != nil || !os.SameFile(s.inputIdentity, actual) {
			return errResetExecutionEvidence
		}
	}
	// Enumerate the complete RO namespace. No key/env/token/socket or undeclared
	// source is allowed in the mount, including hidden descendants or symlinks.
	allowed := map[string]bool{"pre-intent-source-pins.json": false, "pre-intent-inputs.json": false, "native-helper": true, "native-helper/d101-host-reader": false,
		"pre-intent-inputs": true, "pre-intent-inputs/" + s.reviewed.OperationID: true, "pre-intent-inputs/" + s.reviewed.OperationID + "/configuration.json": false,
		"pre-intent-inputs/" + s.reviewed.OperationID + "/typed-target.json": false}
	seen := map[string]bool{}
	if err := filepath.WalkDir(s.inputLocal, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return errResetExecutionEvidence
		}
		if path == s.inputLocal {
			return requireResetD101PreIntentDirectory(path, false)
		}
		rel, err := filepath.Rel(s.inputLocal, path)
		if err != nil {
			return errResetExecutionEvidence
		}
		directory, ok := allowed[rel]
		if !ok || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != directory {
			return errResetExecutionEvidence
		}
		seen[rel] = true
		if directory {
			return requireResetD101PreIntentDirectory(path, false)
		}
		return nil
	}); err != nil || len(seen) != len(allowed) {
		return errResetExecutionEvidence
	}
	snapshots := map[string]d101custody.PrivateSnapshot{}
	profile, profileSnapshot, err := d101custody.CapturePrivateOriginal(filepath.Join(s.inputLocal, "pre-intent-source-pins.json"), 16<<10)
	if err != nil {
		return errResetExecutionEvidence
	}
	p, err := decodeResetD101PreIntentProfile(profile.Bytes, s.reviewed)
	if err != nil {
		return err
	}
	snapshots["pre-intent-source-pins.json"] = profileSnapshot
	bindings, bindingsSnapshot, err := d101custody.CapturePrivateOriginal(filepath.Join(s.inputLocal, "pre-intent-inputs.json"), 16<<10)
	if err != nil || bindings.SHA256 != p.InputBindingsSHA {
		return errResetExecutionEvidence
	}
	snapshots["pre-intent-inputs.json"] = bindingsSnapshot
	b, err := d101preinput.Decode(bindings.Bytes)
	if err != nil || b.OriginalOp != p.OriginalOp || b.TargetFingerprint != p.TargetFingerprint || b.AppSourceSHA != p.AppSourceSHA || !reflect.DeepEqual(b.ImagePins, p.ImagePins) || b.ArtifactsRoot != p.ArtifactsRoot {
		return errResetExecutionEvidence
	}
	originals := map[string]d101custody.Original{}
	for role, ref := range map[string]d101preinput.Reference{"configuration": b.Configuration, "typed-target": b.TypedTarget} {
		limit := int64(64 << 10)
		if role == "typed-target" {
			limit = 16 << 10
		}
		value, snapshot, err := d101custody.CapturePrivateOriginal(filepath.Join(s.inputLocal, "pre-intent-inputs", p.OriginalOp, role+".json"), limit)
		if err != nil || value.SHA256 != ref.RawSHA || uint64(len(value.Bytes)) != ref.ByteLength {
			return errResetExecutionEvidence
		}
		originals[role] = value
		snapshots["pre-intent-inputs/"+p.OriginalOp+"/"+role+".json"] = snapshot
	}
	helper, helperSnapshot, err := d101custody.CapturePrivateExecutable(filepath.Join(s.inputLocal, "native-helper", "d101-host-reader"), 32<<20)
	if err != nil || helper.SHA256 != p.HelperSHA {
		return errResetExecutionEvidence
	}
	snapshots["native-helper/d101-host-reader"] = helperSnapshot
	if s.snapshots != nil && !reflect.DeepEqual(snapshots, s.snapshots) {
		return errResetExecutionEvidence
	}
	if s.profileOriginal != nil && (!bytes.Equal(profile.Bytes, s.profileOriginal) || !bytes.Equal(bindings.Bytes, s.bindingsOriginal) || !reflect.DeepEqual(originals, s.inputOriginals)) {
		return errResetExecutionEvidence
	}
	if s.profileOriginal == nil {
		s.profile = p
		s.profileOriginal = append([]byte(nil), profile.Bytes...)
		s.bindingsOriginal = append([]byte(nil), bindings.Bytes...)
		s.inputOriginals = originals
		s.snapshots = snapshots
	}
	return nil
}

func requireResetD101PreIntentDirectory(path string, empty bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, ",\r\n") {
		return errResetExecutionEvidence
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return errResetExecutionEvidence
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errResetExecutionEvidence
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errResetExecutionEvidence
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errResetExecutionEvidence
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) || actual.Mode() != before.Mode() {
		return errResetExecutionEvidence
	}
	if empty {
		names, err := file.Readdirnames(-1)
		if err != nil || len(names) != 0 {
			return errResetExecutionEvidence
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		return errResetExecutionEvidence
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat.Uid != 0 {
		return errResetExecutionEvidence
	}
	return nil
}
