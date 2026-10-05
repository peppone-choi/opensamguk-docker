package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"opensamguk-deployer/internal/d101custody"
	"opensamguk-deployer/internal/d101preinput"
)

// Independent input action: selection/receipt/capture-index/approval originals
// do not exist yet. Only the reviewed native input bindings select the scope.
func readPreIntentInputs(read privateReader) ([]byte, error) {
	if read == nil {
		return nil, d101custody.ErrUnavailable
	}
	installation, err := read(d101preinput.BindingsPath, 16<<10)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	bindings, err := d101preinput.Decode(installation.Bytes)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	originals := map[string]d101custody.Original{}
	for role, ref := range map[string]d101preinput.Reference{"configuration": bindings.Configuration, "typed-target": bindings.TypedTarget} {
		path, err := d101preinput.InputPath(bindings.OriginalOp, role)
		if err != nil {
			return nil, d101custody.ErrUnavailable
		}
		limit := int64(64 << 10)
		if role == "typed-target" {
			limit = 16 << 10
		}
		value, err := read(path, limit)
		if err != nil || value.SHA256 != ref.RawSHA || uint64(len(value.Bytes)) != ref.ByteLength {
			return nil, d101custody.ErrUnavailable
		}
		originals[role] = value
	}
	for role, original := range originals {
		path, _ := d101preinput.InputPath(bindings.OriginalOp, role)
		after, err := read(path, int64(len(original.Bytes)))
		if err != nil || after.SHA256 != original.SHA256 || !bytes.Equal(after.Bytes, original.Bytes) {
			return nil, d101custody.ErrUnavailable
		}
	}
	after, err := read(d101preinput.BindingsPath, 16<<10)
	if err != nil || after.SHA256 != installation.SHA256 || !bytes.Equal(after.Bytes, installation.Bytes) {
		return nil, d101custody.ErrUnavailable
	}
	return json.Marshal(struct {
		SchemaVersion      int    `json:"schemaVersion"`
		InstallationSHA    string `json:"preIntentInstallationSha256"`
		InstallationBytes  string `json:"preIntentInstallationBytesBase64url"`
		ConfigurationBytes string `json:"configurationBytesBase64url"`
		TargetBytes        string `json:"typedTargetBytesBase64url"`
	}{1, installation.SHA256, base64.RawURLEncoding.EncodeToString(installation.Bytes), base64.RawURLEncoding.EncodeToString(originals["configuration"].Bytes), base64.RawURLEncoding.EncodeToString(originals["typed-target"].Bytes)})
}
