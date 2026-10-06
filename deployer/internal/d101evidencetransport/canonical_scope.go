package d101evidencetransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"opensamguk-deployer/internal/d101custody"
)

// Scope digest is C9's derived value hash, not its original RawRef wholeSHA.
// All accepted scope strings are ASCII. Sorted object keys and exact integers
// therefore match UTF8/key-sort/no-whitespace/no-newline C9 encoding.
func CanonicalScopeBytes(scope Scope) ([]byte, error) {
	if ValidateScope(scope) != nil {
		return nil, d101custody.ErrUnavailable
	}
	wire, err := json.Marshal(scope)
	if err != nil {
		return nil, d101custody.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber() // Preserve uint64 budgets; never convert through float64.
	var value any
	if decoder.Decode(&value) != nil {
		return nil, d101custody.ErrUnavailable
	}
	canonical, err := json.Marshal(value) // Maps, including nested maps, sort keys.
	if err != nil || len(canonical) > MetadataMaxBytes {
		return nil, d101custody.ErrUnavailable
	}
	return canonical, nil
}

func ScopeDigest(scope Scope) (string, error) {
	wire, err := CanonicalScopeBytes(scope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}
