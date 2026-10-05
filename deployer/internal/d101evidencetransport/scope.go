// Package d101evidencetransport carries fixed original bytes. These types
// implement C9 common626dd702's existing wire, not issuer or origin authority.
package d101evidencetransport

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"opensamguk-deployer/internal/d101custody"
)

const MetadataMaxBytes = 64 << 10
const OriginalMaxBytes = 64 << 20
const existingDiskReserveBytes uint64 = 10 * 1024 * 1024 * 1024

var rawIDPattern = regexp.MustCompile(`^(?:raw:[A-Za-z0-9._:-]{1,123}|approvalReceipt|combinedCiReceipt|selectedSourceReceipt|isolatedSeedTickReceipt|spaceInventoryReceipt|approvalIntent|configInventory|commandPlan|recoveryPlan|readerBindings|evidenceCatalog|reviewBasis|deploymentCard|approvedReceiptProvenance)$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var opPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revisionPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type RawReference struct {
	LogicalID  string `json:"logicalId"`
	SHA256     string `json:"sha256"`
	ByteLength uint64 `json:"byteLength"`
	MediaType  string `json:"mediaType"`
}

func ValidateRawReference(ref RawReference) error {
	if len(ref.LogicalID) > 128 || !rawIDPattern.MatchString(ref.LogicalID) || !shaPattern.MatchString(ref.SHA256) || ref.ByteLength == 0 || ref.ByteLength > OriginalMaxBytes {
		return d101custody.ErrUnavailable
	}
	switch ref.MediaType {
	case "application/json", "application/xml", "application/zip", "text/plain", "application/octet-stream":
		return nil
	default:
		return d101custody.ErrUnavailable
	}
}

func DecodeRawReference(wire []byte) (RawReference, error) {
	var value RawReference
	if decodeExact(wire, &value, MetadataMaxBytes) != nil || ValidateRawReference(value) != nil {
		return RawReference{}, d101custody.ErrUnavailable
	}
	return value, nil
}

type Window struct {
	WindowOpensAtUnix     int64 `json:"windowOpensAtUnix"`
	DestructiveCutoffUnix int64 `json:"destructiveCutoffUnix"`
	RecoveryDeadlineUnix  int64 `json:"recoveryDeadlineUnix"`
}

type SpaceBudget struct {
	CandidateUnpackedBytes uint64 `json:"CandidateUnpackedBytes"`
	BackupBytes            uint64 `json:"BackupBytes"`
	RecoveryBytes          uint64 `json:"RecoveryBytes"`
	TemporaryBytes         uint64 `json:"TemporaryBytes"`
	NewFileCount           uint64 `json:"NewFileCount"`
	InodeReserve           uint64 `json:"InodeReserve"`
}

type Scope struct {
	OperationID           string            `json:"operationId"`
	ServerID              string            `json:"serverId"`
	WorldID               int               `json:"worldId"`
	TargetFingerprint     string            `json:"targetFingerprint"`
	TypedTargetRef        RawReference      `json:"typedTargetRef"`
	AppSourceSHA          string            `json:"appSourceSha"`
	DockerSourceSHA       string            `json:"dockerSourceSha"`
	OldImageDigests       map[string]string `json:"oldImageDigests"`
	NewImageDigests       map[string]string `json:"newImageDigests"`
	InitialPublicRevision string            `json:"initialPublicRevision"`
	Window                Window            `json:"window"`
	SpaceBudget           SpaceBudget       `json:"spaceBudget"`
}

// This follows common626dd702 plus the existing assembler semantic_format:
// window order, signed-long revision, typed-target binding and budget overflow.
// It does not impose freshness, a raw count/aggregate limit or approval meaning.
func DecodeScope(wire []byte) (Scope, error) {
	var value Scope
	if decodeExact(wire, &value, MetadataMaxBytes) != nil || ValidateScope(value) != nil {
		return Scope{}, d101custody.ErrUnavailable
	}
	return value, nil
}

func ValidateScope(value Scope) error {
	if !opPattern.MatchString(value.OperationID) || value.ServerID != "pep" || value.WorldID != 1 || !shaPattern.MatchString(value.TargetFingerprint) ||
		!sourcePattern.MatchString(value.AppSourceSHA) || !sourcePattern.MatchString(value.DockerSourceSHA) ||
		ValidateRawReference(value.TypedTargetRef) != nil || !strings.HasPrefix(value.TypedTargetRef.LogicalID, "raw:") || value.TypedTargetRef.SHA256 != value.TargetFingerprint ||
		value.TypedTargetRef.MediaType != "application/json" || value.TypedTargetRef.ByteLength > 16<<10 || !revisionPattern.MatchString(value.InitialPublicRevision) {
		return d101custody.ErrUnavailable
	}
	if _, err := strconv.ParseInt(value.InitialPublicRevision, 10, 64); err != nil {
		return d101custody.ErrUnavailable
	}
	w := value.Window
	if w.WindowOpensAtUnix <= 0 || w.DestructiveCutoffUnix <= w.WindowOpensAtUnix || w.RecoveryDeadlineUnix <= w.DestructiveCutoffUnix {
		return d101custody.ErrUnavailable
	}
	for _, pins := range []map[string]string{value.OldImageDigests, value.NewImageDigests} {
		if len(pins) != 5 {
			return d101custody.ErrUnavailable
		}
		for _, id := range []string{"game-api", "game-engine", "web-game", "game-postgres", "game-redis"} {
			pin := pins[id]
			if !strings.HasPrefix(pin, "sha256:") || !shaPattern.MatchString(strings.TrimPrefix(pin, "sha256:")) {
				return d101custody.ErrUnavailable
			}
		}
	}
	b := value.SpaceBudget
	sum := existingDiskReserveBytes
	for _, n := range []uint64{b.CandidateUnpackedBytes, b.BackupBytes, b.RecoveryBytes, b.TemporaryBytes} {
		if n > math.MaxUint64-sum {
			return d101custody.ErrUnavailable
		}
		sum += n
	}
	if b.NewFileCount > math.MaxUint64-b.InodeReserve {
		return d101custody.ErrUnavailable
	}
	return nil
}
