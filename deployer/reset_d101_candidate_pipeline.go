package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"
)

// Generated from this fixed core's stages and pinned seed-only artifact. It is
// reviewed and referenced by the approved card before host installation. The
// installer cannot replace it with request commands or a success switch.
type resetD101CandidateCommandPlan struct {
	SchemaVersion            int                         `json:"schemaVersion"`
	Kind                     string                      `json:"kind"`
	OperationID              string                      `json:"operationId"`
	ApprovalIntentSHA        string                      `json:"approvalIntentSha256"`
	TargetFingerprint        string                      `json:"targetFingerprint"`
	AppSourceSHA             string                      `json:"appSourceSha"`
	DockerSourceSHA          string                      `json:"dockerSourceSha"`
	NewImageDigests          map[string]string           `json:"newImageDigests"`
	SelectedSourceReceiptSHA string                      `json:"selectedSourceReceiptSha256"`
	SelectedEnvelopeSHA      string                      `json:"selectedEnvelopeSha256"`
	CapsReaderSHA            string                      `json:"capsReaderSha256"`
	SeedEntrypoint           string                      `json:"seedEntrypoint"`
	Stages                   []string                    `json:"stages"`
	DestructiveCutoffUnix    int64                       `json:"destructiveCutoffUnix"`
	Resources                resetD101CandidateResources `json:"resources"`
}

var resetD101CandidateStages = []string{"verify-current-authority-dispatch-freeze-space", "pull-pinned-candidate", "journal-before-env-down", "down-original-stack-once", "candidate-postgres-redis", "seed-only-child-exit-zero", "independent-both-db-numeric-50", "immutable-promotion-proof", "live-api-engine-web", "actual-runtime-observation"}

const resetD101CandidateSeedEntrypoint = "opensamguk.engine.boot.D101SeedOnlyCli"

type resetD101CandidatePipeline struct {
	commandOriginal []byte
	commandSHA      string
	cardSHA         string
	plan            resetD101CandidateCommandPlan
	caps            *resetD101CandidateCapsReader
	selected        resetD101VerifiedSelectedReceipt
	seeder          resetD101CandidateSeeder
}

func newResetD101CandidatePipeline(command []byte, card resetDecodedDeploymentCard, intent resetDecodedApprovalIntent, capsOriginal, selectedEnvelope, selectedSPKI []byte, producer string, seeder resetD101CandidateSeeder) (*resetD101CandidatePipeline, error) {
	freshIntent, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	intent = freshIntent
	freshCard, err := decodeResetD101DeploymentCard(card.originalBytes(), card.SHA, intent)
	if err != nil {
		return nil, errResetExecutionEvidence
	}
	card = freshCard
	var plan resetD101CandidateCommandPlan
	if seeder == nil || len(command) == 0 || len(command) > 32*1024 || requireResetIntentShape(command, reflect.TypeOf(plan)) != nil || decodeResetPrivateJSON(command, &plan) != nil ||
		resetD101OriginalSHA(command) != card.Card.CommandPlanSHA || plan.SchemaVersion != 1 || plan.Kind != "D101_ROOT_CANDIDATE_COMMAND_PLAN_V1" ||
		plan.OperationID != intent.Intent.OperationID || plan.ApprovalIntentSHA != intent.SHA || plan.TargetFingerprint != intent.Intent.TargetFingerprint ||
		plan.AppSourceSHA != intent.Intent.AppSourceSHA || plan.DockerSourceSHA != card.Card.DockerSourceSHA || !reflect.DeepEqual(plan.NewImageDigests, intent.Intent.NewImageDigests) ||
		plan.SelectedSourceReceiptSHA != intent.Intent.SelectedSourceReceiptSHA || plan.SelectedEnvelopeSHA != resetD101OriginalSHA(selectedEnvelope) ||
		plan.SeedEntrypoint != resetD101CandidateSeedEntrypoint || !reflect.DeepEqual(plan.Stages, resetD101CandidateStages) || plan.DestructiveCutoffUnix != intent.Intent.DestructiveCutoffUnix {
		return nil, errResetExecutionEvidence
	}
	if requireResetD101CandidateCompose(plan.Resources, plan.OperationID, plan.NewImageDigests) != nil {
		return nil, errResetExecutionEvidence
	}
	caps, err := newResetD101CandidateCapsReader(capsOriginal, plan.CapsReaderSHA)
	if err != nil {
		return nil, err
	}
	p := caps.pins
	if p.OperationID != plan.OperationID || p.ApprovalIntentSHA != plan.ApprovalIntentSHA || p.TargetFingerprint != plan.TargetFingerprint || p.AppSourceSHA != plan.AppSourceSHA || p.Network != plan.Resources.Network || !reflect.DeepEqual(p.ImagePins, plan.NewImageDigests) {
		return nil, errResetExecutionEvidence
	}
	selected, err := decodeResetD101SelectedReceipt(selectedEnvelope, selectedSPKI, resetD101OriginalSHA(selectedSPKI), producer, intent, time.Now())
	if err != nil {
		return nil, err
	}
	plan.NewImageDigests = cloneResetD101Strings(plan.NewImageDigests)
	plan.Stages = append([]string(nil), plan.Stages...)
	return &resetD101CandidatePipeline{append([]byte(nil), command...), card.Card.CommandPlanSHA, card.SHA, plan, caps, selected, seeder}, nil
}

// Native installation reads the actual card, command, DB reader and signed
// selected originals from fixed root-private directories. Current QUERY from
// the independently verified host source pins card/key/intent. It performs no
// Docker command, data change, key issuance or filesystem installation itself.
type resetD101CandidateInstallation struct {
	OperationID               string
	IntentSHA                 string
	CardDirectory             string
	CommandDirectory          string
	CapsDirectory             string
	SelectedEnvelopeDirectory string
	ProducerIdentity          string
}

func (c config) installResetD101CandidatePipeline(ctx context.Context, pins resetD101CandidateInstallation, seeder resetD101CandidateSeeder) (config, error) {
	closed := c
	if c.d101PurposeAuthority == nil || seeder == nil || ctx == nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	for _, dir := range []string{pins.CardDirectory, pins.CommandDirectory, pins.CapsDirectory, pins.SelectedEnvelopeDirectory} {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return closed, errResetExecutionEvidence
		}
	}
	authority, err := c.d101PurposeAuthority(ctx, pins.OperationID, pins.IntentSHA)
	if err != nil {
		return closed, errResetExecutionEvidence
	}
	intent, err := requireResetD101Authority(authority, resetD101PurposeGrantRequest{OperationID: pins.OperationID, ApprovalIntentSHA: pins.IntentSHA, Action: "QUERY"}, time.Now())
	if err != nil {
		return closed, err
	}
	read := func(dir string) ([]byte, error) { return readResetPrivateCustody(dir, pins.OperationID, 0) }
	cardOriginal, err := read(pins.CardDirectory)
	if err != nil {
		return closed, err
	}
	card, err := decodeResetD101DeploymentCard(cardOriginal, authority.DeploymentCardSHA, intent)
	if err != nil {
		return closed, err
	}
	command, err := read(pins.CommandDirectory)
	if err != nil {
		return closed, err
	}
	caps, err := read(pins.CapsDirectory)
	if err != nil {
		return closed, err
	}
	selected, err := read(pins.SelectedEnvelopeDirectory)
	if err != nil {
		return closed, err
	}
	key, err := readResetD101SigningKey(authority.KeyPins)
	if err != nil {
		return closed, err
	}
	defer key.close()
	spki, err := x509.MarshalPKIXPublicKey(key.private.Public())
	if err != nil || resetD101OriginalSHA(spki) != authority.KeyPins.PublicKeySpkiSHA {
		return closed, errResetExecutionEvidence
	}
	pipeline, err := newResetD101CandidatePipeline(command, card, intent, caps, selected, spki, pins.ProducerIdentity, seeder)
	if err != nil || ctx.Err() != nil {
		return closed, errResetExecutionEvidence
	}
	c.d101CandidatePipeline = pipeline
	return c, nil
}
func (p *resetD101CandidatePipeline) requireAdmission(a resetD101CandidateAdmission, authority resetD101VerifiedPurposeAuthority) error {
	if p == nil || p.seeder == nil || p.caps == nil || resetD101OriginalSHA(p.commandOriginal) != p.commandSHA || authority.DeploymentCardSHA != p.cardSHA ||
		p.plan.OperationID != a.OperationID() || p.plan.ApprovalIntentSHA != a.ApprovalIntentSHA() || p.plan.TargetFingerprint != a.TargetFingerprint() || p.plan.AppSourceSHA != a.AppSourceSHA() ||
		p.selected.sha != a.SelectedSourceReceiptSHA() || !reflect.DeepEqual(p.plan.NewImageDigests, a.ImagePins()) || p.plan.DestructiveCutoffUnix != a.Cutoff().Unix() {
		return errResetExecutionEvidence
	}
	return nil
}

// Actual seed-only process output. CID/exit/image facts remain the independent
// Root worker's observations and are never adopted from the process JSON.
const resetD101CandidateSeedOutputPrefix = "D101_SEED_ONLY_RESULT_V1\t"

type resetD101CandidateSeedReceipt struct {
	SchemaVersion            int               `json:"schemaVersion"`
	Kind                     string            `json:"kind"`
	OriginalOp               string            `json:"originalOp"`
	TargetFingerprint        string            `json:"typedTargetFingerprint"`
	AppSourceSHA             string            `json:"appSourceSha"`
	ImagePins                map[string]string `json:"imagePins"`
	SelectedSourceReceiptSHA string            `json:"selectedSourceReceiptSha256"`
	ScenarioRawSHA           string            `json:"scenarioRawSha256"`
	ScenarioRawLength        uint64            `json:"scenarioRawByteLength"`
	EffectiveOptions         map[string]string `json:"effectiveOptions"`
	OptionProvenance         map[string]string `json:"optionProvenance"`
	ActiveGeneralRows        uint64            `json:"activeGeneralRows"`
	ActiveRetainerRows       uint64            `json:"activeRetainerRows"`
	ConfigMaxGeneral         int               `json:"configMaxGeneral"`
	GameEnvMaxGeneral        int               `json:"gameEnvMaxGeneral"`
	ConfigOriginalSHA        string            `json:"candidateConfigOriginalSha256"`
	MetaOriginalSHA          string            `json:"candidateMetaOriginalSha256"`
	GameEnvOriginalSHA       string            `json:"candidateGameEnvOriginalSha256"`
	ObservedGeneration       *int              `json:"observedGeneration"`
	ObservedAtUTC            string            `json:"observedAtUtc"`
}

func (p *resetD101CandidatePipeline) requireSeed(a resetD101CandidateAdmission, e resetD101CandidateSeedEvidence, old map[string]string) error {
	var value resetD101CandidateSeedReceipt
	// Null generation is UNKNOWN, even if the approved input requested zero.
	if p == nil || len(e.Original) == 0 || len(e.Original) > 32*1024 || requireResetIntentShape(e.Original, reflect.TypeOf(value)) != nil || decodeResetPrivateJSON(e.Original, &value) != nil ||
		value.SchemaVersion != 1 || value.Kind != "D101_SEED_ONLY_RESULT_V1" || value.OriginalOp != a.OperationID() || value.TargetFingerprint != a.TargetFingerprint() || value.AppSourceSHA != a.AppSourceSHA() || !reflect.DeepEqual(value.ImagePins, a.ImagePins()) ||
		value.SelectedSourceReceiptSHA != p.selected.sha || value.SelectedSourceReceiptSHA != e.SelectedSourceReceiptSHA || !reflect.DeepEqual(value.EffectiveOptions, p.selected.value.EffectiveOptions) || !reflect.DeepEqual(value.OptionProvenance, p.selected.value.OptionProvenance) ||
		value.ObservedGeneration == nil || *value.ObservedGeneration != 0 || e.ActualGeneration != "0" || e.GenerationProvenanceSHA != p.selected.value.OptionProvenance["SERVER_GENERATION"] || value.ConfigMaxGeneral != 50 || value.GameEnvMaxGeneral != 50 ||
		!resetEvidenceSHA.MatchString(value.ConfigOriginalSHA) || !resetEvidenceSHA.MatchString(value.MetaOriginalSHA) || !resetEvidenceSHA.MatchString(value.GameEnvOriginalSHA) || value.ActiveGeneralRows != 384 || value.ActiveRetainerRows > 384 {
		return errResetExecutionEvidence
	}
	pin := p.selected.value.OriginalPins["selected-scenario.json"]
	if value.ScenarioRawSHA != pin.RawSHA || value.ScenarioRawLength != pin.ByteLength {
		return errResetExecutionEvidence
	}
	ids := map[string]bool{}
	for _, id := range []string{e.WorkerContainerID, e.PostgresContainerID, e.RedisContainerID} {
		if !resetEvidenceSHA.MatchString(id) || ids[id] {
			return errResetExecutionEvidence
		}
		ids[id] = true
		for _, oldID := range old {
			if oldID == id {
				return errResetExecutionEvidence
			}
		}
	}
	if !resetManifestDigest.MatchString(e.WorkerImageID) || e.CompletedAt.Before(e.StartedAt) || !e.CompletedAt.Before(a.Cutoff()) || e.CompletedAt.After(time.Now()) {
		return errResetExecutionEvidence
	}
	observed, err := resetD101RecoveryUTC(value.ObservedAtUTC)
	if err != nil || observed.Before(e.StartedAt) || observed.After(e.CompletedAt) {
		return errResetExecutionEvidence
	}
	return nil
}

type resetD101CandidatePromotionProof struct {
	SchemaVersion            int                         `json:"schemaVersion"`
	Kind                     string                      `json:"kind"`
	OperationID              string                      `json:"operationId"`
	ApprovalIntentSHA        string                      `json:"approvalIntentSha256"`
	TargetFingerprint        string                      `json:"targetFingerprint"`
	CommandPlanSHA           string                      `json:"commandPlanSha256"`
	SelectedSourceReceiptSHA string                      `json:"selectedSourceReceiptSha256"`
	SeedReceiptSHA           string                      `json:"seedReceiptSha256"`
	WorkerContainerID        string                      `json:"workerContainerId"`
	PostgresContainerID      string                      `json:"postgresContainerId"`
	RedisContainerID         string                      `json:"redisContainerId"`
	ActualCapsSHA            string                      `json:"actualCapsSha256"`
	CapsReaderSHA            string                      `json:"capsReaderSha256"`
	ObservedAtUTC            string                      `json:"observedAtUtc"`
	Resources                resetD101CandidateResources `json:"resources"`
	AppSourceSHA             string                      `json:"appSourceSha"`
}

func (c config) runResetD101CandidateThenPromote(ctx context.Context, a resetD101CandidateAdmission, old map[string]string, guard func(context.Context) error) error {
	p := c.d101CandidatePipeline
	if p == nil || guard == nil || ctx == nil || ctx.Err() != nil || guard(ctx) != nil {
		return errResetExecutionEvidence
	}
	a = a.withCandidateResources(p.plan.Resources)
	seed, err := p.seeder(ctx, a, guard)
	if err != nil {
		return errResetExecutionEvidence
	}
	// RepoDigest is inspected from the actual worker ImageID; config determines
	// the repository, not an input environment option.
	if seed.WorkerRepoDigest != "ghcr.io/"+c.ghcrOwner+"/opensamguk@"+a.ImagePins()["game-engine"] {
		return errResetExecutionEvidence
	}
	if p.requireSeed(a, seed, old) != nil {
		return errResetExecutionEvidence
	}
	caps, err := p.caps.observe(ctx, c, a, seed, guard)
	if err != nil || caps.postgresID != seed.PostgresContainerID {
		return errResetExecutionEvidence
	}
	if guard(ctx) != nil || time.Since(caps.completed) >= resetPreflightMaxAge {
		return errResetExecutionEvidence
	}
	// Persist both originals and an exclusive promotion boundary before live up.
	// An uncertain write consumes the boundary; no retry starts another stack.
	if writeResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-candidate-seed"), a.OperationID(), resetD101OriginalSHA(seed.Original), seed.Original) != nil ||
		writeResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-candidate-caps"), a.OperationID(), caps.sha, caps.original) != nil {
		return errResetExecutionEvidence
	}
	proof := resetD101CandidatePromotionProof{SchemaVersion: 1, Kind: "D101_CANDIDATE_PROMOTION_V1", OperationID: a.OperationID(), ApprovalIntentSHA: a.ApprovalIntentSHA(), TargetFingerprint: a.TargetFingerprint(), CommandPlanSHA: p.commandSHA, SelectedSourceReceiptSHA: p.selected.sha, SeedReceiptSHA: resetD101OriginalSHA(seed.Original), WorkerContainerID: seed.WorkerContainerID, PostgresContainerID: seed.PostgresContainerID, RedisContainerID: seed.RedisContainerID, ActualCapsSHA: caps.sha, CapsReaderSHA: caps.readerSHA, ObservedAtUTC: caps.completed.UTC().Format(time.RFC3339Nano), Resources: p.plan.Resources, AppSourceSHA: a.AppSourceSHA()}
	wire, err := json.Marshal(proof)
	if err != nil || createResetImmutablePrivateBytes(filepath.Join(c.serversDir, ".deployer-reset-candidate-promotion"), a.OperationID(), resetD101OriginalSHA(wire), wire, 0) != nil {
		return errResetExecutionEvidence
	}
	if guard(ctx) != nil || time.Since(caps.completed) >= resetPreflightMaxAge {
		return errResetExecutionEvidence
	}
	if err = c.promoteResetD101CandidateApps(ctx, a, seed, guard); err != nil {
		return errResetExecutionEvidence
	}
	return nil
}

// Fixed source command-plan producer. Parents bind these original bytes only
// after this scope and native Compose originals are frozen; no card SHA is put
// into its own referenced command original.
func produceResetD101CandidateCommandPlan(intent resetDecodedApprovalIntent, dockerSourceSHA string, resources resetD101CandidateResources, capsOriginal, selectedEnvelope []byte) ([]byte, error) {
	intent, err := decodeResetApprovalIntent(intent.originalBytes(), intent.SHA)
	if err != nil || !gitSHA40.MatchString(dockerSourceSHA) || requireResetD101CandidateCompose(resources, intent.Intent.OperationID, intent.Intent.NewImageDigests) != nil {
		return nil, errResetExecutionEvidence
	}
	caps, err := newResetD101CandidateCapsReader(capsOriginal, resetD101OriginalSHA(capsOriginal))
	if err != nil {
		return nil, err
	}
	if caps.pins.OperationID != intent.Intent.OperationID || caps.pins.ApprovalIntentSHA != intent.SHA || caps.pins.TargetFingerprint != intent.Intent.TargetFingerprint || caps.pins.AppSourceSHA != intent.Intent.AppSourceSHA || !reflect.DeepEqual(caps.pins.ImagePins, intent.Intent.NewImageDigests) || caps.pins.Network != resources.Network {
		return nil, errResetExecutionEvidence
	}
	plan := resetD101CandidateCommandPlan{SchemaVersion: 1, Kind: "D101_ROOT_CANDIDATE_COMMAND_PLAN_V1", OperationID: intent.Intent.OperationID, ApprovalIntentSHA: intent.SHA, TargetFingerprint: intent.Intent.TargetFingerprint, AppSourceSHA: intent.Intent.AppSourceSHA, DockerSourceSHA: dockerSourceSHA, NewImageDigests: cloneResetD101Strings(intent.Intent.NewImageDigests), SelectedSourceReceiptSHA: intent.Intent.SelectedSourceReceiptSHA, SelectedEnvelopeSHA: resetD101OriginalSHA(selectedEnvelope), CapsReaderSHA: caps.sha, SeedEntrypoint: resetD101CandidateSeedEntrypoint, Stages: append([]string(nil), resetD101CandidateStages...), DestructiveCutoffUnix: intent.Intent.DestructiveCutoffUnix, Resources: resources}
	return json.Marshal(plan)
}
