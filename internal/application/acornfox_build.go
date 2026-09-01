package application

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const AcornFoxBuildCPUMillis int64 = 500
const AcornFoxBuildMemoryBytes int64 = 512 << 20
const AcornFoxBuildDiskBytes int64 = 1 << 30
const AcornFoxBuildTimeoutSeconds int64 = 300

type AcornFoxBuildBinder struct{}

// Bind turns one accepted ready definition into an offline BuildKit request.
// acceptedAt is a durable acceptance fact: callers must reuse it when
// replaying the same accepted request instead of substituting wall-clock time.
func (binder AcornFoxBuildBinder) Bind(def contracts.AcornFoxDockerfileDefinition, source domain.SourceRevision, idempotency, targetRepository, storageKey string, acceptedAt time.Time) (contracts.BuildRequest, error) {
	return binder.bind(def, source, idempotency, targetRepository, storageKey, acceptedAt, contracts.NetworkPolicy{Mode: contracts.NetworkModeOffline})
}

// BindControlledEgress creates a digest-bound request only. It does not make
// a current composition network-capable; a matching worker policy is still
// required by the BuildKit provider and a later runtime acceptance gate.
func (binder AcornFoxBuildBinder) BindControlledEgress(def contracts.AcornFoxDockerfileDefinition, source domain.SourceRevision, idempotency, targetRepository, storageKey, workerPolicyDigest string, acceptedAt time.Time) (contracts.BuildRequest, error) {
	return binder.bind(def, source, idempotency, targetRepository, storageKey, acceptedAt, contracts.NetworkPolicy{Mode: contracts.NetworkModeControlledEgressV1, WorkerPolicyDigest: workerPolicyDigest})
}

func (AcornFoxBuildBinder) bind(def contracts.AcornFoxDockerfileDefinition, source domain.SourceRevision, idempotency, targetRepository, storageKey string, acceptedAt time.Time, network contracts.NetworkPolicy) (contracts.BuildRequest, error) {
	if err := def.Validate(); err != nil || def.Status != contracts.AcornFoxDockerfileReady {
		return contracts.BuildRequest{}, fmt.Errorf("AcornFox Dockerfile definition is not ready")
	}
	if err := verifyAcornFoxDefinitionDigest(def); err != nil {
		return contracts.BuildRequest{}, err
	}
	if err := source.Validate(); err != nil || def.SourceRevisionID != source.ID || def.SourceContentDigest != source.ContentDigest {
		return contracts.BuildRequest{}, fmt.Errorf("AcornFox build source does not match definition")
	}
	if acceptedAt.IsZero() {
		return contracts.BuildRequest{}, fmt.Errorf("AcornFox build accepted time is required")
	}
	idempotency = strings.TrimSpace(idempotency)
	if idempotency == "" {
		return contracts.BuildRequest{}, fmt.Errorf("AcornFox build idempotency is required")
	}
	if err := network.Validate(); err != nil {
		return contracts.BuildRequest{}, fmt.Errorf("AcornFox build network policy is invalid")
	}
	sum := sha256.Sum256([]byte(source.ID.String() + "\x00" + source.ContentDigest + "\x00" + def.DefinitionDigest + "\x00" + def.DockerfileDigest + "\x00" + string(network.EffectiveMode()) + "\x00" + network.WorkerPolicyDigest + "\x00" + idempotency))
	suffix := hex.EncodeToString(sum[:])
	plan := domain.BuildPlan{ID: domain.ID("plan_" + suffix[:32]), SourceRevisionID: source.ID, SourceDigest: source.ContentDigest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: targetRepository, Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: storageKey}, IdempotencyKey: idempotency, CreatedAt: acceptedAt.UTC(), AcornFoxDefinitionDigest: def.DefinitionDigest, AcornFoxDockerfileDigest: def.DockerfileDigest, AcornFoxNetworkMode: string(network.EffectiveMode()), AcornFoxWorkerPolicyDigest: network.WorkerPolicyDigest}
	if err := plan.Validate(); err != nil {
		return contracts.BuildRequest{}, err
	}
	return contracts.BuildRequest{BuildID: domain.ID("build_" + suffix[:32]), Plan: plan, Source: source, Resources: contracts.ResourceLimits{CPUMillis: AcornFoxBuildCPUMillis, MemoryBytes: AcornFoxBuildMemoryBytes, DiskBytes: AcornFoxBuildDiskBytes, TimeoutSeconds: AcornFoxBuildTimeoutSeconds, ConcurrencySlot: 1}, Network: network, Operation: contracts.OperationContext{IdempotencyKey: idempotency, Actor: "acornfox"}}, nil
}

func verifyAcornFoxDefinitionDigest(def contracts.AcornFoxDockerfileDefinition) error {
	canonical, err := contracts.CanonicalAcornFoxDockerfileJSON(def)
	if err != nil {
		return fmt.Errorf("AcornFox Dockerfile definition is invalid")
	}
	digest := sha256.Sum256(canonical)
	if def.DefinitionDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("AcornFox Dockerfile definition digest does not match its contents")
	}
	return nil
}
