package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/importers/dockerfile"
)

var (
	ErrAcornFoxFixCandidateInProgress = errors.New("fix candidate is in progress")
	ErrAcornFoxFixCandidateMismatch   = errors.New("fix candidate source does not match")
	ErrAcornFoxFixCandidateFailed     = errors.New("fix candidate failed")
)

const (
	AcornFoxFixCandidateStageSource   = "source"
	AcornFoxFixCandidateStageApply    = "apply"
	AcornFoxFixCandidateStageBuild    = "build"
	AcornFoxFixCandidateStageRuntime  = "runtime"
	AcornFoxFixCandidateStageComplete = "complete"
)

type acornFoxFixCandidateExecutionError struct {
	stage string
	cause error
}

func (e *acornFoxFixCandidateExecutionError) Error() string {
	return "fix candidate execution failed at " + e.stage
}

func (e *acornFoxFixCandidateExecutionError) Unwrap() error { return e.cause }

func AcornFoxFixCandidateFailureStage(err error) string {
	var failure *acornFoxFixCandidateExecutionError
	if errors.As(err, &failure) {
		return failure.stage
	}
	return "unknown"
}

type AcornFoxFixCandidateStatus string

const (
	AcornFoxFixCandidatePreparing     AcornFoxFixCandidateStatus = "preparing"
	AcornFoxFixCandidateValidated     AcornFoxFixCandidateStatus = "validated"
	AcornFoxFixCandidateSourceMatched AcornFoxFixCandidateStatus = "source_matched"
	AcornFoxFixCandidateFailed        AcornFoxFixCandidateStatus = "failed"
)

type AcornFoxFixCandidateRuntimeEvidence struct {
	TaskID           domain.ID          `json:"task_id"`
	Image            domain.ImageDigest `json:"image"`
	RuntimeState     string             `json:"runtime_state"`
	ProbeOutcome     string             `json:"probe_outcome"`
	HTTPStatus       *int               `json:"http_status,omitempty"`
	CleanupConfirmed bool               `json:"cleanup_confirmed"`
	EvidenceDigest   string             `json:"evidence_digest"`
}

type AcornFoxFixCandidate struct {
	ID                      domain.ID                           `json:"candidate_id"`
	ApplicationID           domain.ID                           `json:"application_id"`
	BaseSourceRevisionID    domain.ID                           `json:"base_source_revision_id"`
	BaseRepositoryURL       string                              `json:"base_repository_url"`
	BaseCommit              string                              `json:"base_commit"`
	BaseTreeDigest          string                              `json:"base_tree_digest"`
	PatchDigest             string                              `json:"patch_digest"`
	ResultTreeDigest        string                              `json:"result_tree_digest"`
	ContainerPort           int                                 `json:"container_port"`
	ChangedPaths            []string                            `json:"changed_paths"`
	CanonicalDiff           string                              `json:"canonical_diff,omitempty"`
	ValidatedImage          domain.ImageDigest                  `json:"validated_image"`
	BuildLogRef             string                              `json:"build_log_ref"`
	BuildEvidenceDigest     string                              `json:"build_evidence_digest"`
	Runtime                 AcornFoxFixCandidateRuntimeEvidence `json:"runtime"`
	MatchedSourceRevisionID domain.ID                           `json:"matched_source_revision_id,omitempty"`
	MatchedCommit           string                              `json:"matched_commit,omitempty"`
	OwnerAdminID            domain.ID                           `json:"-"`
	RequestKey              string                              `json:"-"`
	Status                  AcornFoxFixCandidateStatus          `json:"status"`
	CreatedAt               time.Time                           `json:"created_at"`
	ExpiresAt               time.Time                           `json:"expires_at"`
}

func (c AcornFoxFixCandidate) MarshalJSON() ([]byte, error) {
	if c.Status == AcornFoxFixCandidatePreparing || c.Status == AcornFoxFixCandidateFailed {
		return json.Marshal(struct {
			ID                   domain.ID                  `json:"candidate_id"`
			ApplicationID        domain.ID                  `json:"application_id"`
			BaseSourceRevisionID domain.ID                  `json:"base_source_revision_id"`
			Status               AcornFoxFixCandidateStatus `json:"status"`
			CreatedAt            time.Time                  `json:"created_at"`
		}{ID: c.ID, ApplicationID: c.ApplicationID, BaseSourceRevisionID: c.BaseSourceRevisionID, Status: c.Status, CreatedAt: c.CreatedAt})
	}
	type wire AcornFoxFixCandidate
	return json.Marshal(wire(c))
}

func (c AcornFoxFixCandidate) Validate() error {
	if !acornFoxCandidateID(c.ID) || domain.RequireID(c.ApplicationID, "application id") != nil || domain.RequireID(c.BaseSourceRevisionID, "base source revision id") != nil || domain.RequireID(c.OwnerAdminID, "administrator id") != nil || strings.TrimSpace(c.RequestKey) == "" || len(c.RequestKey) > 256 || c.CreatedAt.IsZero() {
		return domain.ValidationError("fix candidate is invalid")
	}
	if c.Status == AcornFoxFixCandidatePreparing || c.Status == AcornFoxFixCandidateFailed {
		if c.BaseRepositoryURL != "" || c.BaseCommit != "" || c.BaseTreeDigest != "" || c.PatchDigest != "" || c.ResultTreeDigest != "" || c.ContainerPort != 0 || len(c.ChangedPaths) != 0 || c.CanonicalDiff != "" || c.ValidatedImage != (domain.ImageDigest{}) || c.BuildLogRef != "" || c.BuildEvidenceDigest != "" || c.Runtime != (AcornFoxFixCandidateRuntimeEvidence{}) || !c.MatchedSourceRevisionID.Empty() || c.MatchedCommit != "" || !c.ExpiresAt.IsZero() {
			return domain.ValidationError("pending fix candidate contains validation evidence")
		}
		return nil
	}
	if c.BaseRepositoryURL == "" || !acornFoxCandidateCommit(c.BaseCommit) || !acornFoxCandidateDigest(c.BaseTreeDigest) || !acornFoxCandidateDigest(c.PatchDigest) || !acornFoxCandidateDigest(c.ResultTreeDigest) || c.BaseTreeDigest == c.ResultTreeDigest || c.ContainerPort < 1 || c.ContainerPort > 65535 || len(c.ChangedPaths) < 1 || len(c.ChangedPaths) > acornfoxcandidate.MaxChangedFiles || len(c.CanonicalDiff) < 1 || len(c.CanonicalDiff) > acornfoxcandidate.MaxPatchBytes || c.ValidatedImage.Validate() != nil || c.BuildLogRef == "" || !acornFoxCandidateDigest(c.BuildEvidenceDigest) || domain.RequireID(c.Runtime.TaskID, "runtime task id") != nil || c.Runtime.Image != c.ValidatedImage || c.Runtime.RuntimeState != "stopped" || c.Runtime.ProbeOutcome != "responded" || !c.Runtime.CleanupConfirmed || !acornFoxCandidateDigest(c.Runtime.EvidenceDigest) || !c.ExpiresAt.After(c.CreatedAt) {
		return domain.ValidationError("fix candidate is invalid")
	}
	for index, path := range c.ChangedPaths {
		if strings.TrimSpace(path) == "" || index > 0 && c.ChangedPaths[index-1] >= path {
			return domain.ValidationError("fix candidate paths are invalid")
		}
	}
	switch c.Status {
	case AcornFoxFixCandidateValidated:
		if !c.MatchedSourceRevisionID.Empty() || c.MatchedCommit != "" {
			return domain.ValidationError("unmatched fix candidate has source identity")
		}
	case AcornFoxFixCandidateSourceMatched:
		if domain.RequireID(c.MatchedSourceRevisionID, "matched source revision id") != nil || !acornFoxCandidateCommit(c.MatchedCommit) {
			return domain.ValidationError("matched fix candidate lacks source identity")
		}
	default:
		return domain.ValidationError("fix candidate status is invalid")
	}
	return nil
}

type AcornFoxFixCandidateBuildEvidence struct {
	Image          domain.ImageDigest
	LogRef         string
	EvidenceDigest string
}

type AcornFoxFixCandidateBuilder struct {
	Builder          contracts.BuildProvider
	Capacity         contracts.CapacityProvider
	Network          contracts.NetworkPolicy
	TargetRepository string
	StorageKeyPrefix string
	Clock            func() time.Time
}

type AcornFoxFixCandidateBuildValidator interface {
	Build(context.Context, acornfoxcandidate.Snapshot, string, string) (AcornFoxFixCandidateBuildEvidence, error)
}

func (b *AcornFoxFixCandidateBuilder) Build(ctx context.Context, snapshot acornfoxcandidate.Snapshot, idempotencyKey, actor string) (AcornFoxFixCandidateBuildEvidence, error) {
	if b == nil || b.Builder == nil || b.Capacity == nil || snapshot.Validate() != nil || strings.TrimSpace(idempotencyKey) == "" || strings.TrimSpace(actor) == "" || strings.TrimSpace(b.TargetRepository) == "" || strings.TrimSpace(b.StorageKeyPrefix) == "" || b.Network.Validate() != nil {
		return AcornFoxFixCandidateBuildEvidence{}, domain.ValidationError("candidate build is invalid")
	}
	source, err := snapshot.TransientSource()
	if err != nil {
		return AcornFoxFixCandidateBuildEvidence{}, err
	}
	definition, err := dockerfile.Import(source)
	if err != nil || definition.Validate() != nil || definition.Status != contracts.AcornFoxDockerfileReady {
		return AcornFoxFixCandidateBuildEvidence{}, errors.New("candidate Dockerfile is not ready")
	}
	now := time.Now().UTC()
	if b.Clock != nil {
		now = b.Clock().UTC()
	}
	storageKey := strings.TrimSpace(b.StorageKeyPrefix) + "-" + snapshot.ID.String()
	var request contracts.BuildRequest
	if b.Network.EffectiveMode() == contracts.NetworkModeControlledEgressV1 {
		request, err = (AcornFoxBuildBinder{}).BindControlledEgress(definition, source, idempotencyKey+":build", b.TargetRepository, storageKey, b.Network.WorkerPolicyDigest, now)
	} else {
		request, err = (AcornFoxBuildBinder{}).Bind(definition, source, idempotencyKey+":build", b.TargetRepository, storageKey, now)
	}
	if err != nil {
		return AcornFoxFixCandidateBuildEvidence{}, err
	}
	operation := contracts.OperationContext{IdempotencyKey: idempotencyKey + ":capacity", Actor: actor}
	lease, err := b.Capacity.Reserve(ctx, contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: request.Resources, Operation: operation})
	if err != nil {
		return AcornFoxFixCandidateBuildEvidence{}, err
	}
	defer b.Capacity.Release(context.Background(), lease, contracts.OperationContext{IdempotencyKey: idempotencyKey + ":capacity-release", Actor: actor})
	request.Capacity = &lease
	built, err := b.Builder.Build(ctx, request)
	if err != nil {
		return AcornFoxFixCandidateBuildEvidence{}, err
	}
	if built.Artifact == nil || built.Build.ID != request.BuildID || built.Build.PlanID != request.Plan.ID || built.Build.Status != domain.BuildSucceeded || built.Artifact.BuildID != request.BuildID || built.Artifact.Validate() != nil || strings.TrimSpace(built.LogRef) == "" {
		return AcornFoxFixCandidateBuildEvidence{}, errors.New("candidate build result is invalid")
	}
	digest := built.Evidence.Digest
	if !acornFoxCandidateDigest(digest) {
		digest = digestAcornFoxCandidateEvidence(built.Artifact.Image.Repository, built.Artifact.Image.Digest, built.LogRef, built.Artifact.OCIStorageRef)
	}
	return AcornFoxFixCandidateBuildEvidence{Image: built.Artifact.Image, LogRef: built.LogRef, EvidenceDigest: digest}, nil
}

type AcornFoxFixCandidateRuntimeRequest struct {
	CandidateID    domain.ID
	ApplicationID  domain.ID
	Image          domain.ImageDigest
	ContainerPort  int
	IdempotencyKey string
	Actor          string
}

type AcornFoxFixCandidateRuntimeValidator interface {
	ValidateCandidateRuntime(context.Context, AcornFoxFixCandidateRuntimeRequest) (AcornFoxFixCandidateRuntimeEvidence, error)
}

type AcornFoxFixCandidateWorkspace interface {
	Read(context.Context, domain.SourceRevision, []string) (acornfoxcandidate.ReadResult, error)
	ApplyFor(context.Context, domain.ID, domain.SourceRevision, string, []byte, time.Duration) (acornfoxcandidate.Snapshot, error)
	Verify(acornfoxcandidate.Snapshot) error
	Release(acornfoxcandidate.Snapshot) error
}

type AcornFoxFixCandidateStore interface {
	GetSourceRevision(context.Context, domain.ID) (domain.SourceRevision, error)
	GetAcornFoxSourceMetadata(context.Context, domain.ID, domain.ID) (contracts.AcornFoxSourceMetadata, error)
	AcornFoxApplicationHasActiveSecrets(context.Context, domain.ID) (bool, error)
	ReplayAcornFoxFixCandidate(context.Context, AcornFoxFixCandidateCreateRequest, string) (*AcornFoxFixCandidate, error)
	BeginAcornFoxFixCandidate(context.Context, AcornFoxFixCandidateCreateRequest, string, time.Time) (*AcornFoxFixCandidate, error)
	CompleteAcornFoxFixCandidate(context.Context, AcornFoxFixCandidate, string) error
	FailAcornFoxFixCandidate(context.Context, domain.ID, string, string, time.Time) error
	GetAcornFoxFixCandidate(context.Context, domain.ID, domain.ID) (AcornFoxFixCandidate, error)
	MatchAcornFoxFixCandidateSource(context.Context, domain.ID, domain.ID, domain.ID, string, time.Time) (AcornFoxFixCandidate, error)
}

type AcornFoxFixCandidatePublisher interface {
	CreateVerifiedCandidate(context.Context, AcornFoxDeliveryCreateRequest, domain.ImageDigest) (AcornFoxDeliveryResult, error)
	ReplayVerifiedCandidate(context.Context, AcornFoxDeliveryCreateRequest, domain.ImageDigest) (AcornFoxDeliveryResult, bool, error)
}

type AcornFoxFixCandidateCreateRequest struct {
	ApplicationID        domain.ID
	BaseSourceRevisionID domain.ID
	Paths                []string
	UnifiedDiff          []byte
	ContainerPort        int
	IdempotencyKey       string
	OwnerAdminID         domain.ID
}

type AcornFoxFixCandidateService struct {
	Store     AcornFoxFixCandidateStore
	Workspace AcornFoxFixCandidateWorkspace
	Builder   AcornFoxFixCandidateBuildValidator
	Runtime   AcornFoxFixCandidateRuntimeValidator
	Publisher AcornFoxFixCandidatePublisher
	Lifetime  time.Duration
	Clock     func() time.Time
}

func (s *AcornFoxFixCandidateService) ReadSource(ctx context.Context, applicationID, sourceRevisionID domain.ID, paths []string) (acornfoxcandidate.ReadResult, error) {
	if s == nil || s.Store == nil || s.Workspace == nil || applicationID.Empty() || sourceRevisionID.Empty() {
		return acornfoxcandidate.ReadResult{}, domain.ValidationError("candidate source read is invalid")
	}
	base, err := s.Store.GetSourceRevision(ctx, sourceRevisionID)
	if err != nil {
		return acornfoxcandidate.ReadResult{}, err
	}
	metadata, err := s.Store.GetAcornFoxSourceMetadata(ctx, applicationID, sourceRevisionID)
	if err != nil {
		return acornfoxcandidate.ReadResult{}, err
	}
	if base.ApplicationID != applicationID || base.Kind != domain.SourceGitHTTPS || !base.Immutable || metadata.Availability != contracts.AcornFoxAvailable || metadata.RepositoryURL != base.Locator {
		return acornfoxcandidate.ReadResult{}, domain.ValidationError("candidate source is not an application-owned public Git revision")
	}
	return s.Workspace.Read(ctx, base, paths)
}

func (s *AcornFoxFixCandidateService) ReadSourceForAI(ctx context.Context, applicationID, sourceRevisionID domain.ID, paths []string) (acornfoxcandidate.ReadResult, error) {
	if s == nil || s.Store == nil {
		return acornfoxcandidate.ReadResult{}, domain.NewError(domain.ErrUnavailable, "candidate source read is unavailable")
	}
	hasSecrets, err := s.Store.AcornFoxApplicationHasActiveSecrets(ctx, applicationID)
	if err != nil {
		return acornfoxcandidate.ReadResult{}, err
	}
	if hasSecrets {
		return acornfoxcandidate.ReadResult{}, domain.NewError(domain.ErrForbidden, "AI source read is unavailable for applications with secret references")
	}
	return s.ReadSource(ctx, applicationID, sourceRevisionID, paths)
}

func (s *AcornFoxFixCandidateService) Publish(ctx context.Context, applicationID, candidateID, ownerAdminID domain.ID, idempotencyKey string) (AcornFoxDeliveryResult, error) {
	if s == nil || s.Store == nil || s.Publisher == nil || applicationID.Empty() || candidateID.Empty() || ownerAdminID.Empty() || strings.TrimSpace(idempotencyKey) == "" {
		return AcornFoxDeliveryResult{}, domain.ValidationError("candidate publish is invalid")
	}
	candidate, err := s.Store.GetAcornFoxFixCandidate(ctx, applicationID, candidateID)
	if err != nil {
		return AcornFoxDeliveryResult{}, err
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	if candidate.OwnerAdminID != ownerAdminID || candidate.Status != AcornFoxFixCandidateSourceMatched {
		return AcornFoxDeliveryResult{}, ErrAcornFoxFixCandidateMismatch
	}
	request := AcornFoxDeliveryCreateRequest{ApplicationID: applicationID, SourceRevisionID: candidate.MatchedSourceRevisionID, ContainerPort: candidate.ContainerPort, IdempotencyKey: acornFoxCandidatePublishKey(candidate.ID, idempotencyKey), Actor: ownerAdminID.String()}
	if replay, found, err := s.Publisher.ReplayVerifiedCandidate(ctx, request, candidate.ValidatedImage); err != nil || found {
		return replay, err
	}
	if !now.Before(candidate.ExpiresAt) {
		return AcornFoxDeliveryResult{}, ErrAcornFoxFixCandidateMismatch
	}
	return s.Publisher.CreateVerifiedCandidate(ctx, request, candidate.ValidatedImage)
}

func acornFoxCandidatePublishKey(candidateID domain.ID, clientKey string) string {
	sum := sha256.Sum256([]byte(candidateID.String() + "\x00" + strings.TrimSpace(clientKey)))
	return "acornfox:candidate-publish:" + hex.EncodeToString(sum[:16])
}

func (s *AcornFoxFixCandidateService) Replay(ctx context.Context, request AcornFoxFixCandidateCreateRequest) (*AcornFoxFixCandidate, error) {
	if s == nil || s.Store == nil {
		return nil, domain.NewError(domain.ErrUnavailable, "fix candidate is unavailable")
	}
	if err := validateAcornFoxFixCandidateRequest(request); err != nil {
		return nil, err
	}
	return s.Store.ReplayAcornFoxFixCandidate(ctx, request, acornFoxFixCandidateRequestDigest(request))
}

func (s *AcornFoxFixCandidateService) Create(ctx context.Context, request AcornFoxFixCandidateCreateRequest) (AcornFoxFixCandidate, error) {
	if s == nil || s.Store == nil || s.Workspace == nil || s.Builder == nil || s.Runtime == nil {
		return AcornFoxFixCandidate{}, domain.NewError(domain.ErrUnavailable, "fix candidate is unavailable")
	}
	accepted, inserted, digest, err := s.Accept(ctx, request)
	if err != nil || !inserted {
		return accepted, err
	}
	return s.Execute(ctx, accepted, request, digest)
}

// Accept validates and durably reserves the stable identity returned to a
// caller before candidate build and runtime work starts.
func (s *AcornFoxFixCandidateService) Accept(ctx context.Context, request AcornFoxFixCandidateCreateRequest) (AcornFoxFixCandidate, bool, string, error) {
	if s == nil || s.Store == nil || s.Workspace == nil || s.Builder == nil || s.Runtime == nil {
		return AcornFoxFixCandidate{}, false, "", domain.NewError(domain.ErrUnavailable, "fix candidate is unavailable")
	}
	if err := validateAcornFoxFixCandidateRequest(request); err != nil {
		return AcornFoxFixCandidate{}, false, "", err
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	lifetime := s.Lifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	if lifetime < 5*time.Minute || lifetime > 24*time.Hour {
		return AcornFoxFixCandidate{}, false, "", domain.ValidationError("fix candidate lifetime is invalid")
	}
	digest := acornFoxFixCandidateRequestDigest(request)
	if replay, err := s.Store.BeginAcornFoxFixCandidate(ctx, request, digest, now); err != nil {
		return AcornFoxFixCandidate{}, false, "", err
	} else if replay != nil {
		return *replay, false, digest, nil
	}
	accepted := AcornFoxFixCandidate{ID: AcornFoxFixCandidateIDFromRequestDigest(digest), ApplicationID: request.ApplicationID, BaseSourceRevisionID: request.BaseSourceRevisionID, OwnerAdminID: request.OwnerAdminID, RequestKey: request.IdempotencyKey, Status: AcornFoxFixCandidatePreparing, CreatedAt: now}
	if err := accepted.Validate(); err != nil {
		return AcornFoxFixCandidate{}, false, "", err
	}
	return accepted, true, digest, nil
}

// Execute performs the bounded work for a previously accepted candidate.
func (s *AcornFoxFixCandidateService) Execute(ctx context.Context, accepted AcornFoxFixCandidate, request AcornFoxFixCandidateCreateRequest, digest string) (AcornFoxFixCandidate, error) {
	if accepted.Validate() != nil || accepted.Status != AcornFoxFixCandidatePreparing || accepted.ID != AcornFoxFixCandidateIDFromRequestDigest(digest) || digest != acornFoxFixCandidateRequestDigest(request) || accepted.ApplicationID != request.ApplicationID || accepted.BaseSourceRevisionID != request.BaseSourceRevisionID || accepted.OwnerAdminID != request.OwnerAdminID || accepted.RequestKey != request.IdempotencyKey {
		return AcornFoxFixCandidate{}, domain.ValidationError("accepted fix candidate is invalid")
	}
	lifetime := s.Lifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	fail := func(stage string, cause error) (AcornFoxFixCandidate, error) {
		failedAt := time.Now().UTC()
		if s.Clock != nil {
			failedAt = s.Clock().UTC()
		}
		failContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Store.FailAcornFoxFixCandidate(failContext, request.ApplicationID, request.IdempotencyKey, digest, failedAt)
		return AcornFoxFixCandidate{}, &acornFoxFixCandidateExecutionError{stage: stage, cause: cause}
	}
	base, err := s.Store.GetSourceRevision(ctx, request.BaseSourceRevisionID)
	if err != nil || base.ApplicationID != request.ApplicationID || base.Kind != domain.SourceGitHTTPS || !base.Immutable {
		if err == nil {
			err = domain.ValidationError("candidate base source is invalid")
		}
		return fail(AcornFoxFixCandidateStageSource, err)
	}
	metadata, err := s.Store.GetAcornFoxSourceMetadata(ctx, request.ApplicationID, request.BaseSourceRevisionID)
	if err != nil || metadata.Availability != contracts.AcornFoxAvailable || metadata.RepositoryURL != base.Locator {
		if err == nil {
			err = domain.ValidationError("candidate base source is not proven public")
		}
		return fail(AcornFoxFixCandidateStageSource, err)
	}
	read, err := s.Workspace.Read(ctx, base, request.Paths)
	if err != nil || read.BaseTreeDigest != base.ContentDigest {
		if err == nil {
			err = errors.New("candidate base read is inconsistent")
		}
		return fail(AcornFoxFixCandidateStageSource, err)
	}
	snapshot, err := s.Workspace.ApplyFor(ctx, accepted.ID, base, metadata.RepositoryURL, request.UnifiedDiff, lifetime)
	if err != nil {
		return fail(AcornFoxFixCandidateStageApply, err)
	}
	defer s.Workspace.Release(snapshot)
	allowed := make(map[string]bool, len(read.Files))
	for _, file := range read.Files {
		allowed[file.Path] = true
	}
	for _, path := range snapshot.ChangedPaths {
		if !allowed[path] {
			return fail(AcornFoxFixCandidateStageApply, domain.ValidationError("candidate changed a file outside the reviewed context"))
		}
	}
	if err := s.Workspace.Verify(snapshot); err != nil {
		return fail(AcornFoxFixCandidateStageApply, err)
	}
	built, err := s.Builder.Build(ctx, snapshot, request.IdempotencyKey, request.OwnerAdminID.String())
	if err != nil {
		return fail(AcornFoxFixCandidateStageBuild, err)
	}
	runtime, err := s.Runtime.ValidateCandidateRuntime(ctx, AcornFoxFixCandidateRuntimeRequest{CandidateID: snapshot.ID, ApplicationID: request.ApplicationID, Image: built.Image, ContainerPort: request.ContainerPort, IdempotencyKey: request.IdempotencyKey + ":runtime", Actor: request.OwnerAdminID.String()})
	if err != nil || !runtime.CleanupConfirmed || runtime.Image != built.Image {
		if err == nil {
			err = errors.New("candidate runtime cleanup was not confirmed")
		}
		return fail(AcornFoxFixCandidateStageRuntime, err)
	}
	candidate := AcornFoxFixCandidate{
		ID: snapshot.ID, ApplicationID: request.ApplicationID, BaseSourceRevisionID: base.ID,
		BaseRepositoryURL: metadata.RepositoryURL, BaseCommit: base.Commit, BaseTreeDigest: base.ContentDigest,
		PatchDigest: snapshot.PatchDigest, ResultTreeDigest: snapshot.TreeDigest, ContainerPort: request.ContainerPort,
		ChangedPaths: append([]string(nil), snapshot.ChangedPaths...), CanonicalDiff: string(snapshot.CanonicalDiff),
		ValidatedImage: built.Image, BuildLogRef: built.LogRef, BuildEvidenceDigest: built.EvidenceDigest,
		Runtime: runtime, OwnerAdminID: request.OwnerAdminID, RequestKey: request.IdempotencyKey, Status: AcornFoxFixCandidateValidated,
		CreatedAt: accepted.CreatedAt, ExpiresAt: snapshot.ExpiresAt,
	}
	if err := candidate.Validate(); err != nil {
		return fail(AcornFoxFixCandidateStageComplete, err)
	}
	if err := s.Store.CompleteAcornFoxFixCandidate(ctx, candidate, digest); err != nil {
		return fail(AcornFoxFixCandidateStageComplete, err)
	}
	return candidate, nil
}

func (s *AcornFoxFixCandidateService) MatchSource(ctx context.Context, applicationID, candidateID, sourceRevisionID, ownerAdminID domain.ID) (AcornFoxFixCandidate, error) {
	if s == nil || s.Store == nil || applicationID.Empty() || candidateID.Empty() || sourceRevisionID.Empty() || ownerAdminID.Empty() {
		return AcornFoxFixCandidate{}, domain.ValidationError("candidate source match is invalid")
	}
	candidate, err := s.Store.GetAcornFoxFixCandidate(ctx, applicationID, candidateID)
	if err != nil {
		return AcornFoxFixCandidate{}, err
	}
	if candidate.OwnerAdminID != ownerAdminID || candidate.Status != AcornFoxFixCandidateValidated {
		return AcornFoxFixCandidate{}, ErrAcornFoxFixCandidateMismatch
	}
	source, err := s.Store.GetSourceRevision(ctx, sourceRevisionID)
	if err != nil {
		return AcornFoxFixCandidate{}, err
	}
	metadata, err := s.Store.GetAcornFoxSourceMetadata(ctx, applicationID, sourceRevisionID)
	if err != nil {
		return AcornFoxFixCandidate{}, err
	}
	if source.ApplicationID != applicationID || source.Kind != domain.SourceGitHTTPS || source.Locator != candidate.BaseRepositoryURL || source.ContentDigest != candidate.ResultTreeDigest || metadata.Availability != contracts.AcornFoxAvailable || metadata.RepositoryURL != candidate.BaseRepositoryURL || source.Commit == "" {
		return AcornFoxFixCandidate{}, ErrAcornFoxFixCandidateMismatch
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	return s.Store.MatchAcornFoxFixCandidateSource(ctx, applicationID, candidateID, sourceRevisionID, source.Commit, now)
}

func validateAcornFoxFixCandidateRequest(request AcornFoxFixCandidateCreateRequest) error {
	if request.ApplicationID.Empty() || request.BaseSourceRevisionID.Empty() || request.OwnerAdminID.Empty() || strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 256 || len(request.Paths) < 1 || len(request.Paths) > acornfoxcandidate.MaxChangedFiles || len(request.UnifiedDiff) < 1 || len(request.UnifiedDiff) > acornfoxcandidate.MaxPatchBytes || request.ContainerPort < 1 || request.ContainerPort > 65535 {
		return domain.ValidationError("fix candidate request is invalid")
	}
	seen := make(map[string]bool, len(request.Paths))
	for _, path := range request.Paths {
		if strings.TrimSpace(path) == "" || seen[path] {
			return domain.ValidationError("fix candidate paths must be nonempty and unique")
		}
		seen[path] = true
	}
	if err := acornfoxcandidate.ValidatePatch(request.UnifiedDiff, request.Paths); err != nil {
		return domain.ValidationError("fix candidate patch is invalid")
	}
	return nil
}

func acornFoxFixCandidateRequestDigest(request AcornFoxFixCandidateCreateRequest) string {
	paths := append([]string(nil), request.Paths...)
	sort.Strings(paths)
	hash := sha256.New()
	for _, value := range []string{request.ApplicationID.String(), request.OwnerAdminID.String(), request.IdempotencyKey, request.BaseSourceRevisionID.String(), strings.Join(paths, "\x00"), string(request.UnifiedDiff), fmt.Sprint(request.ContainerPort)} {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func AcornFoxFixCandidateIDFromRequestDigest(digest string) domain.ID {
	if !acornFoxCandidateDigest(digest) {
		return ""
	}
	return domain.ID("candidate_" + digest[7:39])
}

func acornFoxCandidateID(id domain.ID) bool {
	value := id.String()
	if len(value) != len("candidate_")+32 || !strings.HasPrefix(value, "candidate_") {
		return false
	}
	for _, character := range value[len("candidate_"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func digestAcornFoxCandidateEvidence(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func acornFoxCandidateDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value[7:])
	return err == nil && len(decoded) == sha256.Size
}

func acornFoxCandidateCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
