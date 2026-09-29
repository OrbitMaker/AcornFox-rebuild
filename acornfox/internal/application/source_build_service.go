package application

import (
	"context"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

type SourceBuildService struct {
	RunStore      appcontracts.SourceBuiltRunStore
	ExportArchive func(context.Context, appcontracts.SourceBuiltArtifactFact) (*sourcebuildexecution.BuiltOCIReader, error)
	Store         appcontracts.SourceBuildPublicStore
	Policy        appcontracts.SourceBuildPolicyFact
	Available     func(context.Context) error
}

func (s *SourceBuildService) admit(ctx context.Context) error {
	if s == nil || s.Store == nil || s.Available == nil {
		return domain.NewError(domain.ErrUnavailable, "source-build integration unavailable")
	}
	if err := s.Store.SourceBuildSchemaReady(ctx); err != nil {
		return domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	if err := s.Available(ctx); err != nil {
		return domain.NewError(domain.ErrUnavailable, "source-build runtime unavailable")
	}
	return nil
}

var publicSourceCommit = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func (s *SourceBuildService) Prepare(ctx context.Context, admin domain.ID, in appcontracts.CreateSourcePrepareIntentInput) (appcontracts.SourceBuildPublicIntent, error) {
	if err := s.admit(ctx); err != nil {
		return appcontracts.SourceBuildPublicIntent{}, err
	}
	in.AppName = strings.TrimSpace(in.AppName)
	in.Repository = strings.TrimSpace(in.Repository)
	in.Commit = strings.TrimSpace(in.Commit)
	in.ExpectedContentDigest = strings.ToLower(strings.TrimSpace(in.ExpectedContentDigest))
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	canonical, err := appcontracts.CanonicalAcornFoxPublicRepositoryURL(in.Repository)
	rawURL, rawErr := url.Parse(in.Repository)
	u, parseErr := url.Parse(canonical)
	if err != nil || rawErr != nil || parseErr != nil || rawURL.User != nil || rawURL.RawQuery != "" || rawURL.Fragment != "" || u.Scheme != "https" || !publicSourceCommit.MatchString(in.Commit) {
		return appcontracts.SourceBuildPublicIntent{}, domain.ValidationError("explicit public HTTPS repository and pinned commit required")
	}
	host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || net.ParseIP(host) != nil {
		return appcontracts.SourceBuildPublicIntent{}, domain.ValidationError("explicit public HTTPS repository and pinned commit required")
	}
	// Syntax is not public-network provenance; the actual Source provider still
	// enforces public DNS/pinned endpoints and TLS before returning a revision.
	in.Repository = canonical
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 120
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 120 {
		return appcontracts.SourceBuildPublicIntent{}, domain.ValidationError("prepare timeout must be1..120seconds")
	}
	f, err := s.Store.CreateSourcePrepareIntent(ctx, admin, in)
	if err != nil {
		return appcontracts.SourceBuildPublicIntent{}, err
	}
	return publicAcceptedSourceIntent(f), nil
}
func (s *SourceBuildService) ApproveBuild(ctx context.Context, admin domain.ID, in appcontracts.SourceBuildPublicApprovalInput) (appcontracts.SourceBuildPublicIntent, error) {
	if err := s.admit(ctx); err != nil {
		return appcontracts.SourceBuildPublicIntent{}, err
	}
	in.ServiceName = strings.TrimSpace(in.ServiceName)
	in.ContextPath = strings.TrimSpace(in.ContextPath)
	in.DockerfilePath = strings.TrimSpace(in.DockerfilePath)
	in.TargetRepository = strings.TrimSpace(in.TargetRepository)
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	in.SourceDigest = strings.ToLower(strings.TrimSpace(in.SourceDigest))
	if in.ContextPath != "." || in.DockerfilePath != "Dockerfile" || !appcontracts.ValidPublicSourceBuildServiceName(in.ServiceName) || !appcontracts.ValidPublicSourceBuildResources(in.Resources) {
		return appcontracts.SourceBuildPublicIntent{}, domain.ValidationError("fixed Dockerfile/context and finite build budget required")
	}
	policy := s.Policy
	policy.Resources = in.Resources
	if policy.NetworkMode != "controlled_egress_v1" || policy.WorkerPolicyDigest == "" {
		return appcontracts.SourceBuildPublicIntent{}, domain.NewError(domain.ErrUnavailable, "trusted installed build network policy unavailable")
	}
	f, err := s.Store.ApprovePublicSourceBuildPlan(ctx, admin, in, policy)
	if err != nil {
		return appcontracts.SourceBuildPublicIntent{}, err
	}
	return publicAcceptedSourceIntent(f), nil
}
func (s *SourceBuildService) Read(ctx context.Context, admin, id domain.ID) (appcontracts.SourceBuildPublicIntent, error) {
	if s == nil || s.Store == nil {
		return appcontracts.SourceBuildPublicIntent{}, domain.NewError(domain.ErrUnavailable, "source-build integration unavailable")
	}
	if err := s.Store.SourceBuildSchemaReady(ctx); err != nil {
		return appcontracts.SourceBuildPublicIntent{}, domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	return s.Store.ReadPublicSourceBuildIntent(ctx, admin, id)
}
func publicAcceptedSourceIntent(f appcontracts.SourceBuildIntentFact) appcontracts.SourceBuildPublicIntent {
	out := appcontracts.SourceBuildPublicIntent{IntentID: f.ID, Stage: f.Stage, State: f.State, ApplicationID: f.ApplicationID, OperationID: f.OperationID, PrepareIntentID: f.PrepareIntentID, BuildID: f.BuildID}
	if f.Source != nil {
		out.SourceRevisionID = f.Source.ID
		out.SourceDigest = f.Source.ContentDigest
	}
	if f.Plan != nil {
		out.PlanID = f.Plan.ID
	}
	return out
}

// PreviewRun reads and verifies the real immutable SourceRole archive before
// storing a user-reviewable source-origin plan. It never imports into Docker or
// creates a deployment task; that requires a separate explicit confirmation.
func (s *SourceBuildService) PreviewRun(ctx context.Context, admin domain.ID, in appcontracts.SourceRunPlanInput) (appcontracts.ImagePlan, error) {
	var zero appcontracts.ImagePlan
	if s == nil || s.RunStore == nil || s.ExportArchive == nil || s.Available == nil {
		return zero, domain.NewError(domain.ErrUnavailable, "source-built runtime handoff unavailable")
	}
	if err := s.RunStore.SourceBuildSchemaReady(ctx); err != nil {
		return zero, domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	if in.BuildIntentID.Empty() || in.ArtifactID.Empty() || in.IdempotencyKey == "" || len(in.IdempotencyKey) > 256 || in.Port < 0 || in.Port > 65535 {
		return zero, domain.ValidationError("source-run original artifact, key or port invalid")
	}
	env, err := normalizeEnvironment(in.Environment)
	if err != nil {
		return zero, err
	}
	volumes, err := normalizeVolumes(in.Volumes)
	if err != nil {
		return zero, err
	}
	resources, err := normalizeResources(in.Resources)
	if err != nil {
		return zero, err
	}
	fact, err := s.RunStore.ReadSourceBuiltArtifact(ctx, admin, in.BuildIntentID, in.ArtifactID)
	if err != nil {
		return zero, err
	}
	canon := appcontracts.CanonicalExecutionInput{AppName: fact.AppName, Repository: fact.Image.Repository, ResolvedRef: fact.Image.Digest, Port: in.Port, Environment: env, Resources: resources, Volumes: volumes}
	if replay, found, err := s.RunStore.ReadSourceRunPlanReplay(ctx, admin, in, canon); err != nil {
		return zero, err
	} else if found {
		return replay, nil
	}
	if err := s.Available(ctx); err != nil {
		return zero, domain.NewError(domain.ErrUnavailable, "source role unavailable")
	}
	transferCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	reader, err := s.ExportArchive(transferCtx, fact)
	if err != nil {
		return zero, domain.NewError(domain.ErrUnavailable, "original source-built archive unavailable")
	}
	observed := reader.Identity()
	_, readErr := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || observed.ArchiveSize != fact.SizeBytes || observed.ManifestDigest != fact.Image.Digest || observed.OS != "linux" || observed.Architecture != "amd64" || observed.ConfigDigest == "" {
		return zero, domain.NewError(domain.ErrConflict, "source-built OCI identity could not be verified")
	}
	return s.RunStore.CreateSourceRunPlan(transferCtx, admin, in, canon, appcontracts.SourceRunOCIIdentity{ArchiveSize: observed.ArchiveSize, ManifestDigest: observed.ManifestDigest, ConfigDigest: observed.ConfigDigest, OS: observed.OS, Architecture: observed.Architecture})
}
func (s *SourceBuildService) ReadRunPlan(ctx context.Context, admin, planID domain.ID) (appcontracts.ImagePlan, error) {
	if s == nil || s.RunStore == nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnavailable, "source-built runtime handoff unavailable")
	}
	if err := s.RunStore.SourceBuildSchemaReady(ctx); err != nil {
		return appcontracts.ImagePlan{}, domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	return s.RunStore.ReadSourceRunPlan(ctx, admin, planID)
}
func (s *SourceBuildService) ConfirmRun(ctx context.Context, admin domain.ID, in appcontracts.ConfirmImagePlanInput) (appcontracts.ConfirmImagePlanResult, error) {
	if s == nil || s.RunStore == nil {
		return appcontracts.ConfirmImagePlanResult{}, domain.NewError(domain.ErrUnavailable, "source-built runtime handoff unavailable")
	}
	if err := s.RunStore.SourceBuildSchemaReady(ctx); err != nil {
		return appcontracts.ConfirmImagePlanResult{}, domain.NewError(domain.ErrUnavailable, "source-build schema unavailable")
	}
	if in.PlanID.Empty() || in.PlanDigest == "" || in.IdempotencyKey == "" || len(in.IdempotencyKey) > 256 {
		return appcontracts.ConfirmImagePlanResult{}, domain.ValidationError("original source-run plan, digest and confirmation key required")
	}
	return s.RunStore.ConfirmSourceRunPlan(ctx, admin, in)
}
