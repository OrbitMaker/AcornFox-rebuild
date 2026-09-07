package application

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type candidateBuildProvider struct {
	request contracts.BuildRequest
}

func (p *candidateBuildProvider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}

func (p *candidateBuildProvider) Cancel(context.Context, contracts.OperationContext) error {
	return nil
}

func (p *candidateBuildProvider) Build(_ context.Context, request contracts.BuildRequest) (contracts.BuildResult, error) {
	p.request = request
	image, _ := domain.ParseImageDigest(request.Plan.TargetRepository, "sha256:"+strings.Repeat("a", 64))
	artifact := &domain.Artifact{ID: "artifact_candidate", BuildID: request.BuildID, Image: image, OCIStorageRef: "oci://candidate", SizeBytes: 123, CreatedAt: request.Plan.CreatedAt}
	return contracts.BuildResult{Build: domain.Build{ID: request.BuildID, PlanID: request.Plan.ID, Status: domain.BuildSucceeded}, Artifact: artifact, LogRef: "candidate-log", Evidence: contracts.Evidence{Digest: "sha256:" + strings.Repeat("b", 64)}}, nil
}

type candidateCapacity struct{ lease contracts.CapacityLease }

func (c *candidateCapacity) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (c *candidateCapacity) Preflight(context.Context, contracts.CapacityRequest) (contracts.CapacitySnapshot, contracts.Evidence, error) {
	return contracts.CapacitySnapshot{}, contracts.Evidence{}, nil
}
func (c *candidateCapacity) Reserve(_ context.Context, request contracts.CapacityRequest) (contracts.CapacityLease, error) {
	c.lease = contracts.CapacityLease{ID: "candidate-capacity", Scope: contracts.CapacityBuild, Resources: request.Resources, ExpiresAt: time.Now().Add(time.Minute)}
	return c.lease, nil
}
func (c *candidateCapacity) Activate(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}
func (c *candidateCapacity) Release(context.Context, contracts.CapacityLease, contracts.OperationContext) error {
	return nil
}

func TestAcornFoxFixCandidateBuilderUsesTransientNonGitSource(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := applicationCandidateSnapshot(t, now)
	provider := &candidateBuildProvider{}
	builder := &AcornFoxFixCandidateBuilder{Builder: provider, Capacity: &candidateCapacity{}, Network: contracts.NetworkPolicy{Mode: contracts.NetworkModeOffline}, TargetRepository: "local/acornfox-candidate", StorageKeyPrefix: "candidate", Clock: func() time.Time { return now }}
	evidence, err := builder.Build(context.Background(), snapshot, "fix-1", "admin_1")
	if err != nil {
		t.Fatal(err)
	}
	if provider.request.Source.Kind != domain.SourceUpload || provider.request.Source.Commit != "" || provider.request.Source.Locator != "candidate://"+snapshot.ID.String() || provider.request.Plan.SourceDigest != snapshot.TreeDigest || provider.request.Capacity == nil || evidence.Image.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("request=%+v evidence=%+v", provider.request, evidence)
	}
}

type fixCandidateStoreFixture struct {
	base, imported domain.SourceRevision
	metadata       map[domain.ID]contracts.AcornFoxSourceMetadata
	completed      AcornFoxFixCandidate
	failed         bool
	hasSecrets     bool
	beginCalls     int
}

func (f *fixCandidateStoreFixture) AcornFoxApplicationHasActiveSecrets(context.Context, domain.ID) (bool, error) {
	return f.hasSecrets, nil
}
func (f *fixCandidateStoreFixture) ReplayAcornFoxFixCandidate(context.Context, AcornFoxFixCandidateCreateRequest, string) (*AcornFoxFixCandidate, error) {
	return nil, nil
}

func (f *fixCandidateStoreFixture) GetSourceRevision(_ context.Context, id domain.ID) (domain.SourceRevision, error) {
	if id == f.base.ID {
		return f.base, nil
	}
	if id == f.imported.ID {
		return f.imported, nil
	}
	return domain.SourceRevision{}, errors.New("missing")
}
func (f *fixCandidateStoreFixture) GetAcornFoxSourceMetadata(_ context.Context, _ domain.ID, id domain.ID) (contracts.AcornFoxSourceMetadata, error) {
	value, ok := f.metadata[id]
	if !ok {
		return contracts.AcornFoxSourceMetadata{}, errors.New("missing")
	}
	return value, nil
}
func (f *fixCandidateStoreFixture) BeginAcornFoxFixCandidate(context.Context, AcornFoxFixCandidateCreateRequest, string, time.Time) (*AcornFoxFixCandidate, error) {
	f.beginCalls++
	return nil, nil
}
func (f *fixCandidateStoreFixture) CompleteAcornFoxFixCandidate(_ context.Context, value AcornFoxFixCandidate, _ string) error {
	f.completed = value
	return nil
}
func (f *fixCandidateStoreFixture) FailAcornFoxFixCandidate(context.Context, domain.ID, string, string, time.Time) error {
	f.failed = true
	return nil
}
func (f *fixCandidateStoreFixture) GetAcornFoxFixCandidate(context.Context, domain.ID, domain.ID) (AcornFoxFixCandidate, error) {
	return f.completed, nil
}
func (f *fixCandidateStoreFixture) MatchAcornFoxFixCandidateSource(_ context.Context, _, _, source domain.ID, commit string, _ time.Time) (AcornFoxFixCandidate, error) {
	f.completed.Status, f.completed.MatchedSourceRevisionID, f.completed.MatchedCommit = AcornFoxFixCandidateSourceMatched, source, commit
	return f.completed, nil
}

type fixCandidateWorkspaceFixture struct{ snapshot acornfoxcandidate.Snapshot }

func (f fixCandidateWorkspaceFixture) Read(_ context.Context, base domain.SourceRevision, _ []string) (acornfoxcandidate.ReadResult, error) {
	return acornfoxcandidate.ReadResult{BaseSourceRevisionID: base.ID, BaseCommit: base.Commit, BaseTreeDigest: base.ContentDigest, Files: []acornfoxcandidate.SourceFile{{Path: "Dockerfile", Content: "base", Bytes: 4}}}, nil
}
func (f fixCandidateWorkspaceFixture) ApplyFor(_ context.Context, id domain.ID, _ domain.SourceRevision, _ string, _ []byte, _ time.Duration) (acornfoxcandidate.Snapshot, error) {
	value := f.snapshot
	value.ID = id
	return value, nil
}
func (f fixCandidateWorkspaceFixture) Verify(acornfoxcandidate.Snapshot) error  { return nil }
func (f fixCandidateWorkspaceFixture) Release(acornfoxcandidate.Snapshot) error { return nil }

type fixCandidateBuilderFixture struct {
	evidence AcornFoxFixCandidateBuildEvidence
}

func (f fixCandidateBuilderFixture) Build(context.Context, acornfoxcandidate.Snapshot, string, string) (AcornFoxFixCandidateBuildEvidence, error) {
	return f.evidence, nil
}

type fixCandidateRuntimeFixture struct {
	evidence AcornFoxFixCandidateRuntimeEvidence
}

func (f fixCandidateRuntimeFixture) ValidateCandidateRuntime(context.Context, AcornFoxFixCandidateRuntimeRequest) (AcornFoxFixCandidateRuntimeEvidence, error) {
	return f.evidence, nil
}

type fixCandidatePublisherFixture struct {
	request AcornFoxDeliveryCreateRequest
	image   domain.ImageDigest
	replay  *AcornFoxDeliveryResult
}

func (f *fixCandidatePublisherFixture) CreateVerifiedCandidate(_ context.Context, request AcornFoxDeliveryCreateRequest, image domain.ImageDigest) (AcornFoxDeliveryResult, error) {
	f.request, f.image = request, image
	return AcornFoxDeliveryResult{DeploymentID: "dep_candidate", OperationID: "op_candidate", TaskID: "task_candidate", Status: "accepted"}, nil
}

func (f *fixCandidatePublisherFixture) ReplayVerifiedCandidate(_ context.Context, request AcornFoxDeliveryCreateRequest, image domain.ImageDigest) (AcornFoxDeliveryResult, bool, error) {
	f.request, f.image = request, image
	if f.replay == nil {
		return AcornFoxDeliveryResult{}, false, nil
	}
	return *f.replay, true, nil
}

func TestAcornFoxFixCandidateServiceBindsPublicBaseRuntimeAndSourceMatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	snapshot := applicationCandidateSnapshot(t, now)
	base := domain.SourceRevision{ID: snapshot.BaseSourceRevisionID, ApplicationID: snapshot.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: snapshot.BaseRepositoryURL, Ref: "main", Commit: snapshot.BaseCommit, ContentDigest: snapshot.BaseTreeDigest, WorkspaceRef: "/immutable/base", CreatedAt: now, Immutable: true}
	imported := base
	imported.ID, imported.Commit, imported.ContentDigest = "src_imported", strings.Repeat("d", 40), snapshot.TreeDigest
	image, _ := domain.ParseImageDigest("local/candidate", "sha256:"+strings.Repeat("a", 64))
	store := &fixCandidateStoreFixture{base: base, imported: imported, metadata: map[domain.ID]contracts.AcornFoxSourceMetadata{
		base.ID:     {SourceRevisionID: base.ID, Availability: contracts.AcornFoxAvailable, RepositoryURL: base.Locator},
		imported.ID: {SourceRevisionID: imported.ID, Availability: contracts.AcornFoxAvailable, RepositoryURL: base.Locator},
	}}
	runtime := AcornFoxFixCandidateRuntimeEvidence{TaskID: "task_candidate", Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: "sha256:" + strings.Repeat("e", 64)}
	publisher := &fixCandidatePublisherFixture{}
	service := &AcornFoxFixCandidateService{Store: store, Workspace: fixCandidateWorkspaceFixture{snapshot: snapshot}, Builder: fixCandidateBuilderFixture{evidence: AcornFoxFixCandidateBuildEvidence{Image: image, LogRef: "log", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)}}, Runtime: fixCandidateRuntimeFixture{evidence: runtime}, Publisher: publisher, Clock: func() time.Time { return now }, Lifetime: time.Hour}
	request := AcornFoxFixCandidateCreateRequest{ApplicationID: base.ApplicationID, BaseSourceRevisionID: base.ID, Paths: []string{"Dockerfile"}, UnifiedDiff: snapshot.CanonicalDiff, ContainerPort: 8080, IdempotencyKey: "fix-1", OwnerAdminID: "admin_1"}
	candidate, err := service.Create(context.Background(), request)
	if err != nil || candidate.Status != AcornFoxFixCandidateValidated || candidate.BaseCommit != base.Commit || candidate.ValidatedImage != image || store.failed {
		t.Fatalf("candidate=%+v failed=%v err=%v", candidate, store.failed, err)
	}
	matched, err := service.MatchSource(context.Background(), base.ApplicationID, candidate.ID, imported.ID, request.OwnerAdminID)
	if err != nil || matched.Status != AcornFoxFixCandidateSourceMatched || matched.MatchedSourceRevisionID != imported.ID {
		t.Fatalf("matched=%+v err=%v", matched, err)
	}
	published, err := service.Publish(context.Background(), base.ApplicationID, candidate.ID, request.OwnerAdminID, "publish-1")
	if err != nil || published.Status != "accepted" || publisher.request.SourceRevisionID != imported.ID || publisher.request.ContainerPort != request.ContainerPort || publisher.request.IdempotencyKey != acornFoxCandidatePublishKey(candidate.ID, "publish-1") || publisher.image != image {
		t.Fatalf("published=%+v request=%+v image=%+v err=%v", published, publisher.request, publisher.image, err)
	}
	store.imported.ContentDigest = "sha256:" + strings.Repeat("f", 64)
	store.completed = candidate
	if _, err := service.MatchSource(context.Background(), base.ApplicationID, candidate.ID, imported.ID, request.OwnerAdminID); !errors.Is(err, ErrAcornFoxFixCandidateMismatch) {
		t.Fatalf("mismatched source err=%v", err)
	}
}

func TestAcornFoxFixCandidatePublishReplaysAcceptedReceiptAfterExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	candidate := persistedApplicationCandidate(now)
	candidate.Status = AcornFoxFixCandidateSourceMatched
	candidate.MatchedSourceRevisionID = "src_imported"
	candidate.MatchedCommit = strings.Repeat("d", 40)
	candidate.ExpiresAt = now.Add(-time.Minute)
	receipt := AcornFoxDeliveryResult{DeploymentID: "dep_replay", OperationID: "op_replay", TaskID: "task_replay", Status: "accepted"}
	store := &fixCandidateStoreFixture{completed: candidate}
	publisher := &fixCandidatePublisherFixture{replay: &receipt}
	service := &AcornFoxFixCandidateService{Store: store, Publisher: publisher, Clock: func() time.Time { return now }}
	got, err := service.Publish(context.Background(), candidate.ApplicationID, candidate.ID, candidate.OwnerAdminID, "publish-stable")
	if err != nil || got != receipt {
		t.Fatalf("receipt=%+v err=%v", got, err)
	}
	publisher.replay = nil
	if _, err := service.Publish(context.Background(), candidate.ApplicationID, candidate.ID, candidate.OwnerAdminID, "publish-never-accepted"); !errors.Is(err, ErrAcornFoxFixCandidateMismatch) {
		t.Fatalf("expired new publish err=%v", err)
	}
}

func persistedApplicationCandidate(now time.Time) AcornFoxFixCandidate {
	image, _ := domain.ParseImageDigest("local/candidate", "sha256:"+strings.Repeat("a", 64))
	return AcornFoxFixCandidate{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", BaseRepositoryURL: "https://github.com/OrbitMaker/acornfox.git", BaseCommit: strings.Repeat("b", 40), BaseTreeDigest: "sha256:" + strings.Repeat("1", 64), PatchDigest: "sha256:" + strings.Repeat("2", 64), ResultTreeDigest: "sha256:" + strings.Repeat("3", 64), ContainerPort: 8080, ChangedPaths: []string{"Dockerfile"}, CanonicalDiff: "diff\n", ValidatedImage: image, BuildLogRef: "log", BuildEvidenceDigest: "sha256:" + strings.Repeat("4", 64), Runtime: AcornFoxFixCandidateRuntimeEvidence{TaskID: "task_candidate", Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: "sha256:" + strings.Repeat("5", 64)}, OwnerAdminID: "admin_candidate", RequestKey: "candidate-key", Status: AcornFoxFixCandidateValidated, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour)}
}

func TestAcornFoxFixCandidateServiceRefusesAISourceReadWhenApplicationHasActiveSecrets(t *testing.T) {
	store := &fixCandidateStoreFixture{hasSecrets: true}
	service := &AcornFoxFixCandidateService{Store: store, Workspace: fixCandidateWorkspaceFixture{}}
	_, err := service.ReadSourceForAI(context.Background(), "app_candidate", "src_base", []string{"Dockerfile"})
	if err == nil || !domain.IsCode(err, domain.ErrForbidden) {
		t.Fatalf("read err=%v", err)
	}
}

func TestAcornFoxFixCandidateAcceptedIdentityBindsOwnerKeyAndBody(t *testing.T) {
	base := AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", Paths: []string{"Dockerfile", "main.go"}, UnifiedDiff: []byte("diff\n"), ContainerPort: 8080, IdempotencyKey: "candidate-key", OwnerAdminID: "admin_candidate"}
	digest := acornFoxFixCandidateRequestDigest(base)
	id := AcornFoxFixCandidateIDFromRequestDigest(digest)
	if !acornFoxCandidateID(id) {
		t.Fatalf("id=%s digest=%s", id, digest)
	}
	reordered := base
	reordered.Paths = []string{"main.go", "Dockerfile"}
	if got := AcornFoxFixCandidateIDFromRequestDigest(acornFoxFixCandidateRequestDigest(reordered)); got != id {
		t.Fatalf("path order changed identity: %s != %s", got, id)
	}
	variants := []AcornFoxFixCandidateCreateRequest{base, base, base, base}
	variants[0].OwnerAdminID = "admin_other"
	variants[1].IdempotencyKey = "candidate-other"
	variants[2].UnifiedDiff = []byte("different\n")
	variants[3].ContainerPort = 8081
	for index, variant := range variants {
		if got := AcornFoxFixCandidateIDFromRequestDigest(acornFoxFixCandidateRequestDigest(variant)); got == id {
			t.Fatalf("variant %d did not change identity", index)
		}
	}
	accepted := AcornFoxFixCandidate{ID: id, ApplicationID: base.ApplicationID, BaseSourceRevisionID: base.BaseSourceRevisionID, OwnerAdminID: base.OwnerAdminID, RequestKey: base.IdempotencyKey, Status: AcornFoxFixCandidatePreparing, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(accepted)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(wire, &object) != nil || len(object) != 5 || object["status"] == nil || object["validated_image"] != nil {
		t.Fatalf("accepted wire=%s", wire)
	}
}

func TestAcornFoxFixCandidateRejectsDuplicatePathsBeforeReservation(t *testing.T) {
	request := AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", Paths: []string{"Dockerfile", "Dockerfile"}, UnifiedDiff: []byte("diff\n"), ContainerPort: 8080, IdempotencyKey: "candidate-key", OwnerAdminID: "admin_candidate"}
	store := &fixCandidateStoreFixture{}
	service := &AcornFoxFixCandidateService{Store: store, Workspace: fixCandidateWorkspaceFixture{}, Builder: fixCandidateBuilderFixture{}, Runtime: fixCandidateRuntimeFixture{}}
	if _, _, _, err := service.Accept(context.Background(), request); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("duplicate paths err=%v", err)
	}
	if store.beginCalls != 0 {
		t.Fatalf("duplicate paths reserved %d rows", store.beginCalls)
	}
}

func applicationCandidateSnapshot(t *testing.T, now time.Time) acornfoxcandidate.Snapshot {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]\nEXPOSE 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app"), []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	tree, err := foundation.HashDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	return acornfoxcandidate.Snapshot{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_base", BaseRepositoryURL: "https://github.com/OrbitMaker/acornfox.git", BaseCommit: strings.Repeat("c", 40), BaseTreeDigest: "sha256:" + strings.Repeat("1", 64), PatchDigest: "sha256:" + strings.Repeat("2", 64), TreeDigest: "sha256:" + tree, ChangedPaths: []string{"Dockerfile"}, CanonicalDiff: []byte("diff --git a/Dockerfile b/Dockerfile\n--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1 +1 @@\n-a\n+b\n"), WorkspaceRef: root, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
}
