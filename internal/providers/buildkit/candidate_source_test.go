package buildkit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxcandidate"
)

func TestBuildKitAcceptsSealedTransientCandidateWithoutGitCommit(t *testing.T) {
	provider, _, source := testProvider(t, writingRunner(t, "candidate build\n"))
	snapshot := acornfoxcandidate.Snapshot{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: source.ApplicationID, BaseSourceRevisionID: "src_public_base", BaseRepositoryURL: "https://github.com/OrbitMaker/acornfox.git", BaseCommit: strings.Repeat("a", 40), BaseTreeDigest: "sha256:" + strings.Repeat("b", 64), PatchDigest: "sha256:" + strings.Repeat("c", 64), TreeDigest: source.ContentDigest, ChangedPaths: []string{"Dockerfile"}, CanonicalDiff: []byte("diff\n"), WorkspaceRef: source.WorkspaceRef, CreatedAt: time.Unix(1, 0).UTC(), ExpiresAt: time.Unix(2, 0).UTC()}
	transient, err := snapshot.TransientSource()
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("candidate-source", transient)
	request.Plan.SourceRevisionID = transient.ID
	request.Plan.SourceDigest = transient.ContentDigest
	request.Plan.SecretRefs = nil
	bindAcornFoxDigests(t, &request)
	result, err := provider.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if transient.Commit != "" || transient.Kind != "upload" || result.Artifact == nil || result.Artifact.Image.Digest != testDigest || result.Build.PlanID != request.Plan.ID {
		t.Fatalf("transient=%+v result=%+v", transient, result)
	}
}
