//go:build integration

package acornfoxcandidate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/source"
)

func TestCandidateReadsCanonicalPublicGitRevisionAndAppliesKnownFix(t *testing.T) {
	if os.Getenv("OPEN_CARD_AFB_CANDIDATE_PUBLIC_GIT_TEST") != "1" {
		t.Skip("set OPEN_CARD_AFB_CANDIDATE_PUBLIC_GIT_TEST=1 for the canonical public Git fixture")
	}
	resolvers := strings.Split(strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_CANDIDATE_GIT_RESOLVERS")), ",")
	if len(resolvers) == 1 && resolvers[0] == "" {
		resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	root := t.TempDir()
	uploadRoot, workspaceRoot := filepath.Join(root, "uploads"), filepath.Join(root, "workspaces")
	if err := os.Mkdir(uploadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspaceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := source.New(source.Config{UploadRoot: uploadRoot, WorkspaceRoot: workspaceRoot, GitResolverEndpoints: resolvers})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	prepared, err := provider.Prepare(ctx, contracts.PrepareSourceRequest{ApplicationID: "app_candidate_public", Kind: domain.SourceGitHTTPS, Locator: "https://github.com/OrbitMaker/acornfox.git", Ref: "refs/heads/codex/pi-test-broken-20260908", Operation: contracts.OperationContext{IdempotencyKey: "candidate-public-base", Deadline: time.Now().Add(90 * time.Second), Actor: "candidate-test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: prepared.Revision, Operation: contracts.OperationContext{IdempotencyKey: "candidate-public-base-release", Actor: "candidate-test"}})
	if prepared.Revision.Commit != "4504127dea582ffaa7f6fde1729aa0629216a724" {
		t.Fatalf("resolved commit=%s", prepared.Revision.Commit)
	}
	candidateRoot := filepath.Join(root, "candidate-sources")
	if err := os.Mkdir(candidateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(workspaceRoot, candidateRoot)
	if err != nil {
		t.Fatal(err)
	}
	read, err := manager.Read(ctx, prepared.Revision, []string{"Dockerfile"})
	if err != nil || len(read.Files) != 1 || !strings.Contains(read.Files[0].Content, "COPY --chmod=0500 hello /hello") {
		t.Fatalf("read=%+v err=%v", read, err)
	}
	patch := []byte("diff --git a/Dockerfile b/Dockerfile\n--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1,5 +1,5 @@\n FROM scratch\n-COPY --chmod=0500 hello /hello\n+COPY --chmod=0555 hello /hello\n RUN [\"/hello\", \"--self-test\"]\n USER 10001:10001\n EXPOSE 8000\n")
	candidate, err := manager.Apply(ctx, prepared.Revision, prepared.Revision.Locator, patch, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Release(candidate)
	fixed, err := os.ReadFile(filepath.Join(candidate.WorkspaceRef, "Dockerfile"))
	if err != nil || !strings.Contains(string(fixed), "COPY --chmod=0555 hello /hello") || candidate.BaseCommit != prepared.Revision.Commit {
		t.Fatalf("candidate=%+v fixed=%q err=%v", candidate, fixed, err)
	}
}
