package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/observability"
)

func TestCandidateBuildLogSinkPersistsRedactedReadbackWithoutM4Index(t *testing.T) {
	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 1024, MaxTotalBytes: 8192, MaxBuildFiles: 4})
	if err != nil {
		t.Fatal(err)
	}
	sink := &acornFoxCandidateBuildLogSink{logs: logs, redactionRoots: []string{"/private/candidate"}}
	request := candidateBuildLogRequestFixture()
	ref, err := sink.StoreBuildLog(context.Background(), request, "build passed /private/candidate\n")
	if err != nil || !strings.HasPrefix(ref, "candidate-log://"+request.Source.ID.String()+"/sha256:") {
		t.Fatalf("ref=%q err=%v", ref, err)
	}
	stored, err := logs.Read(observability.LogCategoryBuild, "candidate-"+request.Source.ID.String())
	if err != nil || strings.Contains(string(stored), "/private/candidate") || !strings.Contains(string(stored), "[REDACTED]") {
		t.Fatalf("stored=%q err=%v", stored, err)
	}
	replayed, err := sink.StoreBuildLog(context.Background(), request, "build passed /private/candidate\n")
	if err != nil || replayed != ref {
		t.Fatalf("replayed=%q err=%v", replayed, err)
	}
	if _, err := sink.StoreBuildLog(context.Background(), request, "changed output\n"); err == nil {
		t.Fatal("changed candidate log replay was accepted")
	}
	request.Source.Kind = domain.SourceGitHTTPS
	if _, err := sink.StoreBuildLog(context.Background(), request, "normal build\n"); err == nil {
		t.Fatal("normal build entered candidate log sink")
	}
}

func TestPrepareCandidateWorkRootRejectsLooseOrLinkedDirectory(t *testing.T) {
	parent := t.TempDir()
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxCandidateWorkRoot(loose); err == nil {
		t.Fatal("loose candidate work root was accepted")
	}
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if err := prepareAcornFoxCandidateWorkRoot(linked); err == nil {
		t.Fatal("linked candidate work root was accepted")
	}
}

func TestRecoverCandidateBuildRootRemovesOnlyKnownBuildResidue(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "build-stale")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "metadata.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAcornFoxCandidateBuildRoot(root); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAcornFoxCandidateBuildRoot(root); err == nil {
		t.Fatal("unknown candidate build residue was removed")
	}
	if _, err := os.Stat(filepath.Join(root, "foreign")); err != nil {
		t.Fatalf("unknown residue did not remain fail-closed: %v", err)
	}
}

func candidateBuildLogRequestFixture() contracts.BuildRequest {
	now := time.Unix(1_700_000_000, 0).UTC()
	source := domain.SourceRevision{ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", Kind: domain.SourceUpload, Locator: "candidate://candidate_0123456789abcdef0123456789abcdef", ContentDigest: "sha256:" + strings.Repeat("a", 64), WorkspaceRef: "/private/candidate", CreatedAt: now, Immutable: true}
	return contracts.BuildRequest{BuildID: "build_candidate", Source: source, Plan: domain.BuildPlan{ID: "plan_candidate", SourceRevisionID: source.ID, SourceDigest: source.ContentDigest, ServiceName: "web", Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: "acornfox.local/apps", Output: domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "candidate"}, IdempotencyKey: "candidate-build", CreatedAt: now}}
}
