package acornfoxcandidate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

func TestManagerReadsAppliesSealsAndAdaptsCandidateWithoutGitIdentity(t *testing.T) {
	manager, base := candidateFixture(t)
	read, err := manager.Read(context.Background(), base, []string{"Dockerfile"})
	if err != nil || len(read.Files) != 1 || read.BaseCommit != base.Commit || !strings.Contains(read.Files[0].Content, "0550") {
		t.Fatalf("read=%+v manager=%+v err=%#v", read, manager, err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	manager.clock = func() time.Time { return now }
	snapshot, err := manager.Apply(context.Background(), base, base.Locator, validCandidatePatch(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Release(snapshot)
	if err := manager.Verify(snapshot); err != nil || snapshot.BaseCommit != base.Commit || snapshot.TreeDigest == base.ContentDigest || snapshot.CreatedAt != now || len(snapshot.ChangedPaths) != 1 || snapshot.ChangedPaths[0] != "Dockerfile" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if strings.Contains(string(snapshot.CanonicalDiff), "index 1111111") || !strings.Contains(string(snapshot.CanonicalDiff), "@@ -1,4 +1,4 @@") {
		t.Fatalf("canonical diff was not regenerated from the sealed preimage/result: %s", snapshot.CanonicalDiff)
	}
	changed, err := os.ReadFile(filepath.Join(snapshot.WorkspaceRef, "Dockerfile"))
	if err != nil || !strings.Contains(string(changed), "0555") || strings.Contains(string(changed), "0550") {
		t.Fatalf("changed=%q err=%v", changed, err)
	}
	info, err := os.Stat(filepath.Join(snapshot.WorkspaceRef, "Dockerfile"))
	if err != nil || info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("candidate was not sealed: info=%v err=%v", info, err)
	}
	original, err := os.ReadFile(filepath.Join(base.WorkspaceRef, "Dockerfile"))
	if err != nil || !strings.Contains(string(original), "0550") {
		t.Fatalf("immutable base changed: %q err=%v", original, err)
	}

	transient, err := snapshot.TransientSource()
	if err != nil || transient.Kind != domain.SourceUpload || transient.Commit != "" || transient.Locator != "candidate://"+snapshot.ID.String() {
		t.Fatalf("transient=%+v err=%v", transient, err)
	}
}

func TestManagerAppliesDurablyReservedCandidateIdentity(t *testing.T) {
	manager, base := candidateFixture(t)
	id := domain.ID("candidate_0123456789abcdef0123456789abcdef")
	snapshot, err := manager.ApplyFor(context.Background(), id, base, base.Locator, validCandidatePatch(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Release(snapshot)
	if snapshot.ID != id || filepath.Base(snapshot.WorkspaceRef) != id.String() {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if _, err := manager.ApplyFor(context.Background(), "candidate_invalid", base, base.Locator, validCandidatePatch(), time.Hour); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("invalid reserved id err=%v", err)
	}
}

func TestManagerRejectsUnsafePatchShapesAndBaseLinks(t *testing.T) {
	for name, patch := range map[string]string{
		"traversal": "diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n",
		"rename":    "diff --git a/a b/b\nsimilarity index 100%\nrename from a\nrename to b\n",
		"mode":      "diff --git a/a b/a\nold mode 100644\nnew mode 100755\n",
		"binary":    "diff --git a/a b/a\nGIT binary patch\nliteral 0\n",
		"addition":  "diff --git a/a b/a\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+a\n",
		"sensitive": "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-a\n+b\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validatePatch([]byte(patch)); err == nil {
				t.Fatalf("unsafe patch accepted: %s", patch)
			}
		})
	}

	manager, base := candidateFixture(t)
	linked := filepath.Join(base.WorkspaceRef, "linked")
	if err := os.Link(filepath.Join(base.WorkspaceRef, "Dockerfile"), linked); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Read(context.Background(), base, []string{"Dockerfile"}); !errors.Is(err, ErrInvalidBase) {
		t.Fatalf("hard-linked base err=%v", err)
	}
}

func TestManagerRejectsStaleBaseAndPatchPreimage(t *testing.T) {
	manager, base := candidateFixture(t)
	if err := os.WriteFile(filepath.Join(base.WorkspaceRef, "Dockerfile"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), base, base.Locator, validCandidatePatch(), time.Hour); !errors.Is(err, ErrInvalidBase) {
		t.Fatalf("stale base err=%v", err)
	}
}

func candidateFixture(t *testing.T) (*Manager, domain.SourceRevision) {
	t.Helper()
	workspaceRoot := t.TempDir()
	baseRoot := filepath.Join(workspaceRoot, "base")
	if err := os.Mkdir(baseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"Dockerfile": "FROM scratch\nCOPY --chmod=0550 app /app\nENTRYPOINT [\"/app\"]\nEXPOSE 8080\n",
		"app":        "fixture executable\n",
	} {
		mode := os.FileMode(0o600)
		if path == "app" {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(baseRoot, path), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := foundation.HashDirectory(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	base := domain.SourceRevision{ID: "src_public_base", ApplicationID: "app_candidate", Kind: domain.SourceGitHTTPS, Locator: "https://github.com/OrbitMaker/acornfox.git", Ref: "main", Commit: "f78b7df2922b7af805a398a3e108bed1828928ae", ContentDigest: "sha256:" + digest, WorkspaceRef: baseRoot, CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
	manager, err := NewManager(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	return manager, base
}

func validCandidatePatch() []byte {
	return []byte("diff --git a/Dockerfile b/Dockerfile\nindex 1111111..2222222 100644\n--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1,4 +1,4 @@\n FROM scratch\n-COPY --chmod=0550 app /app\n+COPY --chmod=0555 app /app\n ENTRYPOINT [\"/app\"]\n EXPOSE 8080\n")
}
