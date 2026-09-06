package buildkit

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	sourceprovider "github.com/open-card/open-card/internal/providers/source"
)

func TestImportedSourceContextKeepsDockerCopyModesAndDigest(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	root := t.TempDir()
	uploads := filepath.Join(root, "uploads")
	workspace := filepath.Join(root, "workspaces")
	files := []struct {
		path, body string
		mode       os.FileMode
	}{{"Dockerfile", "FROM scratch\nCOPY . /app/\nUSER 65532:65532\nENTRYPOINT [\"/app/bin/hello\"]\n", 0644}, {"bin/hello", "#!/bin/sh\nprintf hello\\n\n", 0755}, {"public/data.txt", "container user must be able to read this\n", 0644}}
	for _, file := range files {
		path := filepath.Join(uploads, "modes/files", file.path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.body), file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	source, err := sourceprovider.New(sourceprovider.Config{UploadRoot: uploads, WorkspaceRoot: workspace, Limits: foundation.ArchiveLimits{MaxFiles: 10, MaxUnpackedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(workspace, func(path string, _ os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	prepared, err := source.Prepare(context.Background(), contracts.PrepareSourceRequest{ApplicationID: "app_modes", Kind: domain.SourceUpload, Locator: "upload://modes", Operation: contracts.OperationContext{IdempotencyKey: "source-modes"}})
	if err != nil {
		t.Fatal(err)
	}
	runRoot := filepath.Join(root, "private-build")
	if err := os.Mkdir(runRoot, 0700); err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: Config{WorkspaceRoot: canonicalWorkspace}}
	destination, _, err := provider.copyBuildContext(prepared.Revision, domain.BuildPlan{Kind: domain.BuildDockerfile, ContextPath: ".", DockerfilePath: "Dockerfile"}, runRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		info, err := os.Lstat(filepath.Join(destination, file.path))
		if err != nil || info.Mode().Perm() != file.mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeSymlink) != 0 {
			t.Fatalf("COPY input %s lost its ordinary container mode: %v %v", file.path, info, err)
		}
		raw, err := os.ReadFile(filepath.Join(destination, file.path))
		if err != nil || string(raw) != file.body {
			t.Fatal("context copy changed source bytes")
		}
	}
	for _, dir := range []string{destination, filepath.Join(destination, "bin"), filepath.Join(destination, "public")} {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0755 {
			t.Fatal("COPY directory cannot be traversed by a non-root container user", err)
		}
	}
	if info, err := os.Stat(runRoot); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("host build parent lost privacy")
	}
	for _, tree := range []string{prepared.Revision.WorkspaceRef, destination} {
		digest, err := foundation.HashDirectory(tree)
		if err != nil || "sha256:"+digest != prepared.Revision.ContentDigest {
			t.Fatal("source executable identity changed across immutable publication and context copy", err)
		}
	}
}

func TestCopyContextRejectsHardlinksAndSymlinks(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(root, "outside")
			if err := os.WriteFile(outside, []byte("retain"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "hardlink" {
				err = os.Link(outside, filepath.Join(source, "input"))
			} else {
				err = os.Symlink(outside, filepath.Join(source, "input"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := copyTree(source, filepath.Join(root, "destination")); err == nil {
				t.Fatal("linked build-context input was accepted")
			}
			if raw, err := os.ReadFile(outside); err != nil || string(raw) != "retain" {
				t.Fatal("outside input was altered")
			}
		})
	}
}
