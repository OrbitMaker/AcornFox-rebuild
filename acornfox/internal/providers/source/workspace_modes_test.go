package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

func TestSourceModesSurviveFolderTarAndZipPublication(t *testing.T) {
	files := []foundation.TreeEntry{{Path: "bin/hello", Data: []byte("#!/bin/sh\nprintf hello\\n\n"), Mode: os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0771}, {Path: "data.txt", Data: []byte("readable by container users\n"), Mode: os.ModeSetuid | 0666}}
	wantDigest, err := foundation.DigestTree(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"folder", "tar", "zip"} {
		t.Run(format, func(t *testing.T) {
			uploads := t.TempDir()
			stored := filepath.Join(uploads, "modes")
			if err := os.Mkdir(stored, 0700); err != nil {
				t.Fatal(err)
			}
			if format == "folder" {
				for _, f := range files {
					path := filepath.Join(stored, "files", f.Path)
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, f.Data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, f.Mode); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				var content bytes.Buffer
				name := "archive.zip"
				if format == "zip" {
					writer := zip.NewWriter(&content)
					for _, f := range files {
						header := &zip.FileHeader{Name: f.Path, Method: zip.Store}
						header.SetMode(f.Mode)
						out, err := writer.CreateHeader(header)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = out.Write(f.Data); err != nil {
							t.Fatal(err)
						}
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					name = "archive.tar.gz"
					gz := gzip.NewWriter(&content)
					writer := tar.NewWriter(gz)
					for _, f := range files {
						mode := int64(04666)
						if f.Path == "bin/hello" {
							mode = 07771
						}
						if err := writer.WriteHeader(&tar.Header{Name: f.Path, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(f.Data))}); err != nil {
							t.Fatal(err)
						}
						if _, err := writer.Write(f.Data); err != nil {
							t.Fatal(err)
						}
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(stored, name), content.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
			workspace := filepath.Join(t.TempDir(), "workspaces")
			provider := newTestProvider(t, uploads, workspace)
			request := contracts.PrepareSourceRequest{ApplicationID: "app_modes", Kind: domain.SourceUpload, Locator: "upload://modes", Operation: contracts.OperationContext{IdempotencyKey: "modes"}}
			result, err := provider.Prepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			assertImmutableMode(t, filepath.Join(result.Revision.WorkspaceRef, "bin/hello"), 0555)
			assertImmutableMode(t, filepath.Join(result.Revision.WorkspaceRef, "data.txt"), 0444)
			assertImmutableMode(t, filepath.Join(result.Revision.WorkspaceRef, "bin"), 0555)
			got, err := foundation.HashDirectory(result.Revision.WorkspaceRef)
			if err != nil || got != wantDigest || result.Revision.ContentDigest != "sha256:"+wantDigest {
				t.Fatal("publication changed the source's canonical executable identity", err)
			}
			replay, err := provider.Prepare(context.Background(), request)
			if err != nil || replay.Revision.ContentDigest != result.Revision.ContentDigest {
				t.Fatal("immutable mode publication was not replayable", err)
			}
		})
	}
}
func assertImmutableMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeSymlink) != 0 {
		t.Fatalf("unexpected sanitized source mode for %s: %v %v", filepath.Base(path), info, err)
	}
}

func TestPublicGitPreservesExecutableBitAndBindsModeOnlyChanges(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	script := filepath.Join(fixture.work, "hello")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf hello\\n\n"), 0755); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, "-C", fixture.work, "add", "hello")
	runFixtureGit(t, "-C", fixture.work, "update-index", "--chmod=+x", "hello")
	runFixtureGit(t, "-C", fixture.work, "commit", "-m", "executable fixture")
	runFixtureGit(t, "-C", fixture.work, "push", "origin", "main")
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_modes", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "git-executable"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	assertImmutableMode(t, filepath.Join(first.Revision.WorkspaceRef, "hello"), 0555)
	assertImmutableMode(t, filepath.Join(first.Revision.WorkspaceRef, "README.md"), 0444)
	hash, err := foundation.HashDirectory(first.Revision.WorkspaceRef)
	if err != nil || first.Revision.ContentDigest != "sha256:"+hash {
		t.Fatal("Git digest changed after making the workspace immutable")
	}
	runFixtureGit(t, "-C", fixture.work, "update-index", "--chmod=-x", "hello")
	runFixtureGit(t, "-C", fixture.work, "commit", "-m", "non-executable fixture")
	runFixtureGit(t, "-C", fixture.work, "push", "origin", "main")
	request.Operation.IdempotencyKey = "git-not-executable"
	second, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	assertImmutableMode(t, filepath.Join(second.Revision.WorkspaceRef, "hello"), 0444)
	if second.Revision.ContentDigest == first.Revision.ContentDigest {
		t.Fatal("executable-bit-only Git change lost its identity")
	}
}
