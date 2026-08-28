package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

func TestPrepareUploadDirectoryPublishesImmutableIdempotentRevision(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	sourceRoot := filepath.Join(uploads, "site")
	if err := os.MkdirAll(filepath.Join(sourceRoot, "public"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "public", "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, ".DS_Store"), []byte("machine-specific"), 0o644); err != nil {
		t.Fatal(err)
	}
	provider := newTestProvider(t, uploads, workspace)
	request := uploadRequest(sourceRoot, "upload-directory")
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision.ID != second.Revision.ID || first.Revision.ContentDigest != second.Revision.ContentDigest {
		t.Fatalf("idempotent retry changed revision: %#v %#v", first.Revision, second.Revision)
	}
	if first.Revision.Kind != domain.SourceUpload || !first.Revision.Immutable || first.Revision.WorkspaceRef == "" {
		t.Fatalf("source revision is incomplete: %#v", first.Revision)
	}
	if first.Evidence.Redacted != true || len(first.Evidence.Refs) != 1 || strings.Contains(first.Evidence.Refs[0].Locator, sourceRoot) {
		t.Fatalf("evidence leaked source details: %#v", first.Evidence)
	}
	if content, err := os.ReadFile(filepath.Join(first.Revision.WorkspaceRef, "public", "index.html")); err != nil || string(content) != "hello" {
		t.Fatalf("published workspace is wrong: %q %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(first.Revision.WorkspaceRef, ".DS_Store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system metadata was materialized: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(first.Revision.WorkspaceRef, "public", "index.html"))
		if err != nil || info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("published file is not read-only: %v %v", info, err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "public", "index.html"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := provider.Prepare(context.Background(), uploadRequest(sourceRoot, "upload-directory-2"))
	if err != nil {
		t.Fatal(err)
	}
	if third.Revision.ContentDigest == first.Revision.ContentDigest || third.Revision.WorkspaceRef == first.Revision.WorkspaceRef {
		t.Fatalf("changed upload did not create an independent immutable revision: %#v %#v", first.Revision, third.Revision)
	}
}

func TestPrepareStoredG3UploadReferenceNeverAcceptsClientPath(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	stored := filepath.Join(uploads, "upload_1", "files", "src")
	if err := os.MkdirAll(stored, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stored, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := newTestProvider(t, uploads, workspace)
	result, err := provider.Prepare(context.Background(), uploadRequest("upload://upload_1", "g3-upload-ref"))
	if err != nil || result.Revision.Locator != "upload://upload_1" {
		t.Fatalf("stored upload result=%+v err=%v", result, err)
	}
	if _, err := provider.Prepare(context.Background(), uploadRequest("upload://../outside", "g3-upload-bad")); err == nil {
		t.Fatal("unsafe stored upload reference was accepted")
	}
}

func TestPrepareAcceptsFolderZipTarGzAndTgzAndTracksExplicitReupload(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	folder := filepath.Join(uploads, "folder")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "index.html"), []byte("same-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(uploads, "site.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(zipFile)
	entry, err := zipWriter.Create("index.html")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("same-content"))
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"site.tar.gz", "site.tgz"} {
		file, err := os.Create(filepath.Join(uploads, name))
		if err != nil {
			t.Fatal(err)
		}
		compressed := gzip.NewWriter(file)
		archive := tar.NewWriter(compressed)
		data := []byte("same-content")
		if err := archive.WriteHeader(&tar.Header{Name: "index.html", Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = archive.Write(data)
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	provider := newTestProvider(t, uploads, workspace)
	results := make([]contracts.PrepareSourceResult, 0, 4)
	for index, locator := range []string{folder, zipPath, filepath.Join(uploads, "site.tar.gz"), filepath.Join(uploads, "site.tgz")} {
		result, err := provider.Prepare(context.Background(), uploadRequest(locator, fmt.Sprintf("format-%d", index)))
		if err != nil {
			t.Fatalf("prepare %s: %v", locator, err)
		}
		results = append(results, result)
	}
	for _, result := range results {
		if result.Revision.ContentDigest != results[0].Revision.ContentDigest || result.Revision.WorkspaceRef != results[0].Revision.WorkspaceRef {
			t.Fatalf("equivalent formats changed content identity: %#v", results)
		}
	}
	replayed, err := provider.Prepare(context.Background(), uploadRequest(folder, "format-0"))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Revision.ID != results[0].Revision.ID {
		t.Fatal("same request key did not replay revision")
	}
	reuploaded, err := provider.Prepare(context.Background(), uploadRequest(folder, "explicit-reupload"))
	if err != nil {
		t.Fatal(err)
	}
	if reuploaded.Revision.ID == results[0].Revision.ID || reuploaded.Revision.ContentDigest != results[0].Revision.ContentDigest {
		t.Fatal("explicit re-upload did not create a traceable revision over the same content")
	}
}

func TestPrepareRejectsUnsafeUploadInputsWithoutLeakingLocator(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	provider := newTestProvider(t, uploads, workspace)

	symlink := filepath.Join(uploads, "link")
	if err := os.Symlink("/etc", symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, request := range []contracts.PrepareSourceRequest{
		uploadRequest(symlink, "unsafe-link"),
		uploadRequest(t.TempDir(), "outside-upload-root"),
		{ApplicationID: "app_1", Kind: domain.SourceGitSSH, Locator: "git@example.com:private/repo.git", Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "ssh-is-disabled"}},
	} {
		_, err := provider.Prepare(context.Background(), request)
		assertSafeProviderError(t, err, request.Locator)
	}
}

func TestPrepareArchiveRejectsTraversalAndSpecialFiles(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	provider := newTestProvider(t, uploads, workspace)

	traversal := filepath.Join(uploads, "bad.tar")
	writeTar(t, traversal, []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg, Size: 1}}, [][]byte{[]byte("x")})
	_, err := provider.Prepare(context.Background(), uploadRequest(traversal, "bad-tar"))
	assertSafeProviderError(t, err, traversal)

	linked := filepath.Join(uploads, "bad.zip")
	writeZipSymlink(t, linked)
	_, err = provider.Prepare(context.Background(), uploadRequest(linked, "bad-zip"))
	assertSafeProviderError(t, err, linked)
}

func TestPrepareHonorsContentDigestAndIdempotencyConflicts(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	sourceRoot := filepath.Join(uploads, "site")
	if err := os.Mkdir(sourceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	provider := newTestProvider(t, uploads, workspace)
	request := uploadRequest(sourceRoot, "same-key")
	request.ContentDigest = "sha256:not-the-tree"
	_, err := provider.Prepare(context.Background(), request)
	assertProviderCode(t, err, contracts.ErrConflict)
	request.ContentDigest = ""
	if _, err := provider.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Ref = "ignored-but-part-of-request"
	_, err = provider.Prepare(context.Background(), request)
	assertProviderCode(t, err, contracts.ErrConflict)
}

func TestPrepareUsesBoundedArchiveLimits(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	archive := filepath.Join(uploads, "many.zip")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, name := range []string{"one", "two"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{UploadRoot: uploads, WorkspaceRoot: workspace, Limits: foundation.ArchiveLimits{MaxFiles: 1, MaxUnpackedBytes: 8}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTreeWritable(t, workspace) })
	_, err = provider.Prepare(context.Background(), uploadRequest(archive, "archive-limit"))
	assertProviderCode(t, err, contracts.ErrValidation)
}

func TestPrepareRejectsCompressionBombBeforeWorkspacePublication(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	archivePath := filepath.Join(uploads, "bomb.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("large.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(bytes.Repeat([]byte{0}, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{UploadRoot: uploads, WorkspaceRoot: workspace, Limits: foundation.ArchiveLimits{MaxFiles: 10, MaxUnpackedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Prepare(context.Background(), uploadRequest(archivePath, "compression-bomb"))
	assertProviderCode(t, err, contracts.ErrValidation)
	entries, readErr := os.ReadDir(workspace)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("compression bomb published workspace entries: %#v", entries)
	}
}

func TestGitArchiveExtractionAcceptsBoundedExecutableFixture(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, item := range []struct {
		name string
		mode int64
		data []byte
	}{
		{"Dockerfile", 0o664, []byte("FROM scratch\n")},
		{"index.html", 0o664, []byte("proof")},
		{"open-card-static-server", 0o775, bytes.Repeat([]byte("x"), 8<<20)},
	} {
		if err := writer.WriteHeader(&tar.Header{Name: item.name, Mode: item.mode, Size: int64(len(item.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractTar(tar.NewReader(bytes.NewReader(archive.Bytes())), t.TempDir(), foundation.DefaultArchiveLimits); err != nil {
		t.Fatalf("bounded Git archive fixture was rejected: %v", err)
	}
}

func TestTarUploadAcceptsConventionalArchiveRootDirectoryEntry(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "./", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	content := []byte("safe")
	if err := writer.WriteHeader(&tar.Header{Name: "./index.html", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := extractTar(tar.NewReader(bytes.NewReader(archive.Bytes())), destination, foundation.DefaultArchiveLimits); err != nil {
		t.Fatalf("conventional archive root was rejected: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "index.html")); err != nil || string(got) != "safe" {
		t.Fatalf("archive content mismatch: %q err=%v", got, err)
	}
}

func TestExtractGitArchiveStreamsLargeExecutableWithoutDeadlock(t *testing.T) {
	repository := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", repository}, args...)...)
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	runGit("init", "-q")
	runGit("config", "user.name", "fixture")
	runGit("config", "user.email", "fixture@invalid")
	if err := os.WriteFile(filepath.Join(repository, "Dockerfile"), []byte("FROM scratch\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "server"), bytes.Repeat([]byte("x"), 8<<20), 0o775); err != nil {
		t.Fatal(err)
	}
	runGit("add", "Dockerfile", "server")
	runGit("commit", "-q", "-m", "fixture")
	commitOutput, err := exec.Command("git", "-C", repository, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{gitBinary: "git", limits: foundation.DefaultArchiveLimits}
	if err := provider.extractGitArchive(context.Background(), filepath.Join(repository, ".git"), strings.TrimSpace(string(commitOutput)), t.TempDir()); err != nil {
		t.Fatalf("Git archive stream was rejected: %v", err)
	}
}

func TestReleaseDeletesOnlyProviderOwnedWorkspaceAndIsIdempotent(t *testing.T) {
	uploads := t.TempDir()
	workspace := filepath.Join(t.TempDir(), "workspaces")
	sourceRoot := filepath.Join(uploads, "site")
	if err := os.Mkdir(sourceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	provider := newTestProvider(t, uploads, workspace)
	prepared, err := provider.Prepare(context.Background(), uploadRequest(sourceRoot, "release-source"))
	if err != nil {
		t.Fatal(err)
	}
	release := contracts.ReleaseSourceRequest{Revision: prepared.Revision, Operation: contracts.OperationContext{IdempotencyKey: "release-source:cleanup"}}
	if err := provider.Release(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prepared.Revision.WorkspaceRef); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace was not deleted: %v", err)
	}
	if err := provider.Release(context.Background(), release); err != nil {
		t.Fatalf("release replay failed: %v", err)
	}
	outside := prepared.Revision
	outside.WorkspaceRef = uploads
	if err := provider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: outside, Operation: contracts.OperationContext{IdempotencyKey: "release-outside"}}); err == nil {
		t.Fatal("release accepted a workspace outside provider ownership")
	}
	if _, err := os.Stat(sourceRoot); err != nil {
		t.Fatalf("release touched upload input: %v", err)
	}
}

func newTestProvider(t *testing.T, uploads, workspace string) *Provider {
	t.Helper()
	provider, err := New(Config{UploadRoot: uploads, WorkspaceRoot: workspace, Limits: foundation.ArchiveLimits{MaxFiles: 32, MaxUnpackedBytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTreeWritable(t, workspace) })
	return provider
}

func makeTreeWritable(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func uploadRequest(locator, key string) contracts.PrepareSourceRequest {
	if strings.HasPrefix(locator, "upload://") {
		return contracts.PrepareSourceRequest{ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: locator, Operation: contracts.OperationContext{IdempotencyKey: key}}
	}
	id := "upload_" + strings.NewReplacer("/", "_", "\\", "_", ".", "_").Replace(key)
	root := filepath.Dir(locator)
	final := filepath.Join(root, id)
	if _, err := os.Lstat(final); errors.Is(err, os.ErrNotExist) {
		if info, statErr := os.Lstat(locator); statErr == nil && info.Mode()&fs.ModeSymlink == 0 {
			if info.IsDir() {
				if err := copySourceUploadFixture(locator, filepath.Join(final, "files")); err != nil {
					panic(err)
				}
			} else {
				if err := os.MkdirAll(final, 0o700); err != nil {
					panic(err)
				}
				name := "archive" + archiveFixtureExtension(locator)
				input, openErr := os.Open(locator)
				if openErr != nil {
					panic(openErr)
				}
				output, createErr := os.OpenFile(filepath.Join(final, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if createErr != nil {
					_ = input.Close()
					panic(createErr)
				}
				_, copyErr := io.Copy(output, input)
				_ = input.Close()
				_ = output.Close()
				if copyErr != nil {
					panic(copyErr)
				}
			}
		}
	}
	return contracts.PrepareSourceRequest{ApplicationID: "app_1", Kind: domain.SourceUpload, Locator: "upload://" + id, Operation: contracts.OperationContext{IdempotencyKey: key}}
}

func archiveFixtureExtension(path string) string {
	switch {
	case strings.HasSuffix(path, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(path, ".tgz"):
		return ".tgz"
	case strings.HasSuffix(path, ".zip"):
		return ".zip"
	default:
		return ".invalid"
	}
}

func copySourceUploadFixture(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == "." {
			if rel == "." {
				return os.MkdirAll(target, 0o700)
			}
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("test source upload fixture must not follow symlink")
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func assertSafeProviderError(t *testing.T, err error, locator string) {
	t.Helper()
	assertProviderCode(t, err, contracts.ErrValidation)
	if strings.Contains(err.Error(), locator) {
		t.Fatalf("error leaked source locator: %v", err)
	}
}

func assertProviderCode(t *testing.T, err error, code contracts.ErrorCode) {
	t.Helper()
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != code {
		t.Fatalf("error = %T %v, want %s", err, err, code)
	}
	if providerErr.Details["evidence_ref"] == "" || providerErr.Details["log_ref"] == "" {
		t.Fatalf("error omitted safe refs: %#v", providerErr)
	}
}

func writeTar(t *testing.T, path string, headers []*tar.Header, bodies [][]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for i, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZipSymlink(t *testing.T, path string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	header := &zip.FileHeader{Name: "link"}
	header.SetMode(os.ModeSymlink | 0o777)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("/etc")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
