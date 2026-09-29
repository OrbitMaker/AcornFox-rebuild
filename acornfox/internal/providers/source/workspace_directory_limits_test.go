package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/foundation"
)

func TestMaterializationDirectoryLimitsRejectDeepAndEmptyFanout(t *testing.T) {
	limits := foundation.ArchiveLimits{MaxFiles: 2, MaxUnpackedBytes: 1024}
	sourceRoot := t.TempDir()
	deep := filepath.Join(sourceRoot, "one", "two", "three")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyDirectory(sourceRoot, t.TempDir(), limits); !errors.Is(err, errUploadRejected) {
		t.Fatalf("deep directory tree error=%v", err)
	}

	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range []string{"empty-one/", "empty-two/", "empty-three/"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractTar(tar.NewReader(&archive), t.TempDir(), limits); !errors.Is(err, errUploadRejected) {
		t.Fatalf("empty directory fanout error=%v", err)
	}
}

func TestMaterializationDirectoryLimitsCountImplicitParentsAcrossTarAndZip(t *testing.T) {
	limits := foundation.ArchiveLimits{MaxFiles: 2, MaxUnpackedBytes: 1024}
	var tarPayload bytes.Buffer
	tarWriter := tar.NewWriter(&tarPayload)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "one/two/three/file.txt", Typeflag: tar.TypeReg, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractTar(tar.NewReader(&tarPayload), t.TempDir(), limits); !errors.Is(err, errUploadRejected) {
		t.Fatalf("implicit tar parent error=%v", err)
	}

	zipPath := filepath.Join(t.TempDir(), "implicit.zip")
	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	entry, err := zipWriter.Create("one/two/three/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractZIP(zipPath, t.TempDir(), limits); !errors.Is(err, errUploadRejected) {
		t.Fatalf("implicit zip parent error=%v", err)
	}
}

func TestBoundedGitObjectDirectoryCountsDirectoriesAndMissingRootFails(t *testing.T) {
	limits := foundation.ArchiveLimits{MaxFiles: 1, MaxUnpackedBytes: 1024}
	if err := boundedGitObjectDirectory(filepath.Join(t.TempDir(), "missing"), limits); !errors.Is(err, errGitTooLarge) {
		t.Fatalf("missing Git object root error=%v", err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "objects", "pack"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := boundedGitObjectDirectory(root, limits); !errors.Is(err, errGitTooLarge) {
		t.Fatalf("Git directory fanout error=%v", err)
	}
	if strings.Contains(errGitTooLarge.Error(), root) {
		t.Fatal("Git bound error leaked path")
	}
}
