package sourceupload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func newTestManager(t *testing.T, limits Limits) *Manager {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	manager, err := New(Config{Root: root, Limits: limits, Clock: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestDirectoryStagesPrivateFilesAndCanonicalDigest(t *testing.T) {
	manager := newTestManager(t, Limits{})
	session, err := manager.Begin("upload_1")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.WriteDirectoryFile("src/main.go", strings.NewReader("code")); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("code"))
	file := domain.SourceUploadFile{Path: "src/main.go", Bytes: 4, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	stored, err := session.Finalize(domain.SourceUploadDirectory, []domain.SourceUploadFile{file}, "upload-key")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Upload.StorageRef != "upload://upload_1" || stored.Upload.FileCount != 1 || strings.Contains(stored.Upload.StorageRef, manager.root) {
		t.Fatalf("stored=%+v", stored)
	}
	if info, err := os.Lstat(filepath.Join(stored.Path, "files", "src", "main.go")); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("staged file=%+v err=%v", info, err)
	}
}

func TestUploadRejectsLimitsDuplicateAndUnsafePaths(t *testing.T) {
	manager := newTestManager(t, Limits{MaxTotalBytes: 5, MaxFileBytes: 4, MaxFiles: 1, MaxPathBytes: 512, MaxManifest: 64})
	session, err := manager.Begin("upload_2")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.WriteDirectoryFile("../escape", strings.NewReader("x")); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("unsafe path=%v", err)
	}
	if err := session.WriteDirectoryFile("a.txt", bytes.NewReader([]byte("12345"))); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("file limit=%v", err)
	}
	session.Abort()
	if entries, err := os.ReadDir(manager.root); err != nil || len(entries) != 0 {
		t.Fatalf("failed directory upload left staging entries=%v err=%v", entries, err)
	}

	archive, err := manager.Begin("upload_3")
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteArchive("bad.rar", strings.NewReader("x")); !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("archive extension=%v", err)
	}
	archive.Abort()
}
