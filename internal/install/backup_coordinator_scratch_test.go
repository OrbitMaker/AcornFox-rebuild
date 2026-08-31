package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func scratchTaskStore(t *testing.T) (*platformBackupLocalStore, *DurableWriter, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "transaction"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	parent, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	child, err := parent.OpenChildWriter("transaction", durableDirMode)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newPlatformBackupLocalStore(child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close(); _ = parent.Close() })
	return store, child, filepath.Join(root, "transaction")
}

func scratchDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func scratchVerify(want []byte) func(io.ReadSeeker) error {
	return func(value io.ReadSeeker) error {
		got, err := io.ReadAll(value)
		if err != nil || !bytes.Equal(got, want) {
			return ErrPlatformBackupLocal
		}
		return nil
	}
}

func TestPlatformBackupLocalLeafMapAndAcceptedOpen(t *testing.T) {
	store, writer, _ := scratchTaskStore(t)
	seen := map[string]bool{}
	for leaf := platformBackupLocalControlPlaneDump; leaf <= platformBackupLocalReadback; leaf++ {
		spec, ok := platformBackupLocalSpec(leaf)
		if !ok || spec.name == "" || seen[spec.name] || spec.maxSize <= 0 {
			t.Fatalf("leaf=%d spec=%+v ok=%t", leaf, spec, ok)
		}
		seen[spec.name] = true
		if !spec.accepted {
			continue
		}
		body := []byte("accepted-leaf")
		if err := writer.WriteMetadata(spec.name, body); err != nil {
			t.Fatal(err)
		}
		opened, err := store.openAccepted(leaf, int64(len(body)), scratchDigest(body))
		if err != nil {
			t.Fatalf("leaf=%d open=%v", leaf, err)
		}
		got, err := io.ReadAll(opened)
		if closeErr := opened.Close(); err != nil || closeErr != nil || !bytes.Equal(got, body) {
			t.Fatalf("leaf=%d read=%q err=%v close=%v", leaf, got, err, closeErr)
		}
	}
	if len(seen) != 15 {
		t.Fatalf("fixed leaf map count=%d", len(seen))
	}
	if _, err := store.openAccepted(platformBackupLocalPackagePartial, 1, scratchDigest([]byte("x"))); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("partial accepted: %v", err)
	}
}

func TestPlatformBackupLocalCandidateNoReplaceCommitAndAbort(t *testing.T) {
	store, _, root := scratchTaskStore(t)
	body := []byte("streaming package bytes")
	candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write(body); err != nil {
		t.Fatal(err)
	}
	if _, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("partial no-replace=%v", err)
	}
	if err := candidate.Commit(scratchVerify(body)); err != nil {
		t.Fatal(err)
	}
	opened, err := store.openAccepted(platformBackupLocalPackage, int64(len(body)), scratchDigest(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
	if _, err := os.Lstat(filepath.Join(root, "package.tar.partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial remains: %v", err)
	}
	if err := candidate.Abort(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("abort after link=%v", err)
	}
	newCandidate, err := store.beginStream(platformBackupLocalEncryptedPartial, platformBackupLocalEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if err := newCandidate.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "encrypted.ocbkp.partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abort left partial: %v", err)
	}
}

func TestPlatformBackupLocalCandidatePostLinkUnknownPreservesEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	store, err := newPlatformBackupLocalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("post-link")
	candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write(body); err != nil {
		t.Fatal(err)
	}
	// Commit's file fsync is first and its post-link parent fsync is second.
	fault.fail = "directory-parent-fsync"
	if err := candidate.Commit(scratchVerify(body)); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("post-link result=%v", err)
	}
	for _, name := range []string{"package.tar", "package.tar.partial"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("post-link evidence %s: %v", name, err)
		}
	}
	if err := candidate.Abort(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("abort removed ambiguous evidence: %v", err)
	}
}

func TestPlatformBackupLocalCandidateReconcilesLinkAfterSideEffectError(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	store, err := newPlatformBackupLocalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("link-side-effect")
	candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write(body); err != nil {
		t.Fatal(err)
	}
	fault.afterRename = func() error { return errors.New("injected link result is unknown") }
	if err := candidate.Commit(scratchVerify(body)); err != nil {
		t.Fatalf("link side-effect was not reconciled: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "package.tar.partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial persisted after recovered link: %v", err)
	}
}

func TestPlatformBackupLocalRemoveAllowlistAndReadbackSafety(t *testing.T) {
	store, writer, root := scratchTaskStore(t)
	for _, leaf := range []platformBackupLocalLeaf{platformBackupLocalPackage, platformBackupLocalReadback} {
		if err := store.removeUncommitted(leaf); !errors.Is(err, ErrPlatformBackupLocal) {
			t.Fatalf("removed non-partial leaf=%d err=%v", leaf, err)
		}
	}
	candidate, err := store.beginStream(platformBackupLocalEncryptedPartial, platformBackupLocalEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMetadata("package.tar.partial", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := store.removeUncommitted(platformBackupLocalPackagePartial); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "readback.tmp"), []byte("stale"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	readback, err := store.openReadback()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readback.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := readback.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "readback.tmp")); err != nil || len(raw) != 0 {
		t.Fatalf("readback not truncated: %q %v", raw, err)
	}
	if err := os.Chmod(filepath.Join(root, "readback.tmp"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openReadback(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("wrong-mode readback=%v", err)
	}
}

func TestPlatformBackupLocalRejectsUnsafeRootLeafAndSecrets(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := newPlatformBackupLocalStore(writer); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("root=%v", err)
	}

	store, _, path := scratchTaskStore(t)
	if err := os.Symlink("elsewhere", filepath.Join(path, "package.tar")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openAccepted(platformBackupLocalPackage, 1, scratchDigest([]byte("x"))); !errors.Is(err, ErrPlatformBackupLocal) || bytes.Contains([]byte(err.Error()), []byte("elsewhere")) {
		t.Fatalf("symlink=%v", err)
	}
	if err := os.Remove(filepath.Join(path, "package.tar")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "package.tar"), []byte("x"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(path, "package.tar"), filepath.Join(path, "package-copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openAccepted(platformBackupLocalPackage, 1, scratchDigest([]byte("x"))); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("linkcount=%v", err)
	}
}

func TestPlatformBackupLocalRejectsReplacementAndInjectedOwnerMismatch(t *testing.T) {
	store, writer, transaction := scratchTaskStore(t)
	body := []byte("owner-check")
	if err := writer.WriteMetadata("package.tar", body); err != nil {
		t.Fatal(err)
	}
	moved := transaction + "-moved"
	if err := os.Rename(transaction, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(transaction, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openAccepted(platformBackupLocalPackage, int64(len(body)), scratchDigest(body)); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("replacement=%v", err)
	}
	if _, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("replacement begin=%v", err)
	}
	if _, err := store.openReadback(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("replacement readback=%v", err)
	}

	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	faultWriter, fault := renameHookWriter(t, root)
	defer faultWriter.Close()
	fault.fail = "owner-mismatch"
	if _, err := newPlatformBackupLocalStore(faultWriter); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("owner-mismatched constructor=%v", err)
	}
}

func TestPlatformBackupLocalCandidateFailureBoundaries(t *testing.T) {
	for _, failure := range []string{"chmod", "chown", "write", "fsync1", "close", "link-conflict", "remove"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, durableDirMode); err != nil {
				t.Fatal(err)
			}
			writer, fault := renameHookWriter(t, root)
			defer writer.Close()
			store, err := newPlatformBackupLocalStore(writer)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "chmod" || failure == "chown" {
				fault.fail = failure
				if _, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage); !errors.Is(err, ErrPlatformBackupLocal) {
					t.Fatalf("begin=%v", err)
				}
				return
			}
			candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
			if err != nil {
				t.Fatal(err)
			}
			fault.fail = failure
			if failure == "write" {
				if _, err := candidate.Write([]byte("value")); !errors.Is(err, ErrPlatformBackupLocal) {
					t.Fatalf("write=%v", err)
				}
				return
			}
			fault.fail = ""
			if _, err := candidate.Write([]byte("value")); err != nil {
				t.Fatal(err)
			}
			if failure == "link-conflict" {
				fault.fail = ""
				if err := writer.WriteMetadata("package.tar", []byte("old-final")); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "close" {
				fault.closeCalls = 0
			}
			if failure != "link-conflict" {
				fault.fail = failure
			}
			if err := candidate.Commit(scratchVerify([]byte("value"))); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("commit=%v", err)
			}
			if failure == "fsync1" && fault.closeCalls != 2 {
				t.Fatalf("fsync failure skipped partial close: close_calls=%d", fault.closeCalls)
			}
			if failure == "link-conflict" {
				if raw, err := os.ReadFile(filepath.Join(root, "package.tar")); err != nil || !bytes.Equal(raw, []byte("old-final")) {
					t.Fatalf("conflicting final mutation: %q %v", raw, err)
				}
			}
		})
	}
}

func TestPlatformBackupLocalReadbackRejectsSymlinkOwnerAndLinkcount(t *testing.T) {
	store, _, root := scratchTaskStore(t)
	if err := os.Symlink("target", filepath.Join(root, "readback.tmp")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openReadback(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("symlink readback=%v", err)
	}
	if err := os.Remove(filepath.Join(root, "readback.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "readback.tmp"), []byte("x"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "readback.tmp"), filepath.Join(root, "readback-copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openReadback(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("linkcount readback=%v", err)
	}

	faultRoot := t.TempDir()
	if err := os.Chmod(faultRoot, durableDirMode); err != nil {
		t.Fatal(err)
	}
	faultWriter, fault := renameHookWriter(t, faultRoot)
	defer faultWriter.Close()
	faultStore, err := newPlatformBackupLocalStore(faultWriter)
	if err != nil {
		t.Fatal(err)
	}
	if err := faultWriter.WriteMetadata("readback.tmp", []byte("x")); err != nil {
		t.Fatal(err)
	}
	fault.fail = "owner-mismatch"
	if _, err := faultStore.openReadback(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("owner readback=%v", err)
	}
}

func TestPlatformBackupLocalReadbackBoundsWritesAndSeeks(t *testing.T) {
	store, _, _ := scratchTaskStore(t)
	readback, err := store.openReadback()
	if err != nil {
		t.Fatal(err)
	}
	readback.maxSize = 3
	if _, err := readback.Write([]byte("four")); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("over-cap write=%v", err)
	}
	if _, err := readback.Write([]byte("x")); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("failed write retried=%v", err)
	}
	if err := readback.Close(); err != nil {
		t.Fatal(err)
	}
	readback, err = store.openReadback()
	if err != nil {
		t.Fatal(err)
	}
	readback.maxSize = 3
	if _, err := readback.Seek(4, io.SeekStart); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("over-cap seek=%v", err)
	}
	if err := readback.Close(); err != nil {
		t.Fatal(err)
	}
}

type scratchAfterOpenOps struct {
	durableOps
	target string
	after  func()
	fired  bool
}

func (o *scratchAfterOpenOps) OpenFile(name string, flag int, mode os.FileMode) (*os.File, error) {
	file, err := o.durableOps.OpenFile(name, flag, mode)
	if err == nil && !o.fired && name == o.target {
		o.fired = true
		o.after()
	}
	return file, err
}

func TestPlatformBackupLocalRejectsReplacementImmediatelyAfterOpen(t *testing.T) {
	for name, testCase := range map[string]struct {
		target   string
		prepare  func(t *testing.T, root string)
		exercise func(*platformBackupLocalStore) error
	}{
		"begin": {
			target: "package.tar.partial",
			exercise: func(store *platformBackupLocalStore) error {
				_, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
				return err
			},
		},
		"accepted": {
			target: "package.tar",
			prepare: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "package.tar"), []byte("body"), durableFileMode); err != nil {
					t.Fatal(err)
				}
			},
			exercise: func(store *platformBackupLocalStore) error {
				_, err := store.openAccepted(platformBackupLocalPackage, 4, scratchDigest([]byte("body")))
				return err
			},
		},
		"readback": {
			target: "readback.tmp",
			exercise: func(store *platformBackupLocalStore) error {
				_, err := store.openReadback()
				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			target, prepare, exercise := testCase.target, testCase.prepare, testCase.exercise
			root := t.TempDir()
			if err := os.Chmod(root, durableDirMode); err != nil {
				t.Fatal(err)
			}
			if prepare != nil {
				prepare(t, root)
			}
			opened, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
			moved := root + "-moved"
			ops := &scratchAfterOpenOps{durableOps: base, target: target, after: func() {
				if err := os.Rename(root, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, durableDirMode); err != nil {
					t.Fatal(err)
				}
			}}
			writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), ops)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			store, err := newPlatformBackupLocalStore(writer)
			if err != nil {
				t.Fatal(err)
			}
			if err := exercise(store); !errors.Is(err, ErrPlatformBackupLocal) || !ops.fired {
				t.Fatalf("after-open result=%v fired=%t", err, ops.fired)
			}
		})
	}
}

func TestPlatformBackupLocalReadbackClosePreservesStaleRootEvidence(t *testing.T) {
	store, _, transaction := scratchTaskStore(t)
	readback, err := store.openReadback()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readback.Write([]byte("evidence")); err != nil {
		t.Fatal(err)
	}
	moved := transaction + "-moved"
	if err := os.Rename(transaction, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(transaction, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := readback.Close(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("replaced-root close=%v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(moved, "readback.tmp")); err != nil || !bytes.Equal(raw, []byte("evidence")) {
		t.Fatalf("stale-root evidence=%q err=%v", raw, err)
	}
}

type scratchReaderCloseCountOps struct {
	durableOps
	closeCalls int
}

func (o *scratchReaderCloseCountOps) CloseFile(file *os.File) error {
	o.closeCalls++
	return o.durableOps.CloseFile(file)
}

func staleAcceptedReader(t *testing.T) (*platformBackupLocalReader, *scratchReaderCloseCountOps, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	seed, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("reader")
	if err := seed.WriteMetadata("package.tar", body); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	ops := &scratchReaderCloseCountOps{durableOps: base}
	writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	store, err := newPlatformBackupLocalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.openAccepted(platformBackupLocalPackage, int64(len(body)), scratchDigest(body))
	if err != nil {
		t.Fatal(err)
	}
	localReader, ok := reader.(*platformBackupLocalReader)
	if !ok {
		t.Fatal("accepted reader type changed")
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	return localReader, ops, root
}

func TestPlatformBackupLocalAcceptedReaderRejectsStaleRootAndCloses(t *testing.T) {
	for name, exercise := range map[string]func(*platformBackupLocalReader) error{
		"read":  func(reader *platformBackupLocalReader) error { _, err := reader.Read(make([]byte, 1)); return err },
		"seek":  func(reader *platformBackupLocalReader) error { _, err := reader.Seek(0, io.SeekStart); return err },
		"close": func(reader *platformBackupLocalReader) error { return reader.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			reader, ops, _ := staleAcceptedReader(t)
			if err := exercise(reader); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("stale %s=%v", name, err)
			}
			if name != "close" {
				if err := reader.Close(); !errors.Is(err, ErrPlatformBackupLocal) {
					t.Fatalf("stale cleanup close=%v", err)
				}
			}
			// One constructor close plus the reader close proves the stale reader
			// descriptor was released exactly once.
			if ops.closeCalls != 2 {
				t.Fatalf("close calls=%d", ops.closeCalls)
			}
			if err := reader.Close(); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("second close=%v", err)
			}
			if ops.closeCalls != 2 {
				t.Fatalf("second close changed count=%d", ops.closeCalls)
			}
		})
	}
}

func TestPlatformBackupLocalAcceptedReaderNormalUse(t *testing.T) {
	store, writer, _ := scratchTaskStore(t)
	body := []byte("normal reader")
	if err := writer.WriteMetadata("package.tar", body); err != nil {
		t.Fatal(err)
	}
	reader, err := store.openAccepted(platformBackupLocalPackage, int64(len(body)), scratchDigest(body))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("read=%q err=%v", got, err)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformBackupLocalLargeStreaming(t *testing.T) {
	store, _, _ := scratchTaskStore(t)
	body := bytes.Repeat([]byte("chunk"), backupEncryptionChunkSize/5+3)
	candidate, err := store.beginStream(platformBackupLocalEncryptedPartial, platformBackupLocalEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(body); start += 65537 {
		end := start + 65537
		if end > len(body) {
			end = len(body)
		}
		if _, err := candidate.Write(body[start:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := candidate.Commit(scratchVerify(body)); err != nil {
		t.Fatal(err)
	}
	opened, err := store.openAccepted(platformBackupLocalEncrypted, int64(len(body)), scratchDigest(body))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if copied, err := io.Copy(io.Discard, opened); err != nil || copied != int64(len(body)) {
		t.Fatalf("copied=%d err=%v", copied, err)
	}
}

func TestPlatformBackupLocalCandidateCloseBoundaries(t *testing.T) {
	for name, closeAt := range map[string]int{"partial-verify": 3, "root-sync": 4, "final-verify": 6} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, durableDirMode); err != nil {
				t.Fatal(err)
			}
			opened, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
			fault := &scratchNthCloseOps{durableOps: base, failAt: closeAt}
			writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), fault)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			store, err := newPlatformBackupLocalStore(writer)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := candidate.Write([]byte("close-boundary")); err != nil {
				t.Fatal(err)
			}
			if err := candidate.Commit(scratchVerify([]byte("close-boundary"))); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("close boundary=%v", err)
			}
		})
	}
}

type scratchNthCloseOps struct {
	durableOps
	failAt int
	calls  int
}

func (o *scratchNthCloseOps) CloseFile(file *os.File) error {
	o.calls++
	if o.calls == o.failAt {
		return errors.New("injected close failure")
	}
	return o.durableOps.CloseFile(file)
}

type scratchShortWriteOps struct{ durableOps }

func (o scratchShortWriteOps) Write(file *os.File, value []byte) (int, error) {
	n, err := o.durableOps.Write(file, value)
	if err == nil && n > 0 {
		return n - 1, nil
	}
	return n, err
}

func TestPlatformBackupLocalCandidateShortWriteIsTerminalAndBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	base := realDurableOps{durableRoot: osDurableRoot{root: opened}}
	writer, err := newDurableWriter(root, os.Getuid(), os.Getgid(), scratchShortWriteOps{durableOps: base})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	store, err := newPlatformBackupLocalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := candidate.Write([]byte("short")); !errors.Is(err, ErrPlatformBackupLocal) || n != len("short")-1 || candidate.size != int64(n) {
		t.Fatalf("short write n=%d size=%d err=%v", n, candidate.size, err)
	}
	if _, err := candidate.Write([]byte("retry")); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("short write retried=%v", err)
	}
	if err := candidate.Commit(scratchVerify([]byte("short"))); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("short write committed=%v", err)
	}
	candidate, err = store.beginStream(platformBackupLocalEncryptedPartial, platformBackupLocalEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := platformBackupLocalSpec(platformBackupLocalEncryptedPartial)
	candidate.size = spec.maxSize
	if _, err := candidate.Write([]byte("x")); !errors.Is(err, ErrPlatformBackupLocal) || !candidate.failed {
		t.Fatalf("cap was not fail-closed: %v", err)
	}
}
