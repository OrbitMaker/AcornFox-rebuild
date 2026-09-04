package install

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func newAcornFoxRepoTaskRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	return root
}

func acquireAcornFoxRepoStore(t *testing.T, root string) (*TaskAcornFoxRepoStore, AcornFoxRepoStoreLock) {
	t.Helper()
	store, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return store, lock
}

func TestTaskAcornFoxRepoStoreCreateReplayTransitionAndResume(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	store, lock := acquireAcornFoxRepoStore(t, root)
	journal := newAcornFoxRepoJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	next := advanceAcornFoxRepoJournal(t, journal, AcornFoxRepoLiveMaterialized, acornFoxRepoDigest("b"))
	if err := store.Save(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Resume(context.Background()); err != nil || !sameAcornFoxRepoJournal(got, next) {
		t.Fatalf("resume = %#v, %v", got, err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, freshLock := acquireAcornFoxRepoStore(t, root)
	defer fresh.Close()
	defer freshLock.Release()
	if err := fresh.Create(context.Background(), journal); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("old journal replay after transition = %v, want conflict", err)
	}
	if err := fresh.Save(context.Background(), next); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("stale CAS save = %v, want conflict", err)
	}
}

func TestTaskAcornFoxRepoStoreRecoveryTransitionAndClosedSurface(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	store, lock := acquireAcornFoxRepoStore(t, root)
	defer store.Close()
	defer lock.Release()
	journal := newAcornFoxRepoJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	recovery := journal
	recovery.Revision++
	recovery.NeedsRecovery = true
	recovery.Failure = &AcornFoxRepoFailureV1{Code: "write_unknown", Digest: acornFoxRepoDigest("f")}
	recovery.History = append(recovery.History, AcornFoxRepoHistoryV1{Revision: recovery.Revision, From: journal.Phase, To: journal.Phase, EvidenceSHA256: recovery.Failure.Digest})
	if err := store.Save(context.Background(), recovery); err != nil {
		t.Fatal(err)
	}
	resolved := recovery
	resolved.Revision++
	resolved.NeedsRecovery = false
	resolved.Failure = nil
	resolved.History = append(resolved.History, AcornFoxRepoHistoryV1{Revision: resolved.Revision, From: recovery.Phase, To: recovery.Phase, EvidenceSHA256: recovery.History[len(recovery.History)-1].EvidenceSHA256})
	if err := store.Save(context.Background(), resolved); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != acornFoxRepoInstallLock || entries[1].Name() != acornFoxRepoInstallDir {
		t.Fatalf("closed store changed unexpected root entries: %#v", entries)
	}
}

func TestTaskAcornFoxRepoStoreConcurrentFirstCreateAndCAS(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	journal := newAcornFoxRepoJournal()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
			if err != nil {
				errs <- err
				return
			}
			defer store.Close()
			lock, err := store.Acquire(context.Background())
			if errors.Is(err, ErrAcornFoxRepoLocked) {
				return
			}
			if err == nil {
				err = store.Create(context.Background(), journal)
				_ = lock.Release()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	store, lock := acquireAcornFoxRepoStore(t, root)
	defer store.Close()
	defer lock.Release()
	if got, err := store.Load(context.Background()); err != nil || !sameAcornFoxRepoJournal(got, journal) {
		t.Fatalf("first create result = %#v, %v", got, err)
	}
}

type acornFoxRepoFaultFile struct {
	acornFoxRepoFile
	write func([]byte) (int, error)
}

func (f acornFoxRepoFaultFile) Write(raw []byte) (int, error) { return f.write(raw) }

func TestTaskAcornFoxRepoStoreSaveUnknownReadbackAndPartialFailure(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	store, lock := acquireAcornFoxRepoStore(t, root)
	defer store.Close()
	defer lock.Release()
	journal := newAcornFoxRepoJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	next := advanceAcornFoxRepoJournal(t, journal, AcornFoxRepoLiveMaterialized, acornFoxRepoDigest("b"))
	original := store.fs.openFile
	store.fs.openFile = func(root *os.Root, name string, flags int, mode os.FileMode) (acornFoxRepoFile, error) {
		file, err := original(root, name, flags, mode)
		if err != nil || name != acornFoxRepoInstallJournal || flags&os.O_WRONLY == 0 {
			return file, err
		}
		return acornFoxRepoFaultFile{acornFoxRepoFile: file, write: func(raw []byte) (int, error) {
			n, _ := file.Write(raw)
			return n, errors.New("post-write")
		}}, nil
	}
	if err := store.Save(context.Background(), next); err != nil {
		t.Fatalf("post-write unknown did not reconcile: %v", err)
	}
	store.fs.openFile = original
	partial := advanceAcornFoxRepoJournal(t, next, AcornFoxRepoStaticVerified, acornFoxRepoDigest("d"))
	store.fs.openFile = func(root *os.Root, name string, flags int, mode os.FileMode) (acornFoxRepoFile, error) {
		file, err := original(root, name, flags, mode)
		if err != nil || name != acornFoxRepoInstallJournal || flags&os.O_WRONLY == 0 {
			return file, err
		}
		return acornFoxRepoFaultFile{acornFoxRepoFile: file, write: func(raw []byte) (int, error) {
			if len(raw) == 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, io.ErrUnexpectedEOF
		}}, nil
	}
	if err := store.Save(context.Background(), partial); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("partial write = %v, want conflict", err)
	}
}

func TestTaskAcornFoxRepoStoreRejectsUnsafeRootsReplacementAndHardlinks(t *testing.T) {
	root := newAcornFoxRepoTaskRoot(t)
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskAcornFoxRepoStore(link, os.Getuid(), os.Getgid()); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("symlink root = %v", err)
	}
	store, lock := acquireAcornFoxRepoStore(t, root)
	journal := newAcornFoxRepoJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, acornFoxRepoInstallJournal), filepath.Join(root, "foreign-hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("hardlinked journal = %v", err)
	}
	if err := os.Remove(filepath.Join(root, "foreign-hardlink")); err != nil {
		t.Fatal(err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("replaced root = %v", err)
	}
}
