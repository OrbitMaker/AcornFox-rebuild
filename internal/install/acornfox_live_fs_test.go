package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcornFoxLiveMaterializeRejectsSymlinkAndHardlinkTargets(t *testing.T) {
	for _, shape := range []string{"symlink", "hardlink", "extra"} {
		t.Run(shape, func(t *testing.T) {
			root, _, published, substrate := newAcornFox03CPublished(t)
			store := newAcornFoxLiveStore(t, root, published, substrate)
			if err := os.Mkdir(filepath.Join(root, acornFoxLiveDir), durableDirMode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, acornFoxLiveDir, "foreign")
			switch shape {
			case "symlink":
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(path, []byte("x"), durableFileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, filepath.Join(root, "foreign-link")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(path, []byte("x"), durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxLiveConflict) {
				t.Fatalf("%s = %v", shape, err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("%s target overwritten: %v", shape, err)
			}
		})
	}
}

func TestAcornFoxLiveMaterializeFreshResumeCleansExactTemporary(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	entries, err := acornFoxLiveExpectedEntries(published)
	if err != nil {
		t.Fatal(err)
	}
	var fileEntry SubstrateEntry
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile && entry.Path == AcornFoxUpgradeHelperPath {
			fileEntry = entry
			break
		}
	}
	if fileEntry.Path == "" {
		t.Fatal("upgrade helper missing")
	}
	source, err := published.openLiveSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	raw, err := acornFoxLiveReadSource(source, published, fileEntry)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{acornFoxLiveDir, durableDirMode}, {"live/opt", 0o755}, {"live/opt/acornfox", 0o755}, {"live/opt/acornfox/upgrade-tools", 0o755}} {
		if err = os.Mkdir(filepath.Join(root, filepath.FromSlash(directory.path)), directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := store.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(root, filepath.FromSlash(acornFoxLiveTemp(journal.TransactionID, acornFoxLivePath(fileEntry.Path))))
	if err = os.WriteFile(temp, raw, os.FileMode(fileEntry.Mode)); err != nil {
		t.Fatal(err)
	}
	if _, err = materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh resume temp remains: %v", err)
	}
}

func TestAcornFoxLiveMaterializeRejectsPublishedSourceTamper(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	path := filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxUpgradeHelperPath))
	if err := os.WriteFile(path, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("source tamper = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered source mutated live: %v", err)
	}
}

func TestAcornFoxLiveMaterializeFaultStepsFreshResume(t *testing.T) {
	steps := []string{"mkdir", "mkdir-post", "open", "chmod", "modeled-apply", "write", "short-write", "sync", "sync-post", "close", "close-post", "link", "link-post", "parent-sync", "remove", "stat"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root, _, published, substrate := newAcornFox03CPublished(t)
			store := newAcornFoxLiveStore(t, root, published, substrate)
			fired := false
			acornFoxLiveFaultStep = func(got string) error {
				if !fired && got == step {
					fired = true
					return errors.New("injected")
				}
				return nil
			}
			t.Cleanup(func() { acornFoxLiveFaultStep = func(string) error { return nil } })
			_, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256)
			acornFoxLiveFaultStep = func(string) error { return nil }
			if !fired || !errors.Is(err, ErrAcornFoxLiveConflict) {
				t.Fatalf("step=%s fired=%t err=%v", step, fired, err)
			}
			if _, err = materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
				t.Fatalf("fresh resume %s: %v", step, err)
			}
		})
	}
}
