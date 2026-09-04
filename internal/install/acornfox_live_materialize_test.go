package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newAcornFoxLiveStore(t *testing.T, root string, published *PublishedAcornFoxSubstrateV1, receipt InactiveSubstrateReceiptV1) *TaskAcornFoxRepoStore {
	t.Helper()
	store, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	journal := newAcornFoxRepoJournal()
	journal.BindingSHA256 = receipt.CandidateReceipt.BindingSHA256
	journal.SubstrateReceiptSHA256 = sha256Hex(raw)
	prepared, err := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
	if err != nil {
		t.Fatal(err)
	}
	journal.History[0].EvidenceSHA256 = prepared
	if err = journal.Validate(); err != nil {
		t.Fatal(err)
	}
	if err = store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	if err = lock.Release(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestAcornFoxLiveMaterializePreparedSubstrateExactly(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	lease, err := store.mintPreparedLease(context.Background(), published, substrate.CandidateReceipt.BindingSHA256)
	if err != nil {
		t.Fatalf("lease=%v", err)
	}
	entries, err := acornFoxLiveExpectedEntries(published)
	if err != nil {
		t.Fatalf("entries=%v", err)
	}
	if _, err = acornFoxLiveMakeReceipt(lease.journal, published, entries); err != nil {
		t.Fatalf("receipt=%v", err)
	}
	source, err := published.openLiveSourceRoot()
	if err != nil {
		t.Fatalf("source=%v", err)
	}
	defer source.Close()
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile {
			if _, err = acornFoxLiveReadSource(source, published, entry); err != nil {
				t.Fatalf("source %s=%v", entry.Path, err)
			}
		}
	}
	if err = lease.Release(); err != nil {
		t.Fatalf("release=%v", err)
	}
	receipt, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err = receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "task_live_materialized" || receipt.OwnershipEvidence != "modeled" {
		t.Fatalf("receipt=%#v", receipt)
	}
	journal, err := store.Resume(context.Background())
	if err != nil || journal.Phase != AcornFoxRepoStaticVerified || journal.LiveTreeSHA256 != receipt.LiveTreeSHA256 || journal.StaticSetSHA256 != receipt.StaticSetSHA256 {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, acornFoxLiveReceipt))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseAcornFoxLiveReceiptV1(raw); err != nil || got.LiveTreeSHA256 != receipt.LiveTreeSHA256 {
		t.Fatalf("live receipt=%#v err=%v", got, err)
	}
	for _, forbidden := range []string{"current", "active", "previous", "activation", ".wants"} {
		if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir, forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("forbidden live pointer %q: %v", forbidden, err)
		}
	}
	upgrade := filepath.Join(root, acornFoxLiveDir, filepath.FromSlash(AcornFoxUpgradeHelperPath))
	sourceUpgrade := filepath.Join(root, acornFoxSubstrateRootfs, filepath.FromSlash(AcornFoxUpgradeHelperPath))
	targetInfo, err := os.Lstat(upgrade)
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Lstat(sourceUpgrade)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(targetInfo, sourceInfo) || acornFoxRepoNlink(targetInfo) != 1 {
		t.Fatal("live helper reused substrate inode")
	}
	if _, err = materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
}

func TestAcornFoxLiveMaterializeRejectsForeignLiveState(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	if err := os.Mkdir(filepath.Join(root, acornFoxLiveDir), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, acornFoxLiveDir, "foreign"), []byte("x"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxLiveConflict) {
		t.Fatalf("foreign state = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir, "foreign")); err != nil {
		t.Fatalf("foreign state overwritten: %v", err)
	}
	if journal, journalErr := store.Resume(context.Background()); journalErr != nil || journal.NeedsRecovery {
		t.Fatalf("foreign conflict wrote recovery=%#v err=%v", journal, journalErr)
	}
}

func TestAcornFoxLiveMaterializeRejectsBindingMismatchWithoutLive(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	if _, err := materializeAcornFoxLive(context.Background(), store, published, acornFoxRepoDigest("f")); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("binding mismatch = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatch mutated live: %v", err)
	}
}

func TestAcornFoxLiveMaterializeDoesNotReturnReceiptWhenLeaseReleaseFails(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	acornFoxLiveLeaseRelease = func(lease *acornFoxPreparedRepoLease) error {
		_ = lease.Release()
		return errors.New("release injected")
	}
	t.Cleanup(func() {
		acornFoxLiveLeaseRelease = func(lease *acornFoxPreparedRepoLease) error { return lease.Release() }
	})
	got, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256)
	if !errors.Is(err, ErrAcornFoxLiveReleaseUnknown) || got.SchemaVersion != 0 || len(got.Entries) != 0 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	acornFoxLiveLeaseRelease = func(lease *acornFoxPreparedRepoLease) error { return lease.Release() }
	if _, err = materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatalf("fresh retry=%v", err)
	}
}

func TestAcornFoxLiveVerifiedLeaseRejectsReceiptAndTreeDrift(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*testing.T, string, InactiveSubstrateReceiptV1)
	}{
		{"receipt-symlink", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			path := filepath.Join(root, acornFoxLiveReceipt)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("elsewhere", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt-hardlink", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			if err := os.Link(filepath.Join(root, acornFoxLiveReceipt), filepath.Join(root, "receipt-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt-mode", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			if err := os.Chmod(filepath.Join(root, acornFoxLiveReceipt), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt-noncanonical", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			path := filepath.Join(root, acornFoxLiveReceipt)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, append(raw, ' '), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"release-helper", func(t *testing.T, root string, r InactiveSubstrateReceiptV1) {
			if err := os.WriteFile(filepath.Join(root, acornFoxLiveDir, filepath.FromSlash(AcornFoxHealthcheckHelperPath(r.CandidateReceipt))), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra-live", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			if err := os.WriteFile(filepath.Join(root, acornFoxLiveDir, "extra"), []byte("x"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-live", func(t *testing.T, root string, _ InactiveSubstrateReceiptV1) {
			if err := os.Remove(filepath.Join(root, acornFoxLiveDir, filepath.FromSlash(AcornFoxUpgradeHelperPath))); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _, published, substrate := newAcornFox03CPublished(t)
			store := newAcornFoxLiveStore(t, root, published, substrate)
			if _, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
				t.Fatal(err)
			}
			test.apply(t, root, substrate)
			if lease, err := store.mintLiveVerifiedLease(context.Background(), published, substrate.CandidateReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxRepoConflict) || lease != nil {
				t.Fatalf("lease=%#v err=%v", lease, err)
			}
			journal, err := store.Resume(context.Background())
			if err != nil || journal.Phase != AcornFoxRepoStaticVerified {
				t.Fatalf("journal=%#v err=%v", journal, err)
			}
		})
	}
}

func TestAcornFoxLiveVerifiedLeaseRequiresVerifiedTreeAndReplays(t *testing.T) {
	root, _, published, substrate := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, substrate)
	if _, err := materializeAcornFoxLive(context.Background(), store, published, substrate.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	first, err := store.mintLiveVerifiedLease(context.Background(), published, substrate.CandidateReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if first.receipt.ReleaseID != substrate.CandidateReceipt.ReleaseID {
		t.Fatal("lease did not pin receipt")
	}
	other, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if blocked, lockErr := other.mintLiveVerifiedLease(context.Background(), published, substrate.CandidateReceipt.BindingSHA256); blocked != nil || !errors.Is(lockErr, ErrAcornFoxRepoLocked) {
		t.Fatalf("lock lifetime lease=%#v err=%v", blocked, lockErr)
	}
	if err = first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := store.mintLiveVerifiedLease(context.Background(), published, substrate.CandidateReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Release(); err != nil {
		t.Fatal(err)
	}
}
