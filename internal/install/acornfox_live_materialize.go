package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var (
	ErrAcornFoxLiveConflict        = errors.New("AcornFox live materialization conflicts with task state")
	ErrAcornFoxLiveRecoveryUnknown = errors.New("AcornFox live recovery persistence is unknown")
	ErrAcornFoxLiveReleaseUnknown  = errors.New("AcornFox live lease release is unknown")
)

// acornFoxLiveFaultStep is a deliberately local test seam for the live
// materializer's persistence boundaries. Production uses the no-op function;
// it is not a reusable filesystem layer and never accepts caller authority.
var acornFoxLiveFaultStep = func(string) error { return nil }
var acornFoxLiveLeaseRelease = func(lease *acornFoxPreparedRepoLease) error { return lease.Release() }

func acornFoxLiveStep(name string) error { return acornFoxLiveFaultStep(name) }

// materializeAcornFoxLive is deliberately package-private. Its only authority
// is a sealed published substrate plus a locked repo-store lease; callers do
// not provide deployment paths, units, accounts, versions, or host identity.
func materializeAcornFoxLive(ctx context.Context, store *TaskAcornFoxRepoStore, substrate *PublishedAcornFoxSubstrateV1, bindingSHA256 string) (result AcornFoxLiveReceiptV1, returnedErr error) {
	lease, err := store.mintPreparedLease(ctx, substrate, bindingSHA256)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, err
	}
	defer func() {
		if releaseErr := acornFoxLiveLeaseRelease(lease); releaseErr != nil && returnedErr == nil {
			result, returnedErr = AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveReleaseUnknown
		}
	}()
	return (&acornFoxLiveMaterializer{lease: lease}).Materialize(ctx)
}

type acornFoxLiveMaterializer struct{ lease *acornFoxPreparedRepoLease }

func (m *acornFoxLiveMaterializer) Materialize(ctx context.Context) (result AcornFoxLiveReceiptV1, returnedErr error) {
	effectful := false
	markEffect := func() { effectful = true }
	defer func() {
		if returnedErr == nil || !effectful || m == nil || m.lease == nil || m.lease.store == nil || m.lease.journal.NeedsRecovery {
			return
		}
		failed := acornFoxLiveFailureJournal(m.lease.journal)
		if m.lease.store.Save(context.Background(), failed) == nil {
			m.lease.journal = failed
			return
		}
		observed, err := m.lease.store.Resume(context.Background())
		if err == nil && sameAcornFoxRepoJournal(observed, failed) {
			m.lease.journal = observed
		}
		returnedErr = ErrAcornFoxLiveRecoveryUnknown
	}()
	if ctx == nil || ctx.Err() != nil || m == nil || m.lease == nil || m.lease.store == nil || m.lease.substrate == nil || !m.lease.store.ownsLock() {
		return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
	}
	if !sameAcornFoxLiveTaskRoot(m.lease.store, m.lease.substrate) || m.lease.substrate.Verify() != nil {
		return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
	}
	source, err := m.lease.substrate.openLiveSourceRoot()
	if err != nil {
		return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
	}
	defer source.Close()
	target, err := m.lease.store.openRoot()
	if err != nil {
		return AcornFoxLiveReceiptV1{}, err
	}
	defer target.Close()
	entries, err := acornFoxLiveExpectedEntries(m.lease.substrate)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("clean temps: %w", ErrAcornFoxLiveConflict)
	}
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile {
			if _, err = acornFoxLiveReadSource(source, m.lease.substrate, entry); err != nil {
				return AcornFoxLiveReceiptV1{}, fmt.Errorf("source %s: %w", entry.Path, ErrAcornFoxLiveConflict)
			}
		}
	}
	receipt, err := acornFoxLiveMakeReceipt(m.lease.journal, m.lease.substrate, entries)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("validate existing: %w", ErrAcornFoxLiveConflict)
	}
	if err = acornFoxLiveEnsureRoot(target, m.lease.store, markEffect); err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("ensure root: %w", ErrAcornFoxLiveConflict)
	}
	if err = acornFoxLiveCleanTemps(target, m.lease.store, m.lease.journal.TransactionID, source, m.lease.substrate, entries, markEffect); err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("clean temps: %w", ErrAcornFoxLiveConflict)
	}
	if err = acornFoxLiveValidateExisting(target, m.lease.store, entries, receipt); err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("validate existing: %w", ErrAcornFoxLiveConflict)
	}
	journal := m.lease.journal
	if journal.NeedsRecovery {
		next := acornFoxLiveRecoveredJournal(journal, receipt)
		if m.lease.store.Save(ctx, next) != nil {
			return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveRecoveryUnknown
		}
		journal, m.lease.journal = next, next
	}
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryDirectory && acornFoxLiveEnsureDir(target, m.lease.store, acornFoxLivePath(entry.Path), os.FileMode(entry.Mode), markEffect) != nil {
			return AcornFoxLiveReceiptV1{}, fmt.Errorf("ensure directory %s: %w", entry.Path, ErrAcornFoxLiveConflict)
		}
	}
	for _, entry := range entries {
		if entry.Kind != SubstrateEntryFile {
			continue
		}
		raw, readErr := acornFoxLiveReadSource(source, m.lease.substrate, entry)
		if readErr != nil {
			return AcornFoxLiveReceiptV1{}, fmt.Errorf("read file %s: %w", entry.Path, ErrAcornFoxLiveConflict)
		}
		if writeErr := acornFoxLiveWriteFile(target, m.lease.store, m.lease.journal.TransactionID, acornFoxLivePath(entry.Path), raw, os.FileMode(entry.Mode), markEffect); writeErr != nil {
			return AcornFoxLiveReceiptV1{}, fmt.Errorf("write file %s (%v): %w", entry.Path, writeErr, ErrAcornFoxLiveConflict)
		}
	}
	raw, err := MarshalAcornFoxLiveReceiptV1(receipt)
	if err != nil || acornFoxLiveWriteFile(target, m.lease.store, m.lease.journal.TransactionID, acornFoxLiveReceipt, raw, durableFileMode, markEffect) != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("write receipt: %w", ErrAcornFoxLiveConflict)
	}
	if err = acornFoxLiveVerifyTarget(target, m.lease.store, entries, receipt); err != nil {
		return AcornFoxLiveReceiptV1{}, fmt.Errorf("verify live target: %w", ErrAcornFoxLiveConflict)
	}
	if journal.Phase == AcornFoxRepoPrepared {
		next, nextErr := acornFoxLiveAdvance(journal, AcornFoxRepoLiveMaterialized, receipt)
		if nextErr != nil || m.lease.store.Save(ctx, next) != nil {
			return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
		}
		journal, m.lease.journal = next, next
	}
	if journal.Phase == AcornFoxRepoLiveMaterialized {
		if err = acornFoxLiveVerifyTarget(target, m.lease.store, entries, receipt); err != nil {
			return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
		}
		next, nextErr := acornFoxLiveAdvance(journal, AcornFoxRepoStaticVerified, receipt)
		if nextErr != nil || m.lease.store.Save(ctx, next) != nil {
			return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
		}
		journal, m.lease.journal = next, next
	}
	if journal.Phase != AcornFoxRepoStaticVerified || journal.LiveTreeSHA256 != receipt.LiveTreeSHA256 || journal.OwnershipPlanSHA256 != receipt.OwnershipPlanSHA256 || journal.StaticSetSHA256 != receipt.StaticSetSHA256 {
		return AcornFoxLiveReceiptV1{}, ErrAcornFoxLiveConflict
	}
	return receipt, nil
}

func acornFoxLiveExpectedEntries(substrate *PublishedAcornFoxSubstrateV1) ([]SubstrateEntry, error) {
	if substrate == nil || substrate.receipt.Validate() != nil {
		return nil, ErrAcornFoxLiveConflict
	}
	entries := append([]SubstrateEntry(nil), substrate.receipt.Entries...)
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate.receipt)
	if err != nil {
		return nil, err
	}
	entries = append(entries, SubstrateEntry{Path: "var/lib/acornfox/install/releases/" + substrate.receipt.CandidateReceipt.ReleaseID + ".json", Kind: SubstrateEntryFile, Mode: durableFileMode, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(raw)), SHA256: sha256Hex(raw)})
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := validateAcornFoxLiveSourceEntries(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func validateAcornFoxLiveSourceEntries(entries []SubstrateEntry) error {
	seen := map[string]bool{}
	for _, entry := range entries {
		if seen[entry.Path] || validateRelativePath(entry.Path) != nil || entry.Mode&0o022 != 0 || entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory || entry.Size < 0 {
			return ErrAcornFoxLiveConflict
		}
		seen[entry.Path] = true
	}
	return nil
}

func acornFoxLiveMakeReceipt(journal AcornFoxRepoJournalV1, substrate *PublishedAcornFoxSubstrateV1, source []SubstrateEntry) (AcornFoxLiveReceiptV1, error) {
	entries := make([]AcornFoxLiveEntryV1, 0, len(source))
	for _, entry := range source {
		live, err := acornFoxLiveEntryFor(entry)
		if err != nil {
			return AcornFoxLiveReceiptV1{}, err
		}
		entries = append(entries, live)
	}
	tree, err := acornFoxLiveDigest(entries)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, err
	}
	plan, err := acornFoxLiveOwnershipDigest(entries)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, err
	}
	static, err := acornFoxLiveStaticDigest(entries)
	if err != nil {
		return AcornFoxLiveReceiptV1{}, err
	}
	return AcornFoxLiveReceiptV1{SchemaVersion: AcornFoxLiveReceiptV1Schema, State: "task_live_materialized", BindingSHA256: journal.BindingSHA256, SubstrateReceiptSHA256: journal.SubstrateReceiptSHA256, ReleaseID: substrate.receipt.CandidateReceipt.ReleaseID, LiveTreeSHA256: tree, OwnershipPlanSHA256: plan, StaticSetSHA256: static, OwnershipEvidence: "symbolic", Entries: entries}, nil
}

func acornFoxLiveReadSource(root *os.Root, substrate *PublishedAcornFoxSubstrateV1, entry SubstrateEntry) ([]byte, error) {
	path := acornFoxSubstrateTarget(entry.Path)
	if entry.Path == "var/lib/acornfox/install/releases/"+substrate.receipt.CandidateReceipt.ReleaseID+".json" {
		path = acornFoxSubstrateReceipt
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, entry.Size+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(entry.Mode) || info.Size() != entry.Size || len(raw) != int(entry.Size) || sha256Hex(raw) != entry.SHA256 {
		return nil, ErrAcornFoxLiveConflict
	}
	return raw, nil
}

func acornFoxLivePath(path string) string {
	return filepath.ToSlash(filepath.Join(acornFoxLiveDir, path))
}
func acornFoxLiveTemp(transactionID, path string) string {
	name := sha256Hex([]byte("acornfox-live-temp-v1\x00" + transactionID + "\x00" + path))
	return filepath.ToSlash(filepath.Join(parentDirectory(path), ".acornfox-live.tmp-"+name))
}

func acornFoxLiveEnsureRoot(root *os.Root, store *TaskAcornFoxRepoStore, markEffect func()) error {
	info, err := root.Lstat(acornFoxLiveDir)
	if errors.Is(err, os.ErrNotExist) {
		if err = acornFoxLiveStep("mkdir"); err != nil {
			return err
		}
		mkdirErr := root.Mkdir(acornFoxLiveDir, durableDirMode)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return mkdirErr
		}
		if mkdirErr == nil {
			markEffect()
		}
		if err = acornFoxLiveStep("mkdir-post"); err != nil {
			return err
		}
		file, openErr := root.OpenFile(acornFoxLiveDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err = acornFoxLiveSyncDir(root, "."); err != nil {
			return err
		}
		info, err = root.Lstat(acornFoxLiveDir)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != durableDirMode || verifyOwner(info, store.uid, store.gid) != nil {
		return ErrAcornFoxLiveConflict
	}
	return nil
}

func acornFoxLiveEnsureDir(root *os.Root, store *TaskAcornFoxRepoStore, path string, mode os.FileMode, markEffect func()) error {
	info, err := root.Lstat(path)
	created := errors.Is(err, os.ErrNotExist)
	if created {
		if err = acornFoxLiveStep("mkdir"); err != nil {
			return err
		}
		mkdirErr := root.Mkdir(path, mode)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return mkdirErr
		}
		if mkdirErr == nil {
			markEffect()
		}
		if err = acornFoxLiveStep("mkdir-post"); err != nil {
			return err
		}
		info, err = root.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || verifyOwner(info, store.uid, store.gid) != nil {
		return ErrAcornFoxLiveConflict
	}
	if created {
		file, openErr := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		return acornFoxLiveSyncDir(root, parentDirectory(path))
	}
	return nil
}

func acornFoxLiveWriteFile(root *os.Root, store *TaskAcornFoxRepoStore, transactionID, path string, raw []byte, mode os.FileMode, markEffect func()) error {
	if info, err := root.Lstat(path); err == nil {
		if acornFoxLiveExactFile(root, store, path, raw, mode, false) {
			return nil
		}
		_ = info
		return ErrAcornFoxLiveConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp := acornFoxLiveTemp(transactionID, path)
	if info, err := root.Lstat(temp); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || acornFoxRepoNlink(info) != 1 || verifyOwner(info, store.uid, store.gid) != nil || !acornFoxLiveExactFile(root, store, temp, raw, mode, true) {
			return ErrAcornFoxLiveConflict
		}
		if err = acornFoxLiveStep("remove"); err != nil {
			return ErrAcornFoxLiveConflict
		}
		if err = root.Remove(temp); err != nil {
			return ErrAcornFoxLiveConflict
		}
		markEffect()
		if acornFoxLiveSyncDir(root, parentDirectory(path)) != nil {
			return ErrAcornFoxLiveConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := acornFoxLiveStep("open"); err != nil {
		return err
	}
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	markEffect()
	if err = acornFoxLiveStep("chmod"); err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = acornFoxLiveStep("modeled-apply")
	}
	if err == nil {
		remaining := raw
		for len(remaining) > 0 && err == nil {
			if err = acornFoxLiveStep("write"); err != nil {
				break
			}
			chunk := remaining
			shortErr := acornFoxLiveStep("short-write")
			if shortErr != nil && len(chunk) > 1 {
				chunk = chunk[:len(chunk)/2]
			}
			n, writeErr := file.Write(chunk)
			if n > 0 {
				markEffect()
			}
			if n < 0 || n > len(remaining) {
				err = ErrAcornFoxLiveConflict
				break
			}
			remaining = remaining[n:]
			if shortErr != nil {
				err = shortErr
			} else if writeErr != nil {
				err = writeErr
			} else if n == 0 {
				err = io.ErrShortWrite
			}
		}
	}
	if err == nil {
		err = acornFoxLiveStep("sync")
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = acornFoxLiveStep("sync-post")
	}
	if err == nil {
		err = acornFoxLiveStep("close")
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = acornFoxLiveStep("close-post")
	}
	if err != nil {
		return err
	}
	if !acornFoxLiveExactFile(root, store, temp, raw, mode, true) {
		return ErrAcornFoxLiveConflict
	}
	if err = acornFoxLiveStep("link"); err != nil {
		return err
	}
	if err = root.Link(temp, path); err != nil {
		if !acornFoxLiveExactFile(root, store, path, raw, mode, false) {
			return err
		}
	} else {
		markEffect()
	}
	if err = acornFoxLiveStep("link-post"); err != nil {
		return err
	}
	if err = acornFoxLiveSyncDir(root, parentDirectory(path)); err != nil {
		return err
	}
	if !acornFoxLiveExactFile(root, store, path, raw, mode, true) {
		return ErrAcornFoxLiveConflict
	}
	tempInfo, tempErr := root.Lstat(temp)
	if tempErr != nil || acornFoxRepoNlink(tempInfo) != 2 || !acornFoxLiveExactFile(root, store, temp, raw, mode, true) {
		return ErrAcornFoxLiveConflict
	}
	if err = acornFoxLiveStep("remove"); err != nil {
		return ErrAcornFoxLiveConflict
	}
	if err = root.Remove(temp); err != nil {
		return ErrAcornFoxLiveConflict
	}
	markEffect()
	if acornFoxLiveSyncDir(root, parentDirectory(path)) != nil {
		return ErrAcornFoxLiveConflict
	}
	if !acornFoxLiveExactFile(root, store, path, raw, mode, false) {
		return ErrAcornFoxLiveConflict
	}
	return nil
}

func acornFoxLiveExactFile(root *os.Root, store *TaskAcornFoxRepoStore, path string, raw []byte, mode os.FileMode, allowTwoLink bool) bool {
	if acornFoxLiveStep("stat") != nil {
		return false
	}
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || info.Size() != int64(len(raw)) || verifyOwner(info, store.uid, store.gid) != nil || (!allowTwoLink && acornFoxRepoNlink(info) != 1) || (allowTwoLink && acornFoxRepoNlink(info) != 1 && acornFoxRepoNlink(info) != 2) {
		return false
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	opened, statErr := file.Stat()
	got, readErr := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	closeErr := file.Close()
	return statErr == nil && readErr == nil && closeErr == nil && os.SameFile(info, opened) && bytes.Equal(got, raw)
}

func acornFoxLiveSyncDir(root *os.Root, path string) error {
	if err := acornFoxLiveStep("parent-sync"); err != nil {
		return err
	}
	if path == "" {
		path = "."
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func acornFoxLiveCleanTemps(root *os.Root, store *TaskAcornFoxRepoStore, transactionID string, source *os.Root, substrate *PublishedAcornFoxSubstrateV1, entries []SubstrateEntry, markEffect func()) error {
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile {
			raw, err := acornFoxLiveReadSource(source, substrate, entry)
			if err != nil {
				return err
			}
			temp := acornFoxLiveTemp(transactionID, acornFoxLivePath(entry.Path))
			if info, statErr := root.Lstat(temp); statErr == nil {
				if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, store.uid, store.gid) != nil {
					return ErrAcornFoxLiveConflict
				}
				if acornFoxRepoNlink(info) == 2 {
					final := acornFoxLivePath(entry.Path)
					finalInfo, finalErr := root.Lstat(final)
					if finalErr != nil || !os.SameFile(info, finalInfo) || !acornFoxLiveExactFile(root, store, final, raw, os.FileMode(entry.Mode), true) {
						return ErrAcornFoxLiveConflict
					}
				} else if acornFoxRepoNlink(info) != 1 {
					return ErrAcornFoxLiveConflict
				}
				if acornFoxLiveStep("remove") != nil {
					return ErrAcornFoxLiveConflict
				}
				if root.Remove(temp) != nil {
					return ErrAcornFoxLiveConflict
				}
				markEffect()
				if acornFoxLiveSyncDir(root, parentDirectory(temp)) != nil {
					return ErrAcornFoxLiveConflict
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		}
	}
	return nil
}

func acornFoxLiveValidateExisting(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry, receipt AcornFoxLiveReceiptV1) error {
	want := map[string]SubstrateEntry{}
	for _, entry := range entries {
		want[entry.Path] = entry
	}
	return acornFoxLiveWalk(root, acornFoxLiveDir, func(relative string, info os.FileInfo) error {
		if relative == "receipt.json" {
			return nil
		}
		entry, ok := want[relative]
		if !ok || (entry.Kind == SubstrateEntryDirectory) != info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, store.uid, store.gid) != nil || (!info.IsDir() && acornFoxRepoNlink(info) != 1) {
			return ErrAcornFoxLiveConflict
		}
		return nil
	})
}

func acornFoxLiveVerifyTarget(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry, receipt AcornFoxLiveReceiptV1) error {
	if err := acornFoxLiveValidateExisting(root, store, entries, receipt); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Path] = true
		path := acornFoxLivePath(entry.Path)
		if entry.Kind == SubstrateEntryDirectory {
			info, err := root.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode().Perm() != os.FileMode(entry.Mode) {
				return ErrAcornFoxLiveConflict
			}
			continue
		}
		raw := make([]byte, 0)
		file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, entry.Size+1))
		info, statErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || info.Size() != entry.Size || sha256Hex(raw) != entry.SHA256 {
			return ErrAcornFoxLiveConflict
		}
	}
	if len(seen) != len(entries) {
		return ErrAcornFoxLiveConflict
	}
	raw, err := MarshalAcornFoxLiveReceiptV1(receipt)
	if err != nil || !acornFoxLiveExactFile(root, store, acornFoxLiveReceipt, raw, durableFileMode, false) {
		return ErrAcornFoxLiveConflict
	}
	return nil
}

func acornFoxLiveWalk(root *os.Root, directory string, visit func(string, os.FileInfo) error) error {
	file, err := root.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	children, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return ErrAcornFoxLiveConflict
	}
	for _, child := range children {
		path := filepath.ToSlash(filepath.Join(directory, child.Name()))
		info, err := root.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return ErrAcornFoxLiveConflict
		}
		relative := strings.TrimPrefix(path, acornFoxLiveDir+"/")
		if err = visit(relative, info); err != nil {
			return err
		}
		if info.IsDir() {
			if err = acornFoxLiveWalk(root, path, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func acornFoxLiveAdvance(old AcornFoxRepoJournalV1, phase AcornFoxRepoPhase, receipt AcornFoxLiveReceiptV1) (AcornFoxRepoJournalV1, error) {
	next := old
	next.Revision++
	next.Phase = phase
	switch phase {
	case AcornFoxRepoLiveMaterialized:
		next.LiveTreeSHA256 = receipt.LiveTreeSHA256
	case AcornFoxRepoStaticVerified:
		next.OwnershipPlanSHA256, next.StaticSetSHA256 = receipt.OwnershipPlanSHA256, receipt.StaticSetSHA256
	default:
		return next, ErrAcornFoxLiveConflict
	}
	next.History = append(next.History, AcornFoxRepoHistoryV1{Revision: next.Revision, Kind: AcornFoxRepoHistoryAdvance, From: old.Phase, To: phase, EvidenceSHA256: acornFoxRepoPhaseEvidence(next, phase)})
	if next.Validate() != nil {
		return AcornFoxRepoJournalV1{}, ErrAcornFoxLiveConflict
	}
	return next, nil
}

func acornFoxLiveFailureJournal(old AcornFoxRepoJournalV1) AcornFoxRepoJournalV1 {
	next := old
	next.Revision++
	next.NeedsRecovery = true
	next.Failure = &AcornFoxRepoFailureV1{Code: "live_materialize_effect_failure", Digest: acornFoxRepoEvidence("acornfox-live-effect-failure-v1\x00", old.BindingSHA256, old.SubstrateReceiptSHA256, string(old.Phase))}
	next.History = append(next.History, AcornFoxRepoHistoryV1{Revision: next.Revision, Kind: AcornFoxRepoHistoryFailure, From: old.Phase, To: old.Phase, EvidenceSHA256: next.Failure.Digest})
	return next
}

func acornFoxLiveRecoveredJournal(old AcornFoxRepoJournalV1, receipt AcornFoxLiveReceiptV1) AcornFoxRepoJournalV1 {
	next := old
	next.Revision++
	next.NeedsRecovery, next.Failure = false, nil
	evidence := ""
	if old.Failure != nil {
		evidence, _ = AcornFoxRepoRecoveredEvidence(old, old.Phase, old.Failure.Digest)
	}
	next.History = append(next.History, AcornFoxRepoHistoryV1{Revision: next.Revision, Kind: AcornFoxRepoHistoryRecovered, From: old.Phase, To: old.Phase, EvidenceSHA256: evidence})
	return next
}
