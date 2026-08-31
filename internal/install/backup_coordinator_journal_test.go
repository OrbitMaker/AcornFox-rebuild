package install

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func platformBackupJournalFixture(t *testing.T) []PlatformBackupJournalV1 {
	t.Helper()
	packageRaw, context := platformCryptoFixture(t)
	manifest, err := VerifyPlatformBackupV3Package(bytes.NewReader(packageRaw), PlatformBackupDiscardSink{})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{6}, 32)
	var encrypted bytes.Buffer
	encryptionReceipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, context, bytes.NewReader(bytes.Repeat([]byte{8}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	created := manifest.CreatedAt
	base := PlatformBackupJournalV1{SchemaVersion: 1, BackupID: manifest.BackupID, Reason: manifest.Reason, CreatedAt: created, UpdatedAt: created}
	prepared := base
	prepared.Phase, prepared.Revision = PlatformBackupJournalPrepared, 1
	captured := prepared
	captured.Phase, captured.Revision, captured.UpdatedAt = PlatformBackupJournalCaptured, 2, created.Add(time.Second)
	captured.Capture = &PlatformBackupJournalCaptureV1{Manifest: manifest, KeyVersion: context.KeyVersion}
	packaged := captured
	packaged.Phase, packaged.Revision, packaged.UpdatedAt = PlatformBackupJournalPackaged, 3, captured.UpdatedAt.Add(time.Second)
	packaged.Package = &PlatformBackupJournalPackageV1{ManifestSHA256: context.PackageManifestSHA256, PackageSHA256: context.PackageSHA256, PackageSize: int64(len(packageRaw))}
	encryptedJournal := packaged
	encryptedJournal.Phase, encryptedJournal.Revision, encryptedJournal.UpdatedAt = PlatformBackupJournalEncrypted, 4, packaged.UpdatedAt.Add(time.Second)
	encryptedJournal.Encryption = &PlatformBackupJournalEncryptionV1{Context: context, Receipt: encryptionReceipt}
	publishing := encryptedJournal
	publishing.Phase, publishing.Revision, publishing.UpdatedAt = PlatformBackupJournalPublishing, 5, encryptedJournal.UpdatedAt.Add(time.Second)
	committed := publishing
	committed.Phase, committed.Revision, committed.UpdatedAt = PlatformBackupJournalCommitted, 6, publishing.UpdatedAt.Add(time.Second)
	remote := platformRemoteReceipt(PlatformBackupPublishRequest{EncryptionContext: context, EncryptionReceipt: encryptionReceipt, CreatedAt: created}, PlatformBackupStoreObject{ObjectKey: context.ObjectKey, VersionID: "data-version-1", SHA256: encryptionReceipt.ObjectSHA256, Size: encryptionReceipt.ObjectSize})
	remoteRaw, err := MarshalPlatformBackupRemoteReceiptV2(remote)
	if err != nil {
		t.Fatal(err)
	}
	committed.RemoteCommit = &PlatformBackupJournalRemoteCommitV1{Receipt: remote, ReceiptObjectKey: platformBackupReceiptObjectKey(context), ReceiptVersionID: "receipt-version-1", ReceiptSHA256: sha256Hex(remoteRaw), ReceiptSize: int64(len(remoteRaw))}
	return []PlatformBackupJournalV1{prepared, captured, packaged, encryptedJournal, publishing, committed}
}

func TestPlatformBackupJournalCanonicalRoundTripAndCommitted(t *testing.T) {
	for _, want := range platformBackupJournalFixture(t) {
		raw, err := MarshalPlatformBackupJournalV1(want)
		if err != nil {
			t.Fatalf("phase=%s marshal=%v", want.Phase, err)
		}
		got, err := ParsePlatformBackupJournalV1(raw)
		if err != nil || got.Phase != want.Phase || got.Revision != want.Revision {
			t.Fatalf("phase=%s got=%+v err=%v", want.Phase, got, err)
		}
		if want.Phase == PlatformBackupJournalCommitted {
			committed, err := got.Committed()
			if err != nil || committed.Validate() != nil || !bytes.Equal(committed.ReceiptContent, journalReceiptContent(t, *want.RemoteCommit)) {
				t.Fatalf("committed=%+v err=%v", committed, err)
			}
		}
	}
}

func journalReceiptContent(t *testing.T, remote PlatformBackupJournalRemoteCommitV1) []byte {
	t.Helper()
	raw, err := MarshalPlatformBackupRemoteReceiptV2(remote.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func clonePlatformBackupJournal(t *testing.T, value PlatformBackupJournalV1) PlatformBackupJournalV1 {
	t.Helper()
	raw, err := MarshalPlatformBackupJournalV1(value)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := ParsePlatformBackupJournalV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestPlatformBackupJournalStrictJSONAndProgressiveBindings(t *testing.T) {
	all := platformBackupJournalFixture(t)
	preparedRaw, err := MarshalPlatformBackupJournalV1(all[0])
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"missing":   bytes.Replace(preparedRaw, []byte(`,"reason":"manual"`), nil, 1),
		"unknown":   append(append([]byte(nil), preparedRaw[:len(preparedRaw)-1]...), []byte(`,"extra":1}`)...),
		"duplicate": append([]byte(`{"schema_version":1,`), preparedRaw[1:]...),
		"null":      bytes.Replace(preparedRaw, []byte(`"reason":"manual"`), []byte(`"reason":null`), 1),
		"trailing":  append(append([]byte(nil), preparedRaw...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlatformBackupJournalV1(raw); !errors.Is(err, ErrPlatformBackupJournal) {
				t.Fatalf("accepted malformed journal: %v", err)
			}
		})
	}
	for i := 0; i < len(all); i++ {
		for _, mutate := range []func(*PlatformBackupJournalV1){
			func(v *PlatformBackupJournalV1) { v.Revision++ },
			func(v *PlatformBackupJournalV1) { v.UpdatedAt = v.CreatedAt.Add(-time.Second) },
		} {
			bad := all[i]
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatalf("phase=%s accepted base drift", all[i].Phase)
			}
		}
	}
	unknownPhase := clonePlatformBackupJournal(t, all[5])
	unknownPhase.Phase, unknownPhase.Revision = "UNKNOWN", 0
	if unknownPhase.Validate() == nil {
		t.Fatal("accepted an unknown phase")
	}
	preparedTimeDrift := clonePlatformBackupJournal(t, all[0])
	preparedTimeDrift.UpdatedAt = preparedTimeDrift.CreatedAt.Add(time.Second)
	if preparedTimeDrift.Validate() == nil {
		t.Fatal("prepared journal accepted an updated time after creation")
	}
	for _, mutate := range []func(*PlatformBackupJournalV1){
		func(v *PlatformBackupJournalV1) { v.Capture.Manifest.Reason = "other" },
		func(v *PlatformBackupJournalV1) { v.Package.ManifestSHA256 = strings.Repeat("a", 64) },
		func(v *PlatformBackupJournalV1) { v.Encryption.Context.KeyVersion = "key-other" },
		func(v *PlatformBackupJournalV1) { v.Encryption.Receipt.PlaintextSize++ },
		func(v *PlatformBackupJournalV1) { v.RemoteCommit.Receipt.DataVersionID = "other-version" },
		func(v *PlatformBackupJournalV1) { v.RemoteCommit.ReceiptSHA256 = strings.Repeat("a", 64) },
	} {
		bad := clonePlatformBackupJournal(t, all[5])
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted cross-binding drift")
		}
	}
	for _, early := range []int{0, 1, 2, 3, 4} {
		bad := clonePlatformBackupJournal(t, all[early])
		bad.RemoteCommit = all[5].RemoteCommit
		if bad.Validate() == nil {
			t.Fatalf("phase=%s accepted early remote commit", bad.Phase)
		}
	}
	committedRaw, err := MarshalPlatformBackupJournalV1(all[5])
	if err != nil || bytes.Contains(committedRaw, []byte("postgresql://")) || bytes.Contains(committedRaw, []byte("secret")) {
		t.Fatalf("journal leaked sensitive bytes: %v", err)
	}
}

func journalTaskStore(t *testing.T) (*durablePlatformBackupJournalStore, *DurableWriter, string) {
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
	store, err := newDurablePlatformBackupJournalStore(child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close(); _ = parent.Close() })
	return store, child, filepath.Join(root, "transaction")
}

func TestPlatformBackupJournalStoreCreateAndAdvanceCAS(t *testing.T) {
	store, _, _ := journalTaskStore(t)
	all := platformBackupJournalFixture(t)
	if err := store.Create(all[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(all[0]); err != nil {
		t.Fatalf("exact create did not converge: %v", err)
	}
	conflict := all[0]
	conflict.Reason = "other"
	if err := store.Create(conflict); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("conflict=%v", err)
	}
	for i := 1; i < len(all); i++ {
		if err := store.Advance(all[i-1], all[i]); err != nil {
			t.Fatalf("advance %d: %v", i, err)
		}
	}
	stale := all[4]
	if err := store.Advance(stale, all[5]); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("stale advance=%v", err)
	}
	nonAdjacent := all[1]
	if err := store.Advance(all[5], nonAdjacent); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("non-adjacent=%v", err)
	}
}

func TestPlatformBackupJournalStoreReconcilesOnlyExactNext(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	store, err := newDurablePlatformBackupJournalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	all := platformBackupJournalFixture(t)
	if err := store.Create(all[0]); err != nil {
		t.Fatal(err)
	}
	fault.fail = "parent-fsync"
	if err := store.Advance(all[0], all[1]); err != nil {
		t.Fatalf("post-rename unknown did not reconcile exact next: %v", err)
	}
	fault.fail = "write"
	if err := store.Advance(all[1], all[2]); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("pre-write failure=%v", err)
	}
	got, err := store.Load()
	if err != nil || got.Phase != PlatformBackupJournalCaptured {
		t.Fatalf("old state was not preserved: %+v %v", got, err)
	}
}

func TestPlatformBackupJournalStoreCreateReconcilesPostLinkSyncUnknown(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	store, err := newDurablePlatformBackupJournalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	// CreateMetadata synchronizes its temp file twice before the post-link
	// parent sync. Align the shared fault seam's link-parent trigger with that
	// final durability boundary.
	fault.syncCalls = -2
	fault.fail = "link-parent-fsync"
	prepared := platformBackupJournalFixture(t)[0]
	if err := store.Create(prepared); err != nil {
		t.Fatalf("post-link unknown did not converge: %v", err)
	}
	got, err := store.Load()
	if err != nil || got.Phase != PlatformBackupJournalPrepared || !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Fatalf("created journal=%+v err=%v", got, err)
	}
}

func TestPlatformBackupJournalStoreRejectsUnsafeLeafAndRoot(t *testing.T) {
	store, _, path := journalTaskStore(t)
	if err := os.Symlink("other", filepath.Join(path, platformBackupJournalFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("symlink load=%v", err)
	}
	if err := os.Remove(filepath.Join(path, platformBackupJournalFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, platformBackupJournalFile), []byte(`{}`), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, platformBackupJournalFile), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("wrong-mode load=%v", err)
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := newDurablePlatformBackupJournalStore(writer); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("wrong-mode root=%v", err)
	}
}

func TestPlatformBackupJournalStoreRejectsInjectedOwnerMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, root)
	defer writer.Close()
	fault.fail = "owner-mismatch"
	if _, err := newDurablePlatformBackupJournalStore(writer); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("owner-mismatched constructor=%v", err)
	}
	fault.fail = ""
	store, err := newDurablePlatformBackupJournalStore(writer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(platformBackupJournalFixture(t)[0]); err != nil {
		t.Fatal(err)
	}
	fault.fail = "owner-mismatch"
	if _, err := store.Load(); !errors.Is(err, ErrPlatformBackupJournal) {
		t.Fatalf("owner-mismatched load=%v", err)
	}
}
