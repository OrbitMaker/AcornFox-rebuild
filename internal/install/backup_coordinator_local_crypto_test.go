package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func localCryptoFixture(t *testing.T) (*platformBackupLocalStore, PlatformBackupJournalCaptureV1, PlatformBackupJournalPackageV1, *BackupKeyMaterial) {
	t.Helper()
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	packageEvidence, err := store.buildPackage(capture)
	if err != nil {
		t.Fatal(err)
	}
	key := &BackupKeyMaterial{state: &backupKeyMaterialState{version: capture.KeyVersion, material: bytes.Repeat([]byte{7}, 32)}}
	return store, capture, packageEvidence, key
}

func cryptoPackagedJournal(capture PlatformBackupJournalCaptureV1, evidence PlatformBackupJournalPackageV1) PlatformBackupJournalV1 {
	return PlatformBackupJournalV1{SchemaVersion: 1, Revision: 3, Phase: PlatformBackupJournalPackaged, BackupID: capture.Manifest.BackupID, Reason: capture.Manifest.Reason, CreatedAt: capture.Manifest.CreatedAt, UpdatedAt: capture.Manifest.CreatedAt.Add(2), Capture: &capture, Package: &evidence}
}

func TestPlatformBackupLocalEncryptPackageAndOpenExactCiphertext(t *testing.T) {
	store, capture, packageEvidence, key := localCryptoFixture(t)
	journal := cryptoPackagedJournal(capture, packageEvidence)
	encryption, err := store.encryptPackage(journal, key, bytes.NewReader(bytes.Repeat([]byte{3}, 8)))
	if err != nil || encryption.Context.Validate() != nil || encryption.Receipt.Validate() != nil {
		t.Fatalf("encryption=%+v err=%v", encryption, err)
	}
	if encryption.Context.KeyVersion != capture.KeyVersion || encryption.Context.PackageSHA256 != packageEvidence.PackageSHA256 || encryption.Receipt.PlaintextSize != packageEvidence.PackageSize {
		t.Fatalf("context/receipt drift: %+v %+v", encryption.Context, encryption.Receipt)
	}
	encryptedJournal := journal
	encryptedJournal.Phase, encryptedJournal.Revision, encryptedJournal.UpdatedAt = PlatformBackupJournalEncrypted, 4, journal.UpdatedAt.Add(1)
	encryptedJournal.Encryption = &encryption
	reader, err := store.openEncrypted(encryptedJournal)
	if err != nil {
		t.Fatal(err)
	}
	if copied, err := io.Copy(io.Discard, reader); err != nil || copied != encryption.Receipt.ObjectSize {
		t.Fatalf("copied=%d err=%v", copied, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := store.transaction.ReadMetadata("readback.tmp"); err != nil || len(raw) != 0 {
		t.Fatalf("readback retained plaintext: %q %v", raw, err)
	}
}

func TestPlatformBackupLocalEncryptRejectsKeyAndRandomWithoutFinal(t *testing.T) {
	for name, mutate := range map[string]func(*BackupKeyMaterial, *PlatformBackupJournalPackageV1, *bytes.Reader){
		"version": func(key *BackupKeyMaterial, _ *PlatformBackupJournalPackageV1, _ *bytes.Reader) {
			key.state.version = "key-other"
		},
		"package": func(_ *BackupKeyMaterial, evidence *PlatformBackupJournalPackageV1, _ *bytes.Reader) {
			evidence.PackageSHA256 = string(bytes.Repeat([]byte("a"), 64))
		},
		"random": func(_ *BackupKeyMaterial, _ *PlatformBackupJournalPackageV1, random *bytes.Reader) {
			*random = *bytes.NewReader(nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, capture, packageEvidence, key := localCryptoFixture(t)
			random := bytes.NewReader(bytes.Repeat([]byte{4}, 8))
			mutate(key, &packageEvidence, random)
			journal := cryptoPackagedJournal(capture, packageEvidence)
			if _, err := store.encryptPackage(journal, key, random); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("encrypt=%v", err)
			}
			if _, err := store.transaction.ops.Lstat("encrypted.ocbkp"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected encryption published final: %v", err)
			}
		})
	}
}

func TestPlatformBackupLocalEncryptionResetRejectsUnsafeLeaf(t *testing.T) {
	store, _, _, _ := localCryptoFixture(t)
	if err := os.Symlink("other", store.transaction.rootPath+"/encrypted.ocbkp"); err != nil {
		t.Fatal(err)
	}
	if err := store.resetUnjournaledEncryption(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("unsafe reset=%v", err)
	}
}

func TestPlatformBackupLocalEncryptRequiresPackagedJournalBeforeReset(t *testing.T) {
	store, capture, packageEvidence, key := localCryptoFixture(t)
	packaged := cryptoPackagedJournal(capture, packageEvidence)
	encryption, err := store.encryptPackage(packaged, key, bytes.NewReader(bytes.Repeat([]byte{6}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.transaction.ops.Link("encrypted.ocbkp", "encrypted.ocbkp.partial"); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []PlatformBackupJournalPhase{PlatformBackupJournalEncrypted, PlatformBackupJournalPublishing} {
		journal := packaged
		journal.Phase, journal.Revision, journal.UpdatedAt, journal.Encryption = phase, journalPhaseRevision(phase), packaged.UpdatedAt.Add(1), &encryption
		if _, err := store.encryptPackage(journal, key, bytes.NewReader(bytes.Repeat([]byte{6}, 8))); !errors.Is(err, ErrPlatformBackupLocal) {
			t.Fatalf("phase=%s encrypt=%v", phase, err)
		}
		for _, name := range []string{"encrypted.ocbkp", "encrypted.ocbkp.partial"} {
			if _, err := store.transaction.ops.Lstat(name); err != nil {
				t.Fatalf("phase=%s removed %s: %v", phase, name, err)
			}
		}
	}
}

func TestPlatformBackupLocalResetUnjournaledEncryptionHandlesExactHardlinkPair(t *testing.T) {
	store, writer, _ := scratchTaskStore(t)
	if err := writer.WriteMetadata("package.tar", []byte("package")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMetadata("readback.tmp", []byte("readback")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMetadata("encrypted.ocbkp", []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := writer.ops.Link("encrypted.ocbkp", "encrypted.ocbkp.partial"); err != nil {
		t.Fatal(err)
	}
	if err := store.resetUnjournaledEncryption(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"encrypted.ocbkp", "encrypted.ocbkp.partial"} {
		if _, err := writer.ops.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reset left %s: %v", name, err)
		}
	}
	for _, name := range []string{"package.tar", "readback.tmp"} {
		if raw, err := writer.ReadMetadata(name); err != nil || len(raw) == 0 {
			t.Fatalf("reset changed %s: %q %v", name, raw, err)
		}
	}
}

func TestPlatformBackupLocalResetPreservesHardlinkPairOnFirstRemoveFailure(t *testing.T) {
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
	if err := writer.WriteMetadata("encrypted.ocbkp", []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := writer.ops.Link("encrypted.ocbkp", "encrypted.ocbkp.partial"); err != nil {
		t.Fatal(err)
	}
	fault.fail = "remove"
	if err := store.resetUnjournaledEncryption(); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("reset=%v", err)
	}
	for _, name := range []string{"encrypted.ocbkp", "encrypted.ocbkp.partial"} {
		if _, err := writer.ops.Lstat(name); err != nil {
			t.Fatalf("failed reset removed %s: %v", name, err)
		}
	}
}
