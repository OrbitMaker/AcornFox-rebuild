package install

import (
	"errors"
	"io"
	"os"
)

func (s *platformBackupLocalStore) encryptPackage(journal PlatformBackupJournalV1, key *BackupKeyMaterial, random io.Reader) (PlatformBackupJournalEncryptionV1, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || journal.Validate() != nil || journal.Phase != PlatformBackupJournalPackaged || journal.Capture == nil || journal.Package == nil || journal.Encryption != nil || journal.RemoteCommit != nil || key == nil || random == nil {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	capture, packageEvidence := *journal.Capture, *journal.Package
	if !platformBackupCaptureValid(capture) || !platformBackupPackageEvidenceValid(capture, packageEvidence) {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	version, err := key.Version()
	if err != nil || version != capture.KeyVersion {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	packageReader, err := s.openPackage(capture, packageEvidence)
	if err != nil {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	closedPackage := false
	defer func() {
		if !closedPackage {
			_ = packageReader.Close()
		}
	}()
	if err := s.resetUnjournaledEncryption(); err != nil {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	context := BackupEncryptionContextV2{
		BackupID: capture.Manifest.BackupID, SourceInstallationIDSHA256: capture.Manifest.SourceInstallationIDSHA256,
		PackageManifestSHA256: packageEvidence.ManifestSHA256, PackageSHA256: packageEvidence.PackageSHA256,
		SourceActivationID: capture.Manifest.SourceActivationID, SourceActivationJSONSHA256: capture.Manifest.SourceActivationJSONSHA256,
		ReleaseID: capture.Manifest.SourceRelease.ID, ReleaseManifestSHA256: capture.Manifest.SourceRelease.ManifestSHA256,
		ObjectKey: "open-card/backups/" + capture.Manifest.SourceInstallationIDSHA256 + "/" + capture.Manifest.BackupID + ".ocbkp", KeyVersion: version,
	}
	if context.Validate() != nil {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	candidate, err := s.beginStream(platformBackupLocalEncryptedPartial, platformBackupLocalEncrypted)
	if err != nil {
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	var receipt BackupEncryptionReceipt
	err = key.WithBytes(func(bytes []byte) error {
		var encryptErr error
		receipt, encryptErr = EncryptPlatformBackup(candidate, packageReader, bytes, context, random)
		if encryptErr != nil {
			return ErrPlatformBackupLocal
		}
		return candidate.Commit(func(ciphertext io.ReadSeeker) error {
			readback, openErr := s.openReadback()
			if openErr != nil {
				return ErrPlatformBackupLocal
			}
			decryptErr := DecryptPlatformBackup(io.Discard, localCryptoReadback{readback}, ciphertext, bytes, context, receipt)
			closeErr := readback.Close()
			if decryptErr != nil || closeErr != nil {
				return ErrPlatformBackupLocal
			}
			return nil
		})
	})
	closeErr := packageReader.Close()
	closedPackage = true
	if err != nil || closeErr != nil || receipt.Validate() != nil {
		_ = candidate.Abort()
		return PlatformBackupJournalEncryptionV1{}, ErrPlatformBackupLocal
	}
	return PlatformBackupJournalEncryptionV1{Context: context, Receipt: receipt}, nil
}

// localCryptoReadback supplies the deliberate truncate capability required by
// the encryption quarantine API without exposing scratch paths to callers.
type localCryptoReadback struct {
	*platformBackupLocalReadbackFile
}

func (r localCryptoReadback) Truncate(size int64) error {
	if r.platformBackupLocalReadbackFile == nil || r.file == nil || r.store == nil || r.store.transaction == nil || r.store.transaction.VerifyLiveRoot() != nil || size != 0 {
		return ErrPlatformBackupLocal
	}
	if err := r.file.Truncate(0); err != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (s *platformBackupLocalStore) openEncrypted(journal PlatformBackupJournalV1) (platformBackupLocalReadSeeker, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || journal.Validate() != nil || (journal.Phase != PlatformBackupJournalEncrypted && journal.Phase != PlatformBackupJournalPublishing && journal.Phase != PlatformBackupJournalCommitted) || journal.Capture == nil || journal.Package == nil || journal.Encryption == nil {
		return nil, ErrPlatformBackupLocal
	}
	capture, packageEvidence, encryptionEvidence := *journal.Capture, *journal.Package, *journal.Encryption
	if !platformBackupCaptureValid(capture) || !platformBackupPackageEvidenceValid(capture, packageEvidence) || encryptionEvidence.Context.Validate() != nil || encryptionEvidence.Receipt.Validate() != nil {
		return nil, ErrPlatformBackupLocal
	}
	context := encryptionEvidence.Context
	if !platformBackupContextMatchesManifest(context, capture.Manifest) || context.PackageManifestSHA256 != packageEvidence.ManifestSHA256 || context.PackageSHA256 != packageEvidence.PackageSHA256 || context.KeyVersion != capture.KeyVersion || encryptionEvidence.Receipt.PlaintextSHA256 != packageEvidence.PackageSHA256 || encryptionEvidence.Receipt.PlaintextSize != packageEvidence.PackageSize {
		return nil, ErrPlatformBackupLocal
	}
	return s.openAccepted(platformBackupLocalEncrypted, encryptionEvidence.Receipt.ObjectSize, encryptionEvidence.Receipt.ObjectSHA256)
}

func platformBackupPackageEvidenceValid(capture PlatformBackupJournalCaptureV1, evidence PlatformBackupJournalPackageV1) bool {
	if evidence.PackageSize <= 0 || evidence.PackageSize > PlatformBackupV3MaxPackageSize || !validSHA(evidence.PackageSHA256) || !validSHA(evidence.ManifestSHA256) {
		return false
	}
	raw, err := MarshalPlatformBackupV3(capture.Manifest)
	return err == nil && evidence.ManifestSHA256 == platformBackupLocalSHA(raw)
}

func (s *platformBackupLocalStore) resetUnjournaledEncryption() error {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	partialSpec, _ := platformBackupLocalSpec(platformBackupLocalEncryptedPartial)
	finalSpec, _ := platformBackupLocalSpec(platformBackupLocalEncrypted)
	partial, partialErr := s.transaction.ops.Lstat(partialSpec.name)
	final, finalErr := s.transaction.ops.Lstat(finalSpec.name)
	if partialErr != nil && !errors.Is(partialErr, os.ErrNotExist) || finalErr != nil && !errors.Is(finalErr, os.ErrNotExist) {
		return ErrPlatformBackupLocal
	}
	partialPresent, finalPresent := partialErr == nil, finalErr == nil
	if !partialPresent && !finalPresent {
		return nil
	}
	if partialPresent && finalPresent {
		if !platformBackupLocalLinkedFileValid(partial, s.transaction, partialSpec.maxSize) || !platformBackupLocalLinkedFileValid(final, s.transaction, finalSpec.maxSize) || !os.SameFile(partial, final) {
			return ErrPlatformBackupLocal
		}
		if s.transaction.RemoveMetadata(partialSpec.name) != nil {
			return ErrPlatformBackupLocal
		}
		final, finalErr = s.transaction.ops.Lstat(finalSpec.name)
		if finalErr != nil || !platformBackupLocalFileValid(final, s.transaction, finalSpec.maxSize) {
			return ErrPlatformBackupLocal
		}
	}
	if finalPresent && (finalErr != nil || !platformBackupLocalFileValid(final, s.transaction, finalSpec.maxSize)) {
		return ErrPlatformBackupLocal
	}
	if partialPresent && !finalPresent && !platformBackupLocalFileValid(partial, s.transaction, partialSpec.maxSize) {
		return ErrPlatformBackupLocal
	}
	if finalPresent && s.transaction.RemoveMetadata(finalSpec.name) != nil {
		return ErrPlatformBackupLocal
	}
	if partialPresent && !finalPresent && s.transaction.RemoveMetadata(partialSpec.name) != nil {
		return ErrPlatformBackupLocal
	}
	if _, err := s.transaction.ops.Lstat(partialSpec.name); !errors.Is(err, os.ErrNotExist) {
		return ErrPlatformBackupLocal
	}
	if _, err := s.transaction.ops.Lstat(finalSpec.name); !errors.Is(err, os.ErrNotExist) {
		return ErrPlatformBackupLocal
	}
	return nil
}
