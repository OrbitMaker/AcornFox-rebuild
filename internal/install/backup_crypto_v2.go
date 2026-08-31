package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
)

const (
	BackupEncryptionContextV2Schema        = "open-card.platform-backup-encryption-context"
	BackupEncryptionContextV2SchemaVersion = 2
)

// BackupEncryptionContextV2 binds an encrypted PlatformBackupV3 archive to
// its package bytes and the durable identities carried by its manifest. It
// contains only opaque identifiers and digests, never installation IDs, keys,
// or plaintext backup material.
type BackupEncryptionContextV2 struct {
	BackupID                   string `json:"backup_id"`
	SourceInstallationIDSHA256 string `json:"source_installation_id_sha256"`
	PackageManifestSHA256      string `json:"package_manifest_sha256"`
	PackageSHA256              string `json:"package_sha256"`
	SourceActivationID         string `json:"source_activation_id"`
	SourceActivationJSONSHA256 string `json:"source_activation_json_sha256"`
	ReleaseID                  string `json:"release_id"`
	ReleaseManifestSHA256      string `json:"release_manifest_sha256"`
	ObjectKey                  string `json:"object_key"`
	KeyVersion                 string `json:"key_version"`
}

func (c BackupEncryptionContextV2) Validate() error {
	expectedObjectKey := "open-card/backups/" + c.SourceInstallationIDSHA256 + "/" + c.BackupID + ".ocbkp"
	if !validBackupID(c.BackupID) || !validSHA(c.SourceInstallationIDSHA256) || !validSHA(c.PackageManifestSHA256) || !validSHA(c.PackageSHA256) || !validID(c.SourceActivationID) || !validSHA(c.SourceActivationJSONSHA256) || !validID(c.ReleaseID) || !validSHA(c.ReleaseManifestSHA256) || !backupKeyVersion.MatchString(c.KeyVersion) || c.ObjectKey != expectedObjectKey {
		return ErrBackupEncryption
	}
	return nil
}

// backupEncryptionContextV2Wire makes schema identity part of every
// serialized/digested V2 context while keeping the public context limited to
// durable binding fields.
type backupEncryptionContextV2Wire struct {
	Schema                     string `json:"schema"`
	SchemaVersion              int    `json:"schema_version"`
	BackupID                   string `json:"backup_id"`
	SourceInstallationIDSHA256 string `json:"source_installation_id_sha256"`
	PackageManifestSHA256      string `json:"package_manifest_sha256"`
	PackageSHA256              string `json:"package_sha256"`
	SourceActivationID         string `json:"source_activation_id"`
	SourceActivationJSONSHA256 string `json:"source_activation_json_sha256"`
	ReleaseID                  string `json:"release_id"`
	ReleaseManifestSHA256      string `json:"release_manifest_sha256"`
	ObjectKey                  string `json:"object_key"`
	KeyVersion                 string `json:"key_version"`
}

func backupEncryptionContextV2WireFor(context BackupEncryptionContextV2) backupEncryptionContextV2Wire {
	return backupEncryptionContextV2Wire{
		Schema: BackupEncryptionContextV2Schema, SchemaVersion: BackupEncryptionContextV2SchemaVersion,
		BackupID: context.BackupID, SourceInstallationIDSHA256: context.SourceInstallationIDSHA256,
		PackageManifestSHA256: context.PackageManifestSHA256, PackageSHA256: context.PackageSHA256,
		SourceActivationID: context.SourceActivationID, SourceActivationJSONSHA256: context.SourceActivationJSONSHA256,
		ReleaseID: context.ReleaseID, ReleaseManifestSHA256: context.ReleaseManifestSHA256,
		ObjectKey: context.ObjectKey, KeyVersion: context.KeyVersion,
	}
}

func backupEncryptionContextV2FromWire(value backupEncryptionContextV2Wire) BackupEncryptionContextV2 {
	return BackupEncryptionContextV2{
		BackupID: value.BackupID, SourceInstallationIDSHA256: value.SourceInstallationIDSHA256,
		PackageManifestSHA256: value.PackageManifestSHA256, PackageSHA256: value.PackageSHA256,
		SourceActivationID: value.SourceActivationID, SourceActivationJSONSHA256: value.SourceActivationJSONSHA256,
		ReleaseID: value.ReleaseID, ReleaseManifestSHA256: value.ReleaseManifestSHA256,
		ObjectKey: value.ObjectKey, KeyVersion: value.KeyVersion,
	}
}

func MarshalBackupEncryptionContextV2(context BackupEncryptionContextV2) ([]byte, error) {
	if context.Validate() != nil {
		return nil, ErrBackupEncryption
	}
	return json.Marshal(backupEncryptionContextV2WireFor(context))
}

func ParseBackupEncryptionContextV2(raw []byte) (BackupEncryptionContextV2, error) {
	var wire backupEncryptionContextV2Wire
	fields := []string{"schema", "schema_version", "backup_id", "source_installation_id_sha256", "package_manifest_sha256", "package_sha256", "source_activation_id", "source_activation_json_sha256", "release_id", "release_manifest_sha256", "object_key", "key_version"}
	if decodeStrict(raw, &wire) != nil || requireStrictFields(raw, fields) != nil || wire.Schema != BackupEncryptionContextV2Schema || wire.SchemaVersion != BackupEncryptionContextV2SchemaVersion {
		return BackupEncryptionContextV2{}, ErrBackupEncryption
	}
	context := backupEncryptionContextV2FromWire(wire)
	canonical, err := MarshalBackupEncryptionContextV2(context)
	if err != nil || string(raw) != string(canonical) {
		return BackupEncryptionContextV2{}, ErrBackupEncryption
	}
	return context, nil
}

func backupContextDigestV2(context BackupEncryptionContextV2) (string, error) {
	raw, err := MarshalBackupEncryptionContextV2(context)
	if err != nil {
		return "", ErrBackupEncryption
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// EncryptPlatformBackup encrypts a strictly verified PlatformBackupV3 archive.
// It validates the archive and all V2 bindings before any ciphertext is
// emitted, then uses the unchanged V1 AES-256-GCM-CHUNKED wire framing.
func EncryptPlatformBackup(destination io.Writer, source io.ReadSeeker, key []byte, context BackupEncryptionContextV2, random io.Reader) (BackupEncryptionReceipt, error) {
	contextDigest, err := backupContextDigestV2(context)
	if err != nil {
		return BackupEncryptionReceipt{}, ErrBackupEncryption
	}
	return encryptBackup(destination, source, key, contextDigest, random, func(value io.ReadSeeker) (int64, string, uint32, error) {
		return platformBackupEncryptionEvidence(value, context)
	})
}

// DecryptPlatformBackup leaves destination untouched until the ciphertext,
// receipt, V2 context, and recovered PlatformBackupV3 archive all verify.
func DecryptPlatformBackup(destination io.Writer, scratch io.ReadWriteSeeker, source io.Reader, key []byte, context BackupEncryptionContextV2, receipt BackupEncryptionReceipt) error {
	contextDigest, err := backupContextDigestV2(context)
	if err != nil {
		rejectBackupDecryption(scratch)
		return ErrBackupEncryption
	}
	return decryptBackup(destination, scratch, source, key, contextDigest, receipt, func(value io.ReadSeeker) error {
		if _, _, _, err := platformBackupEncryptionEvidence(value, context); err != nil {
			return ErrBackupEncryption
		}
		return nil
	})
}

// platformBackupEncryptionEvidence streams and strictly verifies a complete
// canonical package. It hashes the archive and its package.json without ever
// buffering the archive, and rewinds source for the following encryption pass.
func platformBackupEncryptionEvidence(source io.ReadSeeker, context BackupEncryptionContextV2) (int64, string, uint32, error) {
	if source == nil || context.Validate() != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	hash := sha256.New()
	count := &backupEncryptionCountWriter{}
	manifest, err := VerifyPlatformBackupV3Package(io.TeeReader(source, io.MultiWriter(hash, count)), PlatformBackupDiscardSink{})
	if err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	manifestSHA, err := platformBackupManifestSHA256(source)
	if err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	packageSHA := hex.EncodeToString(hash.Sum(nil))
	if count.size <= 0 || count.size > math.MaxInt64-backupEncryptionChunkSize || packageSHA != context.PackageSHA256 || manifestSHA != context.PackageManifestSHA256 || !platformBackupContextMatchesManifest(context, manifest) {
		return 0, "", 0, ErrBackupEncryption
	}
	chunks := (count.size + backupEncryptionChunkSize - 1) / backupEncryptionChunkSize
	if chunks <= 0 || chunks > math.MaxUint32 {
		return 0, "", 0, ErrBackupEncryption
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return 0, "", 0, ErrBackupEncryption
	}
	return count.size, packageSHA, uint32(chunks), nil
}

type backupEncryptionCountWriter struct{ size int64 }

func (w *backupEncryptionCountWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > math.MaxInt64-w.size {
		return 0, ErrBackupEncryption
	}
	w.size += int64(len(value))
	return len(value), nil
}

func platformBackupManifestSHA256(source io.ReadSeeker) (string, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", ErrBackupEncryption
	}
	block, err := platformBackupReadBlock(source)
	if err != nil {
		return "", ErrBackupEncryption
	}
	size, ok := platformBackupHeaderSize(block)
	if !ok || size <= 0 || size > PlatformBackupV3MaxTextMemberSize || !platformBackupHeaderMatches(block, PlatformBackupV3Manifest, size, platformBackupV3Mode) {
		return "", ErrBackupEncryption
	}
	hash := sha256.New()
	if copied, err := io.Copy(hash, io.LimitReader(source, size)); err != nil || copied != size {
		return "", ErrBackupEncryption
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func platformBackupContextMatchesManifest(context BackupEncryptionContextV2, manifest PlatformBackupV3) bool {
	return context.BackupID == manifest.BackupID &&
		context.SourceInstallationIDSHA256 == manifest.SourceInstallationIDSHA256 &&
		context.SourceActivationID == manifest.SourceActivationID &&
		context.SourceActivationJSONSHA256 == manifest.SourceActivationJSONSHA256 &&
		context.ReleaseID == manifest.SourceRelease.ID &&
		context.ReleaseManifestSHA256 == manifest.SourceRelease.ManifestSHA256
}
