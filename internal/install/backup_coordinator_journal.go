package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"time"
)

// ErrPlatformBackupJournal intentionally carries no provider, path, key, or
// plaintext details. A coordinator can safely surface it across its boundary.
var ErrPlatformBackupJournal = errors.New("platform backup journal validation failed")

type PlatformBackupJournalPhase string

const (
	PlatformBackupJournalPrepared   PlatformBackupJournalPhase = "PREPARED"
	PlatformBackupJournalCaptured   PlatformBackupJournalPhase = "CAPTURED"
	PlatformBackupJournalPackaged   PlatformBackupJournalPhase = "PACKAGED"
	PlatformBackupJournalEncrypted  PlatformBackupJournalPhase = "ENCRYPTED"
	PlatformBackupJournalPublishing PlatformBackupJournalPhase = "PUBLISHING"
	PlatformBackupJournalCommitted  PlatformBackupJournalPhase = "COMMITTED"
)

type PlatformBackupJournalCaptureV1 struct {
	Manifest   PlatformBackupV3 `json:"manifest"`
	KeyVersion string           `json:"key_version"`
}

type PlatformBackupJournalPackageV1 struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	PackageSHA256  string `json:"package_sha256"`
	PackageSize    int64  `json:"package_size"`
}

type PlatformBackupJournalEncryptionV1 struct {
	Context BackupEncryptionContextV2 `json:"context"`
	Receipt BackupEncryptionReceipt   `json:"receipt"`
}

type PlatformBackupJournalRemoteCommitV1 struct {
	Receipt          PlatformBackupRemoteReceiptV2 `json:"receipt"`
	ReceiptObjectKey string                        `json:"receipt_object_key"`
	ReceiptVersionID string                        `json:"receipt_version_id"`
	ReceiptSHA256    string                        `json:"receipt_sha256"`
	ReceiptSize      int64                         `json:"receipt_size"`
}

// Committed reconstructs only a canonical, independently valid remote commit.
func (r PlatformBackupJournalRemoteCommitV1) Committed() (PlatformBackupCommittedV2, error) {
	raw, err := MarshalPlatformBackupRemoteReceiptV2(r.Receipt)
	if err != nil || !validPlatformBackupReceiptKey(r.ReceiptObjectKey, r.Receipt.SourceInstallationIDSHA256, r.Receipt.BackupID) || !validRemoteBackupVersionID(r.ReceiptVersionID) || !validSHA(r.ReceiptSHA256) || r.ReceiptSize <= 0 || r.ReceiptSize > platformBackupRemoteReceiptMaxSize || int64(len(raw)) != r.ReceiptSize {
		return PlatformBackupCommittedV2{}, ErrPlatformBackupJournal
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != r.ReceiptSHA256 {
		return PlatformBackupCommittedV2{}, ErrPlatformBackupJournal
	}
	committed := PlatformBackupCommittedV2{Receipt: r.Receipt, ReceiptObjectKey: r.ReceiptObjectKey, ReceiptVersionID: r.ReceiptVersionID, ReceiptSHA256: r.ReceiptSHA256, ReceiptSize: r.ReceiptSize, ReceiptContent: raw}
	if committed.Validate() != nil {
		return PlatformBackupCommittedV2{}, ErrPlatformBackupJournal
	}
	return committed, nil
}

// PlatformBackupJournalV1 is the local, resumable coordinator state. Evidence
// is append-only by phase: a later phase must retain every prior pointer.
type PlatformBackupJournalV1 struct {
	SchemaVersion int                                  `json:"schema_version"`
	Revision      int64                                `json:"revision"`
	Phase         PlatformBackupJournalPhase           `json:"phase"`
	BackupID      string                               `json:"backup_id"`
	Reason        string                               `json:"reason"`
	CreatedAt     time.Time                            `json:"created_at"`
	UpdatedAt     time.Time                            `json:"updated_at"`
	Capture       *PlatformBackupJournalCaptureV1      `json:"capture,omitempty"`
	Package       *PlatformBackupJournalPackageV1      `json:"package,omitempty"`
	Encryption    *PlatformBackupJournalEncryptionV1   `json:"encryption,omitempty"`
	RemoteCommit  *PlatformBackupJournalRemoteCommitV1 `json:"remote_commit,omitempty"`
}

func (j PlatformBackupJournalV1) Validate() error {
	phaseRevision := journalPhaseRevision(j.Phase)
	if j.SchemaVersion != 1 || phaseRevision == 0 || j.Revision != phaseRevision || !validBackupID(j.BackupID) || !validBackupReason(j.Reason) || !journalTime(j.CreatedAt) || !journalTime(j.UpdatedAt) || j.UpdatedAt.Before(j.CreatedAt) {
		return ErrPlatformBackupJournal
	}
	if j.Phase == PlatformBackupJournalPrepared {
		if !j.UpdatedAt.Equal(j.CreatedAt) || j.Capture != nil || j.Package != nil || j.Encryption != nil || j.RemoteCommit != nil {
			return ErrPlatformBackupJournal
		}
		return nil
	}
	if j.Capture == nil || j.captureValid() != nil {
		return ErrPlatformBackupJournal
	}
	if j.Phase == PlatformBackupJournalCaptured {
		if j.Package != nil || j.Encryption != nil || j.RemoteCommit != nil {
			return ErrPlatformBackupJournal
		}
		return nil
	}
	if j.Package == nil || j.packageValid() != nil {
		return ErrPlatformBackupJournal
	}
	if j.Phase == PlatformBackupJournalPackaged {
		if j.Encryption != nil || j.RemoteCommit != nil {
			return ErrPlatformBackupJournal
		}
		return nil
	}
	if j.Encryption == nil || j.encryptionValid() != nil {
		return ErrPlatformBackupJournal
	}
	if j.Phase == PlatformBackupJournalEncrypted || j.Phase == PlatformBackupJournalPublishing {
		if j.RemoteCommit != nil {
			return ErrPlatformBackupJournal
		}
		return nil
	}
	if j.RemoteCommit == nil || j.remoteCommitValid() != nil {
		return ErrPlatformBackupJournal
	}
	return nil
}

func journalPhaseRevision(phase PlatformBackupJournalPhase) int64 {
	switch phase {
	case PlatformBackupJournalPrepared:
		return 1
	case PlatformBackupJournalCaptured:
		return 2
	case PlatformBackupJournalPackaged:
		return 3
	case PlatformBackupJournalEncrypted:
		return 4
	case PlatformBackupJournalPublishing:
		return 5
	case PlatformBackupJournalCommitted:
		return 6
	default:
		return 0
	}
}

func journalTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func (j PlatformBackupJournalV1) captureValid() error {
	c := j.Capture
	if c == nil || c.Manifest.Validate() != nil || c.Manifest.BackupID != j.BackupID || c.Manifest.Reason != j.Reason || !c.Manifest.CreatedAt.Equal(j.CreatedAt) || !backupKeyVersion.MatchString(c.KeyVersion) {
		return ErrPlatformBackupJournal
	}
	return nil
}

func (j PlatformBackupJournalV1) packageValid() error {
	if j.Capture == nil || j.Package == nil || !validSHA(j.Package.ManifestSHA256) || !validSHA(j.Package.PackageSHA256) || j.Package.PackageSize <= 0 || j.Package.PackageSize > PlatformBackupV3MaxPackageSize {
		return ErrPlatformBackupJournal
	}
	raw, err := MarshalPlatformBackupV3(j.Capture.Manifest)
	if err != nil || sha256Hex(raw) != j.Package.ManifestSHA256 {
		return ErrPlatformBackupJournal
	}
	return nil
}

func (j PlatformBackupJournalV1) encryptionValid() error {
	if j.Capture == nil || j.Package == nil || j.Encryption == nil || j.Encryption.Context.Validate() != nil || j.Encryption.Receipt.Validate() != nil {
		return ErrPlatformBackupJournal
	}
	c := j.Encryption.Context
	m := j.Capture.Manifest
	p := j.Package
	if !platformBackupContextMatchesManifest(c, m) || c.PackageManifestSHA256 != p.ManifestSHA256 || c.PackageSHA256 != p.PackageSHA256 || c.KeyVersion != j.Capture.KeyVersion || j.Encryption.Receipt.PlaintextSHA256 != p.PackageSHA256 || j.Encryption.Receipt.PlaintextSize != p.PackageSize {
		return ErrPlatformBackupJournal
	}
	return nil
}

func (j PlatformBackupJournalV1) remoteCommitValid() error {
	if j.Encryption == nil || j.RemoteCommit == nil {
		return ErrPlatformBackupJournal
	}
	r := j.RemoteCommit.Receipt
	c := j.Encryption.Context
	if !r.CreatedAt.Equal(j.CreatedAt) || r.BackupID != c.BackupID || r.SourceInstallationIDSHA256 != c.SourceInstallationIDSHA256 || r.PackageManifestSHA256 != c.PackageManifestSHA256 || r.PackageSHA256 != c.PackageSHA256 || r.SourceActivationID != c.SourceActivationID || r.SourceActivationJSONSHA256 != c.SourceActivationJSONSHA256 || r.ReleaseID != c.ReleaseID || r.ReleaseManifestSHA256 != c.ReleaseManifestSHA256 || r.DataObjectKey != c.ObjectKey || r.KeyVersion != c.KeyVersion || r.EncryptionReceipt != j.Encryption.Receipt {
		return ErrPlatformBackupJournal
	}
	_, err := j.RemoteCommit.Committed()
	return err
}

func (j PlatformBackupJournalV1) Committed() (PlatformBackupCommittedV2, error) {
	if j.Validate() != nil || j.Phase != PlatformBackupJournalCommitted || j.RemoteCommit == nil {
		return PlatformBackupCommittedV2{}, ErrPlatformBackupJournal
	}
	return j.RemoteCommit.Committed()
}

func MarshalPlatformBackupJournalV1(j PlatformBackupJournalV1) ([]byte, error) {
	if j.Validate() != nil {
		return nil, ErrPlatformBackupJournal
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return nil, ErrPlatformBackupJournal
	}
	return raw, nil
}

func ParsePlatformBackupJournalV1(raw []byte) (PlatformBackupJournalV1, error) {
	var j PlatformBackupJournalV1
	base := []string{"schema_version", "revision", "phase", "backup_id", "reason", "created_at", "updated_at"}
	if decodeStrict(raw, &j) != nil || requireStrictFields(raw, base) != nil || !journalRawFields(raw, j) || j.Validate() != nil {
		return PlatformBackupJournalV1{}, ErrPlatformBackupJournal
	}
	canonical, err := MarshalPlatformBackupJournalV1(j)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PlatformBackupJournalV1{}, ErrPlatformBackupJournal
	}
	return j, nil
}

func journalRawFields(raw []byte, j PlatformBackupJournalV1) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range []string{"capture", "package", "encryption", "remote_commit"} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	if j.Capture != nil && !journalRequiredObject(fields["capture"], []string{"manifest", "key_version"}) {
		return false
	}
	if j.Package != nil && !journalRequiredObject(fields["package"], []string{"manifest_sha256", "package_sha256", "package_size"}) {
		return false
	}
	if j.Encryption != nil && !journalRequiredObject(fields["encryption"], []string{"context", "receipt"}) {
		return false
	}
	if j.RemoteCommit != nil && !journalRequiredObject(fields["remote_commit"], []string{"receipt", "receipt_object_key", "receipt_version_id", "receipt_sha256", "receipt_size"}) {
		return false
	}
	return true
}

func journalRequiredObject(raw json.RawMessage, names []string) bool {
	return requireStrictFields(raw, names) == nil
}

// durablePlatformBackupJournalStore is intentionally private: only the
// coordinator that already owns the future global upgrade flock can obtain its
// fixed transaction-child writer. This store never creates or acquires another
// lock; coordinator-level concurrency serialization belongs to that caller.
type durablePlatformBackupJournalStore struct{ transaction *DurableWriter }

const platformBackupJournalFile = "journal.json"

func newDurablePlatformBackupJournalStore(transaction *DurableWriter) (*durablePlatformBackupJournalStore, error) {
	if transaction == nil || transaction.VerifyLiveRoot() != nil || transaction.rootInfo == nil || transaction.rootInfo.Mode().Perm() != durableDirMode {
		return nil, ErrPlatformBackupJournal
	}
	root, err := transaction.ops.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPlatformBackupJournal
	}
	info, statErr := transaction.ops.Stat(root)
	closeErr := transaction.ops.CloseFile(root)
	if statErr != nil || closeErr != nil || !info.IsDir() || info.Mode().Perm() != durableDirMode || !os.SameFile(info, transaction.rootInfo) || verifyOwner(info, transaction.uid, transaction.gid) != nil {
		return nil, ErrPlatformBackupJournal
	}
	return &durablePlatformBackupJournalStore{transaction: transaction}, nil
}

func (s *durablePlatformBackupJournalStore) Load() (PlatformBackupJournalV1, error) {
	if s == nil || s.transaction == nil {
		return PlatformBackupJournalV1{}, ErrPlatformBackupJournal
	}
	raw, err := s.transaction.ReadMetadata(platformBackupJournalFile)
	if err != nil {
		return PlatformBackupJournalV1{}, ErrPlatformBackupJournal
	}
	j, err := ParsePlatformBackupJournalV1(raw)
	if err != nil {
		return PlatformBackupJournalV1{}, ErrPlatformBackupJournal
	}
	return j, nil
}

func (s *durablePlatformBackupJournalStore) Create(j PlatformBackupJournalV1) error {
	if s == nil || s.transaction == nil || j.Phase != PlatformBackupJournalPrepared || j.Revision != 1 {
		return ErrPlatformBackupJournal
	}
	raw, err := MarshalPlatformBackupJournalV1(j)
	if err != nil {
		return ErrPlatformBackupJournal
	}
	err = s.transaction.CreateMetadata(platformBackupJournalFile, raw)
	if err == nil {
		return s.exact(raw)
	}
	if errors.Is(err, os.ErrExist) || errors.Is(err, ErrDurableCommitUnknown) {
		return s.exact(raw)
	}
	return ErrPlatformBackupJournal
}

func (s *durablePlatformBackupJournalStore) Advance(expected, next PlatformBackupJournalV1) error {
	if s == nil || s.transaction == nil || expected.Validate() != nil || next.Validate() != nil || !journalAdjacent(expected, next) {
		return ErrPlatformBackupJournal
	}
	expectedRaw, err := MarshalPlatformBackupJournalV1(expected)
	if err != nil || s.exact(expectedRaw) != nil {
		return ErrPlatformBackupJournal
	}
	nextRaw, err := MarshalPlatformBackupJournalV1(next)
	if err != nil {
		return ErrPlatformBackupJournal
	}
	err = s.transaction.WriteMetadata(platformBackupJournalFile, nextRaw)
	if err == nil || errors.Is(err, ErrDurableCommitUnknown) {
		return s.exact(nextRaw)
	}
	return ErrPlatformBackupJournal
}

func (s *durablePlatformBackupJournalStore) exact(want []byte) error {
	if s == nil || s.transaction == nil {
		return ErrPlatformBackupJournal
	}
	got, err := s.transaction.ReadMetadata(platformBackupJournalFile)
	if err != nil || !bytes.Equal(got, want) {
		return ErrPlatformBackupJournal
	}
	if _, err := ParsePlatformBackupJournalV1(got); err != nil {
		return ErrPlatformBackupJournal
	}
	return nil
}

func journalAdjacent(old, next PlatformBackupJournalV1) bool {
	if next.Revision != old.Revision+1 || journalPhaseRevision(next.Phase) != journalPhaseRevision(old.Phase)+1 || !next.UpdatedAt.After(old.UpdatedAt) || old.SchemaVersion != next.SchemaVersion || old.BackupID != next.BackupID || old.Reason != next.Reason || !old.CreatedAt.Equal(next.CreatedAt) || !sameJournalEvidence(old, next) {
		return false
	}
	return true
}

func sameJournalEvidence(old, next PlatformBackupJournalV1) bool {
	if old.Capture != nil && (next.Capture == nil || !journalPointerSame(old.Capture, next.Capture)) || old.Package != nil && (next.Package == nil || !journalPointerSame(old.Package, next.Package)) || old.Encryption != nil && (next.Encryption == nil || !journalPointerSame(old.Encryption, next.Encryption)) || old.RemoteCommit != nil && (next.RemoteCommit == nil || !journalPointerSame(old.RemoteCommit, next.RemoteCommit)) {
		return false
	}
	return true
}

func journalPointerSame(left, right any) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}
