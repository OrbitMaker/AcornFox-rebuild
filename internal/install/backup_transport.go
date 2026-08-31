package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrRemoteBackupContract is returned for invalid local inputs and receipts.
	ErrRemoteBackupContract = errors.New("remote backup contract validation failed")
	// ErrRemoteBackupTransport deliberately hides object-store implementation errors.
	ErrRemoteBackupTransport = errors.New("remote backup publication could not be verified")
)

// RemoteBackupV1 is the secret-free durable receipt for an encrypted object.
// VersionID is required: callers must never later delete an unqualified key.
type RemoteBackupV1 struct {
	SchemaVersion              int                     `json:"schema_version"`
	BackupID                   string                  `json:"backup_id"`
	CreatedAt                  time.Time               `json:"created_at"`
	ObjectKey                  string                  `json:"object_key"`
	VersionID                  string                  `json:"version_id"`
	BackupMetadataSHA256       string                  `json:"backup_metadata_sha256"`
	EncryptedObjectSHA256      string                  `json:"encrypted_object_sha256"`
	EncryptedObjectSize        int64                   `json:"encrypted_object_size"`
	EncryptionReceipt          BackupEncryptionReceipt `json:"encryption_receipt"`
	EncryptionReceiptSHA256    string                  `json:"encryption_receipt_sha256"`
	KeyVersion                 string                  `json:"key_version"`
	SourceActivationID         string                  `json:"source_activation_id"`
	SourceActivationJSONSHA256 string                  `json:"source_activation_json_sha256"`
	ReleaseID                  string                  `json:"release_id"`
	ReleaseManifestSHA256      string                  `json:"release_manifest_sha256"`
}

func (r RemoteBackupV1) Validate() error {
	if r.SchemaVersion != 1 || !validBackupID(r.BackupID) || r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC ||
		!validBackupObjectKey(r.ObjectKey, r.BackupID) || !validRemoteBackupVersionID(r.VersionID) || !validSHA(r.BackupMetadataSHA256) || !validSHA(r.EncryptedObjectSHA256) || r.EncryptedObjectSize <= 0 ||
		!validSHA(r.EncryptionReceiptSHA256) || !validID(r.KeyVersion) || !validID(r.SourceActivationID) || !validSHA(r.SourceActivationJSONSHA256) ||
		!validID(r.ReleaseID) || !validSHA(r.ReleaseManifestSHA256) {
		return ErrRemoteBackupContract
	}
	receiptDigest, err := BackupEncryptionReceiptSHA256(r.EncryptionReceipt)
	if err != nil || receiptDigest != r.EncryptionReceiptSHA256 || r.EncryptionReceipt.ObjectSHA256 != r.EncryptedObjectSHA256 || r.EncryptionReceipt.ObjectSize != r.EncryptedObjectSize {
		return ErrRemoteBackupContract
	}
	if context := r.encryptionContext(); context.Validate() != nil {
		return ErrRemoteBackupContract
	}
	return nil
}

func (r RemoteBackupV1) encryptionContext() BackupEncryptionContext {
	return BackupEncryptionContext{
		BackupID: r.BackupID, BackupMetadataSHA256: r.BackupMetadataSHA256, SourceActivationID: r.SourceActivationID,
		SourceActivationJSONSHA256: r.SourceActivationJSONSHA256, ReleaseID: r.ReleaseID, ReleaseManifestSHA256: r.ReleaseManifestSHA256,
		ObjectKey: r.ObjectKey, KeyVersion: r.KeyVersion,
	}
}

// EncryptionContext reconstructs the exact authenticated, secret-free
// context needed to verify a downloaded object using only this durable receipt.
func (r RemoteBackupV1) EncryptionContext() (BackupEncryptionContext, error) {
	if r.Validate() != nil {
		return BackupEncryptionContext{}, ErrRemoteBackupContract
	}
	return r.encryptionContext(), nil
}

func MarshalRemoteBackupV1(receipt RemoteBackupV1) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrRemoteBackupContract
	}
	return json.Marshal(receipt)
}

func ParseRemoteBackupV1(raw []byte) (RemoteBackupV1, error) {
	var receipt RemoteBackupV1
	if err := decodeStrict(raw, &receipt); err != nil {
		return receipt, ErrRemoteBackupContract
	}
	if err := requireStrictFields(raw, []string{
		"schema_version", "backup_id", "created_at", "object_key", "version_id", "backup_metadata_sha256", "encrypted_object_sha256", "encrypted_object_size",
		"encryption_receipt", "encryption_receipt_sha256", "key_version", "source_activation_id", "source_activation_json_sha256", "release_id", "release_manifest_sha256",
	}); err != nil || receipt.Validate() != nil {
		return receipt, ErrRemoteBackupContract
	}
	return receipt, nil
}

// RemoteBackupObjectKey is the sole constructor for the remote object name.
func RemoteBackupObjectKey(scope, backupID string) (string, error) {
	if !validID(scope) || !validBackupID(backupID) {
		return "", ErrRemoteBackupContract
	}
	return "open-card/backups/" + scope + "/" + backupID + ".ocbkp", nil
}

// RemoteBackupObject is a version-qualified encrypted object identity. It
// intentionally holds no endpoint, authorization, or signed URL material.
type RemoteBackupObject struct {
	ObjectKey string
	VersionID string
	SHA256    string
	Size      int64
}

// RemoteBackupExpectedObject is the immutable content identity passed to a
// conditional create. It has no version until the provider accepts or finds
// the exact object.
type RemoteBackupExpectedObject struct {
	ObjectKey string
	SHA256    string
	Size      int64
}

func (o RemoteBackupExpectedObject) Validate() error {
	backupID, ok := backupIDFromRemoteObjectKey(o.ObjectKey)
	if !ok || !validBackupObjectKey(o.ObjectKey, backupID) || !validSHA(o.SHA256) || o.Size <= 0 {
		return ErrRemoteBackupContract
	}
	return nil
}

func (o RemoteBackupObject) Validate() error {
	backupID, ok := backupIDFromRemoteObjectKey(o.ObjectKey)
	if !ok || !validBackupObjectKey(o.ObjectKey, backupID) || !validRemoteBackupVersionID(o.VersionID) || !validSHA(o.SHA256) || o.Size <= 0 {
		return ErrRemoteBackupContract
	}
	return nil
}

func backupIDFromRemoteObjectKey(key string) (string, bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "open-card" || parts[1] != "backups" || !validID(parts[2]) || !strings.HasSuffix(parts[3], ".ocbkp") {
		return "", false
	}
	backupID := strings.TrimSuffix(parts[3], ".ocbkp")
	return backupID, validBackupID(backupID)
}

// Remote stores own version identifiers. They are opaque to Open Card and are
// never used as paths or shell input, so only a nonempty bounded text value is
// required rather than the narrower local install-ID grammar.
func validRemoteBackupVersionID(value string) bool {
	if len(value) == 0 || len(value) > 256 || value == "null" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~=-", r) {
			continue
		}
		return false
	}
	return true
}

// BackupObjectStore is the deliberately small, credential-free remote object
// boundary. Each operation is version-aware; DeleteVersion has no key-only
// form by design.
type BackupObjectStore interface {
	PutIfAbsent(context.Context, RemoteBackupExpectedObject, io.Reader) (RemoteBackupObject, error)
	Head(context.Context, string) (RemoteBackupObject, error)
	Get(context.Context, string, string) (io.ReadCloser, RemoteBackupObject, error)
	List(context.Context, string) ([]RemoteBackupObject, error)
	DeleteVersion(context.Context, string, string) error
}

// RemoteBackupDecryptionCheck opts into a second readback check of the
// authenticated encryption layer. Scratch and Destination are owned by the
// caller; DecryptBackup keeps Destination empty if the remote object is bad.
type RemoteBackupDecryptionCheck struct {
	Key         []byte
	Scratch     io.ReadWriteSeeker
	Destination io.Writer
}

func (c *RemoteBackupDecryptionCheck) valid() bool {
	return c != nil && len(c.Key) == 32 && c.Scratch != nil && c.Destination != nil
}

type RemoteBackupPublishRequest struct {
	Object            io.ReadSeeker
	CreatedAt         time.Time
	EncryptionContext BackupEncryptionContext
	EncryptionReceipt BackupEncryptionReceipt
	ExpectedExisting  *RemoteBackupV1
	DecryptionCheck   *RemoteBackupDecryptionCheck
}

// PublishRemoteBackup verifies a local encrypted object before it is offered
// to the store, then verifies its remote immutable version and readback. It
// returns only fixed contract errors, never backend error text.
func PublishRemoteBackup(ctx context.Context, store BackupObjectStore, request RemoteBackupPublishRequest) (RemoteBackupV1, error) {
	if store == nil || request.Object == nil || request.EncryptionContext.Validate() != nil || request.EncryptionReceipt.Validate() != nil ||
		request.CreatedAt.IsZero() || request.CreatedAt.Location() != time.UTC || request.DecryptionCheck != nil && !request.DecryptionCheck.valid() {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	encryptionDigest, err := BackupEncryptionReceiptSHA256(request.EncryptionReceipt)
	if err != nil {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	if err := verifySeekableObject(request.Object, request.EncryptionReceipt.ObjectSize, request.EncryptionReceipt.ObjectSHA256); err != nil {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	base := RemoteBackupV1{
		SchemaVersion: 1, BackupID: request.EncryptionContext.BackupID, CreatedAt: request.CreatedAt, ObjectKey: request.EncryptionContext.ObjectKey,
		BackupMetadataSHA256: request.EncryptionContext.BackupMetadataSHA256, EncryptedObjectSHA256: request.EncryptionReceipt.ObjectSHA256,
		EncryptedObjectSize: request.EncryptionReceipt.ObjectSize, EncryptionReceipt: request.EncryptionReceipt, EncryptionReceiptSHA256: encryptionDigest,
		KeyVersion: request.EncryptionContext.KeyVersion, SourceActivationID: request.EncryptionContext.SourceActivationID,
		SourceActivationJSONSHA256: request.EncryptionContext.SourceActivationJSONSHA256, ReleaseID: request.EncryptionContext.ReleaseID,
		ReleaseManifestSHA256: request.EncryptionContext.ReleaseManifestSHA256,
	}
	if request.ExpectedExisting != nil && !sameRemoteBackupBinding(*request.ExpectedExisting, base) {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	expected := RemoteBackupExpectedObject{ObjectKey: base.ObjectKey, SHA256: base.EncryptedObjectSHA256, Size: base.EncryptedObjectSize}
	if expected.Validate() != nil {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	if _, err := request.Object.Seek(0, io.SeekStart); err != nil {
		return RemoteBackupV1{}, ErrRemoteBackupContract
	}
	stored, putErr := store.PutIfAbsent(ctx, expected, request.Object)
	if putErr != nil {
		stored, putErr = store.Head(ctx, expected.ObjectKey)
		if putErr != nil || !matchesExpectedObject(stored, expected) {
			return RemoteBackupV1{}, ErrRemoteBackupTransport
		}
	} else if !matchesExpectedObject(stored, expected) {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	if request.ExpectedExisting != nil && stored.VersionID != request.ExpectedExisting.VersionID {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	head, err := store.Head(ctx, expected.ObjectKey)
	if err != nil || head != stored {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	base.VersionID = stored.VersionID
	if base.Validate() != nil {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	stream, got, err := store.Get(ctx, stored.ObjectKey, stored.VersionID)
	if err != nil || stream == nil || got != stored {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	if err := verifyRemoteObjectStream(stream, stored, request.DecryptionCheck, request.EncryptionContext, request.EncryptionReceipt); err != nil {
		_ = stream.Close()
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	if err := stream.Close(); err != nil {
		return RemoteBackupV1{}, ErrRemoteBackupTransport
	}
	return base, nil
}

func BackupEncryptionReceiptSHA256(receipt BackupEncryptionReceipt) (string, error) {
	raw, err := MarshalBackupEncryptionReceipt(receipt)
	if err != nil {
		return "", ErrRemoteBackupContract
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func verifySeekableObject(source io.ReadSeeker, expectedSize int64, expectedSHA256 string) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return ErrRemoteBackupContract
	}
	if err := verifyObjectStream(source, expectedSize, expectedSHA256); err != nil {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return ErrRemoteBackupContract
	}
	return nil
}

func verifyObjectStream(source io.Reader, expectedSize int64, expectedSHA256 string) error {
	hash := sha256.New()
	size, err := io.Copy(hash, source)
	if err != nil || size != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		return ErrRemoteBackupContract
	}
	return nil
}

func matchesExpectedObject(actual RemoteBackupObject, expected RemoteBackupExpectedObject) bool {
	return actual.Validate() == nil && actual.ObjectKey == expected.ObjectKey && actual.SHA256 == expected.SHA256 && actual.Size == expected.Size
}

func verifyRemoteObjectStream(source io.Reader, expected RemoteBackupObject, decrypt *RemoteBackupDecryptionCheck, encryptionContext BackupEncryptionContext, encryptionReceipt BackupEncryptionReceipt) error {
	hash := sha256.New()
	counted := &countingReader{reader: io.TeeReader(source, hash)}
	if decrypt == nil {
		if _, err := io.Copy(io.Discard, counted); err != nil {
			return ErrRemoteBackupContract
		}
	} else if err := DecryptBackup(decrypt.Destination, decrypt.Scratch, counted, decrypt.Key, encryptionContext, encryptionReceipt); err != nil {
		return ErrRemoteBackupContract
	}
	if counted.size != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return ErrRemoteBackupContract
	}
	return nil
}

func sameRemoteBackupBinding(receipt, base RemoteBackupV1) bool {
	return receipt.Validate() == nil && receipt.SchemaVersion == base.SchemaVersion && receipt.BackupID == base.BackupID && receipt.CreatedAt.Equal(base.CreatedAt) &&
		receipt.ObjectKey == base.ObjectKey && receipt.BackupMetadataSHA256 == base.BackupMetadataSHA256 && receipt.EncryptedObjectSHA256 == base.EncryptedObjectSHA256 && receipt.EncryptedObjectSize == base.EncryptedObjectSize &&
		receipt.EncryptionReceipt == base.EncryptionReceipt &&
		receipt.EncryptionReceiptSHA256 == base.EncryptionReceiptSHA256 && receipt.KeyVersion == base.KeyVersion && receipt.SourceActivationID == base.SourceActivationID &&
		receipt.SourceActivationJSONSHA256 == base.SourceActivationJSONSHA256 && receipt.ReleaseID == base.ReleaseID && receipt.ReleaseManifestSHA256 == base.ReleaseManifestSHA256
}

type RemoteBackupVersionRef struct {
	ObjectKey string
	VersionID string
}

func (r RemoteBackupVersionRef) Validate() error {
	if _, ok := backupIDFromRemoteObjectKey(r.ObjectKey); !ok || !validRemoteBackupVersionID(r.VersionID) {
		return ErrRemoteBackupContract
	}
	return nil
}

type RemoteBackupRetentionPlan struct {
	Keep   []RemoteBackupVersionRef
	Delete []RemoteBackupVersionRef
}

// PlanRemoteBackupRetention is deliberately pure: it produces only
// version-qualified deletions and never calls DeleteVersion.
func PlanRemoteBackupRetention(receipts []RemoteBackupV1, protected []RemoteBackupVersionRef) (RemoteBackupRetentionPlan, error) {
	unique := make(map[RemoteBackupVersionRef]RemoteBackupV1, len(receipts))
	keys := make(map[string]RemoteBackupVersionRef, len(receipts))
	for _, receipt := range receipts {
		if receipt.Validate() != nil {
			return RemoteBackupRetentionPlan{}, ErrRemoteBackupContract
		}
		ref := RemoteBackupVersionRef{ObjectKey: receipt.ObjectKey, VersionID: receipt.VersionID}
		if existing, ok := unique[ref]; ok && existing != receipt {
			return RemoteBackupRetentionPlan{}, ErrRemoteBackupContract
		}
		if existing, ok := keys[receipt.ObjectKey]; ok && existing != ref {
			return RemoteBackupRetentionPlan{}, ErrRemoteBackupContract
		}
		unique[ref], keys[receipt.ObjectKey] = receipt, ref
	}
	protectedSet := make(map[RemoteBackupVersionRef]struct{}, len(protected))
	for _, ref := range protected {
		if ref.Validate() != nil {
			return RemoteBackupRetentionPlan{}, ErrRemoteBackupContract
		}
		protectedSet[ref] = struct{}{}
	}
	values := make([]RemoteBackupV1, 0, len(unique))
	for _, receipt := range unique {
		values = append(values, receipt)
	}
	sort.Slice(values, func(i, j int) bool {
		if !values[i].CreatedAt.Equal(values[j].CreatedAt) {
			return values[i].CreatedAt.After(values[j].CreatedAt)
		}
		if values[i].ObjectKey != values[j].ObjectKey {
			return values[i].ObjectKey < values[j].ObjectKey
		}
		return values[i].VersionID < values[j].VersionID
	})
	keep := make(map[RemoteBackupVersionRef]struct{}, len(values))
	days, weeks := map[string]struct{}{}, map[string]struct{}{}
	for _, receipt := range values {
		ref := RemoteBackupVersionRef{ObjectKey: receipt.ObjectKey, VersionID: receipt.VersionID}
		utc := receipt.CreatedAt.UTC()
		day := utc.Format("2006-01-02")
		if len(days) < 7 {
			if _, ok := days[day]; !ok {
				days[day] = struct{}{}
				keep[ref] = struct{}{}
			}
		}
		year, week := utc.ISOWeek()
		weekKey := strconv.Itoa(year) + "-" + strconv.Itoa(week)
		if len(weeks) < 4 {
			if _, ok := weeks[weekKey]; !ok {
				weeks[weekKey] = struct{}{}
				keep[ref] = struct{}{}
			}
		}
	}
	for ref := range protectedSet {
		if _, exists := unique[ref]; exists {
			keep[ref] = struct{}{}
		}
	}
	plan := RemoteBackupRetentionPlan{}
	for ref := range unique {
		if _, ok := keep[ref]; ok {
			plan.Keep = append(plan.Keep, ref)
		} else {
			plan.Delete = append(plan.Delete, ref)
		}
	}
	sortVersionRefs(plan.Keep)
	sortVersionRefs(plan.Delete)
	return plan, nil
}

func sortVersionRefs(values []RemoteBackupVersionRef) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ObjectKey != values[j].ObjectKey {
			return values[i].ObjectKey < values[j].ObjectKey
		}
		return values[i].VersionID < values[j].VersionID
	})
}
