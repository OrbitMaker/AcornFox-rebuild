package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"
)

const PlatformBackupRemoteReceiptV2Schema = "open-card.platform-backup.remote-receipt.v2"

const platformBackupRemoteReceiptMaxSize = PlatformBackupV3MaxTextMemberSize

// PlatformBackupStoreObject is a version-qualified object returned by the
// publication store. Object keys are opaque to the store; this package binds
// the two accepted key forms to the encryption context before use.
type PlatformBackupStoreObject struct {
	ObjectKey string
	VersionID string
	SHA256    string
	Size      int64
}

type PlatformBackupExpectedObject struct {
	ObjectKey string
	SHA256    string
	Size      int64
}

// PlatformBackupVersionedStore is intentionally separate from BackupObjectStore
// so the V3 visibility commit cannot accidentally use V1 create-only semantics.
// PutReconciled must either write the expected immutable content or reconcile a
// prior equivalent write; every subsequent read is version-qualified.
type PlatformBackupVersionedStore interface {
	PutReconciled(context.Context, PlatformBackupExpectedObject, io.Reader) (PlatformBackupStoreObject, error)
	HeadCurrentVersion(context.Context, string) (PlatformBackupStoreObject, error)
	Get(context.Context, string, string) (io.ReadCloser, PlatformBackupStoreObject, error)
	ListVersions(context.Context, string) ([]PlatformBackupStoreObject, error)
	DeleteVersion(context.Context, string, string) error
}

// VersionedBackupObjectStore is retained as a descriptive spelling for callers.
type VersionedBackupObjectStore = PlatformBackupVersionedStore

// PlatformBackupRemoteReceiptV2 is the companion visibility record. It never
// contains its own object version or hash: those are local observation facts.
type PlatformBackupRemoteReceiptV2 struct {
	Schema                     string                  `json:"schema"`
	BackupID                   string                  `json:"backup_id"`
	CreatedAt                  time.Time               `json:"created_at"`
	SourceInstallationIDSHA256 string                  `json:"source_installation_id_sha256"`
	PackageManifestSHA256      string                  `json:"package_manifest_sha256"`
	PackageSHA256              string                  `json:"package_sha256"`
	SourceActivationID         string                  `json:"source_activation_id"`
	SourceActivationJSONSHA256 string                  `json:"source_activation_json_sha256"`
	ReleaseID                  string                  `json:"release_id"`
	ReleaseManifestSHA256      string                  `json:"release_manifest_sha256"`
	DataObjectKey              string                  `json:"data_object_key"`
	DataVersionID              string                  `json:"data_version_id"`
	DataSHA256                 string                  `json:"data_sha256"`
	DataSize                   int64                   `json:"data_size"`
	EncryptionReceipt          BackupEncryptionReceipt `json:"encryption_receipt"`
	EncryptionReceiptSHA256    string                  `json:"encryption_receipt_sha256"`
	KeyVersion                 string                  `json:"key_version"`
}

func (r PlatformBackupRemoteReceiptV2) Validate() error {
	if r.Schema != PlatformBackupRemoteReceiptV2Schema || !validBackupID(r.BackupID) || r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC ||
		!validSHA(r.SourceInstallationIDSHA256) || !validSHA(r.PackageManifestSHA256) || !validSHA(r.PackageSHA256) || !validID(r.SourceActivationID) ||
		!validSHA(r.SourceActivationJSONSHA256) || !validID(r.ReleaseID) || !validSHA(r.ReleaseManifestSHA256) || !validRemoteBackupVersionID(r.DataVersionID) ||
		!validSHA(r.DataSHA256) || r.DataSize <= 0 || !backupKeyVersion.MatchString(r.KeyVersion) || r.EncryptionReceipt.Validate() != nil || !validSHA(r.EncryptionReceiptSHA256) {
		return ErrRemoteBackupContract
	}
	context := r.encryptionContext()
	if context.Validate() != nil || r.DataObjectKey != context.ObjectKey || r.EncryptionReceipt.ObjectSHA256 != r.DataSHA256 || r.EncryptionReceipt.ObjectSize != r.DataSize {
		return ErrRemoteBackupContract
	}
	digest, err := BackupEncryptionReceiptSHA256(r.EncryptionReceipt)
	if err != nil || digest != r.EncryptionReceiptSHA256 {
		return ErrRemoteBackupContract
	}
	return nil
}

func (r PlatformBackupRemoteReceiptV2) encryptionContext() BackupEncryptionContextV2 {
	return BackupEncryptionContextV2{
		BackupID: r.BackupID, SourceInstallationIDSHA256: r.SourceInstallationIDSHA256, PackageManifestSHA256: r.PackageManifestSHA256, PackageSHA256: r.PackageSHA256,
		SourceActivationID: r.SourceActivationID, SourceActivationJSONSHA256: r.SourceActivationJSONSHA256, ReleaseID: r.ReleaseID,
		ReleaseManifestSHA256: r.ReleaseManifestSHA256, ObjectKey: r.DataObjectKey, KeyVersion: r.KeyVersion,
	}
}

func MarshalPlatformBackupRemoteReceiptV2(receipt PlatformBackupRemoteReceiptV2) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrRemoteBackupContract
	}
	return json.Marshal(receipt)
}

func ParsePlatformBackupRemoteReceiptV2(raw []byte) (PlatformBackupRemoteReceiptV2, error) {
	var receipt PlatformBackupRemoteReceiptV2
	fields := []string{"schema", "backup_id", "created_at", "source_installation_id_sha256", "package_manifest_sha256", "package_sha256", "source_activation_id", "source_activation_json_sha256", "release_id", "release_manifest_sha256", "data_object_key", "data_version_id", "data_sha256", "data_size", "encryption_receipt", "encryption_receipt_sha256", "key_version"}
	if decodeStrict(raw, &receipt) != nil || requireStrictFields(raw, fields) != nil || receipt.Validate() != nil {
		return PlatformBackupRemoteReceiptV2{}, ErrRemoteBackupContract
	}
	canonical, err := MarshalPlatformBackupRemoteReceiptV2(receipt)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PlatformBackupRemoteReceiptV2{}, ErrRemoteBackupContract
	}
	return receipt, nil
}

// PlatformBackupCommittedV2 is the local complete commit observation. Only a
// successfully read-back companion receipt makes the data object discoverable.
type PlatformBackupCommittedV2 struct {
	Receipt          PlatformBackupRemoteReceiptV2
	ReceiptObjectKey string
	ReceiptVersionID string
	ReceiptSHA256    string
	ReceiptSize      int64
	ReceiptContent   []byte
}

func (r PlatformBackupCommittedV2) Validate() error {
	if r.Receipt.Validate() != nil || !validPlatformBackupReceiptKey(r.ReceiptObjectKey, r.Receipt.SourceInstallationIDSHA256, r.Receipt.BackupID) ||
		!validRemoteBackupVersionID(r.ReceiptVersionID) || !validSHA(r.ReceiptSHA256) || r.ReceiptSize <= 0 || r.ReceiptSize > platformBackupRemoteReceiptMaxSize || len(r.ReceiptContent) == 0 || int64(len(r.ReceiptContent)) != r.ReceiptSize {
		return ErrRemoteBackupContract
	}
	if sum := sha256.Sum256(r.ReceiptContent); hex.EncodeToString(sum[:]) != r.ReceiptSHA256 {
		return ErrRemoteBackupContract
	}
	parsed, err := ParsePlatformBackupRemoteReceiptV2(r.ReceiptContent)
	if err != nil || parsed != r.Receipt {
		return ErrRemoteBackupContract
	}
	return nil
}

type PlatformBackupDecryptionCheck struct {
	Key     []byte
	Scratch io.ReadWriteSeeker
}

func (c *PlatformBackupDecryptionCheck) valid() bool {
	return c != nil && len(c.Key) == 32 && c.Scratch != nil
}

type PlatformBackupPublishRequest struct {
	Encrypted         io.ReadSeeker
	EncryptionContext BackupEncryptionContextV2
	EncryptionReceipt BackupEncryptionReceipt
	CreatedAt         time.Time
	ExpectedExisting  *PlatformBackupCommittedV2
	DecryptionCheck   *PlatformBackupDecryptionCheck
}

// PublishPlatformBackup writes data first and publishes the companion receipt
// last. The receipt is the only visibility commit and no cleanup deletion is
// attempted after an incomplete publication.
func PublishPlatformBackup(ctx context.Context, store PlatformBackupVersionedStore, request PlatformBackupPublishRequest) (PlatformBackupCommittedV2, error) {
	if store == nil || request.Encrypted == nil || request.EncryptionContext.Validate() != nil || request.EncryptionReceipt.Validate() != nil ||
		request.CreatedAt.IsZero() || request.CreatedAt.Location() != time.UTC || !request.DecryptionCheck.valid() ||
		request.EncryptionReceipt.ObjectSHA256 == "" || request.EncryptionReceipt.ObjectSize <= 0 {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	if request.ExpectedExisting != nil && (request.ExpectedExisting.Validate() != nil || !platformExpectedExistingMatchesRequest(*request.ExpectedExisting, request)) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	if err := verifySeekableObject(request.Encrypted, request.EncryptionReceipt.ObjectSize, request.EncryptionReceipt.ObjectSHA256); err != nil {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	dataExpected := PlatformBackupExpectedObject{ObjectKey: request.EncryptionContext.ObjectKey, SHA256: request.EncryptionReceipt.ObjectSHA256, Size: request.EncryptionReceipt.ObjectSize}
	if !validPlatformBackupExpected(dataExpected, false) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	if request.ExpectedExisting != nil {
		return replayPlatformBackup(ctx, store, request, dataExpected, *request.ExpectedExisting)
	}
	data, err := publishPlatformObject(ctx, store, dataExpected, request.Encrypted)
	if err != nil {
		return PlatformBackupCommittedV2{}, err
	}
	if err := verifyPlatformDataReadback(ctx, store, data, request.DecryptionCheck, request.EncryptionContext, request.EncryptionReceipt); err != nil {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	receipt := platformRemoteReceipt(request, data)
	receiptRaw, err := MarshalPlatformBackupRemoteReceiptV2(receipt)
	if err != nil {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	receiptExpected := PlatformBackupExpectedObject{ObjectKey: platformBackupReceiptObjectKey(request.EncryptionContext), SHA256: sha256Hex(receiptRaw), Size: int64(len(receiptRaw))}
	if !validPlatformBackupExpected(receiptExpected, true) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	receiptObject, err := publishPlatformObject(ctx, store, receiptExpected, bytes.NewReader(receiptRaw))
	if err != nil {
		return PlatformBackupCommittedV2{}, err
	}
	readback, err := readPlatformObject(ctx, store, receiptObject)
	if err != nil || !bytes.Equal(readback, receiptRaw) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	committed := PlatformBackupCommittedV2{Receipt: receipt, ReceiptObjectKey: receiptObject.ObjectKey, ReceiptVersionID: receiptObject.VersionID, ReceiptSHA256: receiptObject.SHA256, ReceiptSize: receiptObject.Size, ReceiptContent: readback}
	if committed.Validate() != nil {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	return committed, nil
}

// replayPlatformBackup makes replay a read-only verification operation. A
// current-head mismatch is a conflict even if an older exact version remains
// readable: callers must not resurrect stale visibility records.
func replayPlatformBackup(ctx context.Context, store PlatformBackupVersionedStore, request PlatformBackupPublishRequest, dataExpected PlatformBackupExpectedObject, existing PlatformBackupCommittedV2) (PlatformBackupCommittedV2, error) {
	data := PlatformBackupStoreObject{ObjectKey: existing.Receipt.DataObjectKey, VersionID: existing.Receipt.DataVersionID, SHA256: existing.Receipt.DataSHA256, Size: existing.Receipt.DataSize}
	if !matchesPlatformExpected(data, dataExpected) || !samePlatformRemoteReceiptBinding(existing.Receipt, platformRemoteReceipt(request, data)) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	head, err := store.HeadCurrentVersion(ctx, data.ObjectKey)
	if err != nil || head != data {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	if err := verifyPlatformDataReadback(ctx, store, data, request.DecryptionCheck, request.EncryptionContext, request.EncryptionReceipt); err != nil {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	receiptObject := PlatformBackupStoreObject{ObjectKey: existing.ReceiptObjectKey, VersionID: existing.ReceiptVersionID, SHA256: existing.ReceiptSHA256, Size: existing.ReceiptSize}
	if !validPlatformBackupStoreObject(receiptObject) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupContract
	}
	head, err = store.HeadCurrentVersion(ctx, receiptObject.ObjectKey)
	if err != nil || head != receiptObject {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	raw, err := readPlatformObject(ctx, store, receiptObject)
	if err != nil || !bytes.Equal(raw, existing.ReceiptContent) {
		return PlatformBackupCommittedV2{}, ErrRemoteBackupTransport
	}
	return existing, nil
}

func platformRemoteReceipt(request PlatformBackupPublishRequest, data PlatformBackupStoreObject) PlatformBackupRemoteReceiptV2 {
	digest, _ := BackupEncryptionReceiptSHA256(request.EncryptionReceipt)
	c := request.EncryptionContext
	return PlatformBackupRemoteReceiptV2{Schema: PlatformBackupRemoteReceiptV2Schema, BackupID: c.BackupID, CreatedAt: request.CreatedAt, SourceInstallationIDSHA256: c.SourceInstallationIDSHA256,
		PackageManifestSHA256: c.PackageManifestSHA256, PackageSHA256: c.PackageSHA256, SourceActivationID: c.SourceActivationID, SourceActivationJSONSHA256: c.SourceActivationJSONSHA256,
		ReleaseID: c.ReleaseID, ReleaseManifestSHA256: c.ReleaseManifestSHA256, DataObjectKey: data.ObjectKey, DataVersionID: data.VersionID, DataSHA256: data.SHA256,
		DataSize: data.Size, EncryptionReceipt: request.EncryptionReceipt, EncryptionReceiptSHA256: digest, KeyVersion: c.KeyVersion}
}

func publishPlatformObject(ctx context.Context, store PlatformBackupVersionedStore, expected PlatformBackupExpectedObject, source io.Reader) (PlatformBackupStoreObject, error) {
	object, putErr := store.PutReconciled(ctx, expected, source)
	if putErr != nil {
		object, putErr = store.HeadCurrentVersion(ctx, expected.ObjectKey)
		if putErr != nil || !matchesPlatformExpected(object, expected) {
			return PlatformBackupStoreObject{}, ErrRemoteBackupTransport
		}
	} else if !matchesPlatformExpected(object, expected) {
		return PlatformBackupStoreObject{}, ErrRemoteBackupTransport
	}
	head, err := store.HeadCurrentVersion(ctx, expected.ObjectKey)
	if err != nil || head != object {
		return PlatformBackupStoreObject{}, ErrRemoteBackupTransport
	}
	return object, nil
}

func verifyPlatformDataReadback(ctx context.Context, store PlatformBackupVersionedStore, object PlatformBackupStoreObject, decrypt *PlatformBackupDecryptionCheck, encryptionContext BackupEncryptionContextV2, receipt BackupEncryptionReceipt) error {
	stream, got, err := store.Get(ctx, object.ObjectKey, object.VersionID)
	if err != nil || stream == nil || got != object {
		if stream != nil {
			_ = stream.Close()
		}
		return ErrRemoteBackupTransport
	}
	hash := sha256.New()
	counted := &countingReader{reader: io.TeeReader(stream, hash)}
	decryptErr := DecryptPlatformBackup(io.Discard, decrypt.Scratch, counted, decrypt.Key, encryptionContext, receipt)
	closeErr := stream.Close()
	if decryptErr != nil || closeErr != nil || counted.size != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.SHA256 {
		return ErrRemoteBackupTransport
	}
	return nil
}

func readPlatformObject(ctx context.Context, store PlatformBackupVersionedStore, object PlatformBackupStoreObject) ([]byte, error) {
	stream, got, err := store.Get(ctx, object.ObjectKey, object.VersionID)
	if err != nil || stream == nil || got != object {
		if stream != nil {
			_ = stream.Close()
		}
		return nil, ErrRemoteBackupTransport
	}
	if object.Size > platformBackupRemoteReceiptMaxSize {
		_ = stream.Close()
		return nil, ErrRemoteBackupTransport
	}
	data, readErr := io.ReadAll(io.LimitReader(stream, object.Size+1))
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != object.Size || sha256Hex(data) != object.SHA256 {
		return nil, ErrRemoteBackupTransport
	}
	return data, nil
}

// DiscoverCommittedPlatformBackups reads exactly one installation namespace.
// Data blobs are deliberately ignored: absent a valid receipt they are
// invisible. Any object outside or unknown within that managed namespace is a
// store contract failure rather than a candidate from another installation.
func DiscoverCommittedPlatformBackups(ctx context.Context, store PlatformBackupVersionedStore, installationSHA256 string) ([]PlatformBackupCommittedV2, error) {
	if store == nil || !validSHA(installationSHA256) {
		return nil, ErrRemoteBackupContract
	}
	namespace := platformBackupInstallationPrefix(installationSHA256)
	objects, err := store.ListVersions(ctx, namespace)
	if err != nil {
		return nil, ErrRemoteBackupTransport
	}
	seen := make(map[string]struct{}, len(objects))
	committed := make([]PlatformBackupCommittedV2, 0, len(objects))
	for _, object := range objects {
		if !validPlatformBackupStoreObject(object) || !strings.HasPrefix(object.ObjectKey, namespace+"/") {
			return nil, ErrRemoteBackupTransport
		}
		if platformBackupDataInInstallation(object.ObjectKey, installationSHA256) {
			continue
		}
		if !strings.HasSuffix(object.ObjectKey, ".receipt.json") {
			return nil, ErrRemoteBackupTransport
		}
		if _, exists := seen[object.ObjectKey]; exists {
			return nil, ErrRemoteBackupTransport
		}
		seen[object.ObjectKey] = struct{}{}
		raw, err := readPlatformObject(ctx, store, object)
		if err != nil {
			return nil, ErrRemoteBackupTransport
		}
		receipt, err := ParsePlatformBackupRemoteReceiptV2(raw)
		if err != nil || receipt.SourceInstallationIDSHA256 != installationSHA256 || !validPlatformBackupReceiptKey(object.ObjectKey, receipt.SourceInstallationIDSHA256, receipt.BackupID) || !platformBackupDataInInstallation(receipt.DataObjectKey, installationSHA256) {
			return nil, ErrRemoteBackupTransport
		}
		value := PlatformBackupCommittedV2{Receipt: receipt, ReceiptObjectKey: object.ObjectKey, ReceiptVersionID: object.VersionID, ReceiptSHA256: object.SHA256, ReceiptSize: object.Size, ReceiptContent: raw}
		if value.Validate() != nil {
			return nil, ErrRemoteBackupTransport
		}
		committed = append(committed, value)
	}
	sort.Slice(committed, func(i, j int) bool {
		if !committed[i].Receipt.CreatedAt.Equal(committed[j].Receipt.CreatedAt) {
			return committed[i].Receipt.CreatedAt.Before(committed[j].Receipt.CreatedAt)
		}
		return committed[i].ReceiptObjectKey < committed[j].ReceiptObjectKey
	})
	return committed, nil
}

func validPlatformBackupStoreObject(value PlatformBackupStoreObject) bool {
	return value.ObjectKey != "" && len(value.ObjectKey) <= 1024 && !strings.ContainsAny(value.ObjectKey, "\x00\r\n") && validRemoteBackupVersionID(value.VersionID) && validSHA(value.SHA256) && value.Size > 0
}
func matchesPlatformExpected(actual PlatformBackupStoreObject, expected PlatformBackupExpectedObject) bool {
	return validPlatformBackupStoreObject(actual) && actual.ObjectKey == expected.ObjectKey && actual.SHA256 == expected.SHA256 && actual.Size == expected.Size
}
func validPlatformBackupExpected(value PlatformBackupExpectedObject, receipt bool) bool {
	if !validSHA(value.SHA256) || value.Size <= 0 {
		return false
	}
	if receipt {
		parts := strings.Split(value.ObjectKey, "/")
		return len(parts) == 4 && validPlatformBackupPrefix(strings.Join(parts[:2], "/")) && validSHA(parts[2]) && strings.HasSuffix(parts[3], ".receipt.json") && validBackupID(strings.TrimSuffix(parts[3], ".receipt.json"))
	}
	return platformBackupPrefixForDataKey(value.ObjectKey) != ""
}
func validPlatformBackupPrefix(prefix string) bool {
	parts := strings.Split(prefix, "/")
	return len(parts) == 2 && parts[0] == "open-card" && parts[1] == "backups"
}
func platformBackupPrefixForDataKey(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || !validPlatformBackupPrefix(strings.Join(parts[:2], "/")) || !validSHA(parts[2]) || !strings.HasSuffix(parts[3], ".ocbkp") || !validBackupID(strings.TrimSuffix(parts[3], ".ocbkp")) {
		return ""
	}
	return strings.Join(parts[:2], "/")
}
func platformBackupInstallationPrefix(installationSHA256 string) string {
	if !validSHA(installationSHA256) {
		return ""
	}
	return "open-card/backups/" + installationSHA256
}
func platformBackupDataInInstallation(key, installationSHA256 string) bool {
	parts := strings.Split(key, "/")
	return platformBackupPrefixForDataKey(key) != "" && len(parts) == 4 && parts[2] == installationSHA256
}
func platformBackupReceiptObjectKey(context BackupEncryptionContextV2) string {
	return platformBackupPrefixForDataKey(context.ObjectKey) + "/" + context.SourceInstallationIDSHA256 + "/" + context.BackupID + ".receipt.json"
}
func validPlatformBackupReceiptKey(key, installationSHA, backupID string) bool {
	return validSHA(installationSHA) && validBackupID(backupID) && key == "open-card/backups/"+installationSHA+"/"+backupID+".receipt.json"
}
func sha256Hex(raw []byte) string                                              { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func samePlatformRemoteReceiptBinding(a, b PlatformBackupRemoteReceiptV2) bool { return a == b }
func platformExpectedExistingMatchesRequest(existing PlatformBackupCommittedV2, request PlatformBackupPublishRequest) bool {
	c, r := request.EncryptionContext, existing.Receipt
	digest, err := BackupEncryptionReceiptSHA256(request.EncryptionReceipt)
	return err == nil && r.BackupID == c.BackupID && r.CreatedAt.Equal(request.CreatedAt) && r.SourceInstallationIDSHA256 == c.SourceInstallationIDSHA256 &&
		r.PackageManifestSHA256 == c.PackageManifestSHA256 && r.PackageSHA256 == c.PackageSHA256 && r.SourceActivationID == c.SourceActivationID &&
		r.SourceActivationJSONSHA256 == c.SourceActivationJSONSHA256 && r.ReleaseID == c.ReleaseID && r.ReleaseManifestSHA256 == c.ReleaseManifestSHA256 &&
		r.DataObjectKey == c.ObjectKey && r.DataSHA256 == request.EncryptionReceipt.ObjectSHA256 && r.DataSize == request.EncryptionReceipt.ObjectSize &&
		r.EncryptionReceipt == request.EncryptionReceipt && r.EncryptionReceiptSHA256 == digest && r.KeyVersion == c.KeyVersion
}
