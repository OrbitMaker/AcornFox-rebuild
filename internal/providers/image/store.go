// Package image persists immutable OCI archive artifacts on a local filesystem.
// It deliberately does not resolve mutable registry tags: callers must provide
// a repository plus a sha256 digest that has already been resolved upstream.
package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "filesystem-oci-store"
	providerVersion = "m1"
	storeAction     = "store_oci"
	openAction      = "open_oci"
	pullAction      = "pull"
	retainAction    = "retain"
	deleteAction    = "delete"
)

var repositoryPart = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
var storageKeyPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var errArchiveLocked = errors.New("OCI archive publication is locked")

// Config configures the provider-owned root. The root may be absent during
// construction, but it must never be a symlink when used.
type Config struct {
	Root string
}

// Provider implements contracts.ImageStore with immutable archive files and
// adjacent metadata. A process-local mutex makes concurrent StoreOCI calls
// deterministic; publication itself is atomic for concurrent processes too.
type Provider struct {
	metadata contracts.ProviderMetadata
	root     string

	mu         sync.Mutex
	operations map[string]operationRecord
}

type operationRecord struct {
	fingerprint string
	result      contracts.StoreOCIResult
}

type storedRecord struct {
	Image         domain.ImageDigest `json:"image"`
	StorageRef    string             `json:"storage_ref"`
	ContentDigest string             `json:"content_digest"`
	SizeBytes     int64              `json:"size_bytes"`
	Retained      bool               `json:"retained"`
	Running       bool               `json:"running"`
	Rollback      bool               `json:"rollback"`
}

// New constructs an archive store. It performs no filesystem mutation.
func New(config Config) (*Provider, error) {
	root, err := absoluteRoot(config.Root)
	if err != nil {
		return nil, err
	}
	return &Provider{
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities: contracts.NewCapabilitySet(
				contracts.CapabilityImagePull,
				contracts.CapabilityImageRetain,
				contracts.CapabilityImageDelete,
				contracts.CapabilityImageStoreOCI,
				contracts.CapabilityImageOpenOCI,
			),
		},
		root: root, operations: make(map[string]operationRecord),
	}, nil
}

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// Resolve is intentionally unavailable: resolving a tag here would introduce
// tag drift. A controller/registry adapter must resolve it before StoreOCI.
func (p *Provider) Resolve(_ context.Context, request contracts.ImageResolveRequest) (contracts.ImageResolveResult, error) {
	return contracts.ImageResolveResult{}, p.failure(request.Operation, contracts.CapabilityImageResolve, "resolve", contracts.ErrUnsupportedCapability, "mutable image tag resolution is not supported by the archive store", nil)
}

// StoreOCI copies an archive to a temporary sibling, fsyncs it, then publishes
// an immutable read-only archive and record. StorageKey is an opaque caller
// identity, never a path, so it cannot choose a filesystem location.
func (p *Provider) StoreOCI(ctx context.Context, request contracts.StoreOCIRequest) (contracts.StoreOCIResult, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilityImageStoreOCI, storeAction); err != nil {
		return contracts.StoreOCIResult{}, err
	}
	if err := validateImage(request.Image); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrValidation, "image digest is invalid", nil)
	}
	if request.Archive == nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrInvalidArgument, "OCI archive is required", nil)
	}
	ref := storageRef(request.Image)
	if !validStorageKey(request.StorageKey) {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrValidation, "storage key is not a safe opaque identifier", nil)
	}
	fingerprint := imageFingerprint(request.Image, ref, request.StorageKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[request.Operation.IdempotencyKey]; ok {
		if previous.fingerprint != fingerprint {
			return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrConflict, "idempotency key was reused for a different image operation", nil)
		}
		return cloneStoreResult(previous.result), nil
	}
	if err := p.ensureLayout(); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive store is unavailable", err)
	}

	archivePath, recordPath, err := p.paths(request.Image)
	if err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrValidation, "image storage path is invalid", nil)
	}
	unlock, err := acquireImageLock(ctx, request.Operation, archivePath+".lock")
	if err != nil {
		return contracts.StoreOCIResult{}, p.classify(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, err)
	}
	defer unlock()
	temporary, contentDigest, size, err := p.copyTemporary(ctx, request.Operation, archivePath, request.Archive)
	if err != nil {
		return contracts.StoreOCIResult{}, p.classify(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, err)
	}
	defer os.Remove(temporary)
	if size == 0 {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrValidation, "OCI archive is empty", nil)
	}

	if existing, err := p.readRecord(recordPath, archivePath, request.Image); err == nil {
		if existing.ContentDigest != contentDigest || existing.SizeBytes != size {
			return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrConflict, "immutable image already exists with different archive content", nil)
		}
		result := p.result(request.Operation, existing)
		p.operations[request.Operation.IdempotencyKey] = operationRecord{fingerprint: fingerprint, result: result}
		return cloneStoreResult(result), nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "existing OCI archive cannot be verified", err)
	} else if _, recordErr := os.Lstat(recordPath); recordErr == nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "incomplete OCI archive metadata exists", nil)
	} else if !errors.Is(recordErr, fs.ErrNotExist) {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive metadata path cannot be verified", recordErr)
	}
	// An archive without its metadata may be a crashed/host-tampered publish.
	// Never overwrite it, because doing so would turn an integrity ambiguity into
	// an apparently valid image.
	if _, err := os.Lstat(archivePath); err == nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrConflict, "incomplete OCI archive publication exists", nil)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive path cannot be verified", err)
	}
	if err := os.Chmod(temporary, 0o440); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive permissions could not be sealed", err)
	}
	if err := os.Rename(temporary, archivePath); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive could not be published", err)
	}
	if err := syncDirectory(filepath.Dir(archivePath)); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive publication could not be synced", err)
	}
	record := storedRecord{Image: cleanImage(request.Image), StorageRef: ref, ContentDigest: contentDigest, SizeBytes: size}
	if err := writeRecord(recordPath, record); err != nil {
		return contracts.StoreOCIResult{}, p.failure(request.Operation, contracts.CapabilityImageStoreOCI, storeAction, contracts.ErrUnavailable, "OCI archive metadata could not be published", err)
	}
	result := p.result(request.Operation, record)
	p.operations[request.Operation.IdempotencyKey] = operationRecord{fingerprint: fingerprint, result: result}
	return cloneStoreResult(result), nil
}

// OpenOCI returns the immutable archive only after its record and content
// evidence are both verified. The returned descriptor is read-only.
func (p *Provider) OpenOCI(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (io.ReadCloser, contracts.StoreOCIResult, error) {
	if err := p.check(ctx, operation, contracts.CapabilityImageOpenOCI, openAction); err != nil {
		return nil, contracts.StoreOCIResult{}, err
	}
	if err := validateImage(image); err != nil {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrValidation, "image digest is invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLayout(); err != nil {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrUnavailable, "OCI archive store is unavailable", err)
	}
	archivePath, recordPath, err := p.paths(image)
	if err != nil {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrValidation, "image storage path is invalid", nil)
	}
	record, err := p.readRecord(recordPath, archivePath, image)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrNotFound, "OCI archive was not found", nil)
	}
	if err != nil {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrUnavailable, "OCI archive evidence could not be verified", err)
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, contracts.StoreOCIResult{}, p.failure(operation, contracts.CapabilityImageOpenOCI, openAction, contracts.ErrUnavailable, "OCI archive could not be opened", err)
	}
	return file, p.result(operation, record), nil
}

// Pull is a local availability check, not a registry pull. Its image must have
// already been stored by digest, so it cannot observe a mutable tag changing.
func (p *Provider) Pull(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) (contracts.Evidence, error) {
	file, result, err := p.OpenOCI(ctx, image, operation)
	if err != nil {
		return contracts.Evidence{}, err
	}
	if err := file.Close(); err != nil {
		return contracts.Evidence{}, p.failure(operation, contracts.CapabilityImagePull, pullAction, contracts.ErrUnavailable, "OCI archive could not be closed", err)
	}
	return result.Evidence, nil
}

// Retain protects a stored archive from deletion until an explicit admin
// lifecycle action clears it with SetRetained. It is intentionally idempotent.
func (p *Provider) Retain(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	return p.setProtection(ctx, image, operation, retainAction, func(record *storedRecord) { record.Retained = true })
}

// SetRetained is an explicit lifecycle hook for a controller that has proven a
// retained release is no longer required.
func (p *Provider) SetRetained(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext, retained bool) error {
	return p.setProtection(ctx, image, operation, retainAction, func(record *storedRecord) { record.Retained = retained })
}

// SetRunning protects or releases a runtime reference. It is separate from
// Retain so a stopped current version cannot be deleted until its rollback
// reference has also been released.
func (p *Provider) SetRunning(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext, running bool) error {
	return p.setProtection(ctx, image, operation, "set_running", func(record *storedRecord) { record.Running = running })
}

// SetRollback protects or releases a rollback reference.
func (p *Provider) SetRollback(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext, rollback bool) error {
	return p.setProtection(ctx, image, operation, "set_rollback", func(record *storedRecord) { record.Rollback = rollback })
}

func (p *Provider) setProtection(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext, action string, mutate func(*storedRecord)) error {
	if err := p.check(ctx, operation, contracts.CapabilityImageRetain, action); err != nil {
		return err
	}
	if err := validateImage(image); err != nil {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrValidation, "image digest is invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLayout(); err != nil {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrUnavailable, "OCI archive store is unavailable", err)
	}
	archivePath, recordPath, err := p.paths(image)
	if err != nil {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrValidation, "image storage path is invalid", nil)
	}
	unlock, err := acquireImageLock(ctx, operation, archivePath+".lock")
	if err != nil {
		return p.classify(operation, contracts.CapabilityImageRetain, action, err)
	}
	defer unlock()
	record, err := p.readRecord(recordPath, archivePath, image)
	if errors.Is(err, fs.ErrNotExist) {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrNotFound, "OCI archive was not found", nil)
	}
	if err != nil {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrUnavailable, "OCI archive evidence could not be verified", err)
	}
	mutate(&record)
	if err := writeRecord(recordPath, record); err != nil {
		return p.failure(operation, contracts.CapabilityImageRetain, action, contracts.ErrUnavailable, "OCI archive metadata could not be published", err)
	}
	return nil
}

// Delete removes only an existing archive with verified metadata and no live
// retain/running/rollback reference. Any uncertainty fails closed.
func (p *Provider) Delete(ctx context.Context, image domain.ImageDigest, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, contracts.CapabilityImageDelete, deleteAction); err != nil {
		return err
	}
	if err := validateImage(image); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrValidation, "image digest is invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLayout(); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive store is unavailable", err)
	}
	archivePath, recordPath, err := p.paths(image)
	if err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrValidation, "image storage path is invalid", nil)
	}
	unlock, err := acquireImageLock(ctx, operation, archivePath+".lock")
	if err != nil {
		return p.classify(operation, contracts.CapabilityImageDelete, deleteAction, err)
	}
	defer unlock()
	record, err := p.readRecord(recordPath, archivePath, image)
	if errors.Is(err, fs.ErrNotExist) {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrNotFound, "OCI archive was not found", nil)
	}
	if err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive evidence could not be verified", err)
	}
	if record.Retained || record.Running || record.Rollback {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrConflict, "OCI archive has a retained, running, or rollback reference", nil)
	}
	if err := os.Remove(archivePath); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive could not be deleted", err)
	}
	if err := syncDirectory(filepath.Dir(archivePath)); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive deletion could not be synced", err)
	}
	if err := os.Remove(recordPath); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive metadata could not be deleted", err)
	}
	if err := syncDirectory(filepath.Dir(recordPath)); err != nil {
		return p.failure(operation, contracts.CapabilityImageDelete, deleteAction, contracts.ErrUnavailable, "OCI archive metadata deletion could not be synced", err)
	}
	return nil
}

func (p *Provider) paths(image domain.ImageDigest) (string, string, error) {
	if err := validateImage(image); err != nil {
		return "", "", err
	}
	repositoryHash := digestString(image.Repository)
	digest := strings.TrimPrefix(image.Digest, "sha256:")
	archiveDir := filepath.Join(p.root, "archives", repositoryHash)
	recordDir := filepath.Join(p.root, "records", repositoryHash)
	if err := ensureSecureDir(p.root, archiveDir); err != nil {
		return "", "", err
	}
	if err := ensureSecureDir(p.root, recordDir); err != nil {
		return "", "", err
	}
	return filepath.Join(archiveDir, digest+".oci"), filepath.Join(recordDir, digest+".json"), nil
}

func (p *Provider) ensureLayout() error {
	if err := ensureSecureDir(p.root, p.root); err != nil {
		return err
	}
	for _, name := range []string{"archives", "records"} {
		if err := ensureSecureDir(p.root, filepath.Join(p.root, name)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) copyTemporary(ctx context.Context, operation contracts.OperationContext, final string, reader io.Reader) (string, string, int64, error) {
	temporary, err := os.CreateTemp(filepath.Dir(final), ".oci-stage-")
	if err != nil {
		return "", "", 0, err
	}
	name := temporary.Name()
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, hash), contextReader{ctx: ctx, operation: operation, reader: reader})
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(name)
		return "", "", 0, copyErr
	}
	return name, "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

type contextReader struct {
	ctx       context.Context
	operation contracts.OperationContext
	reader    io.Reader
}

func (r contextReader) Read(value []byte) (int, error) {
	if err := contextError(r.ctx, r.operation); err != nil {
		return 0, err
	}
	return r.reader.Read(value)
}

func (p *Provider) readRecord(recordPath, archivePath string, expected domain.ImageDigest) (storedRecord, error) {
	if err := rejectSymlink(recordPath); err != nil {
		return storedRecord{}, err
	}
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return storedRecord{}, err
	}
	var record storedRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return storedRecord{}, fmt.Errorf("decode record: %w", err)
	}
	if err := validateRecord(record, expected); err != nil {
		return storedRecord{}, err
	}
	if err := rejectSymlink(archivePath); err != nil {
		return storedRecord{}, err
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return storedRecord{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return storedRecord{}, errors.New("archive is not a sealed regular file")
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return storedRecord{}, err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return storedRecord{}, copyErr
	}
	if closeErr != nil {
		return storedRecord{}, closeErr
	}
	if size != record.SizeBytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != record.ContentDigest {
		return storedRecord{}, errors.New("archive content does not match stored evidence")
	}
	return record, nil
}

func writeRecord(path string, record storedRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".record-stage-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (p *Provider) result(operation contracts.OperationContext, record storedRecord) contracts.StoreOCIResult {
	id := domain.ID("ev_" + digestString(providerName, operation.IdempotencyKey, record.Image.Repository, record.Image.Digest, record.ContentDigest)[:32])
	return contracts.StoreOCIResult{
		Image: cleanImage(record.Image), StorageRef: record.StorageRef, SizeBytes: record.SizeBytes,
		Evidence: contracts.Evidence{
			Refs:    []domain.EvidenceRef{{ID: id, Kind: "image.oci_store", Digest: record.ContentDigest, Locator: "oci://evidence/" + id.String()}},
			Summary: "immutable OCI archive stored", Digest: record.ContentDigest, Redacted: true,
		},
	}
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if err := p.metadata.Supports(capability); err != nil {
		return p.failure(operation, capability, action, contracts.ErrUnsupportedCapability, "provider capability is not enabled", nil)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, capability, action, contracts.ErrInvalidArgument, "provider idempotency key is required", err)
	}
	if err := contextError(ctx, operation); err != nil {
		return p.classify(operation, capability, action, err)
	}
	return nil
}

func (p *Provider) classify(operation contracts.OperationContext, capability contracts.Capability, action string, err error) error {
	if errors.Is(err, context.Canceled) {
		return p.failure(operation, capability, action, contracts.ErrCancelled, "provider operation was cancelled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(operation, capability, action, contracts.ErrTimeout, "provider operation timed out", err)
	}
	return p.failure(operation, capability, action, contracts.ErrUnavailable, "OCI archive store is unavailable", err)
}

func (p *Provider) failure(operation contracts.OperationContext, capability contracts.Capability, action string, code contracts.ErrorCode, message string, cause error) *contracts.ProviderError {
	retry, retryable := contracts.RetryNever, false
	if code == contracts.ErrUnavailable || code == contracts.ErrTimeout {
		retry, retryable = contracts.RetryBackoff, true
	}
	if code == contracts.ErrCancelled {
		retry, retryable = contracts.RetryAfterReconnect, true
	}
	return &contracts.ProviderError{Provider: providerName, Code: code, Message: message, Retry: retry, Retryable: retryable, Capability: capability, Operation: action, Cause: cause,
		Details: map[string]string{"evidence_ref": "ev_" + digestString(operation.IdempotencyKey)[:32]}}
}

func absoluteRoot(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("OCI store root is required")
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("OCI store root must be a non-symlink directory")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return path, nil
}

func ensureSecureDir(root, path string) error {
	if rel, err := filepath.Rel(root, path); err != nil || (rel != "." && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel))) {
		return errors.New("path escapes OCI store root")
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("OCI store directory is not a non-symlink directory")
		}
		if info.Mode().Perm() != 0o750 {
			if err := os.Chmod(current, 0o750); err != nil {
				return err
			}
		}
		if current == root {
			return nil
		}
	}
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return errors.New("OCI store path is a symlink")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// acquireImageLock is an inter-process publication lock. An abandoned lock is
// intentionally not broken automatically: treating an interrupted publish as
// available could overwrite bytes for an immutable digest. The caller receives
// an unavailable/timeout result and a human can inspect the store safely.
func acquireImageLock(ctx context.Context, operation contracts.OperationContext, path string) (func(), error) {
	started := time.Now()
	for {
		if err := contextError(ctx, operation); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if syncErr := file.Sync(); syncErr != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, syncErr
			}
			if closeErr := file.Close(); closeErr != nil {
				_ = os.Remove(path)
				return nil, closeErr
			}
			if err := syncDirectory(filepath.Dir(path)); err != nil {
				_ = os.Remove(path)
				return nil, err
			}
			return func() {
				_ = os.Remove(path)
				_ = syncDirectory(filepath.Dir(path))
			}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if time.Since(started) >= time.Second {
			return nil, errArchiveLocked
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("OCI archive lock is unsafe")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func validateImage(image domain.ImageDigest) error {
	if strings.TrimSpace(image.Repository) != image.Repository || strings.TrimSpace(image.Digest) != image.Digest || strings.TrimSpace(image.ResolvedTag) != image.ResolvedTag || image.Repository == "" {
		return errors.New("image reference is not exact and immutable")
	}
	for index, part := range strings.Split(image.Repository, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `\\@?#`) {
			return errors.New("image repository is unsafe")
		}
		if index == 0 && strings.Count(part, ":") == 1 {
			host, port, ok := strings.Cut(part, ":")
			if !ok || !repositoryPart.MatchString(host) || port == "" || strings.Trim(port, "0123456789") != "" {
				return errors.New("image repository is unsafe")
			}
			continue
		}
		if !repositoryPart.MatchString(part) {
			return errors.New("image repository is unsafe")
		}
	}
	if err := image.Validate(); err != nil || image.Digest != strings.ToLower(image.Digest) {
		return errors.New("image digest is unsafe")
	}
	if image.ResolvedTag != "" && !tagPattern.MatchString(image.ResolvedTag) {
		return errors.New("image tag annotation is unsafe")
	}
	return nil
}

func validStorageKey(value string) bool {
	if strings.TrimSpace(value) != value || value == "" || len(value) > 512 || filepath.IsAbs(value) || strings.Contains(value, `\\`) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !storageKeyPart.MatchString(part) || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateRecord(record storedRecord, expected domain.ImageDigest) error {
	if err := validateImage(record.Image); err != nil {
		return err
	}
	if cleanImage(record.Image) != cleanImage(expected) || record.StorageRef != storageRef(expected) || record.SizeBytes < 0 || !validSHA256(record.ContentDigest) {
		return errors.New("OCI archive metadata is invalid")
	}
	return nil
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func cleanImage(image domain.ImageDigest) domain.ImageDigest {
	return domain.ImageDigest{Repository: image.Repository, Digest: image.Digest}
}

func storageRef(image domain.ImageDigest) string {
	return "oci/" + digestString(image.Repository) + "/" + strings.TrimPrefix(image.Digest, "sha256:") + ".oci"
}

func imageFingerprint(image domain.ImageDigest, ref, storageKey string) string {
	return digestString(image.Repository, image.Digest, ref, storageKey)
}

func digestString(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, value)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func cloneStoreResult(result contracts.StoreOCIResult) contracts.StoreOCIResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	return result
}

func contextError(ctx context.Context, operation contracts.OperationContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

var _ contracts.ImageStore = (*Provider)(nil)
