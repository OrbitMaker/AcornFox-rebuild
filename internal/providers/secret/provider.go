// Package secret implements the local, file-backed SecretProvider used by the
// control plane. Secret values are encrypted at rest and are only
// materialized as short-lived, owner-readable files for a build operation.
//
// The package deliberately keeps the three filesystem boundaries explicit:
// Root contains encrypted records and non-secret metadata, MaterialRoot
// contains temporary plaintext materializations, and MasterKeyPath contains
// the 32-byte AES key. None of these paths can be selected by a request.
package secret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "filesystem-secret"
	providerVersion = "m1"

	// DefaultMaterialTTL intentionally remains short. Callers may choose a
	// shorter value, but never a value longer than MaxMaterialTTL.
	DefaultMaterialTTL = 5 * time.Minute
	MaxMaterialTTL     = 24 * time.Hour

	maxSecretBytes   = 1 << 20
	maxMetadataBytes = 64 << 10

	secretRecordVersion   = 1
	materialRecordVersion = 1
	secretMagic           = "OCS1"
	secretNonceSize       = 12 // aes.GCM standard nonce size
)

var (
	// These errors are internal sentinels. They are never returned directly:
	// providerError below deliberately removes filesystem paths and causes from
	// the user-visible error string/JSON.
	errSecretNotFound = errors.New("secret record not found")
	errUnsafePath     = errors.New("secret provider path is unsafe")
	errMetadata       = errors.New("secret metadata is invalid")
	errConflict       = errors.New("secret operation conflicts with an existing operation")
	errMaterialGone   = errors.New("secret materialization is no longer available")

	componentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}$`)
	hashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	materialPattern  = regexp.MustCompile(`^mount_[0-9a-f]{48}$`)
)

// Config declares provider-owned storage boundaries. Root and MaterialRoot
// are created as owner-only directories when absent. MasterKeyPath is created
// with a random 32-byte key when absent and must remain an owner-only regular
// file thereafter.
type Config struct {
	Root          string
	MaterialRoot  string
	MasterKeyPath string

	// MaterialTTL is preferred. TTL is retained as a concise compatibility
	// spelling for composition roots that already use it.
	MaterialTTL time.Duration
	TTL         time.Duration
	Clock       func() time.Time
}

// Provider implements both contracts.SecretProvider and
// contracts.BuildSecretResolver. It serializes operations so retries and
// publication cannot race, while the persisted operation digests allow
// idempotent Store/Resolve retries after a process restart.
type Provider struct {
	metadata contracts.ProviderMetadata

	root          string
	vaultRoot     string
	metadataRoot  string
	materialRoot  string
	masterKeyPath string
	masterKey     [32]byte
	ttl           time.Duration
	clock         func() time.Time
	existingOnly  bool

	mu sync.Mutex

	storeOps   map[string]operationRecord
	resolveOps map[string]operationRecord
	revokeOps  map[string]operationRecord
}

type operationRecord struct {
	fingerprint string
	ref         domain.SecretReference
	material    contracts.BuildSecretMaterial
}

// secretMetadata contains only identifiers and cryptographic digests. In
// particular, it has no plaintext, key bytes, or raw operation key.
type secretMetadata struct {
	Version              int               `json:"version"`
	Reference            referenceMetadata `json:"reference"`
	ReferenceDigest      string            `json:"reference_digest"`
	PlaintextDigest      string            `json:"plaintext_digest"`
	CiphertextDigest     string            `json:"ciphertext_digest"`
	OperationDigest      string            `json:"operation_digest"`
	OperationFingerprint string            `json:"operation_fingerprint"`
}

type referenceMetadata struct {
	ID       domain.ID `json:"id"`
	Name     string    `json:"name"`
	Provider string    `json:"provider"`
	Version  string    `json:"version,omitempty"`
}

type materialMetadata struct {
	Version              int       `json:"version"`
	MountID              string    `json:"mount_id"`
	ReferenceDigest      string    `json:"reference_digest"`
	OperationDigest      string    `json:"operation_digest"`
	OperationFingerprint string    `json:"operation_fingerprint"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// New constructs a provider, verifies all boundaries, initializes the master
// key if needed, and removes stale materializations left by an interrupted
// process. No request-controlled path is ever used for filesystem access.
func New(config Config) (*Provider, error) {
	return newProvider(config, false)
}

// OpenExisting opens an already provisioned provider without creating a
// directory or master key and without stage/material recovery. It is for
// consumers that must not mutate secret storage merely by starting up.
func OpenExisting(config Config) (*Provider, error) {
	return newProvider(config, true)
}

func newProvider(config Config, existingOnly bool) (*Provider, error) {
	normalize := normalizeDirectory
	loadKey := loadOrCreateMasterKey
	if existingOnly {
		normalize = normalizeExistingDirectory
		loadKey = loadExistingMasterKey
	}
	root, err := normalize(config.Root, "secret root")
	if err != nil {
		return nil, err
	}
	materialRoot, err := normalize(config.MaterialRoot, "secret material root")
	if err != nil {
		return nil, err
	}
	if samePath(root, materialRoot) {
		return nil, errors.New("secret root and material root must be separate directories")
	}
	ttl := config.MaterialTTL
	if ttl == 0 {
		ttl = config.TTL
	}
	if ttl == 0 {
		ttl = DefaultMaterialTTL
	}
	if ttl <= 0 || ttl > MaxMaterialTTL {
		return nil, errors.New("secret material TTL is outside the allowed range")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	keyPath, key, err := loadKey(config.MasterKeyPath)
	if err != nil {
		return nil, err
	}
	p := &Provider{
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities: contracts.NewCapabilitySet(
				contracts.CapabilitySecretManage,
				contracts.CapabilitySecretResolve,
			),
			SensitiveInputs: []string{"secret.value", "master_key", "build_secret.material"},
		},
		root: root, vaultRoot: filepath.Join(root, "vault"), metadataRoot: filepath.Join(root, "metadata"),
		materialRoot: materialRoot, masterKeyPath: keyPath, masterKey: key, ttl: ttl, clock: clock, existingOnly: existingOnly,
		storeOps: make(map[string]operationRecord), resolveOps: make(map[string]operationRecord), revokeOps: make(map[string]operationRecord),
	}
	if existingOnly {
		if err := p.validateExistingLayout(); err != nil {
			return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretManage, "open", contracts.ErrUnavailable, "secret provider storage is unavailable", err)
		}
	} else if err := p.ensureLayout(); err != nil {
		return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretManage, "initialize", contracts.ErrUnavailable, "secret provider storage is unavailable", err)
	}
	if !existingOnly {
		if err := p.recoverSecretStages(); err != nil {
			return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretManage, "recover", contracts.ErrUnavailable, "secret stage recovery failed", err)
		}
		if err := p.recoverMaterials(); err != nil {
			return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretResolve, "recover", contracts.ErrUnavailable, "secret material recovery failed", err)
		}
	}
	if err := p.loadOperationIndexes(); err != nil {
		return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretManage, "recover", contracts.ErrUnavailable, "secret operation recovery failed", err)
	}
	if err := p.loadMaterialOperationIndexes(); err != nil {
		return nil, p.failure(contracts.OperationContext{}, contracts.CapabilitySecretResolve, "recover", contracts.ErrUnavailable, "secret material operation recovery failed", err)
	}
	return p, nil
}

// NewProvider is an explicit composition-root alias.
func NewProvider(config Config) (*Provider, error) { return New(config) }

// Metadata reports the stable provider contract and intentionally omits all
// configured paths and key material.
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// String and GoString keep accidental diagnostic formatting from dumping the
// provider's unexported master-key array or configured filesystem boundaries.
func (p *Provider) String() string   { return providerName }
func (p *Provider) GoString() string { return providerName + "{}" }

// Store encrypts a secret and returns only its reference. The caller's Value
// is never copied into a durable provider object; the short-lived encryption
// copy is zeroed on every exit path.
func (p *Provider) Store(ctx context.Context, request contracts.SecretRequest) (domain.SecretReference, error) {
	if err := p.check(ctx, request.Operation, contracts.CapabilitySecretManage, "store"); err != nil {
		return domain.SecretReference{}, err
	}
	if err := validateReference(request.Reference); err != nil {
		return domain.SecretReference{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "store", contracts.ErrValidation, "secret reference is invalid", err)
	}
	if len(request.Value) == 0 || len(request.Value) > maxSecretBytes {
		return domain.SecretReference{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "store", contracts.ErrInvalidArgument, "secret value is invalid", nil)
	}
	plainDigest := digestBytes(request.Value)
	refDigest := referenceDigest(request.Reference)
	fingerprint := digestStrings("store", refDigest, plainDigest)
	opDigest := digestStrings(request.Operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.storeOps[opDigest]; ok {
		if previous.fingerprint != fingerprint {
			return domain.SecretReference{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "store", contracts.ErrConflict, "secret operation idempotency key was reused for different input", errConflict)
		}
		return previous.ref, nil
	}

	plaintext, metadata, err := p.readSecret(request.Reference)
	if err == nil {
		zeroBytes(plaintext)
		if metadata.PlaintextDigest != plainDigest {
			return domain.SecretReference{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "store", contracts.ErrConflict, "secret reference already contains different content", errConflict)
		}
		// Existing immutable records are accepted for retries with a new
		// operation key, but only after both files have been validated.
		p.storeOps[opDigest] = operationRecord{fingerprint: fingerprint, ref: request.Reference}
		return request.Reference, nil
	}
	if !errors.Is(err, errSecretNotFound) {
		return domain.SecretReference{}, p.classify(request.Operation, contracts.CapabilitySecretManage, "store", err)
	}

	if err := p.publishSecret(request.Reference, request.Value, plainDigest, opDigest, fingerprint); err != nil {
		if errors.Is(err, errConflict) {
			return domain.SecretReference{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "store", contracts.ErrConflict, "secret reference already contains different content", err)
		}
		return domain.SecretReference{}, p.classify(request.Operation, contracts.CapabilitySecretManage, "store", err)
	}
	p.storeOps[opDigest] = operationRecord{fingerprint: fingerprint, ref: request.Reference}
	return request.Reference, nil
}

// Mount materializes a stored secret for the caller's operation and returns a
// reference-only handle. The file path is intentionally absent from
// contracts.SecretMount; BuildSecretResolver callers receive it through the
// separate, non-JSON Path field.
func (p *Provider) Mount(ctx context.Context, request contracts.SecretRequest) (contracts.SecretMount, error) {
	if edgeCaddyObservationReference(request.Reference) {
		return contracts.SecretMount{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "mount", contracts.ErrForbidden, "edge certificate observations are not secrets", nil)
	}
	if len(request.Value) != 0 {
		return contracts.SecretMount{}, p.failure(request.Operation, contracts.CapabilitySecretManage, "mount", contracts.ErrInvalidArgument, "mount does not accept plaintext secret input", nil)
	}
	material, err := p.ResolveBuildSecret(ctx, request.Reference, request.Operation)
	if err != nil {
		return contracts.SecretMount{}, err
	}
	return contracts.SecretMount{MountID: material.MountID, Reference: material.Reference, ExpiresAt: material.ExpiresAt}, nil
}

// Revoke removes a materialization. It is idempotent when the materialization
// has already expired or been removed, but rejects an unsafe or mismatched
// handle before touching any path.
func (p *Provider) Revoke(ctx context.Context, mount contracts.SecretMount, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, contracts.CapabilitySecretManage, "revoke"); err != nil {
		return err
	}
	if err := validateMount(mount); err != nil {
		return p.failure(operation, contracts.CapabilitySecretManage, "revoke", contracts.ErrValidation, "secret mount is invalid", err)
	}
	fingerprint := digestStrings("revoke", mount.MountID, referenceDigest(mount.Reference))
	opDigest := digestStrings(operation.IdempotencyKey)
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.revokeOps[opDigest]; ok {
		if previous.fingerprint != fingerprint {
			return p.failure(operation, contracts.CapabilitySecretManage, "revoke", contracts.ErrConflict, "secret revoke idempotency key was reused for different input", errConflict)
		}
		return nil
	}
	if err := p.removeMaterialization(mount.MountID, "", referenceDigest(mount.Reference)); err != nil {
		return p.classify(operation, contracts.CapabilitySecretManage, "revoke", err)
	}
	p.revokeOps[opDigest] = operationRecord{fingerprint: fingerprint}
	return nil
}

// ResolveBuildSecret decrypts a stored record into a short-lived 0400 file
// under MaterialRoot. The returned Path is deliberately excluded from JSON.
func (p *Provider) ResolveBuildSecret(ctx context.Context, reference domain.SecretReference, operation contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	if edgeCaddyObservationReference(reference) {
		return contracts.BuildSecretMaterial{}, p.failure(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", contracts.ErrForbidden, "edge certificate observations are not secrets", nil)
	}
	if err := p.check(ctx, operation, contracts.CapabilitySecretResolve, "resolve_build_secret"); err != nil {
		return contracts.BuildSecretMaterial{}, err
	}
	if err := validateReference(reference); err != nil {
		return contracts.BuildSecretMaterial{}, p.failure(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", contracts.ErrValidation, "secret reference is invalid", err)
	}
	refDigest := referenceDigest(reference)
	fingerprint := digestStrings("resolve", refDigest)
	opDigest := digestStrings(operation.IdempotencyKey)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.cleanupExpiredLocked(); err != nil {
		return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
	}
	if previous, ok := p.resolveOps[opDigest]; ok {
		if previous.fingerprint != fingerprint {
			return contracts.BuildSecretMaterial{}, p.failure(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", contracts.ErrConflict, "secret resolve idempotency key was reused for different input", errConflict)
		}
		if material, err := p.verifyMaterial(previous.material, refDigest, opDigest, fingerprint); err == nil {
			material.Reference = reference
			return material, nil
		} else if !errors.Is(err, errMaterialGone) {
			return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
		}
		delete(p.resolveOps, opDigest)
	}

	plaintext, _, err := p.readSecret(reference)
	if err != nil {
		return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
	}
	defer zeroBytes(plaintext)
	if err := contextError(ctx, operation); err != nil {
		return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
	}
	mountID := "mount_" + digestStrings(refDigest, opDigest)[:48]
	expiresAt := p.now().Add(p.ttl).UTC()
	material := contracts.BuildSecretMaterial{MountID: mountID, Reference: reference, Path: p.materialPath(mountID), ExpiresAt: expiresAt}
	if existing, err := p.readMaterialMetadata(mountID); err == nil {
		if existing.ReferenceDigest != refDigest || existing.OperationDigest != opDigest || existing.OperationFingerprint != fingerprint {
			return contracts.BuildSecretMaterial{}, p.failure(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", contracts.ErrConflict, "materialization handle conflicts with existing state", errConflict)
		}
		if !existing.ExpiresAt.After(p.now()) {
			if err := p.removeMaterialization(mountID, "", ""); err != nil {
				return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
			}
		} else {
			material.ExpiresAt = existing.ExpiresAt
			if err := p.verifyMaterialFile(material, refDigest, opDigest, fingerprint); err != nil {
				return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
			}
			p.resolveOps[opDigest] = operationRecord{fingerprint: fingerprint, ref: reference, material: material}
			return material, nil
		}
	} else if !errors.Is(err, errSecretNotFound) {
		return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
	}

	if err := p.publishMaterial(material, plaintext, refDigest, opDigest, fingerprint); err != nil {
		return contracts.BuildSecretMaterial{}, p.classify(operation, contracts.CapabilitySecretResolve, "resolve_build_secret", err)
	}
	p.resolveOps[opDigest] = operationRecord{fingerprint: fingerprint, ref: reference, material: material}
	return material, nil
}

func edgeCaddyObservationReference(reference domain.SecretReference) bool {
	return strings.HasPrefix(reference.ID.String(), "edge-caddy-observation:")
}

// RevokeBuildSecret is the path-aware counterpart of Revoke. A supplied Path
// must exactly equal the deterministic path for MountID and remain below the
// configured MaterialRoot.
func (p *Provider) RevokeBuildSecret(ctx context.Context, material contracts.BuildSecretMaterial, operation contracts.OperationContext) error {
	if err := p.check(ctx, operation, contracts.CapabilitySecretResolve, "revoke_build_secret"); err != nil {
		return err
	}
	if err := validateBuildMaterial(material); err != nil {
		return p.failure(operation, contracts.CapabilitySecretResolve, "revoke_build_secret", contracts.ErrValidation, "build secret material is invalid", err)
	}
	fingerprint := digestStrings("revoke_build", material.MountID, referenceDigest(material.Reference))
	opDigest := digestStrings(operation.IdempotencyKey)
	if err := p.lockForRevoke(ctx, operation); err != nil {
		return p.classify(operation, contracts.CapabilitySecretResolve, "revoke_build_secret", err)
	}
	defer p.mu.Unlock()
	if previous, ok := p.revokeOps[opDigest]; ok {
		if previous.fingerprint != fingerprint {
			return p.failure(operation, contracts.CapabilitySecretResolve, "revoke_build_secret", contracts.ErrConflict, "secret revoke idempotency key was reused for different input", errConflict)
		}
		return nil
	}
	if err := p.removeMaterialization(material.MountID, material.Path, referenceDigest(material.Reference)); err != nil {
		return p.classify(operation, contracts.CapabilitySecretResolve, "revoke_build_secret", err)
	}
	delete(p.resolveOps, opDigest)
	p.revokeOps[opDigest] = operationRecord{fingerprint: fingerprint}
	return nil
}

// lockForRevoke keeps a cleanup caller from waiting indefinitely behind an
// unrelated secret operation. It rechecks context and operation deadlines both
// before and after TryLock, so an expired revoke never enters the critical
// section merely because the mutex became available concurrently.
func (p *Provider) lockForRevoke(ctx context.Context, operation contracts.OperationContext) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := contextError(ctx, operation); err != nil {
			return err
		}
		if p.mu.TryLock() {
			if err := contextError(ctx, operation); err != nil {
				p.mu.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// CleanupExpiredMaterializations is useful for a supervisor that wants an
// explicit periodic cleanup in addition to New's startup recovery.
func (p *Provider) CleanupExpiredMaterializations() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cleanupExpiredLocked()
}

// Close zeroes the in-memory master key. It is optional, but lets a graceful
// process shutdown reduce the lifetime of key bytes held by this provider.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	zeroBytes(p.masterKey[:])
	return nil
}

func (p *Provider) ensureLayout() error {
	if err := ensureSecureDirectory(p.root, false); err != nil {
		return err
	}
	if err := ensureChildDirectory(p.root, p.vaultRoot); err != nil {
		return err
	}
	if err := ensureChildDirectory(p.root, p.metadataRoot); err != nil {
		return err
	}
	if err := ensureSecureDirectory(p.materialRoot, false); err != nil {
		return err
	}
	return nil
}

func (p *Provider) validateExistingLayout() error {
	if err := ensureSecureDirectory(p.root, false); err != nil {
		return err
	}
	for _, path := range []string{p.vaultRoot, p.metadataRoot} {
		if err := ensureExistingChildDirectory(p.root, path); err != nil {
			return err
		}
	}
	if err := ensureSecureDirectory(p.materialRoot, false); err != nil {
		return err
	}
	if err := p.validateExistingMasterKey(); err != nil {
		return err
	}
	return p.validateExistingFiles()
}

func (p *Provider) validateExistingMasterKey() error {
	path, key, err := loadExistingMasterKey(p.masterKeyPath)
	defer zeroBytes(key[:])
	if err != nil || path != p.masterKeyPath || subtle.ConstantTimeCompare(key[:], p.masterKey[:]) != 1 {
		return errUnsafePath
	}
	return nil
}

func (p *Provider) validateExistingFiles() error {
	vault, err := existingProviderFiles(p.vaultRoot, ".enc")
	if err != nil {
		return err
	}
	metadata, err := existingProviderFiles(p.metadataRoot, ".json")
	if err != nil || !sameExistingProviderFiles(vault, metadata) {
		return errUnsafePath
	}
	for name := range vault {
		if !hashPattern.MatchString(name) {
			return errUnsafePath
		}
	}
	secrets, err := existingProviderFiles(p.materialRoot, ".secret", ".json")
	if err != nil {
		return err
	}
	materials, err := existingProviderFiles(p.materialRoot, ".json", ".secret")
	if err != nil || !sameExistingProviderFiles(secrets, materials) {
		return errUnsafePath
	}
	for name := range secrets {
		if !materialPattern.MatchString(name) {
			return errUnsafePath
		}
	}
	return nil
}

func existingProviderFiles(directory, suffix string, allowedOther ...string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, suffix) {
			allowed := false
			for _, other := range allowedOther {
				if strings.HasSuffix(name, other) {
					allowed = true
					break
				}
			}
			if allowed {
				continue
			}
			return nil, errUnsafePath
		}
		base := strings.TrimSuffix(name, suffix)
		if !hashPattern.MatchString(base) && !materialPattern.MatchString(base) {
			return nil, errUnsafePath
		}
		if _, err := securePathState(filepath.Join(directory, name)); err != nil {
			return nil, err
		}
		if _, exists := files[base]; exists {
			return nil, errUnsafePath
		}
		files[base] = struct{}{}
	}
	return files, nil
}

func sameExistingProviderFiles(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for name := range left {
		if _, exists := right[name]; !exists {
			return false
		}
	}
	return true
}

func (p *Provider) publishSecret(reference domain.SecretReference, value []byte, plainDigest, opDigest, fingerprint string) error {
	block, err := aes.NewCipher(p.masterKey[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, secretNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := []byte("open-card-secret-v1:" + referenceDigest(reference))
	ciphertext := aead.Seal(nil, nonce, value, aad)
	blob := make([]byte, 0, len(secretMagic)+len(nonce)+len(ciphertext))
	blob = append(blob, secretMagic...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	zeroBytes(nonce)
	defer zeroBytes(ciphertext)
	defer zeroBytes(blob)

	key := referenceDigest(reference)
	encPath := filepath.Join(p.vaultRoot, key+".enc")
	metaPath := filepath.Join(p.metadataRoot, key+".json")
	metadata := secretMetadata{
		Version: secretRecordVersion, Reference: referenceMetadataFrom(reference), ReferenceDigest: key,
		PlaintextDigest: plainDigest, CiphertextDigest: digestBytes(blob), OperationDigest: opDigest, OperationFingerprint: fingerprint,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return errMetadata
	}

	// An existing pair is immutable. Never overwrite it, even if a caller
	// retries with a different operation key.
	_, encErr := securePathState(encPath)
	_, metaErr := securePathState(metaPath)
	if encErr == nil || metaErr == nil {
		if encErr != nil || metaErr != nil {
			return errMetadata
		}
		plaintext, existing, err := p.readSecret(reference)
		if err != nil {
			return err
		}
		zeroBytes(plaintext)
		if existing.PlaintextDigest != plainDigest {
			return errConflict
		}
		return nil
	}
	if !errors.Is(encErr, errSecretNotFound) || !errors.Is(metaErr, errSecretNotFound) {
		return errors.Join(encErr, metaErr)
	}

	encTemp, err := writeStagedFile(filepath.Dir(encPath), ".secret-stage-", blob, 0o600)
	if err != nil {
		return err
	}
	metaTemp, err := writeStagedFile(filepath.Dir(metaPath), ".metadata-stage-", metadataJSON, 0o600)
	if err != nil {
		_ = os.Remove(encTemp)
		_ = syncDirectory(filepath.Dir(encPath))
		return err
	}
	cleanup := true
	encRenamed, metaRenamed := false, false
	defer func() {
		if cleanup {
			if metaRenamed {
				_ = secureRemoveFile(metaPath)
			}
			if encRenamed {
				_ = secureRemoveFile(encPath)
			}
			_ = os.Remove(encTemp)
			_ = os.Remove(metaTemp)
			_ = syncDirectory(filepath.Dir(encPath))
			_ = syncDirectory(filepath.Dir(metaPath))
		}
	}()
	if err := rejectExistingPath(encPath); err != nil {
		return err
	}
	if err := rejectExistingPath(metaPath); err != nil {
		return err
	}
	if err := publishNoReplace(encTemp, encPath); err != nil {
		return err
	}
	encRenamed = true
	if err := syncDirectory(filepath.Dir(encPath)); err != nil {
		return err
	}
	if err := publishNoReplace(metaTemp, metaPath); err != nil {
		return err
	}
	metaRenamed = true
	if err := syncDirectory(filepath.Dir(metaPath)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (p *Provider) publishMaterial(material contracts.BuildSecretMaterial, plaintext []byte, refDigest, opDigest, fingerprint string) error {
	if len(plaintext) == 0 || len(plaintext) > maxSecretBytes {
		return errors.New("materialized secret is invalid")
	}
	if err := validateMaterialPath(p.materialRoot, material.MountID, material.Path); err != nil {
		return err
	}
	metadata := materialMetadata{Version: materialRecordVersion, MountID: material.MountID, ReferenceDigest: refDigest, OperationDigest: opDigest, OperationFingerprint: fingerprint, ExpiresAt: material.ExpiresAt.UTC()}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return errMetadata
	}
	path := material.Path
	metaPath := materialMetadataPath(material.Path)
	_, materialErr := securePathState(path)
	_, metaErr := securePathState(metaPath)
	if materialErr == nil || metaErr == nil {
		if materialErr != nil || metaErr != nil {
			return errMetadata
		}
		existing, err := p.readMaterialMetadata(material.MountID)
		if err != nil {
			return err
		}
		if existing.ReferenceDigest != refDigest || existing.OperationDigest != opDigest || existing.OperationFingerprint != fingerprint {
			return errConflict
		}
		return p.verifyMaterialFile(material, refDigest, opDigest, fingerprint)
	}
	if !errors.Is(materialErr, errSecretNotFound) || !errors.Is(metaErr, errSecretNotFound) {
		return errors.Join(materialErr, metaErr)
	}

	materialTemp, err := writeStagedFile(filepath.Dir(path), ".material-stage-", plaintext, 0o600)
	if err != nil {
		return err
	}
	metaTemp, err := writeStagedFile(filepath.Dir(metaPath), ".material-metadata-stage-", metadataJSON, 0o600)
	if err != nil {
		_ = os.Remove(materialTemp)
		_ = syncDirectory(filepath.Dir(path))
		return err
	}
	cleanup := true
	materialRenamed, metaRenamed := false, false
	defer func() {
		if cleanup {
			if metaRenamed {
				_ = secureRemoveFile(metaPath)
			}
			if materialRenamed {
				_ = secureRemovePlaintext(path)
			}
			_ = os.Remove(materialTemp)
			_ = os.Remove(metaTemp)
			_ = syncDirectory(filepath.Dir(path))
		}
	}()
	if err := rejectExistingPath(path); err != nil {
		return err
	}
	if err := rejectExistingPath(metaPath); err != nil {
		return err
	}
	if err := os.Chmod(materialTemp, 0o400); err != nil {
		return err
	}
	if err := publishNoReplace(materialTemp, path); err != nil {
		return err
	}
	materialRenamed = true
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := publishNoReplace(metaTemp, metaPath); err != nil {
		return err
	}
	metaRenamed = true
	if err := syncDirectory(filepath.Dir(metaPath)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (p *Provider) readSecret(reference domain.SecretReference) ([]byte, secretMetadata, error) {
	metadata, err := p.readSecretMetadata(reference)
	if err != nil {
		return nil, secretMetadata{}, err
	}
	blob, err := readSecureFile(filepath.Join(p.vaultRoot, referenceDigest(reference)+".enc"), maxSecretBytes+secretNonceSize+len(secretMagic)+aes.BlockSize)
	if err != nil {
		return nil, secretMetadata{}, err
	}
	defer zeroBytes(blob)
	if len(blob) < len(secretMagic)+secretNonceSize || string(blob[:len(secretMagic)]) != secretMagic {
		return nil, secretMetadata{}, errMetadata
	}
	if digestBytes(blob) != metadata.CiphertextDigest {
		return nil, secretMetadata{}, errMetadata
	}
	block, err := aes.NewCipher(p.masterKey[:])
	if err != nil {
		return nil, secretMetadata{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, secretMetadata{}, err
	}
	nonce := blob[len(secretMagic) : len(secretMagic)+secretNonceSize]
	ciphertext := blob[len(secretMagic)+secretNonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte("open-card-secret-v1:"+metadata.ReferenceDigest))
	if err != nil {
		return nil, secretMetadata{}, errMetadata
	}
	if digestBytes(plaintext) != metadata.PlaintextDigest {
		zeroBytes(plaintext)
		return nil, secretMetadata{}, errMetadata
	}
	return plaintext, metadata, nil
}

func (p *Provider) readSecretMetadata(reference domain.SecretReference) (secretMetadata, error) {
	path := filepath.Join(p.metadataRoot, referenceDigest(reference)+".json")
	data, err := readSecureFile(path, maxMetadataBytes)
	if errors.Is(err, errSecretNotFound) {
		return secretMetadata{}, err
	}
	if err != nil {
		return secretMetadata{}, err
	}
	defer zeroBytes(data)
	var metadata secretMetadata
	if err := decodeJSON(data, &metadata); err != nil {
		return secretMetadata{}, errMetadata
	}
	if metadata.Version != secretRecordVersion || metadata.ReferenceDigest != referenceDigest(reference) || metadata.Reference != referenceMetadataFrom(reference) || !hashPattern.MatchString(metadata.PlaintextDigest) || !hashPattern.MatchString(metadata.CiphertextDigest) || !hashPattern.MatchString(metadata.OperationDigest) || !hashPattern.MatchString(metadata.OperationFingerprint) {
		return secretMetadata{}, errMetadata
	}
	encPath := filepath.Join(p.vaultRoot, metadata.ReferenceDigest+".enc")
	if _, err := securePathState(encPath); err != nil {
		if errors.Is(err, errSecretNotFound) {
			return secretMetadata{}, errMetadata
		}
		return secretMetadata{}, err
	}
	return metadata, nil
}

func (p *Provider) readMaterialMetadata(mountID string) (materialMetadata, error) {
	if !materialPattern.MatchString(mountID) {
		return materialMetadata{}, errUnsafePath
	}
	data, err := readSecureFile(materialMetadataPath(p.materialPath(mountID)), maxMetadataBytes)
	if err != nil {
		return materialMetadata{}, err
	}
	defer zeroBytes(data)
	var metadata materialMetadata
	if err := decodeJSON(data, &metadata); err != nil {
		return materialMetadata{}, errMetadata
	}
	if metadata.Version != materialRecordVersion || metadata.MountID != mountID || !hashPattern.MatchString(metadata.ReferenceDigest) || !hashPattern.MatchString(metadata.OperationDigest) || !hashPattern.MatchString(metadata.OperationFingerprint) || metadata.ExpiresAt.IsZero() {
		return materialMetadata{}, errMetadata
	}
	return metadata, nil
}

func (p *Provider) verifyMaterial(material contracts.BuildSecretMaterial, refDigest, opDigest, fingerprint string) (contracts.BuildSecretMaterial, error) {
	if !material.ExpiresAt.After(p.now()) {
		return contracts.BuildSecretMaterial{}, errMaterialGone
	}
	if err := validateMaterialPath(p.materialRoot, material.MountID, material.Path); err != nil {
		return contracts.BuildSecretMaterial{}, err
	}
	metadata, err := p.readMaterialMetadata(material.MountID)
	if err != nil {
		return contracts.BuildSecretMaterial{}, err
	}
	if metadata.ReferenceDigest != refDigest || metadata.OperationDigest != opDigest || metadata.OperationFingerprint != fingerprint || !metadata.ExpiresAt.Equal(material.ExpiresAt) {
		return contracts.BuildSecretMaterial{}, errConflict
	}
	if err := p.verifyMaterialFile(material, refDigest, opDigest, fingerprint); err != nil {
		return contracts.BuildSecretMaterial{}, err
	}
	return material, nil
}

func (p *Provider) verifyMaterialFile(material contracts.BuildSecretMaterial, refDigest, opDigest, fingerprint string) error {
	if err := validateMaterialPath(p.materialRoot, material.MountID, material.Path); err != nil {
		return err
	}
	info, err := securePathState(material.Path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o400 || info.Size() <= 0 || info.Size() > maxSecretBytes {
		return errUnsafePath
	}
	metadata, err := p.readMaterialMetadata(material.MountID)
	if err != nil {
		return err
	}
	if metadata.ReferenceDigest != refDigest || metadata.OperationDigest != opDigest || metadata.OperationFingerprint != fingerprint {
		return errConflict
	}
	return nil
}

func (p *Provider) removeMaterialization(mountID, suppliedPath, expectedReferenceDigest string) error {
	if !materialPattern.MatchString(mountID) {
		return errUnsafePath
	}
	expected := p.materialPath(mountID)
	if suppliedPath != "" {
		if err := validateMaterialPath(p.materialRoot, mountID, suppliedPath); err != nil {
			return err
		}
	}
	metaPath := materialMetadataPath(expected)
	if metadata, err := p.readMaterialMetadata(mountID); err == nil {
		if expectedReferenceDigest != "" && metadata.ReferenceDigest != expectedReferenceDigest {
			return errConflict
		}
	} else if !errors.Is(err, errSecretNotFound) {
		return err
	}
	if err := secureRemovePlaintext(expected); err != nil && !errors.Is(err, errSecretNotFound) {
		return err
	}
	if err := secureRemoveFile(metaPath); err != nil && !errors.Is(err, errSecretNotFound) {
		return err
	}
	return nil
}

func (p *Provider) recoverMaterials() error {
	return p.cleanupExpiredLocked()
}

func (p *Provider) cleanupExpiredLocked() error {
	entries, err := os.ReadDir(p.materialRoot)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".material-") || strings.HasPrefix(name, ".material-stage-") {
			// A staged material file is plaintext and must never survive a
			// restart, regardless of its age.
			if err := secureRemovePlaintext(filepath.Join(p.materialRoot, name)); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			continue
		}
		if strings.HasSuffix(name, ".secret") {
			base := strings.TrimSuffix(name, ".secret")
			seen[base] = struct{}{}
			continue
		}
		if strings.HasSuffix(name, ".json") {
			base := strings.TrimSuffix(name, ".json")
			seen[base] = struct{}{}
			continue
		}
		// The directory is provider-owned. Unknown entries are a fail-closed
		// condition rather than an opportunity to follow attacker-controlled
		// paths.
		return errUnsafePath
	}
	for base := range seen {
		if !materialPattern.MatchString(base) {
			return errUnsafePath
		}
		materialPath := filepath.Join(p.materialRoot, base+".secret")
		metadataPath := filepath.Join(p.materialRoot, base+".json")
		materialState, materialErr := securePathState(materialPath)
		metadata, metadataErr := p.readMaterialMetadata(base)
		if errors.Is(metadataErr, errSecretNotFound) {
			// A plaintext file without a sidecar is not recoverable safely.
			if materialErr != nil && !errors.Is(materialErr, errSecretNotFound) {
				return materialErr
			}
			if materialErr == nil {
				if err := secureRemovePlaintext(materialPath); err != nil {
					return err
				}
			}
			if err := secureRemoveFile(metadataPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			continue
		}
		if metadataErr != nil {
			if materialErr != nil && !errors.Is(materialErr, errSecretNotFound) {
				return materialErr
			}
			if materialErr == nil {
				if err := secureRemovePlaintext(materialPath); err != nil {
					return err
				}
			}
			if err := secureRemoveFile(metadataPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			continue
		}
		if materialErr != nil {
			if errors.Is(materialErr, errSecretNotFound) {
				if err := secureRemoveFile(metadataPath); err != nil && !errors.Is(err, errSecretNotFound) {
					return err
				}
				continue
			}
			return materialErr
		}
		if materialState.Mode().Perm() != 0o400 {
			if err := secureRemovePlaintext(materialPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			if err := secureRemoveFile(metadataPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			return errUnsafePath
		}
		if !metadata.ExpiresAt.After(p.now()) {
			if err := secureRemovePlaintext(materialPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			if err := secureRemoveFile(metadataPath); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
		}
	}
	return nil
}

func (p *Provider) loadOperationIndexes() error {
	entries, err := os.ReadDir(p.metadataRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			return errUnsafePath
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if !hashPattern.MatchString(name) {
			return errUnsafePath
		}
		data, err := readSecureFile(filepath.Join(p.metadataRoot, entry.Name()), maxMetadataBytes)
		if err != nil {
			return err
		}
		var metadata secretMetadata
		decodeErr := decodeJSON(data, &metadata)
		zeroBytes(data)
		if decodeErr != nil || metadata.Version != secretRecordVersion || metadata.ReferenceDigest != name || !hashPattern.MatchString(metadata.PlaintextDigest) || !hashPattern.MatchString(metadata.CiphertextDigest) || !hashPattern.MatchString(metadata.OperationDigest) || !hashPattern.MatchString(metadata.OperationFingerprint) {
			return errMetadata
		}
		ref := domain.SecretReference{ID: metadata.Reference.ID, Name: metadata.Reference.Name, Provider: metadata.Reference.Provider, Version: metadata.Reference.Version}
		if err := validateReference(ref); err != nil || referenceDigest(ref) != name || metadata.Reference != referenceMetadataFrom(ref) || metadata.OperationFingerprint != digestStrings("store", name, metadata.PlaintextDigest) {
			return errMetadata
		}
		plaintext, _, err := p.readSecret(ref)
		if err != nil {
			return err
		}
		zeroBytes(plaintext)
		if previous, exists := p.storeOps[metadata.OperationDigest]; exists && (previous.fingerprint != metadata.OperationFingerprint || previous.ref != ref) {
			return errConflict
		}
		p.storeOps[metadata.OperationDigest] = operationRecord{fingerprint: metadata.OperationFingerprint, ref: ref}
	}
	return nil
}

func (p *Provider) recoverSecretStages() error {
	for _, directory := range []string{p.vaultRoot, p.metadataRoot} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, ".secret-stage-") && !strings.HasPrefix(name, ".metadata-stage-") {
				continue
			}
			if err := secureRemoveFile(filepath.Join(directory, name)); err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
		}
	}
	return nil
}

func (p *Provider) loadMaterialOperationIndexes() error {
	entries, err := os.ReadDir(p.materialRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".secret") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return errUnsafePath
		}
		mountID := strings.TrimSuffix(entry.Name(), ".json")
		if !materialPattern.MatchString(mountID) {
			return errUnsafePath
		}
		metadata, err := p.readMaterialMetadata(mountID)
		if err != nil {
			return err
		}
		material := contracts.BuildSecretMaterial{
			MountID: mountID, Path: p.materialPath(mountID), ExpiresAt: metadata.ExpiresAt,
		}
		previous, exists := p.resolveOps[metadata.OperationDigest]
		if exists && previous.fingerprint != digestStrings("resolve", metadata.ReferenceDigest) {
			return errConflict
		}
		p.resolveOps[metadata.OperationDigest] = operationRecord{fingerprint: metadata.OperationFingerprint, material: material}
	}
	return nil
}

func (p *Provider) materialPath(mountID string) string {
	return filepath.Join(p.materialRoot, mountID+".secret")
}

func (p *Provider) now() time.Time { return p.clock().UTC() }

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, capability contracts.Capability, action string) error {
	if err := p.metadata.Supports(capability); err != nil {
		return p.failure(operation, capability, action, contracts.ErrUnsupportedCapability, "provider capability is not enabled", err)
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, capability, action, contracts.ErrInvalidArgument, "provider idempotency key is required", err)
	}
	if err := contextError(ctx, operation); err != nil {
		return p.classify(operation, capability, action, err)
	}
	validateLayout := p.ensureLayout
	if p.existingOnly {
		validateLayout = p.validateExistingLayout
	}
	if err := validateLayout(); err != nil {
		return p.classify(operation, capability, action, err)
	}
	return nil
}

func (p *Provider) classify(operation contracts.OperationContext, capability contracts.Capability, action string, err error) error {
	if errors.Is(err, context.Canceled) {
		return p.failure(operation, capability, action, contracts.ErrCancelled, "secret provider operation was cancelled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return p.failure(operation, capability, action, contracts.ErrTimeout, "secret provider operation timed out", err)
	}
	if errors.Is(err, errSecretNotFound) {
		return p.failure(operation, capability, action, contracts.ErrNotFound, "secret record was not found", err)
	}
	if errors.Is(err, errUnsafePath) {
		return p.failure(operation, capability, action, contracts.ErrForbidden, "secret provider path is outside its configured boundary", err)
	}
	if errors.Is(err, errConflict) {
		return p.failure(operation, capability, action, contracts.ErrConflict, "secret operation conflicts with existing state", err)
	}
	if errors.Is(err, errMetadata) {
		return p.failure(operation, capability, action, contracts.ErrUnavailable, "secret provider metadata could not be verified", err)
	}
	return p.failure(operation, capability, action, contracts.ErrUnavailable, "secret provider storage is unavailable", err)
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
		Details: map[string]string{"evidence_ref": "ev_" + digestStrings(operation.IdempotencyKey)[:32]}}
}

func validateReference(reference domain.SecretReference) error {
	if err := reference.Validate(); err != nil {
		return err
	}
	for _, value := range []string{string(reference.ID), reference.Name, reference.Provider} {
		if !componentPattern.MatchString(value) || strings.ContainsAny(value, "\\/\x00\r\n") {
			return errors.New("secret reference contains an unsafe component")
		}
	}
	if reference.Version != "" && (!componentPattern.MatchString(reference.Version) || strings.ContainsAny(reference.Version, "\\/\x00\r\n")) {
		return errors.New("secret reference contains an unsafe version")
	}
	return nil
}

func validateMount(mount contracts.SecretMount) error {
	if !materialPattern.MatchString(mount.MountID) {
		return errors.New("secret mount id is invalid")
	}
	if err := validateReference(mount.Reference); err != nil {
		return err
	}
	if mount.ExpiresAt.IsZero() {
		return errors.New("secret mount expiry is required")
	}
	return nil
}

func validateBuildMaterial(material contracts.BuildSecretMaterial) error {
	if !materialPattern.MatchString(material.MountID) {
		return errors.New("build secret mount id is invalid")
	}
	if err := validateReference(material.Reference); err != nil {
		return err
	}
	if material.ExpiresAt.IsZero() || strings.TrimSpace(material.Path) == "" {
		return errors.New("build secret material is incomplete")
	}
	return nil
}

func validateMaterialPath(root, mountID, path string) error {
	if !materialPattern.MatchString(mountID) || strings.TrimSpace(path) == "" {
		return errUnsafePath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return errUnsafePath
	}
	expected := filepath.Clean(filepath.Join(root, mountID+".secret"))
	if filepath.Clean(abs) != expected || !within(root, abs) || filepath.Clean(abs) == filepath.Clean(root) {
		return errUnsafePath
	}
	return nil
}

func normalizeDirectory(value, label string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s is invalid", label)
	}
	abs = filepath.Clean(abs)
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("%s must be a non-symlink directory", label)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := ensureParentSecure(filepath.Dir(abs)); err != nil {
			return "", fmt.Errorf("%s parent is unsafe", label)
		}
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", fmt.Errorf("%s could not be created", label)
		}
	} else {
		return "", fmt.Errorf("%s is unavailable", label)
	}
	if err := ensureSecureDirectory(abs, false); err != nil {
		return "", fmt.Errorf("%s is not secure", label)
	}
	return abs, nil
}

func normalizeExistingDirectory(value, label string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s is invalid", label)
	}
	abs = filepath.Clean(abs)
	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s does not exist", label)
		}
		return "", fmt.Errorf("%s is unavailable", label)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || ensureSecureDirectory(abs, false) != nil {
		return "", fmt.Errorf("%s is not secure", label)
	}
	return abs, nil
}

func loadOrCreateMasterKey(value string) (string, [32]byte, error) {
	var key [32]byte
	if strings.TrimSpace(value) == "" {
		return "", key, errors.New("secret master key path is required")
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", key, errors.New("secret master key path is invalid")
	}
	abs = filepath.Clean(abs)
	if err := ensureParentSecure(filepath.Dir(abs)); err != nil {
		return "", key, errors.New("secret master key parent is unsafe")
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != int64(len(key)) {
			return "", key, errors.New("secret master key file is unsafe")
		}
		data, err := readSecureFile(abs, len(key))
		if err != nil || len(data) != len(key) {
			zeroBytes(data)
			return "", key, errors.New("secret master key could not be read")
		}
		copy(key[:], data)
		zeroBytes(data)
		return abs, key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", key, errors.New("secret master key is unavailable")
	}
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", key, errors.New("secret master key could not be generated")
	}
	file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		zeroBytes(key[:])
		if errors.Is(err, fs.ErrExist) {
			return loadOrCreateMasterKey(abs)
		}
		return "", key, errors.New("secret master key could not be created")
	}
	if _, err := file.Write(key[:]); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(filepath.Dir(abs))
	}
	if err != nil {
		_ = os.Remove(abs)
		zeroBytes(key[:])
		return "", key, errors.New("secret master key could not be persisted")
	}
	return abs, key, nil
}

func loadExistingMasterKey(value string) (string, [32]byte, error) {
	var key [32]byte
	if strings.TrimSpace(value) == "" {
		return "", key, errors.New("secret master key path is required")
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", key, errors.New("secret master key path is invalid")
	}
	abs = filepath.Clean(abs)
	if err := ensureParentSecure(filepath.Dir(abs)); err != nil {
		return "", key, errors.New("secret master key parent is unsafe")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", key, errors.New("secret master key does not exist")
		}
		return "", key, errors.New("secret master key is unavailable")
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != int64(len(key)) {
		return "", key, errors.New("secret master key file is unsafe")
	}
	data, err := readSecureFile(abs, len(key))
	if err != nil || len(data) != len(key) {
		zeroBytes(data)
		return "", key, errors.New("secret master key could not be read")
	}
	copy(key[:], data)
	zeroBytes(data)
	return abs, key, nil
}

func ensureParentSecure(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	// Parent directories need only be non-writable by group/other; they may
	// legitimately be 0755 system directories. Provider-owned roots and files
	// remain strictly owner-only below.
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errUnsafePath
	}
	return nil
}

func ensureSecureDirectory(path string, create bool) error {
	if create {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	// The installer provisions these roots as 0750: the service account owns
	// them, its group may traverse them, and no group/other actor may write.
	// Plaintext files remain stricter (0400), so directory traversal does not
	// grant secret reads.
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o027 != 0 {
		return errUnsafePath
	}
	return nil
}

func ensureChildDirectory(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errUnsafePath
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return ensureSecureDirectory(path, false)
}

func ensureExistingChildDirectory(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errUnsafePath
	}
	return ensureSecureDirectory(path, false)
}

func securePathState(path string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || hasMultipleLinks(info) {
		return nil, errUnsafePath
	}
	return info, nil
}

func readSecureFile(path string, max int) ([]byte, error) {
	info, err := securePathState(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errSecretNotFound
		}
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() != info.Size() {
		return nil, errUnsafePath
	}
	limited := io.LimitReader(file, int64(max)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		zeroBytes(data)
		return nil, err
	}
	if len(data) > max {
		zeroBytes(data)
		return nil, errMetadata
	}
	return data, nil
}

func writeStagedFile(directory, prefix string, data []byte, mode fs.FileMode) (string, error) {
	if err := ensureSecureDirectory(directory, false); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return path, nil
}

func rejectExistingPath(path string) error {
	if _, err := securePathState(path); err == nil {
		return errConflict
	} else if !errors.Is(err, errSecretNotFound) {
		return err
	}
	return nil
}

// publishNoReplace uses a same-directory hard-link publication instead of
// Rename so a concurrent provider process can never replace an already
// published ciphertext, metadata record, or plaintext materialization.
func publishNoReplace(staged, final string) error {
	if err := os.Link(staged, final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errConflict
		}
		return err
	}
	if err := os.Remove(staged); err != nil {
		return err
	}
	return nil
}

func secureRemovePlaintext(path string) error {
	info, err := securePathState(path)
	if errors.Is(err, errSecretNotFound) {
		return errSecretNotFound
	}
	if err != nil {
		return err
	}
	if info.Size() < 0 || info.Size() > maxSecretBytes {
		return errUnsafePath
	}
	// A 0400 materialization is intentionally not writable during its useful
	// lifetime. Temporarily move it to owner read/write for zeroization, then
	// unlink it; the provider mutex and O_NOFOLLOW keep this transition inside
	// the provider's ownership boundary.
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = os.Chmod(path, 0o400)
		return err
	}
	if err := overwriteZeros(file, info.Size()); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Chmod(path, 0o400)
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func hasMultipleLinks(info fs.FileInfo) bool {
	if info == nil || info.Sys() == nil {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return false
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return false
	}
	switch links.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return links.Uint() > 1
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return links.Int() > 1
	default:
		return false
	}
}

func secureRemoveFile(path string) error {
	if _, err := securePathState(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func overwriteZeros(file *os.File, size int64) error {
	const chunk = 32 << 10
	zeros := make([]byte, chunk)
	defer zeroBytes(zeros)
	for remaining := size; remaining > 0; {
		count := int64(len(zeros))
		if remaining < count {
			count = remaining
		}
		if _, err := file.Write(zeros[:count]); err != nil {
			return err
		}
		remaining -= count
	}
	return nil
}

func materialMetadataPath(materialPath string) string {
	return strings.TrimSuffix(materialPath, ".secret") + ".json"
}

func referenceMetadataFrom(reference domain.SecretReference) referenceMetadata {
	return referenceMetadata{ID: reference.ID, Name: reference.Name, Provider: reference.Provider, Version: reference.Version}
}

func referenceDigest(reference domain.SecretReference) string {
	return digestStrings(string(reference.ID), reference.Name, reference.Provider, reference.Version)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func digestStrings(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, value)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
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

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errMetadata
		}
		return err
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

func samePath(first, second string) bool {
	firstAbs, firstErr := filepath.Abs(first)
	secondAbs, secondErr := filepath.Abs(second)
	return firstErr == nil && secondErr == nil && filepath.Clean(firstAbs) == filepath.Clean(secondAbs)
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

var _ contracts.SecretProvider = (*Provider)(nil)
var _ contracts.BuildSecretResolver = (*Provider)(nil)
