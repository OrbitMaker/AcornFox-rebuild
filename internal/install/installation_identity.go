package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

const (
	productionInstallationIdentityCanonicalRoot = "/etc/open-card"
	productionInstallationIdentityLegacyRoot    = "/var/lib/open-card"
	installationIdentityFile                    = "installation-id"
	installationIdentityLockTransaction         = "installation-identity-migration"
)

// ErrInstallationIdentityConflict is deliberately detail-free. Installation
// identity is a root-only secret, so callers must not learn its value from a
// malformed file, a conflict, or a persistence failure.
var ErrInstallationIdentityConflict = errors.New("installation identity conflicts with required state")

// InstallationIdentity is an opaque installation secret. It intentionally
// has no accessor for the raw value: consumers can compare identities or bind
// derived public evidence without accidentally serializing/logging the secret.
type InstallationIdentity struct{ value string }

func (i InstallationIdentity) Equal(other InstallationIdentity) bool {
	return i.value != "" && i.value == other.value
}

// SHA256 returns a public, stable binding for the identity without exposing
// the identity itself.
func (i InstallationIdentity) SHA256() string {
	if i.value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(i.value))
	return hex.EncodeToString(sum[:])
}

// String, GoString and MarshalJSON are intentionally redacted so common
// logging and JSON paths cannot disclose the raw installation identity.
func (InstallationIdentity) String() string   { return "installation-identity(redacted)" }
func (InstallationIdentity) GoString() string { return "install.InstallationIdentity(redacted)" }
func (InstallationIdentity) MarshalJSON() ([]byte, error) {
	return json.Marshal("installation_identity_redacted")
}

// InstallationIdentityLocker is the only migration coordination boundary.
// UpgradeStore implements it; task tests inject a typed fake rather than a
// path or a raw flock descriptor.
type InstallationIdentityLocker interface {
	Acquire(context.Context, string) (UpgradeLock, error)
	PendingTransaction(context.Context) (PendingTransaction, error)
}

// InstallationIdentityStore owns pinned canonical and legacy roots. The
// legacy file is migration input only; no method writes, removes, or otherwise
// mutates it.
type InstallationIdentityStore struct {
	mu        sync.Mutex
	canonical *DurableWriter
	legacy    *DurableWriter
	locker    InstallationIdentityLocker
	ownedLock interface{ Close() error }

	// beforeCreate is task-test-only. It models a competing creator between
	// inspection and CreateMetadata so the production path remains race-safe.
	beforeCreate func()
}

// NewProductionInstallationIdentityStore opens only the two fixed production
// roots and the existing production upgrade coordinator. It accepts no paths,
// ownership, or lock source from callers.
func NewProductionInstallationIdentityStore() (*InstallationIdentityStore, error) {
	canonical, err := ProductionDurableWriter(productionInstallationIdentityCanonicalRoot)
	if err != nil {
		return nil, ErrInstallationIdentityConflict
	}
	legacy, err := ProductionDurableWriter(productionInstallationIdentityLegacyRoot)
	if err != nil {
		_ = canonical.Close()
		return nil, ErrInstallationIdentityConflict
	}
	upgrade, err := ProductionUpgradeStore()
	if err != nil {
		_ = legacy.Close()
		_ = canonical.Close()
		return nil, ErrInstallationIdentityConflict
	}
	return &InstallationIdentityStore{canonical: canonical, legacy: legacy, locker: upgrade, ownedLock: upgrade}, nil
}

// NewTaskInstallationIdentityStore is the task-only constructor. Both roots
// must already be prepared secure directories for uid:gid, and locker must be
// the task's prepared global-upgrade-lock coordinator.
func NewTaskInstallationIdentityStore(canonicalRoot, legacyRoot string, uid, gid int, locker InstallationIdentityLocker) (*InstallationIdentityStore, error) {
	if locker == nil {
		return nil, ErrInstallationIdentityConflict
	}
	canonical, err := TaskDurableWriter(canonicalRoot, uid, gid)
	if err != nil {
		return nil, ErrInstallationIdentityConflict
	}
	legacy, err := TaskDurableWriter(legacyRoot, uid, gid)
	if err != nil {
		_ = canonical.Close()
		return nil, ErrInstallationIdentityConflict
	}
	return &InstallationIdentityStore{canonical: canonical, legacy: legacy, locker: locker}, nil
}

// Close releases every resource opened by this store. A close failure leaves
// the store unavailable, avoiding further use through an ambiguous root.
func (s *InstallationIdentityStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	canonical, legacy, owned := s.canonical, s.legacy, s.ownedLock
	s.canonical, s.legacy, s.locker, s.ownedLock = nil, nil, nil, nil
	var first error
	if owned != nil {
		first = owned.Close()
	}
	if legacy != nil {
		if err := legacy.Close(); err != nil && first == nil {
			first = err
		}
	}
	if canonical != nil {
		if err := canonical.Close(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return ErrInstallationIdentityConflict
	}
	return nil
}

// Resolve reads the canonical path only. New code must never silently fall
// back to the legacy location after migration support has been introduced.
func (s *InstallationIdentityStore) Resolve(ctx context.Context) (InstallationIdentity, error) {
	if ctx == nil || ctx.Err() != nil {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canonical == nil {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
	identity, state := readInstallationIdentity(s.canonical)
	if state != installationIdentityPresent {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
	return identity, nil
}

// Migrate atomically decides the two fixed identity locations while holding
// the global upgrade lock. Only a valid legacy-only identity can create the
// canonical file, and creation is no-replace plus exact reread reconciliation.
func (s *InstallationIdentityStore) Migrate(ctx context.Context) (identity InstallationIdentity, result error) {
	if ctx == nil || ctx.Err() != nil {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canonical == nil || s.legacy == nil || s.locker == nil {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}

	lock, err := s.locker.Acquire(ctx, installationIdentityLockTransaction)
	if err != nil || lock == nil {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			identity = InstallationIdentity{}
			result = ErrInstallationIdentityConflict
		}
	}()

	pending, err := s.locker.PendingTransaction(ctx)
	if err != nil || pending.Marker != UpgradeMarkerAbsent || pending.TransactionID != "" {
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}

	canonical, canonicalState := readInstallationIdentity(s.canonical)
	legacy, legacyState := readInstallationIdentity(s.legacy)
	switch {
	case canonicalState == installationIdentityPresent && legacyState == installationIdentityAbsent:
		return canonical, nil
	case canonicalState == installationIdentityPresent && legacyState == installationIdentityPresent:
		if canonical.Equal(legacy) {
			return canonical, nil
		}
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	case canonicalState == installationIdentityAbsent && legacyState == installationIdentityPresent:
		if s.beforeCreate != nil {
			s.beforeCreate()
		}
		if err := s.canonical.CreateMetadata(installationIdentityFile, []byte(legacy.value+"\n")); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, ErrDurableCommitUnknown) {
			return InstallationIdentity{}, ErrInstallationIdentityConflict
		}
		// Success, a no-replace race, and an unknown post-commit fsync all have
		// the same safe recovery rule: trust only a fresh exact canonical read.
		reconciled, reconciledState := readInstallationIdentity(s.canonical)
		if reconciledState != installationIdentityPresent || !reconciled.Equal(legacy) {
			return InstallationIdentity{}, ErrInstallationIdentityConflict
		}
		return reconciled, nil
	default:
		return InstallationIdentity{}, ErrInstallationIdentityConflict
	}
}

type installationIdentityState uint8

const (
	installationIdentityAbsent installationIdentityState = iota
	installationIdentityPresent
	installationIdentityUnsafe
)

func readInstallationIdentity(writer *DurableWriter) (InstallationIdentity, installationIdentityState) {
	if writer == nil {
		return InstallationIdentity{}, installationIdentityUnsafe
	}
	raw, err := writer.ReadMetadata(installationIdentityFile)
	if errors.Is(err, os.ErrNotExist) {
		return InstallationIdentity{}, installationIdentityAbsent
	}
	if err != nil || len(raw) != 49 || raw[48] != '\n' || !isLowerHex(string(raw[:48])) {
		return InstallationIdentity{}, installationIdentityUnsafe
	}
	return InstallationIdentity{value: string(raw[:48])}, installationIdentityPresent
}
