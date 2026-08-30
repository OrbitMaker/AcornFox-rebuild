package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const productionActiveRoot = "/opt/open-card"

// ErrActiveDatabaseUnavailable is deliberately opaque: callers must not leak
// a DSN or the contents of activation metadata while reporting a fail-closed
// identity error.
var ErrActiveDatabaseUnavailable = errors.New("active database identity unavailable")

// ResolvedActiveDatabase is the non-printable active activation identity.
// DatabaseEnv is deliberately retained as bytes: backup and restore callers
// need the exact root-owned environment binding, but must never serialize or
// print a parsed DSN.
type ResolvedActiveDatabase struct {
	Activation           ActivationV1 `json:"activation"`
	ActivationJSONSHA256 string       `json:"activation_json_sha256"`
	DatabaseEnv          []byte       `json:"-"`
}

// ActiveDatabase is the legacy local-admin compatibility view. New backup and
// restore paths must use ResolvedActiveDatabase so they cannot accidentally
// carry a printable URL through their wire contracts.
type ActiveDatabase struct {
	Activation  ActivationV1
	DatabaseURL string
}

// ActiveDatabaseResolver resolves a single activation beneath a fixed root.
// Production uses /opt/open-card with root ownership; tests must opt into a
// separate task root and explicit expected owner.
type ActiveDatabaseResolver struct {
	root string
	uid  int
	gid  int
}

func ProductionActiveDatabaseResolver() (*ActiveDatabaseResolver, error) {
	return newActiveDatabaseResolver(productionActiveRoot, 0, 0)
}

func TaskActiveDatabaseResolver(root string, uid, gid int) (*ActiveDatabaseResolver, error) {
	if uid < 0 || gid < 0 {
		return nil, ErrActiveDatabaseUnavailable
	}
	return newActiveDatabaseResolver(root, uid, gid)
}

func newActiveDatabaseResolver(root string, uid, gid int) (*ActiveDatabaseResolver, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.Contains(root, "\x00") {
		return nil, ErrActiveDatabaseUnavailable
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownedBy(info, uid, gid) {
		return nil, ErrActiveDatabaseUnavailable
	}
	return &ActiveDatabaseResolver{root: root, uid: uid, gid: gid}, nil
}

// Resolve reads active and current as a single fail-closed identity. It
// repeats the active link check before return, so a pointer replacement during
// the read cannot silently mix activation metadata with a different pointer.
func (r *ActiveDatabaseResolver) Resolve() (ActiveDatabase, error) {
	resolved, err := r.ResolveResolved()
	if err != nil {
		return ActiveDatabase{}, err
	}
	return activeDatabaseCompatibility(resolved)
}

// ResolveResolved reads active and current as a single fail-closed identity.
// It repeats the active link check before return, so a pointer replacement
// during the read cannot silently mix activation metadata with a different
// pointer.
func (r *ActiveDatabaseResolver) ResolveResolved() (ResolvedActiveDatabase, error) {
	root, err := r.openRoot()
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	defer root.Close()
	activationID, err := r.activeID(root)
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	value, err := r.resolveActivation(root, activationID)
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	if err := r.validateCurrent(root); err != nil {
		return ResolvedActiveDatabase{}, err
	}
	if after, err := r.activeID(root); err != nil || after != activationID {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	return value, nil
}

// ResolveActivation validates one explicit candidate slot. It does not fall
// back to active or a legacy server.env; callers must pass an allowlisted ID.
func (r *ActiveDatabaseResolver) ResolveActivation(activationID string) (ActiveDatabase, error) {
	resolved, err := r.ResolveActivationResolved(activationID)
	if err != nil {
		return ActiveDatabase{}, err
	}
	return activeDatabaseCompatibility(resolved)
}

// ResolveActivationResolved validates one explicit candidate slot. It does
// not fall back to active or a legacy server.env; callers must pass an
// allowlisted ID.
func (r *ActiveDatabaseResolver) ResolveActivationResolved(activationID string) (ResolvedActiveDatabase, error) {
	if !validID(activationID) {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	root, err := r.openRoot()
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	defer root.Close()
	return r.resolveActivation(root, activationID)
}

func activeDatabaseCompatibility(resolved ResolvedActiveDatabase) (ActiveDatabase, error) {
	databaseURL, err := ParseDatabaseEnv(resolved.DatabaseEnv)
	if err != nil {
		return ActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	return ActiveDatabase{Activation: resolved.Activation, DatabaseURL: databaseURL}, nil
}

func (r *ActiveDatabaseResolver) openRoot() (*os.Root, error) {
	if r == nil {
		return nil, ErrActiveDatabaseUnavailable
	}
	root, err := os.OpenRoot(r.root)
	if err != nil {
		return nil, ErrActiveDatabaseUnavailable
	}
	return root, nil
}

func (r *ActiveDatabaseResolver) activeID(root *os.Root) (string, error) {
	if !isSymlink(root, "active") {
		return "", ErrActiveDatabaseUnavailable
	}
	target, err := root.Readlink("active")
	if err != nil || filepath.IsAbs(target) || strings.ContainsAny(target, "\x00\\") {
		return "", ErrActiveDatabaseUnavailable
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "activations" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("activations", parts[1])) {
		return "", ErrActiveDatabaseUnavailable
	}
	return parts[1], nil
}

func (r *ActiveDatabaseResolver) resolveActivation(root *os.Root, activationID string) (ResolvedActiveDatabase, error) {
	if !validID(activationID) || !r.secureDir(root, "activations") || !r.secureDir(root, filepath.ToSlash(filepath.Join("activations", activationID))) {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	base := filepath.ToSlash(filepath.Join("activations", activationID))
	activationRaw, err := r.readSecureFile(root, filepath.ToSlash(filepath.Join(base, "activation.json")))
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	activation, err := ParseActivationV1(activationRaw)
	if err != nil || activation.ActivationID != activationID {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	databaseRaw, err := r.readSecureFile(root, filepath.ToSlash(filepath.Join(base, "database.env")))
	if err != nil {
		return ResolvedActiveDatabase{}, err
	}
	sum := sha256.Sum256(databaseRaw)
	if hex.EncodeToString(sum[:]) != activation.DatabaseEnvSHA256 {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	environment, err := PostgresEnvironment(databaseRaw)
	if err != nil || environment.Descriptor.Database != activation.Database.Name {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	if !r.releaseCoherent(root, base, activation.Release.ID) {
		return ResolvedActiveDatabase{}, ErrActiveDatabaseUnavailable
	}
	activationSum := sha256.Sum256(activationRaw)
	return ResolvedActiveDatabase{
		Activation:           activation,
		ActivationJSONSHA256: hex.EncodeToString(activationSum[:]),
		DatabaseEnv:          append([]byte(nil), databaseRaw...),
	}, nil
}

func (r *ActiveDatabaseResolver) releaseCoherent(root *os.Root, base, releaseID string) bool {
	if !validID(releaseID) || !r.runtimeReleaseDir(root, "releases") || !r.runtimeReleaseDir(root, filepath.ToSlash(filepath.Join("releases", releaseID))) {
		return false
	}
	name := filepath.ToSlash(filepath.Join(base, "release"))
	if !isSymlink(root, name) {
		return false
	}
	target, err := root.Readlink(name)
	return err == nil && target == filepath.ToSlash(filepath.Join("..", "..", "releases", releaseID))
}

func (r *ActiveDatabaseResolver) validateCurrent(root *os.Root) error {
	if !isSymlink(root, "current") {
		return ErrActiveDatabaseUnavailable
	}
	target, err := root.Readlink("current")
	if err != nil || target != "active/release" {
		return ErrActiveDatabaseUnavailable
	}
	return nil
}

func (r *ActiveDatabaseResolver) secureDir(root *os.Root, name string) bool {
	info, err := root.Lstat(name)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() == activationSlotDirMode && ownedBy(info, r.uid, r.gid)
}

// runtimeReleaseDir follows the release publication contract: immutable
// runtime content remains root-owned, not writable by group/other, and is
// traversable/readable by service users.  Metadata secrecy belongs to the
// activation slot files, not to release directories.
func (r *ActiveDatabaseResolver) runtimeReleaseDir(root *os.Root, name string) bool {
	info, err := root.Lstat(name)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() == 0o755 && ownedBy(info, r.uid, r.gid)
}

func (r *ActiveDatabaseResolver) readSecureFile(root *os.Root, name string) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrActiveDatabaseUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedBy(info, r.uid, r.gid) {
		return nil, ErrActiveDatabaseUnavailable
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrActiveDatabaseUnavailable)
	}
	return data, nil
}

func isSymlink(root *os.Root, name string) bool {
	info, err := root.Lstat(name)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func ownedBy(info os.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == uid && int(stat.Gid) == gid
}
