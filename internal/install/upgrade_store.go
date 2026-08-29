package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrUpgradeStoreNotImplemented = errors.New("upgrade store method is not implemented")
var ErrUpgradeJournalConflict = errors.New("upgrade journal conflict")
var ErrLegacyProjectionRequired = errors.New("legacy activation projection is required")

const storeUpgradeInProgressPath = "upgrade-in-progress"

type UpgradeStore struct {
	root             string
	dataWriter       *DurableWriter
	activationWriter *DurableWriter
	lock             *upgradeStoreLock
}
type upgradeStoreLock struct {
	file  *os.File
	tx    string
	owner *UpgradeStore
}

func (l *upgradeStoreLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	if l.owner != nil && l.owner.lock == l {
		l.owner.lock = nil
	}
	return err
}

func ProductionUpgradeStore() (*UpgradeStore, error) {
	d, e := ProductionDurableWriter("/var/lib/open-card")
	if e != nil {
		return nil, e
	}
	a, e := ProductionDurableWriter("/opt/open-card")
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	return &UpgradeStore{root: "/", dataWriter: d, activationWriter: a}, nil
}
func TaskUpgradeStore(root string, uid, gid int) (*UpgradeStore, error) {
	d, e := TaskDurableWriter(filepath.Join(root, "var/lib/open-card"), uid, gid)
	if e != nil {
		return nil, e
	}
	a, e := TaskDurableWriter(filepath.Join(root, "opt/open-card"), uid, gid)
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	return &UpgradeStore{root: root, dataWriter: d, activationWriter: a}, nil
}
func (s *UpgradeStore) journal(tx string) string {
	return filepath.ToSlash(filepath.Join("upgrade-transactions", tx+".json"))
}

func (s *UpgradeStore) Acquire(_ context.Context, tx string) (UpgradeLock, error) {
	if s == nil || !validID(tx) {
		return nil, ErrUpgradeJournalConflict
	}
	d := filepath.Join(s.root, "run/lock")
	if err := os.MkdirAll(d, 0700); err != nil {
		return nil, err
	}
	p := filepath.Join(d, "open-card-upgrade.lock")
	fd, err := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	lock := &upgradeStoreLock{file: f, tx: tx, owner: s}
	s.lock = lock
	return lock, nil
}
func (s *UpgradeStore) LoadJournal(_ context.Context, tx string) (UpgradeJournalV1, error) {
	if s == nil || !validID(tx) {
		return UpgradeJournalV1{}, ErrUpgradeJournalConflict
	}
	raw, e := s.dataWriter.ReadMetadata(s.journal(tx))
	if e != nil {
		return UpgradeJournalV1{}, e
	}
	return ParseUpgradeJournalV1(raw)
}
func (s *UpgradeStore) CreateJournal(_ context.Context, j UpgradeJournalV1) error {
	if !s.ownsLock() || s.lock.tx != j.TransactionID {
		return ErrUpgradeJournalConflict
	}
	if e := j.Validate(); e != nil {
		return e
	}
	raw, e := MarshalUpgradeJournalV1(j)
	if e != nil {
		return e
	}
	if err := s.dataWriter.CreateMetadata(s.journal(j.TransactionID), raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrUpgradeJournalConflict
		}
		return err
	}
	return nil
}
func (s *UpgradeStore) SaveJournal(ctx context.Context, j UpgradeJournalV1) error {
	if !s.ownsLock() || s.lock.tx != j.TransactionID {
		return ErrUpgradeJournalConflict
	}
	old, e := s.LoadJournal(ctx, j.TransactionID)
	if e != nil {
		return e
	}
	if j.Revision != old.Revision+1 || len(j.History) != len(old.History)+1 || j.History[len(old.History)].Revision != j.Revision || j.History[len(old.History)].From != old.State {
		return ErrUpgradeJournalConflict
	}
	for i := range old.History {
		if old.History[i] != j.History[i] {
			return ErrUpgradeJournalConflict
		}
	}
	raw, e := MarshalUpgradeJournalV1(j)
	if e != nil {
		return e
	}
	return s.dataWriter.WriteMetadata(s.journal(j.TransactionID), raw)
}
func (s *UpgradeStore) EnsureMarker(_ context.Context, tx string) error {
	if !validID(tx) {
		return ErrUpgradeJournalConflict
	}
	v, e := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if e == nil {
		if string(v) == tx+"\n" {
			return nil
		}
		return ErrUpgradeJournalConflict
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return s.dataWriter.CreateMetadata(storeUpgradeInProgressPath, []byte(tx+"\n"))
}
func (s *UpgradeStore) Marker(ctx context.Context, set bool) error {
	if s == nil || s.lock == nil || s.lock.file == nil || s.lock.tx == "" {
		return ErrUpgradeJournalConflict
	}
	if set {
		return s.EnsureMarker(ctx, s.lock.tx)
	}
	v, e := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if e != nil {
		return e
	}
	if len(v) == 0 {
		return ErrUpgradeJournalConflict
	}
	if string(v) != s.lock.tx+"\n" {
		return ErrUpgradeJournalConflict
	}
	return s.dataWriter.RemoveMetadata(storeUpgradeInProgressPath)
}
func (s *UpgradeStore) Close() error {
	if s == nil {
		return nil
	}
	if s == nil {
		return nil
	}
	if s.dataWriter != nil {
		_ = s.dataWriter.Close()
	}
	if s.activationWriter != nil {
		return s.activationWriter.Close()
	}
	return nil
}

func (s *UpgradeStore) ReadActualState(_ context.Context, oldID, candidateID string) (UpgradeActualState, error) {
	if !s.ownsLock() || !validID(oldID) || !validID(candidateID) {
		return UpgradeActualState{}, ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil {
		return UpgradeActualState{}, err
	}
	marker, err := s.markerTransaction()
	if err != nil {
		return UpgradeActualState{}, err
	}
	actual := UpgradeActualState{
		ActiveID:                     state.ActiveID,
		PreviousID:                   state.PreviousID,
		MarkerTransactionID:          marker,
		PreviousActivationJSONSHA256: state.PreviousJSONSHA256,
	}
	oldDigest, oldExists, err := s.activationDigestIfPresent(oldID)
	if err != nil {
		return UpgradeActualState{}, err
	}
	candidateDigest, candidateExists, err := s.activationDigestIfPresent(candidateID)
	if err != nil {
		return UpgradeActualState{}, err
	}
	actual.OldActivationExists, actual.CandidateActivationExists = oldExists, candidateExists
	actual.OldActivationJSONSHA256, actual.CandidateActivationJSONSHA256 = oldDigest, candidateDigest
	return actual, nil
}
func (s *UpgradeStore) Preflight(_ context.Context, tx string) (ActivationV1, string, bool, error) {
	if !s.ownsLock() || s.lock.tx != tx || !validID(tx) {
		return ActivationV1{}, "", false, ErrUpgradeJournalConflict
	}
	target, err := s.activationWriter.ReadActivationLink(ActivationLinkActive)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && s.legacyCurrentPresent() {
			return ActivationV1{}, "", false, ErrLegacyProjectionRequired
		}
		return ActivationV1{}, "", false, ErrUpgradeJournalConflict
	}
	activeID, ok := activationIDFromTarget(target)
	if !ok {
		return ActivationV1{}, "", false, ErrUpgradeJournalConflict
	}
	activation, digest, err := s.readActivation(activeID)
	if err != nil {
		return ActivationV1{}, "", false, ErrUpgradeJournalConflict
	}
	current, err := s.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	if err != nil || current != "active/release" {
		return ActivationV1{}, "", false, ErrUpgradeJournalConflict
	}
	return activation, digest, false, nil
}
func (s *UpgradeStore) ProjectLegacy(context.Context, string, ActivationV1) (string, error) {
	return "", ErrUpgradeStoreNotImplemented
}
func (s *UpgradeStore) ReadActivationState(context.Context) (UpgradeActivationState, error) {
	if !s.ownsLock() {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	activeTarget, err := s.activationWriter.ReadActivationLink(ActivationLinkActive)
	if err != nil {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	activeID, ok := activationIDFromTarget(activeTarget)
	if !ok {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	_, activeDigest, err := s.readActivation(activeID)
	if err != nil {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	current, err := s.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	if err != nil || current != "active/release" {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	state := UpgradeActivationState{ActiveID: activeID, ActiveActivationJSONSHA256: activeDigest}
	previousTarget, err := s.activationWriter.ReadActivationLink(ActivationLinkPreviousActive)
	if err == nil {
		previousID, ok := activationIDFromTarget(previousTarget)
		if !ok {
			return UpgradeActivationState{}, ErrUpgradeJournalConflict
		}
		_, previousDigest, err := s.readActivation(previousID)
		if err != nil {
			return UpgradeActivationState{}, ErrUpgradeJournalConflict
		}
		state.PreviousID, state.PreviousJSONSHA256 = previousID, previousDigest
	} else if !errors.Is(err, os.ErrNotExist) {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	marker, err := s.markerTransaction()
	if err != nil || marker != "" && marker != s.lock.tx {
		return UpgradeActivationState{}, ErrUpgradeJournalConflict
	}
	state.Marker = marker != ""
	return state, nil
}

func (s *UpgradeStore) ownsLock() bool {
	return s != nil && s.activationWriter != nil && s.dataWriter != nil && s.lock != nil && s.lock.owner == s && s.lock.file != nil && s.lock.tx != ""
}

func activationIDFromTarget(target string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "activations" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("activations", parts[1])) {
		return "", false
	}
	return parts[1], true
}

// readActivation validates one fixed activation slot, including its secure
// metadata, database binding, typed release link, and release manifest.
func (s *UpgradeStore) readActivation(id string) (ActivationV1, string, error) {
	if s == nil || s.activationWriter == nil || !validID(id) {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	slot, err := s.activationSlotWriter(id)
	if err != nil {
		return ActivationV1{}, "", err
	}
	defer slot.Close()
	raw, err := slot.ReadMetadata("activation.json")
	if err != nil {
		return ActivationV1{}, "", err
	}
	activation, err := ParseActivationV1(raw)
	if err != nil || activation.ActivationID != id {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	env, err := slot.ReadMetadata("database.env")
	if err != nil {
		return ActivationV1{}, "", err
	}
	if _, err := ParseDatabaseEnv(env); err != nil || sha256Bytes(env) != activation.DatabaseEnvSHA256 {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	info, err := slot.ops.Lstat("release")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	target, err := slot.ops.Readlink("release")
	if err != nil || target != filepath.ToSlash(filepath.Join("..", "..", "releases", activation.Release.ID)) {
		return ActivationV1{}, "", ErrUpgradeJournalConflict
	}
	if err := s.verifyCandidateRelease(activation); err != nil {
		return ActivationV1{}, "", err
	}
	return activation, sha256Bytes(raw), nil
}

func (s *UpgradeStore) activationDigestIfPresent(id string) (string, bool, error) {
	_, digest, err := s.readActivation(id)
	if err == nil {
		return digest, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return "", false, err
}

func (s *UpgradeStore) markerTransaction() (string, error) {
	if s == nil || s.dataWriter == nil {
		return "", ErrUpgradeJournalConflict
	}
	raw, err := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || len(raw) == 0 || !strings.HasSuffix(string(raw), "\n") || strings.Count(string(raw), "\n") != 1 {
		return "", ErrUpgradeJournalConflict
	}
	tx := strings.TrimSuffix(string(raw), "\n")
	if !validID(tx) {
		return "", ErrUpgradeJournalConflict
	}
	return tx, nil
}

func (s *UpgradeStore) legacyCurrentPresent() bool {
	if s == nil {
		return false
	}
	root, err := os.OpenRoot(s.activationRoot())
	if err != nil {
		return false
	}
	defer root.Close()
	info, err := root.Lstat("current")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := root.Readlink("current")
	if err != nil || filepath.IsAbs(target) || strings.ContainsAny(target, "\x00\\") {
		return false
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "releases" || !validID(parts[1]) || target != filepath.ToSlash(filepath.Join("releases", parts[1])) {
		return false
	}
	legacyEnv := filepath.Join(s.root, "etc/open-card/server.env")
	if s.root == "/" {
		legacyEnv = "/etc/open-card/server.env"
	}
	legacy, err := os.Lstat(legacyEnv)
	return err == nil && legacy.Mode().IsRegular() && legacy.Mode()&os.ModeSymlink == 0
}

// WriteCandidateActivation publishes a candidate activation only after its
// release and database identity have been bound to the durable activation
// metadata. Publication is deliberately append-only: an existing activation
// is accepted only when every persisted object is byte-for-byte equivalent.
func (s *UpgradeStore) WriteCandidateActivation(_ context.Context, activation ActivationV1, databaseEnv []byte) (string, error) {
	if s == nil || s.activationWriter == nil || s.lock == nil || s.lock.owner != s || s.lock.file == nil || s.lock.tx != activation.CreatedByTransactionID {
		return "", ErrUpgradeJournalConflict
	}
	if err := activation.Validate(); err != nil {
		return "", err
	}
	if _, err := ParseDatabaseEnv(databaseEnv); err != nil {
		return "", err
	}
	databaseSum := sha256.Sum256(databaseEnv)
	if hex.EncodeToString(databaseSum[:]) != activation.DatabaseEnvSHA256 {
		return "", ErrUpgradeJournalConflict
	}
	activationRaw, err := MarshalActivationV1(activation)
	if err != nil {
		return "", err
	}
	activationSum := sha256.Sum256(activationRaw)
	digest := hex.EncodeToString(activationSum[:])

	if err := s.verifyCandidateRelease(activation); err != nil {
		return "", err
	}

	created, err := s.createActivationDirectory(activation.ActivationID)
	if err != nil {
		return "", err
	}
	if !created {
		if err := s.matchExistingCandidateActivation(activation, databaseEnv, activationRaw); err != nil {
			return "", ErrUpgradeJournalConflict
		}
		return digest, nil
	}

	slot, err := s.activationSlotWriter(activation.ActivationID)
	if err != nil {
		return "", err
	}
	defer slot.Close()
	if err := slot.SwapActivationReleaseLink(activation.Release.ID); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	if err := slot.CreateMetadata("database.env", databaseEnv); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	if err := slot.CreateMetadata("activation.json", activationRaw); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, err); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	// Each slot operation synchronizes its 0711 root. Also synchronize the
	// activation collection that records the newly-created directory.
	if err := s.syncActivationCollection(); err != nil {
		if outcome := s.candidateWriteOutcome(activation, databaseEnv, activationRaw, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)); outcome == nil {
			return digest, nil
		} else {
			return "", outcome
		}
	}
	return digest, nil
}

// candidateWriteOutcome reconciles only a potentially durable outcome. A
// normal write error remains an error even if a concurrent actor happened to
// construct an equivalent activation afterwards.
func (s *UpgradeStore) candidateWriteOutcome(activation ActivationV1, databaseEnv, activationRaw []byte, cause error) error {
	if !errors.Is(cause, ErrDurableCommitUnknown) {
		return cause
	}
	if err := s.matchExistingCandidateActivation(activation, databaseEnv, activationRaw); err == nil {
		return nil
	}
	return cause
}

// matchExistingCandidateActivation reads all three candidate objects through
// their fixed paths and verifies the exact activation JSON, database.env, and
// typed release link. It is intentionally private so no caller can select an
// arbitrary activation path.
func (s *UpgradeStore) matchExistingCandidateActivation(activation ActivationV1, databaseEnv, activationRaw []byte) error {
	slot, err := s.activationSlotWriter(activation.ActivationID)
	if err != nil {
		return err
	}
	defer slot.Close()
	env, err := slot.ReadMetadata("database.env")
	if err != nil || !bytes.Equal(env, databaseEnv) {
		return ErrUpgradeJournalConflict
	}
	raw, err := slot.ReadMetadata("activation.json")
	if err != nil || !bytes.Equal(raw, activationRaw) {
		return ErrUpgradeJournalConflict
	}
	if _, err := ParseActivationV1(raw); err != nil {
		return ErrUpgradeJournalConflict
	}
	info, err := slot.ops.Lstat("release")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ErrUpgradeJournalConflict
	}
	target, err := slot.ops.Readlink("release")
	if err != nil || target != filepath.ToSlash(filepath.Join("..", "..", "releases", activation.Release.ID)) {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) activationRoot() string {
	if s.root == "/" {
		return "/opt/open-card"
	}
	return filepath.Join(s.root, "opt/open-card")
}

func (s *UpgradeStore) validateActivationRoot() error {
	if s == nil || s.activationWriter == nil {
		return ErrUpgradeJournalConflict
	}
	return s.validateNonWritableDirectory(s.activationRoot())
}

func (s *UpgradeStore) validateActivationLayout() error {
	if err := s.validateActivationRoot(); err != nil {
		return err
	}
	path := filepath.Join(s.activationRoot(), "activations")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != activationSlotDirMode || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) validateNonWritableDirectory(path string) error {
	if s == nil || s.activationWriter == nil {
		return ErrUpgradeJournalConflict
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return ErrUpgradeJournalConflict
	}
	return nil
}

func (s *UpgradeStore) activationSlotWriter(id string) (*DurableWriter, error) {
	if !validID(id) || s.validateActivationLayout() != nil {
		return nil, ErrUpgradeJournalConflict
	}
	path := filepath.Join(s.activationRoot(), "activations", id)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != activationSlotDirMode || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return nil, ErrUpgradeJournalConflict
	}
	return newDurableWriter(path, s.activationWriter.uid, s.activationWriter.gid, nil)
}

func (s *UpgradeStore) syncActivationCollection() error {
	if err := s.validateActivationLayout(); err != nil {
		return err
	}
	writer, err := newDurableWriter(filepath.Join(s.activationRoot(), "activations"), s.activationWriter.uid, s.activationWriter.gid, nil)
	if err != nil {
		return err
	}
	defer writer.Close()
	return writer.SyncRoot()
}

func (s *UpgradeStore) createActivationDirectory(id string) (bool, error) {
	if !validID(id) {
		return false, ErrUpgradeJournalConflict
	}
	if err := s.validateActivationLayout(); err != nil {
		return false, err
	}
	path := filepath.Join(s.activationRoot(), "activations", id)
	if err := os.Mkdir(path, activationSlotDirMode); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != activationSlotDirMode || verifyOwner(info, s.activationWriter.uid, s.activationWriter.gid) != nil {
		return false, ErrUpgradeJournalConflict
	}
	if err := s.syncActivationCollection(); err != nil {
		return false, fmt.Errorf("%w: %v", ErrDurableCommitUnknown, err)
	}
	return true, nil
}

func (s *UpgradeStore) verifyCandidateRelease(activation ActivationV1) error {
	release := activation.Release
	if !release.valid() {
		return ErrUpgradeJournalConflict
	}
	if err := s.validateActivationRoot(); err != nil {
		return err
	}
	if err := s.validateNonWritableDirectory(filepath.Join(s.activationRoot(), "releases")); err != nil {
		return err
	}
	releaseDir := filepath.Join(s.activationRoot(), "releases", release.ID)
	if err := s.validateNonWritableDirectory(releaseDir); err != nil {
		return err
	}
	if err := ensureNoSymlinkBetween(s.activationRoot(), releaseDir); err != nil {
		return err
	}
	manifestPath := filepath.Join(releaseDir, "manifest.json")
	if err := ensureNoSymlinkBetween(releaseDir, manifestPath); err != nil {
		return err
	}
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUpgradeJournalConflict
	}
	digest, err := SHA256File(manifestPath)
	if err != nil || digest != release.ManifestSHA256 {
		return ErrUpgradeJournalConflict
	}
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	if manifest.ReleaseID != release.ID || manifest.Version != release.Version || manifest.SourceCommit != release.SourceCommit || manifest.Architecture != release.Architecture || manifest.MigrationVersion != activation.Database.Migration {
		return ErrUpgradeJournalConflict
	}
	return VerifyRelease(releaseDir, manifest)
}
func (s *UpgradeStore) SetPrevious(_ context.Context, oldID string) error {
	if !s.ownsLock() || !validID(oldID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != oldID {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, oldID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.PreviousID != oldID || after.PreviousJSONSHA256 != state.ActiveActivationJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) RestorePrevious(_ context.Context, expectedCurrent, baselineID, baselineDigest string) error {
	if !s.ownsLock() || !validID(expectedCurrent) || (baselineID == "") != (baselineDigest == "") || baselineID != "" && (!validID(baselineID) || !validSHA(baselineDigest)) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != expectedCurrent || state.PreviousID != expectedCurrent {
		return ErrUpgradeJournalConflict
	}
	if baselineID == "" {
		if err := s.activationWriter.RemoveActivationLink(ActivationLinkPreviousActive); err != nil {
			return err
		}
		after, err := s.ReadActivationState(context.Background())
		if err != nil || after.PreviousID != "" || after.PreviousJSONSHA256 != "" {
			return ErrUpgradeJournalConflict
		}
		return nil
	}
	_, digest, err := s.readActivation(baselineID)
	if err != nil || digest != baselineDigest {
		return ErrUpgradeJournalConflict
	}
	if state.PreviousID == baselineID && state.PreviousJSONSHA256 == baselineDigest {
		return nil
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, baselineID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != expectedCurrent || after.PreviousID != baselineID || after.PreviousJSONSHA256 != baselineDigest {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) SwapActive(_ context.Context, candidateID string) error {
	if !s.ownsLock() || !validID(candidateID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.PreviousID == "" {
		return ErrUpgradeJournalConflict
	}
	_, candidateDigest, err := s.readActivation(candidateID)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkActive, candidateID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != candidateID || after.ActiveActivationJSONSHA256 != candidateDigest || after.PreviousID != state.PreviousID || after.PreviousJSONSHA256 != state.PreviousJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}
func (s *UpgradeStore) RestoreActive(_ context.Context, oldID, expectedCandidateID string) error {
	if !s.ownsLock() || !validID(oldID) || !validID(expectedCandidateID) {
		return ErrUpgradeJournalConflict
	}
	state, err := s.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != expectedCandidateID || state.PreviousID != oldID {
		return ErrUpgradeJournalConflict
	}
	_, oldDigest, err := s.readActivation(oldID)
	if err != nil {
		return ErrUpgradeJournalConflict
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkActive, oldID, ""); err != nil {
		return err
	}
	if err := s.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, expectedCandidateID, ""); err != nil {
		return err
	}
	after, err := s.ReadActivationState(context.Background())
	if err != nil || after.ActiveID != oldID || after.ActiveActivationJSONSHA256 != oldDigest || after.PreviousID != expectedCandidateID || after.PreviousJSONSHA256 != state.ActiveActivationJSONSHA256 {
		return ErrUpgradeJournalConflict
	}
	return nil
}

var _ UpgradeJournalStore = (*UpgradeStore)(nil)
