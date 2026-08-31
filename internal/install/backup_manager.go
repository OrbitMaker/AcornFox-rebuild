package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const productionBackupRoot = "/var/lib/open-card/backups"
const backupLatestLockID = "backup-latest-read"

var (
	ErrBackupConflict    = errors.New("backup conflicts with existing state")
	ErrBackupUnavailable = errors.New("backup cannot be safely created")
)

// BackupCreateRequest intentionally permits only an opaque, bounded reason.
// User text and database connection material must never enter backup metadata.
type BackupCreateRequest struct {
	BackupID string
	Reason   string
}

type backupLocker interface {
	Acquire(context.Context, string) (UpgradeLock, error)
	PendingTransaction(context.Context) (PendingTransaction, error)
}
type backupResolver interface {
	ResolveResolved() (ResolvedActiveDatabase, error)
}

// BackupManager owns only backup publication.  It never changes pointers,
// markers, services, journals, or PostgreSQL topology.
type BackupManager struct {
	locker      backupLocker
	resolver    backupResolver
	snapshotter *PostgresSnapshotter
	writer      *DurableWriter
	now         func() time.Time
	close       func() error
	openChild   func(string) (*DurableWriter, error) // test-only fault seam
}

// ProductionBackupManager has no caller-controlled roots, tools, database
// sources, or lock paths.  The backup root and upgrade flock must have been
// provisioned root-owned by the host.
func ProductionBackupManager() (*BackupManager, error) {
	store, err := ProductionUpgradeStore()
	if err != nil {
		return nil, ErrBackupUnavailable
	}
	resolver, err := ProductionActiveDatabaseResolver()
	if err != nil {
		_ = store.Close()
		return nil, ErrBackupUnavailable
	}
	snapshotter, err := ProductionPostgresSnapshotter()
	if err != nil {
		_ = store.Close()
		return nil, ErrBackupUnavailable
	}
	snapshotter.runner = productionPostgresRunner{}
	writer, err := ProductionDurableWriter(productionBackupRoot)
	if err != nil {
		_ = store.Close()
		return nil, ErrBackupUnavailable
	}
	return newBackupManager(store, resolver, snapshotter, writer, time.Now, func() error {
		first := writer.Close()
		if err := store.Close(); err != nil && first == nil {
			first = err
		}
		return first
	})
}

// TaskBackupManager is the explicit test-only dependency seam.  Callers must
// provide a writer rooted at a prepared 0700 task directory plus fake or
// task-scoped lock, resolver, and runner dependencies.
func TaskBackupManager(locker backupLocker, resolver backupResolver, snapshotter *PostgresSnapshotter, writer *DurableWriter) (*BackupManager, error) {
	return newBackupManager(locker, resolver, snapshotter, writer, time.Now, nil)
}

func newBackupManager(locker backupLocker, resolver backupResolver, snapshotter *PostgresSnapshotter, writer *DurableWriter, now func() time.Time, closeFn func() error) (*BackupManager, error) {
	if locker == nil || resolver == nil || snapshotter == nil || snapshotter.runner == nil || writer == nil || now == nil || writer.VerifyLiveRoot() != nil || writer.rootInfo.Mode().Perm() != durableDirMode {
		return nil, ErrBackupUnavailable
	}
	return &BackupManager{locker: locker, resolver: resolver, snapshotter: snapshotter, writer: writer, now: now, close: closeFn}, nil
}

func (m *BackupManager) Close() error {
	if m == nil || m.close == nil {
		return nil
	}
	closeFn := m.close
	m.close = nil
	return closeFn()
}

func (m *BackupManager) Create(ctx context.Context, request BackupCreateRequest) (metadata ActiveDatabaseBackupV2, resultErr error) {
	if m == nil || !validBackupID(request.BackupID) || !validBackupReason(request.Reason) {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	lock, err := m.locker.Acquire(ctx, request.BackupID)
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	defer func() {
		// A published receipt is not a successful API result until the global
		// upgrade flock is released.  Do not conceal a primary create error,
		// but force callers to retry/reconcile an otherwise successful create.
		if releaseErr := lock.Release(); releaseErr != nil && resultErr == nil {
			metadata = ActiveDatabaseBackupV2{}
			resultErr = ErrBackupUnavailable
		}
	}()
	pending, err := m.locker.PendingTransaction(ctx)
	if err != nil || pending.Marker != UpgradeMarkerAbsent {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	before, identity, err := m.resolveIdentity()
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	created, err := m.writer.CreateChildDirectory(request.BackupID, durableDirMode)
	if err != nil {
		return ActiveDatabaseBackupV2{}, reconcileBackupError(err)
	}
	if !created {
		metadata, inspectErr := m.inspect(request.BackupID)
		if inspectErr != nil || !backupMatchesRequest(metadata, request, identity) {
			return ActiveDatabaseBackupV2{}, ErrBackupConflict
		}
		return metadata, nil
	}
	child, err := m.childWriter(request.BackupID)
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	defer child.Close()
	dump, err := m.writeDump(ctx, child, request.BackupID, before.DatabaseEnv)
	if err != nil {
		return ActiveDatabaseBackupV2{}, err
	}
	_, afterIdentity, err := m.resolveIdentity()
	if err != nil || afterIdentity != identity {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	metadata = ActiveDatabaseBackupV2{
		SchemaVersion:              ActiveDatabaseBackupSchemaVersion,
		BackupID:                   request.BackupID,
		CreatedAt:                  m.now().UTC(),
		Reason:                     request.Reason,
		SourceActivationID:         identity.activationID,
		SourceActivationJSONSHA256: identity.activationSHA,
		SourceRelease:              before.Activation.Release,
		SourceDatabase:             before.Activation.Database,
		DatabaseEnvSHA256:          identity.databaseSHA,
		DumpFile:                   ActiveDatabaseBackupDumpFile,
		DumpSHA256:                 dump.SHA256,
		DumpSize:                   dump.Size,
		DumpFormat:                 ActiveDatabaseBackupDumpFormat,
	}
	raw, err := MarshalActiveDatabaseBackupV2(metadata)
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	if err := child.CreateMetadata("backup.json", raw); err != nil {
		if reconciled, inspectErr := m.inspect(request.BackupID); inspectErr == nil && backupMatchesRequest(reconciled, request, identity) && reconciled.DumpSHA256 == dump.SHA256 && reconciled.DumpSize == dump.Size {
			return reconciled, nil
		}
		return ActiveDatabaseBackupV2{}, reconcileBackupError(err)
	}
	return m.inspect(request.BackupID)
}

func (m *BackupManager) childWriter(backupID string) (*DurableWriter, error) {
	if m.openChild != nil {
		return m.openChild(backupID)
	}
	return m.writer.OpenChildWriter(backupID, durableDirMode)
}

func (m *BackupManager) Inspect(_ context.Context, backupID string) (ActiveDatabaseBackupV2, error) {
	if m == nil || !validBackupID(backupID) {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	return m.inspect(backupID)
}

// Latest returns the most recently created fully verified backup below the
// manager's pinned root. Any entry in the managed backup namespace that does
// not satisfy the exact durable backup contract makes the result ambiguous.
func (m *BackupManager) Latest(ctx context.Context) (metadata ActiveDatabaseBackupV2, resultErr error) {
	if m == nil || m.writer == nil || ctx == nil || ctx.Err() != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	lock, err := m.locker.Acquire(ctx, backupLatestLockID)
	if err != nil || lock == nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	defer func() {
		if err := lock.Release(); err != nil && resultErr == nil {
			metadata = ActiveDatabaseBackupV2{}
			resultErr = ErrBackupUnavailable
		}
	}()
	children, err := m.writer.ReadDirectChildren()
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	var latest ActiveDatabaseBackupV2
	found := false
	for _, child := range children {
		if ctx.Err() != nil {
			return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
		}
		// Only the backup-* namespace is managed here. Other direct entries do
		// not participate in discovery and cannot affect its result.
		if !strings.HasPrefix(child.Name, "backup-") {
			continue
		}
		if !validBackupID(child.Name) || child.Mode&os.ModeSymlink != 0 || !child.Mode.IsDir() || child.Mode.Perm() != durableDirMode {
			return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
		}
		metadata, err := m.inspect(child.Name)
		if err != nil {
			return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
		}
		if !found || metadata.CreatedAt.After(latest.CreatedAt) || (metadata.CreatedAt.Equal(latest.CreatedAt) && metadata.BackupID < latest.BackupID) {
			latest = metadata
			found = true
		}
	}
	if !found || ctx.Err() != nil || m.writer.VerifyLiveRoot() != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	return latest, nil
}

func (m *BackupManager) inspect(backupID string) (ActiveDatabaseBackupV2, error) {
	child, err := m.writer.OpenChildWriter(backupID, durableDirMode)
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	defer child.Close()
	raw, err := child.ReadMetadata("backup.json")
	if err != nil {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	metadata, err := ParseActiveDatabaseBackupV2(raw)
	if err != nil || metadata.BackupID != backupID {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	dump, err := readBackupDump(child, ActiveDatabaseBackupDumpFile)
	if err != nil || dump.SHA256 != metadata.DumpSHA256 || dump.Size != metadata.DumpSize {
		return ActiveDatabaseBackupV2{}, ErrBackupUnavailable
	}
	return metadata, nil
}

type backupIdentity struct {
	activationID, activationSHA, databaseSHA, databaseName string
}

func (m *BackupManager) resolveIdentity() (ResolvedActiveDatabase, backupIdentity, error) {
	active, err := m.resolver.ResolveResolved()
	if err != nil {
		return ResolvedActiveDatabase{}, backupIdentity{}, err
	}
	if !validSHA(active.ActivationJSONSHA256) {
		return ResolvedActiveDatabase{}, backupIdentity{}, ErrBackupUnavailable
	}
	env, err := PostgresEnvironment(active.DatabaseEnv)
	if err != nil {
		return ResolvedActiveDatabase{}, backupIdentity{}, err
	}
	databaseDigest := sha256.Sum256(active.DatabaseEnv)
	return active, backupIdentity{active.Activation.ActivationID, active.ActivationJSONSHA256, hex.EncodeToString(databaseDigest[:]), env.Descriptor.Database}, nil
}

func (m *BackupManager) writeDump(ctx context.Context, child *DurableWriter, backupID string, databaseEnv []byte) (SnapshotEvidence, error) {
	env, err := PostgresEnvironment(databaseEnv)
	if err != nil || !validProcessEnv(env) {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	temporaryName := ".open-card-backup-dump-" + backupID
	finalName := ActiveDatabaseBackupDumpFile
	temporary := filepath.Join(child.rootPath, temporaryName)
	file, err := child.ops.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	if err := child.ops.CloseFile(file); err != nil {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = child.ops.Remove(temporaryName)
		}
	}()
	result := m.snapshotter.runner.Run(ctx, []string{m.snapshotter.tool, "--format=custom", "--file", temporary, "--no-owner", "--no-acl"}, append([]string(nil), env.ChildEnv...))
	if result.Err != nil || result.ExitCode != 0 {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	evidence, err := syncBackupDump(child, temporaryName)
	if err != nil {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	// A hard link is destination no-replace and is rooted in child.ops, so a
	// changed pathname ancestor cannot redirect the published dump.  Rename
	// would replace an existing final target and is therefore forbidden here.
	if err := child.ops.Link(temporaryName, finalName); err != nil {
		return SnapshotEvidence{}, ErrBackupConflict
	}
	if err := child.ops.Remove(temporaryName); err != nil {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	cleanup = false
	if err := child.SyncRoot(); err != nil {
		// A parent-directory fsync can report unknown after the hard link was
		// already published.  Reread through the pinned root; the subsequent
		// metadata publication fsync will also cover this directory entry.
		if confirmed, readErr := readBackupDump(child, finalName); readErr != nil || confirmed != evidence {
			return SnapshotEvidence{}, reconcileBackupError(err)
		}
	}
	if confirmed, err := readBackupDump(child, finalName); err != nil || confirmed != evidence {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	return evidence, nil
}

// syncBackupDump keeps the dump verification on an O_NOFOLLOW descriptor
// rooted below the already-pinned backup slot.  It intentionally does not
// reopen the filesystem path after checking it.
func syncBackupDump(child *DurableWriter, name string) (SnapshotEvidence, error) {
	file, err := child.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotEvidence{}, err
	}
	defer child.ops.CloseFile(file)
	if err := child.ops.Chmod(file, durableFileMode); err != nil {
		return SnapshotEvidence{}, err
	}
	if err := child.ops.Chown(file, child.uid, child.gid); err != nil {
		return SnapshotEvidence{}, err
	}
	info, err := child.ops.Stat(file)
	if err != nil || verifyDurableFile(info, child.uid, child.gid) != nil || info.Size() < 1 {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	if err := child.ops.Sync(file); err != nil {
		return SnapshotEvidence{}, err
	}
	return backupDumpEvidence(file, info.Size())
}

func readBackupDump(child *DurableWriter, name string) (SnapshotEvidence, error) {
	file, err := child.ops.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotEvidence{}, err
	}
	defer child.ops.CloseFile(file)
	info, err := child.ops.Stat(file)
	if err != nil || verifyDurableFile(info, child.uid, child.gid) != nil || info.Size() < 1 {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	return backupDumpEvidence(file, info.Size())
}

func backupDumpEvidence(file *os.File, size int64) (SnapshotEvidence, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return SnapshotEvidence{}, err
	}
	content, err := io.ReadAll(file)
	if err != nil || int64(len(content)) != size {
		return SnapshotEvidence{}, ErrBackupUnavailable
	}
	digest := sha256.Sum256(content)
	return SnapshotEvidence{SHA256: hex.EncodeToString(digest[:]), Size: size}, nil
}

func backupMatchesRequest(metadata ActiveDatabaseBackupV2, request BackupCreateRequest, identity backupIdentity) bool {
	return metadata.BackupID == request.BackupID && metadata.Reason == request.Reason && metadata.SourceActivationID == identity.activationID && metadata.SourceActivationJSONSHA256 == identity.activationSHA && metadata.DatabaseEnvSHA256 == identity.databaseSHA && metadata.SourceDatabase.Name == identity.databaseName
}

func reconcileBackupError(err error) error {
	if errors.Is(err, ErrDurableCommitUnknown) {
		return ErrBackupUnavailable
	}
	return ErrBackupUnavailable
}
