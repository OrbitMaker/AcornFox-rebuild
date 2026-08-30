package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type backupLockFake struct {
	pending  PendingTransaction
	acquires int
	released int
	err      error
	release  error
}

type backupLockHandle struct{ owner *backupLockFake }

func (l *backupLockHandle) Release() error { l.owner.released++; return l.owner.release }
func (l *backupLockFake) Acquire(context.Context, string) (UpgradeLock, error) {
	l.acquires++
	if l.err != nil {
		return nil, l.err
	}
	return &backupLockHandle{owner: l}, nil
}
func (l *backupLockFake) PendingTransaction(context.Context) (PendingTransaction, error) {
	return l.pending, nil
}

type backupResolverFake struct {
	values []ResolvedActiveDatabase
	err    error
	calls  int
}

func (r *backupResolverFake) ResolveResolved() (ResolvedActiveDatabase, error) {
	if r.err != nil {
		return ResolvedActiveDatabase{}, r.err
	}
	if len(r.values) == 0 {
		return ResolvedActiveDatabase{}, errors.New("no active identity")
	}
	v := r.values[0]
	if len(r.values) > 1 {
		r.values = r.values[1:]
	}
	r.calls++
	return v, nil
}

func backupActive(t *testing.T, id string) ResolvedActiveDatabase {
	t.Helper()
	databaseEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user%40name:pa%2Fss@127.0.0.1:5432/open_card?sslmode=require\n")
	a := activationFixture()
	a.ActivationID = id
	a.DatabaseEnvSHA256 = sha256Bytes(databaseEnv)
	raw, err := MarshalActivationV1(a)
	if err != nil {
		t.Fatal(err)
	}
	return ResolvedActiveDatabase{Activation: a, ActivationJSONSHA256: sha256Bytes(raw), DatabaseEnv: databaseEnv}
}

func backupManager(t *testing.T, resolver *backupResolverFake, pg *fakePG) (*BackupManager, string, *backupLockFake) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	lock := &backupLockFake{pending: PendingTransaction{Marker: UpgradeMarkerAbsent}}
	m, err := TaskBackupManager(lock, resolver, snap(t, pg), writer)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Unix(1, 0).UTC() }
	return m, root, lock
}

func dumpWriter(payload string) func([]string) {
	return func(argv []string) {
		for i := range argv {
			if argv[i] == "--file" && i+1 < len(argv) {
				_ = os.WriteFile(argv[i+1], []byte(payload), durableFileMode)
				return
			}
		}
	}
}

func TestBackupManagerCreatesMetadataLastAndReplaysExactBackup(t *testing.T) {
	t.Setenv("OPEN_CARD_DATABASE_URL", "postgresql://ambient:must-not-be-used@127.0.0.1:5432/ambient")
	active := backupActive(t, "activation-backup")
	resolver := &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}
	pg := &fakePG{write: dumpWriter("custom-backup")}
	m, root, lock := backupManager(t, resolver, pg)
	request := BackupCreateRequest{BackupID: "backup-1", Reason: "pre_upgrade"}
	metadata, err := m.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BackupID != request.BackupID || metadata.DumpSize != int64(len("custom-backup")) || metadata.SourceDatabase.Name != "open_card" || strings.Contains(strings.Join(pg.argv, " "), "pa%2Fss") || strings.Contains(strings.Join(pg.env, "\n"), "OPEN_CARD_DATABASE_URL") || strings.Contains(strings.Join(pg.env, "\n"), "must-not-be-used") {
		t.Fatalf("metadata=%+v argv=%q env=%q", metadata, pg.argv, pg.env)
	}
	if got, err := m.Inspect(context.Background(), request.BackupID); err != nil || got != metadata {
		t.Fatalf("inspect=%+v err=%v", got, err)
	}
	// A completed backup is idempotent only when the same active identity and
	// bounded reason are observed again.
	resolver.values = []ResolvedActiveDatabase{active}
	if replay, err := m.Create(context.Background(), request); err != nil || replay != metadata {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	_, statErr := os.Lstat(filepath.Join(root, request.BackupID, "backup.json"))
	if lock.released != 2 || statErr != nil {
		t.Fatalf("lock releases=%d metadata err=%v", lock.released, statErr)
	}
}

func TestBackupManagerRejectsMarkerDriftPartialAndUnsafeMetadata(t *testing.T) {
	active := backupActive(t, "activation-backup")
	resolver := &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}
	pg := &fakePG{write: dumpWriter("custom-backup")}
	m, root, lock := backupManager(t, resolver, pg)
	lock.pending = PendingTransaction{TransactionID: "upgrade-1", Marker: UpgradeMarkerSame}
	if _, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-marker", Reason: "manual"}); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatal(err)
	}
	lock.pending = PendingTransaction{Marker: UpgradeMarkerAbsent}
	resolver.values = []ResolvedActiveDatabase{active, backupActive(t, "activation-other")}
	if _, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-drift", Reason: "manual"}); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatal(err)
	}
	if _, err := m.Inspect(context.Background(), "backup-drift"); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "backup-partial"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-partial", Reason: "manual"}); !errors.Is(err, ErrBackupConflict) {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "backup-unsafe"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(root, "backup-unsafe", "backup.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Inspect(context.Background(), "backup-unsafe"); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatal(err)
	}
}

func TestBackupManagerFailsClosedWithoutSecretLeaksAndReleasesLock(t *testing.T) {
	active := backupActive(t, "activation-backup")
	resolver := &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}
	pg := &fakePG{result: PostgresRunResult{Err: errors.New("postgresql://leak:secret@bad")}}
	m, root, lock := backupManager(t, resolver, pg)
	_, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-fail", Reason: "manual"})
	if !errors.Is(err, ErrBackupUnavailable) || strings.Contains(err.Error(), "secret") || lock.released != 1 {
		t.Fatalf("err=%v releases=%d", err, lock.released)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "backup-fail", "backup.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("metadata unexpectedly published: %v", statErr)
	}
}

func TestBackupManagerReleaseFailureRequiresExactReplay(t *testing.T) {
	active := backupActive(t, "activation-backup")
	resolver := &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}
	pg := &fakePG{write: dumpWriter("custom-backup")}
	m, _, lock := backupManager(t, resolver, pg)
	lock.release = errors.New("injected release")
	request := BackupCreateRequest{BackupID: "backup-release", Reason: "manual"}
	if metadata, err := m.Create(context.Background(), request); !errors.Is(err, ErrBackupUnavailable) || metadata.BackupID != "" {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	// The durable receipt was already published. Once the shared lock is
	// healthy again, replay must reread it exactly rather than overwrite it.
	lock.release = nil
	metadata, err := m.Create(context.Background(), request)
	if err != nil || metadata.BackupID != request.BackupID || lock.released != 2 {
		t.Fatalf("metadata=%+v err=%v releases=%d", metadata, err, lock.released)
	}
}

func TestBackupMetadataStrictAndSnapshotSyncRejectUnsafeFiles(t *testing.T) {
	activation := activationFixture()
	valid := ActiveDatabaseBackupV2{SchemaVersion: ActiveDatabaseBackupSchemaVersion, BackupID: "backup-1", Reason: "manual", SourceActivationID: activation.ActivationID, SourceActivationJSONSHA256: sha("a"), SourceRelease: activation.Release, SourceDatabase: activation.Database, DatabaseEnvSHA256: sha("b"), DumpFile: ActiveDatabaseBackupDumpFile, DumpSHA256: sha("c"), DumpSize: 1, DumpFormat: ActiveDatabaseBackupDumpFormat, CreatedAt: time.Unix(1, 0).UTC()}
	raw, err := MarshalActiveDatabaseBackupV2(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseActiveDatabaseBackupV2(append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)); err == nil {
		t.Fatal("unknown metadata field accepted")
	}
	path := filepath.Join(t.TempDir(), "dump")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := syncSnapshotEvidence(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := syncSnapshotEvidence(path); err == nil {
		t.Fatal("unsafe dump mode accepted")
	}
}

type backupDumpFaultOps struct {
	durableOps
	fail      string
	syncCalls int
}

func (o *backupDumpFaultOps) Chmod(file *os.File, mode os.FileMode) error {
	if o.fail == "chmod" {
		return errors.New("injected chmod")
	}
	return o.durableOps.Chmod(file, mode)
}
func (o *backupDumpFaultOps) Chown(file *os.File, uid, gid int) error {
	if o.fail == "chown" {
		return errors.New("injected chown")
	}
	return o.durableOps.Chown(file, uid, gid)
}
func (o *backupDumpFaultOps) Sync(file *os.File) error {
	o.syncCalls++
	if (o.fail == "temp-fsync" && o.syncCalls == 1) || (o.fail == "parent-fsync" && o.syncCalls == 2) {
		return errors.New("injected fsync")
	}
	return o.durableOps.Sync(file)
}
func (o *backupDumpFaultOps) Link(oldName, newName string) error {
	if o.fail == "publish" {
		return errors.New("injected publish")
	}
	return o.durableOps.Link(oldName, newName)
}
func (o *backupDumpFaultOps) Remove(name string) error {
	if o.fail == "remove-temp" && strings.HasPrefix(name, ".open-card-backup-dump-") {
		return errors.New("injected temp cleanup")
	}
	return o.durableOps.Remove(name)
}

func TestBackupManagerDumpDurabilityFaultsPublishNoMetadataBeforeSuccess(t *testing.T) {
	for _, failure := range []string{"chmod", "chown", "temp-fsync", "publish", "remove-temp"} {
		t.Run(failure, func(t *testing.T) {
			active := backupActive(t, "activation-backup")
			pg := &fakePG{write: dumpWriter("custom-backup")}
			m, root, _ := backupManager(t, &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}, pg)
			m.openChild = func(id string) (*DurableWriter, error) {
				child, err := m.writer.OpenChildWriter(id, durableDirMode)
				if err != nil {
					return nil, err
				}
				child.ops = &backupDumpFaultOps{durableOps: child.ops, fail: failure}
				return child, nil
			}
			_, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-fault-" + failure, Reason: "manual"})
			if !errors.Is(err, ErrBackupUnavailable) && !errors.Is(err, ErrBackupConflict) {
				t.Fatalf("err=%v", err)
			}
			if _, statErr := os.Lstat(filepath.Join(root, "backup-fault-"+failure, activeDatabaseBackupMetadataName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("metadata published after %s: %v", failure, statErr)
			}
		})
	}
}

func TestBackupManagerReconcilesPostPublishDirectorySyncUnknown(t *testing.T) {
	active := backupActive(t, "activation-backup")
	pg := &fakePG{write: dumpWriter("custom-backup")}
	m, root, _ := backupManager(t, &backupResolverFake{values: []ResolvedActiveDatabase{active, active}}, pg)
	m.openChild = func(id string) (*DurableWriter, error) {
		child, err := m.writer.OpenChildWriter(id, durableDirMode)
		if err != nil {
			return nil, err
		}
		child.ops = &backupDumpFaultOps{durableOps: child.ops, fail: "parent-fsync"}
		return child, nil
	}
	metadata, err := m.Create(context.Background(), BackupCreateRequest{BackupID: "backup-parent-sync", Reason: "manual"})
	if err != nil || metadata.DumpFile != ActiveDatabaseBackupDumpFile {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "backup-parent-sync", ActiveDatabaseBackupDumpFile)); err != nil {
		t.Fatal(err)
	}
}
