package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rejectingActiveBackupLock struct{}

func (rejectingActiveBackupLock) Acquire(context.Context, string) (UpgradeLock, error) {
	return rejectingActiveBackupLock{}, nil
}
func (rejectingActiveBackupLock) PendingTransaction(context.Context) (PendingTransaction, error) {
	return PendingTransaction{Marker: UpgradeMarkerAbsent}, nil
}
func (rejectingActiveBackupLock) Release() error { return nil }

type activeBackupRunner struct{ calls int }

func (r *activeBackupRunner) Run(context.Context, []string, []string) PostgresRunResult {
	r.calls++
	return PostgresRunResult{Err: errors.New("backup runner must not execute")}
}

func activeDatabaseFixture(t *testing.T) (*ActiveDatabaseResolver, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	activationID, releaseID := "activation-1", "release-1"
	for _, directory := range []struct {
		name string
		mode os.FileMode
	}{
		{"activations", 0o711},
		{"releases", 0o755},
		{filepath.Join("activations", activationID), 0o711},
		{filepath.Join("releases", releaseID), 0o755},
	} {
		if err := os.Mkdir(filepath.Join(root, directory.name), directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	dsn := "postgresql://admin:secret@127.0.0.1:5432/open_card?sslmode=disable"
	databaseEnv, err := FormatDatabaseEnv(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(databaseEnv)
	activation := ActivationV1{
		SchemaVersion:          ActivationSchemaVersion,
		ActivationID:           activationID,
		Origin:                 "native",
		Release:                ReleaseV1{ID: releaseID, Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "arm64", ManifestSHA256: sha("b")},
		Database:               DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: sha("c")},
		DatabaseEnvSHA256:      hex.EncodeToString(sum[:]),
		CreatedAt:              time.Unix(1, 0).UTC(),
		CreatedByTransactionID: "txn-1",
	}
	activationRaw, err := MarshalActivationV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "activations", activationID)
	if err := os.WriteFile(filepath.Join(base, "activation.json"), activationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "database.env"), databaseEnv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../releases/"+releaseID, filepath.Join(base, "release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("activations/"+activationID, filepath.Join(root, "active")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("active/release", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	resolver, err := TaskActiveDatabaseResolver(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	return resolver, root, dsn
}

func TestActiveDatabaseResolverReturnsOnlyCoherentActiveIdentity(t *testing.T) {
	resolver, _, dsn := activeDatabaseFixture(t)
	resolved, err := resolver.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Activation.ActivationID != "activation-1" || resolved.Activation.Release.ID != "release-1" || resolved.DatabaseURL != dsn {
		t.Fatalf("resolved unexpected active identity: %+v", resolved.Activation)
	}
	if _, err := resolver.ResolveActivation("activation-1"); err != nil {
		t.Fatal(err)
	}
	opaque, err := resolver.ResolveResolved()
	if err != nil {
		t.Fatal(err)
	}
	if opaque.Activation.ActivationID != "activation-1" || !validSHA(opaque.ActivationJSONSHA256) || string(opaque.DatabaseEnv) == "" {
		t.Fatalf("resolved opaque identity is incomplete: %+v", opaque.Activation)
	}
	raw, err := json.Marshal(opaque)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), dsn) || strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), opaque.ActivationJSONSHA256) {
		t.Fatalf("opaque active identity serialized database environment: %s", raw)
	}
	if got, err := resolver.ResolveActivationResolved("activation-1"); err != nil || got.ActivationJSONSHA256 != opaque.ActivationJSONSHA256 {
		t.Fatalf("resolved explicit activation=%+v err=%v", got.Activation, err)
	}
}

func TestActiveDatabaseResolverFailsClosedForPointersAndMetadata(t *testing.T) {
	for _, mutation := range []string{"active", "current", "release", "database-digest", "database-mode", "activation-mode", "activation-corrupt", "activation-collection-0700", "activation-collection-0755", "activation-collection-symlink", "activation-dir-0700", "activation-dir-0755", "activation-dir-symlink", "release-dir-0700", "release-dir-0711", "release-dir-symlink"} {
		t.Run(mutation, func(t *testing.T) {
			resolver, root, _ := activeDatabaseFixture(t)
			base := filepath.Join(root, "activations", "activation-1")
			switch mutation {
			case "active":
				if err := os.Remove(filepath.Join(root, "active")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../outside", filepath.Join(root, "active")); err != nil {
					t.Fatal(err)
				}
			case "current":
				if err := os.Remove(filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/release-1", filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
			case "release":
				if err := os.Remove(filepath.Join(base, "release")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../../releases/other", filepath.Join(base, "release")); err != nil {
					t.Fatal(err)
				}
			case "database-digest":
				if err := os.WriteFile(filepath.Join(base, "database.env"), []byte("OPEN_CARD_DATABASE_URL=postgresql://admin:other@127.0.0.1:5432/open_card?sslmode=disable\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "database-mode":
				if err := os.Chmod(filepath.Join(base, "database.env"), 0o640); err != nil {
					t.Fatal(err)
				}
			case "activation-mode":
				if err := os.Chmod(filepath.Join(base, "activation.json"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "activation-corrupt":
				if err := os.WriteFile(filepath.Join(base, "activation.json"), []byte(`{"schema_version":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "activation-collection-0700":
				if err := os.Chmod(filepath.Join(root, "activations"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "activation-collection-0755":
				if err := os.Chmod(filepath.Join(root, "activations"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "activation-collection-symlink":
				collection := filepath.Join(root, "activations")
				if err := os.Rename(collection, collection+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(collection)+".real", collection); err != nil {
					t.Fatal(err)
				}
			case "activation-dir-0700":
				if err := os.Chmod(base, 0o700); err != nil {
					t.Fatal(err)
				}
			case "activation-dir-0755":
				if err := os.Chmod(base, 0o755); err != nil {
					t.Fatal(err)
				}
			case "activation-dir-symlink":
				if err := os.Rename(base, base+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(base)+".real", base); err != nil {
					t.Fatal(err)
				}
			case "release-dir-0700":
				if err := os.Chmod(filepath.Join(root, "releases", "release-1"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "release-dir-0711":
				if err := os.Chmod(filepath.Join(root, "releases", "release-1"), 0o711); err != nil {
					t.Fatal(err)
				}
			case "release-dir-symlink":
				release := filepath.Join(root, "releases", "release-1")
				if err := os.Rename(release, release+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(release)+".real", release); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := resolver.Resolve(); err == nil {
				t.Fatal("unsafe active identity was accepted")
			}
		})
	}
}

func TestActiveDatabaseResolverRejectsRootOwnerMismatch(t *testing.T) {
	_, root, _ := activeDatabaseFixture(t)
	if _, err := TaskActiveDatabaseResolver(root, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("resolver accepted an unexpected root owner")
	}
}

func TestActiveDatabaseResolverRejectsDatabaseNameDriftBeforeBackupRuns(t *testing.T) {
	resolver, root, _ := activeDatabaseFixture(t)
	base := filepath.Join(root, "activations", "activation-1")
	raw, err := os.ReadFile(filepath.Join(base, "activation.json"))
	if err != nil {
		t.Fatal(err)
	}
	activation, err := ParseActivationV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	activation.Database.Name = "other_database"
	mutated, err := MarshalActivationV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "activation.json"), mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveResolved(); !errors.Is(err, ErrActiveDatabaseUnavailable) {
		t.Fatalf("database-name drift resolution error=%v", err)
	}

	backupRoot := t.TempDir()
	if err := os.Chmod(backupRoot, durableDirMode); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(backupRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	tool := filepath.Join(t.TempDir(), "pg_dump")
	if err := os.WriteFile(tool, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &activeBackupRunner{}
	snapshotter, err := TaskPostgresSnapshotter(tool, runner)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := TaskBackupManager(rejectingActiveBackupLock{}, resolver, snapshotter, writer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), BackupCreateRequest{BackupID: "backup-database-name-drift", Reason: "manual"}); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatalf("backup database-name drift error=%v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("backup runner calls=%d", runner.calls)
	}
	if _, err := os.Lstat(filepath.Join(backupRoot, "backup-database-name-drift", "backup.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup metadata exists after rejected identity: %v", err)
	}
}
