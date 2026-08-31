package healthcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

type latestBackupSourceFunc func(context.Context) (install.ActiveDatabaseBackupV2, error)

func (f latestBackupSourceFunc) Latest(ctx context.Context) (install.ActiveDatabaseBackupV2, error) {
	return f(ctx)
}

func TestTaskBackupProbeClassifiesFreshnessBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		age  time.Duration
		want Severity
	}{
		{"exact_24_hours", 24 * time.Hour, SeverityOK},
		{"over_24_hours", 24*time.Hour + time.Nanosecond, SeverityWarning},
		{"exact_48_hours", 48 * time.Hour, SeverityWarning},
		{"over_48_hours", 48*time.Hour + time.Nanosecond, SeverityCritical},
		{"exact_72_hours", 72 * time.Hour, SeverityCritical},
		{"over_72_hours", 72*time.Hour + time.Nanosecond, SeverityEmergency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backup := healthBackupFixture(now.Add(-tc.age))
			probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) { return backup, nil }), func() time.Time { return now })
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != tc.want || !strings.Contains(fact.Subject, ":healthy:") {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
}

func TestTaskBackupProbeFailsClosedWithoutLeakingReceiptOrSourceDetails(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	valid := healthBackupFixture(now.Add(-time.Hour))
	secret := "postgresql://user:super-secret-value@db.invalid/open-card"
	invalid := valid
	invalid.DumpFile = "private/path/backup.dump"
	for _, tc := range []struct {
		name   string
		backup install.ActiveDatabaseBackupV2
		err    error
		cause  string
	}{
		{"missing", install.ActiveDatabaseBackupV2{}, nil, "missing_backup"},
		{"source_failure", install.ActiveDatabaseBackupV2{}, errors.New(secret), "source_failure"},
		{"future", healthBackupFixture(now.Add(time.Nanosecond)), nil, "future_backup"},
		{"invalid", invalid, nil, "invalid_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) { return tc.backup, tc.err }), func() time.Time { return now })
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, ":"+tc.cause+":") {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
			for _, forbidden := range []string{secret, valid.BackupID, valid.SourceDatabase.Name, invalid.DumpFile} {
				if strings.Contains(fact.Subject, forbidden) {
					t.Fatalf("unsafe subject=%q contains %q", fact.Subject, forbidden)
				}
			}
		})
	}
}

func TestTaskBackupProbeUsesCanonicalReceiptDigestAndOneClockRead(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	backup := healthBackupFixture(now.Add(-time.Hour))
	var clockCalls int
	probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) { return backup, nil }), func() time.Time {
		clockCalls++
		return now
	})
	fact, err := probe.Check(context.Background())
	if err != nil || clockCalls != 1 {
		t.Fatalf("fact=%+v err=%v clock calls=%d", fact, err, clockCalls)
	}
	raw, err := install.MarshalActiveDatabaseBackupV2(backup)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want := backupSubjectVersion + ":healthy:" + hex.EncodeToString(sum[:])
	if fact.Subject != want || strings.Contains(fact.Subject, backup.BackupID) || strings.Contains(fact.Subject, backup.SourceDatabase.Name) {
		t.Fatalf("subject=%q want=%q", fact.Subject, want)
	}
}

func TestTaskBackupProbeCancellationDoesNotPersistCollectorState(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) {
		t.Fatal("cancelled context called source")
		return install.ActiveDatabaseBackupV2{}, nil
	}), func() time.Time { return now })
	fact, err := probe.Check(ctx)
	if !errors.Is(err, context.Canceled) || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, ":cancelled:") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}

	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	complete := collectorProbes(nil, nil)
	for index := range complete {
		if complete[index].Kind == CheckBackup {
			complete[index] = probe
		}
	}
	collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Evaluate(ctx); err == nil {
		t.Fatal("cancelled backup evaluation succeeded")
	}
	if _, err := os.Lstat(filepath.Join(root, incidentStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled evaluation persisted state: %v", err)
	}
}

func TestTaskBackupProbeReturnsCancellationWhenSourceCancelsContext(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) {
		cancel()
		return healthBackupFixture(now.Add(-time.Hour)), nil
	}), func() time.Time {
		t.Fatal("clock read after cancellation")
		return now
	})
	fact, err := probe.Check(ctx)
	if !errors.Is(err, context.Canceled) || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, ":cancelled:") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
}

func TestBackupProbeEmergencyPersistsCollectorIncident(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	secret := "postgresql://user:super-secret-value@db.invalid/open-card"
	probe := taskBackupProbe(t, latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) {
		return install.ActiveDatabaseBackupV2{}, errors.New(secret)
	}), func() time.Time { return now })
	complete := collectorProbes(nil, nil)
	for index := range complete {
		if complete[index].Kind == CheckBackup {
			complete[index] = probe
		}
	}
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := collector.Evaluate(context.Background())
	if err != nil || !evaluation.Decision.Notify || evaluation.Snapshot.Overall != SeverityEmergency {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, incidentStateFile))
	if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "postgresql") {
		t.Fatalf("state=%q err=%v", raw, err)
	}
}

func TestTaskBackupProbeRejectsInvalidDependencies(t *testing.T) {
	if _, err := NewTaskBackupProbe(nil, func() time.Time { return time.Now().UTC() }); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := NewTaskBackupProbe(latestBackupSourceFunc(func(context.Context) (install.ActiveDatabaseBackupV2, error) {
		return install.ActiveDatabaseBackupV2{}, nil
	}), nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}

func taskBackupProbe(t *testing.T, source LatestBackupSource, clock func() time.Time) HostProbe {
	t.Helper()
	probe, err := NewTaskBackupProbe(source, clock)
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

func healthBackupFixture(createdAt time.Time) install.ActiveDatabaseBackupV2 {
	return install.ActiveDatabaseBackupV2{
		SchemaVersion:              install.ActiveDatabaseBackupSchemaVersion,
		BackupID:                   "backup-20260831-a1",
		CreatedAt:                  createdAt.UTC(),
		Reason:                     "pre-upgrade-rc1",
		SourceActivationID:         "activation-1",
		SourceActivationJSONSHA256: strings.Repeat("a", 64),
		SourceRelease: install.ReleaseV1{
			ID: "release-rc1", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("b", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("c", 64),
		},
		SourceDatabase:    install.DatabaseV1{Name: "open_card_act_1234567890abcdef", Migration: "0024", SchemaMigrationsSHA256: strings.Repeat("d", 64)},
		DatabaseEnvSHA256: strings.Repeat("e", 64),
		DumpFile:          install.ActiveDatabaseBackupDumpFile,
		DumpSHA256:        strings.Repeat("f", 64),
		DumpSize:          123,
		DumpFormat:        install.ActiveDatabaseBackupDumpFormat,
	}
}
