package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

type databaseResolverFake struct {
	values []install.ResolvedActiveDatabase
	err    error
	calls  int
}

func (f *databaseResolverFake) ResolveResolved() (install.ResolvedActiveDatabase, error) {
	f.calls++
	if f.err != nil {
		return install.ResolvedActiveDatabase{}, f.err
	}
	if len(f.values) == 0 {
		return install.ResolvedActiveDatabase{}, errors.New("missing fixture")
	}
	value := f.values[0]
	if len(f.values) > 1 {
		f.values = f.values[1:]
	}
	return value, nil
}

type databaseConnectionFake struct {
	current    string
	currentErr error
	rows       []install.MigrationRow
	rowsErr    error
	closeErr   error
	closes     int
}

func (f *databaseConnectionFake) CurrentDatabase(context.Context) (string, error) {
	return f.current, f.currentErr
}
func (f *databaseConnectionFake) MigrationRows(context.Context) ([]install.MigrationRow, error) {
	return append([]install.MigrationRow(nil), f.rows...), f.rowsErr
}
func (f *databaseConnectionFake) Close() error { f.closes++; return f.closeErr }

func healthMigrationRows(n int) []install.MigrationRow {
	rows := make([]install.MigrationRow, n)
	for i := range rows {
		rows[i] = install.MigrationRow{Version: fmt.Sprintf("%04d", i+1), Checksum: fmt.Sprintf("%064x", i+1)}
	}
	return rows
}

func databaseProbeFixture(t *testing.T) (install.ResolvedActiveDatabase, []install.MigrationRow) {
	t.Helper()
	rows := healthMigrationRows(24)
	digest, err := install.CanonicalMigrationRowsSHA256(rows)
	if err != nil {
		t.Fatal(err)
	}
	return install.ResolvedActiveDatabase{
		Activation:           install.ActivationV1{Database: install.DatabaseV1{Name: "open_card_act_0123456789abcdef", Migration: "0024", SchemaMigrationsSHA256: digest}},
		ActivationJSONSHA256: strings.Repeat("a", 64),
		DatabaseEnv:          []byte("OPEN_CARD_DATABASE_URL=postgresql://user:password@db.invalid/open_card_act_0123456789abcdef\n"),
	}, rows
}

func databaseProbe(t *testing.T, resolver *databaseResolverFake, connection *databaseConnectionFake, seenEnv *[]byte) HostProbe {
	t.Helper()
	probe, err := NewTaskDatabaseProbe(resolver, func(databaseEnv []byte) (ActiveDatabaseConnection, error) {
		*seenEnv = append([]byte(nil), databaseEnv...)
		return connection, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

func TestDatabaseProbeVerifiesActiveDatabaseAndCanonicalMigrationDigest(t *testing.T) {
	for _, tc := range []struct {
		migration string
		rowCount  int
	}{{"0023", 23}, {"0024", 24}} {
		t.Run(tc.migration, func(t *testing.T) {
			resolved, _ := databaseProbeFixture(t)
			rows := healthMigrationRows(tc.rowCount)
			digest, err := install.CanonicalMigrationRowsSHA256(rows)
			if err != nil {
				t.Fatal(err)
			}
			resolved.Activation.Database.Migration = tc.migration
			resolved.Activation.Database.SchemaMigrationsSHA256 = digest
			resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}
			connection := &databaseConnectionFake{current: resolved.Activation.Database.Name, rows: rows}
			var seenEnv []byte
			fact, err := databaseProbe(t, resolver, connection, &seenEnv).Check(context.Background())
			if err != nil || fact.Severity != SeverityOK || fact.Subject != databaseProbeVersion+":"+strings.Repeat("a", 64)+":healthy" || resolver.calls != 2 || connection.closes != 1 {
				t.Fatalf("fact=%+v err=%v resolver_calls=%d closes=%d", fact, err, resolver.calls, connection.closes)
			}
			if string(seenEnv) != string(resolved.DatabaseEnv) || strings.Contains(fact.Subject, "password") || strings.Contains(fact.Subject, "db.invalid") {
				t.Fatalf("env=%q subject=%q", seenEnv, fact.Subject)
			}
		})
	}
}

func TestDatabaseProbeClassifiesOperationalAndIdentityFailuresWithoutSecrets(t *testing.T) {
	resolved, rows := databaseProbeFixture(t)
	different := resolved
	different.ActivationJSONSHA256 = strings.Repeat("b", 64)
	for _, tc := range []struct {
		name     string
		resolver *databaseResolverFake
		mutate   func(*databaseConnectionFake)
		want     string
		severity Severity
	}{
		{"resolver", &databaseResolverFake{err: errors.New("postgresql://user:password@secret.invalid/db")}, nil, "activation_unavailable", SeverityCritical},
		{"current database", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func(f *databaseConnectionFake) { f.currentErr = errors.New("password-secret") }, "current_database_unavailable", SeverityCritical},
		{"migration query", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func(f *databaseConnectionFake) { f.rowsErr = errors.New("password-secret") }, "migration_rows_unavailable", SeverityCritical},
		{"database identity", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func(f *databaseConnectionFake) { f.current = "other_database" }, "database_identity_mismatch", SeverityEmergency},
		{"row gap", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func(f *databaseConnectionFake) { f.rows = append(rows[:7:7], rows[8:]...) }, "schema_row_count_mismatch", SeverityEmergency},
		{"checksum", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}, func(f *databaseConnectionFake) { f.rows[5].Checksum = strings.Repeat("f", 64) }, "schema_checksum_mismatch", SeverityEmergency},
		{"pointer drift", &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, different}}, nil, "active_identity_drift", SeverityEmergency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &databaseConnectionFake{current: resolved.Activation.Database.Name, rows: append([]install.MigrationRow(nil), rows...)}
			if tc.mutate != nil {
				tc.mutate(connection)
			}
			var seenEnv []byte
			fact, err := databaseProbe(t, tc.resolver, connection, &seenEnv).Check(context.Background())
			if err != nil || fact.Severity != tc.severity || !strings.HasSuffix(fact.Subject, ":"+tc.want) || strings.Contains(fact.Subject, "password") || strings.Contains(fact.Subject, "secret") {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
			if tc.name != "resolver" && (tc.resolver.calls != 2 || connection.closes != 1 || string(seenEnv) != string(resolved.DatabaseEnv)) {
				t.Fatalf("resolver_calls=%d closes=%d env=%q", tc.resolver.calls, connection.closes, seenEnv)
			}
		})
	}
}

func TestDatabaseProbeTreatsCloseAmbiguityAndCancellationAsUnhealthy(t *testing.T) {
	resolved, rows := databaseProbeFixture(t)
	resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved, resolved}}
	connection := &databaseConnectionFake{current: resolved.Activation.Database.Name, rows: rows, closeErr: errors.New("close password-secret")}
	var seenEnv []byte
	fact, err := databaseProbe(t, resolver, connection, &seenEnv).Check(context.Background())
	if err != nil || fact.Severity != SeverityCritical || !strings.HasSuffix(fact.Subject, ":close_ambiguous") || connection.closes != 1 {
		t.Fatalf("fact=%+v err=%v closes=%d", fact, err, connection.closes)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver = &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved}}
	connection = &databaseConnectionFake{current: resolved.Activation.Database.Name, rows: rows}
	fact, err = databaseProbe(t, resolver, connection, &seenEnv).Check(ctx)
	if !errors.Is(err, errDatabaseProbeCanceled) || fact.Severity != SeverityCritical || resolver.calls != 0 || connection.closes != 0 {
		t.Fatalf("fact=%+v err=%v resolver_calls=%d closes=%d", fact, err, resolver.calls, connection.closes)
	}
}

func TestDatabaseProbeTreatsConnectionAndMigrationVersionDriftAsUnhealthy(t *testing.T) {
	resolved, rows := databaseProbeFixture(t)
	resolver := &databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved}}
	probe, err := NewTaskDatabaseProbe(resolver, func([]byte) (ActiveDatabaseConnection, error) {
		return nil, errors.New("postgresql://user:password@secret.invalid/db")
	})
	if err != nil {
		t.Fatal(err)
	}
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityCritical || !strings.HasSuffix(fact.Subject, ":connection_unavailable") || strings.Contains(fact.Subject, "secret") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}

	drifted := resolved
	drifted.Activation.Database.Migration = "0023"
	resolver = &databaseResolverFake{values: []install.ResolvedActiveDatabase{drifted, drifted}}
	connection := &databaseConnectionFake{current: drifted.Activation.Database.Name, rows: rows}
	var seenEnv []byte
	fact, err = databaseProbe(t, resolver, connection, &seenEnv).Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.HasSuffix(fact.Subject, ":schema_row_count_mismatch") || resolver.calls != 2 {
		t.Fatalf("fact=%+v err=%v resolver_calls=%d", fact, err, resolver.calls)
	}
}

func TestDatabaseProbeRejectsInvalidDependencies(t *testing.T) {
	if _, err := NewTaskDatabaseProbe(nil, func([]byte) (ActiveDatabaseConnection, error) { return nil, nil }); err == nil {
		t.Fatal("nil resolver accepted")
	}
	resolved, _ := databaseProbeFixture(t)
	if _, err := NewTaskDatabaseProbe(&databaseResolverFake{values: []install.ResolvedActiveDatabase{resolved}}, nil); err == nil {
		t.Fatal("nil opener accepted")
	}
}
