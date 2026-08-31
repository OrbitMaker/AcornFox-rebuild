package healthcheck

import (
	"context"
	"errors"
	"strings"

	"github.com/open-card/open-card/internal/install"
)

const databaseProbeVersion = "database-v1"

var errDatabaseProbeCanceled = errors.New("database health probe canceled")

// ActiveDatabaseIdentityResolver is the secret-free active activation read
// boundary. Production composition uses install.ActiveDatabaseResolver; task
// callers can supply a fake without constructing filesystem metadata.
type ActiveDatabaseIdentityResolver interface {
	ResolveResolved() (install.ResolvedActiveDatabase, error)
}

// ActiveDatabaseConnection is the smallest selected-database inspection
// boundary. Its methods expose only the database name and canonical migration
// rows; a DSN cannot cross this interface.
type ActiveDatabaseConnection interface {
	CurrentDatabase(context.Context) (string, error)
	MigrationRows(context.Context) ([]install.MigrationRow, error)
	Close() error
}

// ActiveDatabaseConnectionFactory opens exactly the connection selected by a
// resolved activation's database.env. The bytes are never serialized or used
// as a health subject.
type ActiveDatabaseConnectionFactory func([]byte) (ActiveDatabaseConnection, error)

// NewProductionDatabaseProbe composes the fixed production active resolver
// with the selected-database adapter. It intentionally does not install a
// timer, systemd unit, or collector wiring.
func NewProductionDatabaseProbe() (HostProbe, error) {
	resolver, err := install.ProductionActiveDatabaseResolver()
	if err != nil {
		return HostProbe{}, errLocalProbeFailed
	}
	return NewTaskDatabaseProbe(resolver, func(databaseEnv []byte) (ActiveDatabaseConnection, error) {
		return install.NewSelectedPostgresDatabase(databaseEnv)
	})
}

// NewTaskDatabaseProbe creates the active PostgreSQL identity probe with
// explicit resolver and connection seams. It has no fallback to PG* process
// environment variables or an ambient database URL.
func NewTaskDatabaseProbe(resolver ActiveDatabaseIdentityResolver, open ActiveDatabaseConnectionFactory) (HostProbe, error) {
	if resolver == nil || open == nil {
		return HostProbe{}, errLocalProbeFailed
	}
	return HostProbe{Kind: CheckDatabase, Check: func(ctx context.Context) (HostFact, error) {
		if databaseProbeCanceled(ctx) {
			return databaseFact("", "canceled", SeverityCritical), errDatabaseProbeCanceled
		}

		before, err := resolver.ResolveResolved()
		if err != nil {
			return databaseFact("", "activation_unavailable", SeverityCritical), nil
		}
		identity, ok := databaseActivationIdentity(before)
		if !ok {
			return databaseFact(before.ActivationJSONSHA256, "activation_invalid", SeverityEmergency), nil
		}

		connection, err := open(append([]byte(nil), before.DatabaseEnv...))
		if err != nil || connection == nil {
			return databaseFact(identity, "connection_unavailable", SeverityCritical), nil
		}

		fact, checkErr := checkSelectedDatabase(ctx, connection, before.Activation, identity)
		closeErr := connection.Close()
		if databaseProbeCanceled(ctx) {
			return databaseFact(identity, "canceled", SeverityCritical), errDatabaseProbeCanceled
		}
		if closeErr != nil {
			return databaseFact(identity, "close_ambiguous", SeverityCritical), nil
		}
		if checkErr != nil {
			return databaseFact(identity, "canceled", SeverityCritical), errDatabaseProbeCanceled
		}

		after, err := resolver.ResolveResolved()
		if err != nil {
			return databaseFact(identity, "activation_recheck_unavailable", SeverityCritical), nil
		}
		if !sameActivationJSONIdentity(before, after) {
			return databaseFact(identity, "active_identity_drift", SeverityEmergency), nil
		}
		return fact, nil
	}}, nil
}

func checkSelectedDatabase(ctx context.Context, connection ActiveDatabaseConnection, activation install.ActivationV1, identity string) (HostFact, error) {
	name, err := connection.CurrentDatabase(ctx)
	if databaseProbeCanceled(ctx) {
		return databaseFact(identity, "canceled", SeverityCritical), errDatabaseProbeCanceled
	}
	if err != nil {
		return databaseFact(identity, "current_database_unavailable", SeverityCritical), nil
	}
	if name != activation.Database.Name {
		return databaseFact(identity, "database_identity_mismatch", SeverityEmergency), nil
	}

	expectedRows, supported := supportedMigrationRows(activation.Database.Migration)
	if !supported || !validHealthSHA256(activation.Database.SchemaMigrationsSHA256) {
		return databaseFact(identity, "schema_expectation_invalid", SeverityEmergency), nil
	}
	rows, err := connection.MigrationRows(ctx)
	if databaseProbeCanceled(ctx) {
		return databaseFact(identity, "canceled", SeverityCritical), errDatabaseProbeCanceled
	}
	if err != nil {
		return databaseFact(identity, "migration_rows_unavailable", SeverityCritical), nil
	}
	if len(rows) != expectedRows {
		return databaseFact(identity, "schema_row_count_mismatch", SeverityEmergency), nil
	}
	digest, err := install.CanonicalMigrationRowsSHA256(rows)
	if err != nil {
		return databaseFact(identity, "schema_rows_invalid", SeverityEmergency), nil
	}
	if digest != activation.Database.SchemaMigrationsSHA256 {
		return databaseFact(identity, "schema_checksum_mismatch", SeverityEmergency), nil
	}
	return databaseFact(identity, "healthy", SeverityOK), nil
}

func supportedMigrationRows(migration string) (int, bool) {
	switch migration {
	case "0023":
		return 23, true
	case "0024":
		return 24, true
	default:
		return 0, false
	}
}

func databaseActivationIdentity(value install.ResolvedActiveDatabase) (string, bool) {
	if !validHealthSHA256(value.ActivationJSONSHA256) || value.Activation.Database.Name == "" || !validHealthSHA256(value.Activation.Database.SchemaMigrationsSHA256) {
		return value.ActivationJSONSHA256, false
	}
	if _, ok := supportedMigrationRows(value.Activation.Database.Migration); !ok {
		return value.ActivationJSONSHA256, false
	}
	return value.ActivationJSONSHA256, true
}

func sameActivationJSONIdentity(before, after install.ResolvedActiveDatabase) bool {
	return validHealthSHA256(after.ActivationJSONSHA256) && before.ActivationJSONSHA256 == after.ActivationJSONSHA256
}

func databaseProbeCanceled(ctx context.Context) bool {
	return ctx == nil || ctx.Err() != nil
}

func databaseFact(identity, cause string, severity Severity) HostFact {
	if !validHealthSHA256(identity) {
		identity = strings.Repeat("0", 64)
	}
	return HostFact{Subject: databaseProbeVersion + ":" + identity + ":" + cause, Severity: severity}
}

func validHealthSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}
