package healthcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const backupSubjectVersion = "backup_health_v1"

// LatestBackupSource is the narrow health-read boundary for the latest fully
// verified database backup. install.BackupManager satisfies it directly.
// Scheduling and production lifetime ownership intentionally stay outside the
// health package.
type LatestBackupSource interface {
	Latest(context.Context) (install.ActiveDatabaseBackupV2, error)
}

// NewTaskBackupProbe creates the task-testable Gate7 backup freshness probe.
// It does not construct or retain a BackupManager, so production composition
// owns the manager's privileged root and its Close lifecycle.
func NewTaskBackupProbe(source LatestBackupSource, clock func() time.Time) (HostProbe, error) {
	if source == nil || clock == nil {
		return HostProbe{}, errors.New("backup probe dependencies are required")
	}
	return HostProbe{Kind: CheckBackup, Check: func(ctx context.Context) (HostFact, error) {
		return checkBackup(ctx, source, clock)
	}}, nil
}

func checkBackup(ctx context.Context, source LatestBackupSource, clock func() time.Time) (HostFact, error) {
	if ctx == nil {
		return backupEmergencyFact("cancelled", ""), errors.New("backup probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return backupEmergencyFact("cancelled", ""), err
	}
	backup, err := source.Latest(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return backupEmergencyFact("cancelled", ""), ctx.Err()
		}
		return backupEmergencyFact("source_failure", ""), nil
	}
	if err := ctx.Err(); err != nil {
		return backupEmergencyFact("cancelled", ""), err
	}
	if backup.BackupID == "" {
		return backupEmergencyFact("missing_backup", ""), nil
	}
	if backup.Validate() != nil {
		return backupEmergencyFact("invalid_metadata", ""), nil
	}
	receiptDigest, err := canonicalBackupReceiptDigest(backup)
	if err != nil {
		return backupEmergencyFact("invalid_metadata", ""), nil
	}
	now := clock().UTC() // Capture one observation instant for this receipt.
	if now.IsZero() {
		return backupEmergencyFact("clock_failure", receiptDigest), nil
	}
	age := now.Sub(backup.CreatedAt.UTC())
	if age < 0 {
		return backupEmergencyFact("future_backup", receiptDigest), nil
	}
	return HostFact{Subject: backupSubject("healthy", receiptDigest), Severity: BackupSeverity(age, true)}, nil
}

func canonicalBackupReceiptDigest(backup install.ActiveDatabaseBackupV2) (string, error) {
	raw, err := install.MarshalActiveDatabaseBackupV2(backup)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func backupEmergencyFact(cause, receiptDigest string) HostFact {
	return HostFact{Subject: backupSubject(cause, receiptDigest), Severity: SeverityEmergency}
}

// backupSubject never exposes receipt fields. Healthy and stale observations
// retain the canonical receipt digest; observations without a valid receipt use
// a deterministic digest of only the fixed schema and cause.
func backupSubject(cause, receiptDigest string) string {
	if receiptDigest == "" {
		sum := sha256.Sum256([]byte(backupSubjectVersion + "\n" + cause))
		receiptDigest = hex.EncodeToString(sum[:])
	}
	return backupSubjectVersion + ":" + cause + ":" + receiptDigest
}
