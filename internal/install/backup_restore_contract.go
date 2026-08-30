package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

const (
	ActiveDatabaseBackupSchemaVersion = 2
	activeDatabaseBackupMetadataName  = "backup.json"
	ActiveDatabaseBackupDumpFile      = "control-plane.dump"
	ActiveDatabaseBackupDumpFormat    = "postgres-custom"
)

// ActiveDatabaseBackupV2 is the strict, secret-free receipt for one custom
// PostgreSQL dump. The selected activation (rather than ambient process
// environment) is the authoritative source identity.
//
// It intentionally does not include database.env, a DSN, a password, or an
// arbitrary dump path. DumpFile is fixed within <backup-root>/<backup-id>.
type ActiveDatabaseBackupV2 struct {
	SchemaVersion              int        `json:"schema_version"`
	BackupID                   string     `json:"backup_id"`
	CreatedAt                  time.Time  `json:"created_at"`
	Reason                     string     `json:"reason"`
	SourceActivationID         string     `json:"source_activation_id"`
	SourceActivationJSONSHA256 string     `json:"source_activation_json_sha256"`
	SourceRelease              ReleaseV1  `json:"source_release"`
	SourceDatabase             DatabaseV1 `json:"source_database"`
	DatabaseEnvSHA256          string     `json:"database_env_sha256"`
	DumpFile                   string     `json:"dump_file"`
	DumpSHA256                 string     `json:"dump_sha256"`
	DumpSize                   int64      `json:"dump_size"`
	DumpFormat                 string     `json:"dump_format"`
}

// RestoreSourceV1 binds a database restore request to both the immutable
// backup receipt and its dump. It has no path or environment field: BR3 must
// resolve both only below the configured backup root.
type RestoreSourceV1 struct {
	BackupID                   string `json:"backup_id"`
	BackupMetadataSHA256       string `json:"backup_metadata_sha256"`
	DumpSHA256                 string `json:"dump_sha256"`
	SourceActivationID         string `json:"source_activation_id"`
	SourceActivationJSONSHA256 string `json:"source_activation_json_sha256"`
}

// ActivationRestoreSourceV1 is the non-secret receipt reference persisted in
// a newly-created restore activation. BR3 owns adding this to ActivationV1
// and enforcing the origin-specific linkage.
type ActivationRestoreSourceV1 struct {
	BackupID             string `json:"backup_id"`
	BackupMetadataSHA256 string `json:"backup_metadata_sha256"`
}

func (b ActiveDatabaseBackupV2) Validate() error {
	if b.SchemaVersion != ActiveDatabaseBackupSchemaVersion || !validBackupID(b.BackupID) || b.CreatedAt.IsZero() || b.CreatedAt.Location() != time.UTC || !validBackupReason(b.Reason) || !validID(b.SourceActivationID) || !validSHA(b.SourceActivationJSONSHA256) || !b.SourceRelease.valid() || !b.SourceDatabase.valid() || !validSHA(b.DatabaseEnvSHA256) || b.DumpFile != ActiveDatabaseBackupDumpFile || !validSHA(b.DumpSHA256) || b.DumpSize <= 0 || b.DumpFormat != ActiveDatabaseBackupDumpFormat {
		return fmt.Errorf("invalid active database backup v2")
	}
	return nil
}

func (s RestoreSourceV1) Validate() error {
	if !validBackupID(s.BackupID) || !validSHA(s.BackupMetadataSHA256) || !validSHA(s.DumpSHA256) || !validID(s.SourceActivationID) || !validSHA(s.SourceActivationJSONSHA256) {
		return fmt.Errorf("invalid restore source v1")
	}
	return nil
}

func (s ActivationRestoreSourceV1) Validate() error {
	if !validBackupID(s.BackupID) || !validSHA(s.BackupMetadataSHA256) {
		return fmt.Errorf("invalid activation restore source v1")
	}
	return nil
}

func validBackupID(value string) bool {
	return len(value) > len("backup-") && len(value) <= 128 && len(value) >= 7 && value[:7] == "backup-" && validID(value)
}

// Reasons are labels, not free-form messages: this prevents a future caller
// from turning backup metadata into a secret-bearing error/log channel.
func validBackupReason(value string) bool { return validID(value) }

func ActiveDatabaseBackupMetadataRelativePath(backupID string) (string, error) {
	if !validBackupID(backupID) {
		return "", fmt.Errorf("invalid backup id")
	}
	return filepath.ToSlash(filepath.Join(backupID, activeDatabaseBackupMetadataName)), nil
}

func ActiveDatabaseBackupDumpRelativePath(backupID string) (string, error) {
	if !validBackupID(backupID) {
		return "", fmt.Errorf("invalid backup id")
	}
	return filepath.ToSlash(filepath.Join(backupID, ActiveDatabaseBackupDumpFile)), nil
}

// ActiveDatabaseBackupMetadataPath and ActiveDatabaseBackupDumpPath are the
// only path constructors exposed by this wire contract. BR3 may supply an
// explicit task root in tests, but neither helper accepts a caller-selected
// file name or a path outside the selected backup root.
func ActiveDatabaseBackupMetadataPath(backupRoot, backupID string) (string, error) {
	return activeDatabaseBackupPath(backupRoot, backupID, activeDatabaseBackupMetadataName)
}

func ActiveDatabaseBackupDumpPath(backupRoot, backupID string) (string, error) {
	return activeDatabaseBackupPath(backupRoot, backupID, ActiveDatabaseBackupDumpFile)
}

func activeDatabaseBackupPath(backupRoot, backupID, name string) (string, error) {
	if !safeAbsPath(backupRoot) {
		return "", fmt.Errorf("invalid backup root")
	}
	if !validBackupID(backupID) || (name != activeDatabaseBackupMetadataName && name != ActiveDatabaseBackupDumpFile) {
		return "", fmt.Errorf("invalid backup path")
	}
	return filepath.Join(backupRoot, backupID, name), nil
}

func MarshalActiveDatabaseBackupV2(value ActiveDatabaseBackupV2) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func ParseActiveDatabaseBackupV2(raw []byte) (ActiveDatabaseBackupV2, error) {
	var value ActiveDatabaseBackupV2
	if err := decodeStrict(raw, &value); err != nil {
		return value, err
	}
	if err := requireStrictFields(raw, []string{
		"schema_version", "backup_id", "created_at", "reason", "source_activation_id", "source_activation_json_sha256", "source_release", "source_database", "database_env_sha256", "dump_file", "dump_sha256", "dump_size", "dump_format",
	}); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func MarshalRestoreSourceV1(value RestoreSourceV1) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func ParseRestoreSourceV1(raw []byte) (RestoreSourceV1, error) {
	var value RestoreSourceV1
	if err := decodeStrict(raw, &value); err != nil {
		return value, err
	}
	if err := requireStrictFields(raw, []string{"backup_id", "backup_metadata_sha256", "dump_sha256", "source_activation_id", "source_activation_json_sha256"}); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func MarshalActivationRestoreSourceV1(value ActivationRestoreSourceV1) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func ParseActivationRestoreSourceV1(raw []byte) (ActivationRestoreSourceV1, error) {
	var value ActivationRestoreSourceV1
	if err := decodeStrict(raw, &value); err != nil {
		return value, err
	}
	if err := requireStrictFields(raw, []string{"backup_id", "backup_metadata_sha256"}); err != nil {
		return value, err
	}
	return value, value.Validate()
}

// requireStrictFields closes encoding/json's otherwise-permissive handling
// of missing and explicit-null values after decodeStrict has rejected unknown,
// duplicate, and trailing JSON.
func requireStrictFields(raw []byte, required []string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing required field %q", name)
		}
	}
	return nil
}
