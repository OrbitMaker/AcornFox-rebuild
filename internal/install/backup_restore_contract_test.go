package install

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func activeDatabaseBackupFixture() ActiveDatabaseBackupV2 {
	return ActiveDatabaseBackupV2{
		SchemaVersion:              ActiveDatabaseBackupSchemaVersion,
		BackupID:                   "backup-20260830-a1",
		CreatedAt:                  time.Unix(1, 0).UTC(),
		Reason:                     "pre-upgrade-rc1",
		SourceActivationID:         "activation-1",
		SourceActivationJSONSHA256: sha("a"),
		SourceRelease: ReleaseV1{
			ID:             "release-rc1",
			Version:        "0.8.0-rc.1",
			SourceCommit:   strings.Repeat("b", 40),
			Architecture:   "amd64",
			ManifestSHA256: sha("c"),
		},
		SourceDatabase:    DatabaseV1{Name: "open_card_act_1234567890abcdef", Migration: "0024", SchemaMigrationsSHA256: sha("d")},
		DatabaseEnvSHA256: sha("e"),
		DumpFile:          ActiveDatabaseBackupDumpFile,
		DumpSHA256:        sha("f"),
		DumpSize:          123,
		DumpFormat:        ActiveDatabaseBackupDumpFormat,
	}
}

func TestActiveDatabaseBackupV2StrictRoundTripAndSecretExclusion(t *testing.T) {
	backup := activeDatabaseBackupFixture()
	raw, err := MarshalActiveDatabaseBackupV2(backup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "database_env\"") {
		t.Fatalf("backup receipt serialized secret-bearing environment: %s", raw)
	}
	got, err := ParseActiveDatabaseBackupV2(raw)
	if err != nil || got != backup {
		t.Fatalf("backup round trip = %#v, %v", got, err)
	}
	metadataPath, err := ActiveDatabaseBackupMetadataRelativePath(backup.BackupID)
	if err != nil || metadataPath != backup.BackupID+"/backup.json" {
		t.Fatalf("metadata path=%q err=%v", metadataPath, err)
	}
	dumpPath, err := ActiveDatabaseBackupDumpRelativePath(backup.BackupID)
	if err != nil || dumpPath != backup.BackupID+"/control-plane.dump" {
		t.Fatalf("dump path=%q err=%v", dumpPath, err)
	}
	if full, err := ActiveDatabaseBackupMetadataPath("/var/lib/open-card/backups", backup.BackupID); err != nil || full != "/var/lib/open-card/backups/"+metadataPath {
		t.Fatalf("full metadata path=%q err=%v", full, err)
	}
	if _, err := ActiveDatabaseBackupDumpPath("relative", backup.BackupID); err == nil {
		t.Fatal("relative backup root was accepted")
	}
}

func TestActiveDatabaseBackupV2RejectsWireAndSemanticDrift(t *testing.T) {
	raw, err := MarshalActiveDatabaseBackupV2(activeDatabaseBackupFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]json.RawMessage){
		"unknown": func(fields map[string]json.RawMessage) {
			fields["database_env"] = json.RawMessage(`"postgresql://admin:secret@db/open_card"`)
		},
		"null": func(fields map[string]json.RawMessage) { fields["source_database"] = json.RawMessage(`null`) },
		"dump-file": func(fields map[string]json.RawMessage) {
			fields["dump_file"] = json.RawMessage(`"../control-plane.dump"`)
		},
		"dump-format": func(fields map[string]json.RawMessage) { fields["dump_format"] = json.RawMessage(`"plain"`) },
		"reason": func(fields map[string]json.RawMessage) {
			fields["reason"] = json.RawMessage(`"postgresql://a:secret@db/open_card"`)
		},
		"backup-id": func(fields map[string]json.RawMessage) { fields["backup_id"] = json.RawMessage(`"not-a-backup"`) },
		"created-at-offset": func(fields map[string]json.RawMessage) {
			fields["created_at"] = json.RawMessage(`"1970-01-01T08:00:01+08:00"`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			mutate(fields)
			bad, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseActiveDatabaseBackupV2(bad); err == nil {
				t.Fatal("invalid backup receipt was accepted")
			}
		})
	}
	duplicate := append([]byte(`{"schema_version":2,"schema_version":2,`), raw[1:]...)
	if _, err := ParseActiveDatabaseBackupV2(duplicate); err == nil {
		t.Fatal("duplicate backup field was accepted")
	}
	if _, err := ParseActiveDatabaseBackupV2(append(raw, []byte(" trailing")...)); err == nil {
		t.Fatal("trailing backup JSON was accepted")
	}
}

func TestRestoreSourceContractsAreStrictAndSecretFree(t *testing.T) {
	source := RestoreSourceV1{
		BackupID:                   "backup-20260830-a1",
		BackupMetadataSHA256:       sha("a"),
		DumpSHA256:                 sha("b"),
		SourceActivationID:         "activation-1",
		SourceActivationJSONSHA256: sha("c"),
	}
	raw, err := MarshalRestoreSourceV1(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "postgres") || strings.Contains(string(raw), "env") {
		t.Fatalf("restore source serialized secret-bearing data: %s", raw)
	}
	if got, err := ParseRestoreSourceV1(raw); err != nil || got != source {
		t.Fatalf("restore source=%#v err=%v", got, err)
	}
	if strings.Contains(string(raw), "postgres") || strings.Contains(string(raw), "/") || strings.Contains(string(raw), "env") {
		t.Fatalf("restore source contains path or secret-bearing data: %s", raw)
	}
	activationSource := ActivationRestoreSourceV1{BackupID: source.BackupID, BackupMetadataSHA256: source.BackupMetadataSHA256}
	activationRaw, err := MarshalActivationRestoreSourceV1(activationSource)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseActivationRestoreSourceV1(activationRaw); err != nil || got != activationSource {
		t.Fatalf("activation restore source=%#v err=%v", got, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"backup_id":"backup-20260830-a1","backup_metadata_sha256":null,"dump_sha256":"` + sha("b") + `","source_activation_id":"activation-1","source_activation_json_sha256":"` + sha("c") + `"}`),
		[]byte(`{"backup_id":"backup-20260830-a1","backup_metadata_sha256":"` + sha("a") + `","dump_sha256":"` + sha("b") + `","source_activation_id":"activation-1","source_activation_json_sha256":"` + sha("c") + `","unknown":true}`),
		[]byte(`{"backup_id":"backup-20260830-a1","backup_id":"backup-20260830-a1","backup_metadata_sha256":"` + sha("a") + `","dump_sha256":"` + sha("b") + `","source_activation_id":"activation-1","source_activation_json_sha256":"` + sha("c") + `"}`),
		append(raw, []byte(" trailing")...),
		[]byte(`{"backup_id":"backup-20260830-a1","backup_metadata_sha256":null}`),
		[]byte(`{"backup_id":"backup-20260830-a1","backup_metadata_sha256":"` + sha("a") + `","extra":true}`),
		[]byte(`{"backup_id":"backup-20260830-a1","backup_id":"backup-20260830-a1","backup_metadata_sha256":"` + sha("a") + `"}`),
	} {
		if _, err := ParseActivationRestoreSourceV1(raw); err == nil {
			t.Fatal("invalid activation restore source was accepted")
		}
	}
}
