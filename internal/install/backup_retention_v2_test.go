package install

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func platformRetentionV2Committed(t *testing.T, installation, backupID, receiptVersion, dataVersion string, createdAt time.Time) PlatformBackupCommittedV2 {
	t.Helper()
	dataKey := platformBackupDataObjectKeyV2(installation, backupID)
	encryption := BackupEncryptionReceipt{
		SchemaVersion: 1, Cipher: "AES-256-GCM-CHUNKED", ObjectSHA256: remoteDigest("data-" + backupID), ObjectSize: 1,
		HeaderSHA256: remoteDigest("header-" + backupID), PlaintextSHA256: remoteDigest("plaintext-" + backupID), PlaintextSize: 1, ChunkCount: 1,
	}
	encryptionSHA, err := BackupEncryptionReceiptSHA256(encryption)
	if err != nil {
		t.Fatal(err)
	}
	receipt := PlatformBackupRemoteReceiptV2{
		Schema: PlatformBackupRemoteReceiptV2Schema, BackupID: backupID, CreatedAt: createdAt.UTC(), SourceInstallationIDSHA256: installation,
		PackageManifestSHA256: remoteDigest("manifest-" + backupID), PackageSHA256: remoteDigest("package-" + backupID),
		SourceActivationID: "activation-retention", SourceActivationJSONSHA256: remoteDigest("activation-" + backupID),
		ReleaseID: "release-retention", ReleaseManifestSHA256: remoteDigest("release-" + backupID),
		DataObjectKey: dataKey, DataVersionID: dataVersion, DataSHA256: encryption.ObjectSHA256, DataSize: encryption.ObjectSize,
		EncryptionReceipt: encryption, EncryptionReceiptSHA256: encryptionSHA, KeyVersion: "key-v1",
	}
	raw, err := MarshalPlatformBackupRemoteReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	committed := PlatformBackupCommittedV2{
		Receipt: receipt, ReceiptObjectKey: "open-card/backups/" + installation + "/" + backupID + ".receipt.json", ReceiptVersionID: receiptVersion,
		ReceiptSHA256: sha256Hex(raw), ReceiptSize: int64(len(raw)), ReceiptContent: raw,
	}
	if err := committed.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return committed
}

func platformRetentionV2Target(value PlatformBackupCommittedV2) PlatformBackupRetentionTargetV2 {
	return PlatformBackupRetentionTargetV2{
		BackupID: value.Receipt.BackupID, CreatedAt: value.Receipt.CreatedAt,
		Receipt: PlatformBackupVersionRefV2{ObjectKey: value.ReceiptObjectKey, VersionID: value.ReceiptVersionID},
		Data:    PlatformBackupVersionRefV2{ObjectKey: value.Receipt.DataObjectKey, VersionID: value.Receipt.DataVersionID},
	}
}

func TestPlanPlatformBackupRetentionV2BoundariesProtectionAndExactTargets(t *testing.T) {
	installation := remoteDigest("retention-installation")
	base := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC) // Monday, ISO 2025-W02.
	committed := make([]PlatformBackupCommittedV2, 0, 40)
	for day := 0; day < 40; day++ {
		committed = append(committed, platformRetentionV2Committed(t, installation, fmt.Sprintf("backup-retention-v2-%02d", day), "receipt-v1", fmt.Sprintf("data-v%02d", day), base.AddDate(0, 0, -day)))
	}
	protected := PlatformBackupVersionRefV2{ObjectKey: committed[30].ReceiptObjectKey, VersionID: committed[30].ReceiptVersionID}
	plan, err := PlanPlatformBackupRetentionV2(installation, committed, []PlatformBackupVersionRefV2{protected})
	if err != nil {
		t.Fatal(err)
	}
	keepDays := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 8: true, 15: true, 30: true}
	var wantKeep, wantDelete []PlatformBackupRetentionTargetV2
	for day, value := range committed {
		if keepDays[day] {
			wantKeep = append(wantKeep, platformRetentionV2Target(value))
		} else {
			wantDelete = append(wantDelete, platformRetentionV2Target(value))
		}
	}
	sortPlatformBackupRetentionTargetsV2(wantKeep)
	sortPlatformBackupRetentionTargetsV2(wantDelete)
	if !reflect.DeepEqual(plan.Keep, wantKeep) || !reflect.DeepEqual(plan.Delete, wantDelete) {
		t.Fatalf("plan=%+v want keep=%+v delete=%+v", plan, wantKeep, wantDelete)
	}
	for _, target := range append(append([]PlatformBackupRetentionTargetV2(nil), plan.Keep...), plan.Delete...) {
		if err := target.Validate(); err != nil || target.Receipt.VersionID == "" || target.Data.VersionID == "" {
			t.Fatalf("invalid exact target=%+v err=%v", target, err)
		}
	}
	if got := fmt.Sprintf("%+v", plan); strings.Contains(got, "plaintext-") || strings.Contains(got, "ReceiptContent") {
		t.Fatalf("plan exposed receipt or secret-like content: %s", got)
	}
	if year, week := committed[8].Receipt.CreatedAt.ISOWeek(); year != 2024 || week != 52 {
		t.Fatalf("ISO rollover not exercised: %d-W%02d", year, week)
	}
}

func TestPlanPlatformBackupRetentionV2SameBucketTieUTCBoundaryAndDeterminism(t *testing.T) {
	installation := remoteDigest("tie-installation")
	at := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
	first := platformRetentionV2Committed(t, installation, "backup-retention-v2-tie-a", "receipt-v1", "data-v1", at)
	second := platformRetentionV2Committed(t, installation, "backup-retention-v2-tie-b", "receipt-v1", "data-v2", at)
	plan, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{second, first}, nil)
	if err != nil || !reflect.DeepEqual(plan.Keep, []PlatformBackupRetentionTargetV2{platformRetentionV2Target(first)}) || !reflect.DeepEqual(plan.Delete, []PlatformBackupRetentionTargetV2{platformRetentionV2Target(second)}) {
		t.Fatalf("tie plan=%+v err=%v", plan, err)
	}
	west := platformRetentionV2Committed(t, installation, "backup-retention-v2-west", "receipt-v1", "data-west", time.Date(2024, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -2*3600)))
	east := platformRetentionV2Committed(t, installation, "backup-retention-v2-east", "receipt-v1", "data-east", time.Date(2025, 1, 1, 0, 30, 0, 0, time.FixedZone("east", 2*3600)))
	boundary, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{west, east}, nil)
	if err != nil || len(boundary.Keep) != 2 || len(boundary.Delete) != 0 || west.Receipt.CreatedAt.Day() != 1 || east.Receipt.CreatedAt.Day() != 31 {
		t.Fatalf("UTC boundary plan=%+v west=%s east=%s err=%v", boundary, west.Receipt.CreatedAt, east.Receipt.CreatedAt, err)
	}
	again, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{east, first, west, second}, nil)
	ordered, orderErr := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{first, second, west, east}, nil)
	if err != nil || orderErr != nil || !reflect.DeepEqual(again, ordered) {
		t.Fatalf("input order changed plan: again=%+v/%v ordered=%+v/%v", again, err, ordered, orderErr)
	}
}

func TestPlanPlatformBackupRetentionV2ProtectedMustBeExistingReceipt(t *testing.T) {
	installation := remoteDigest("protected-installation")
	value := platformRetentionV2Committed(t, installation, "backup-retention-v2-protected", "receipt-v1", "data-v1", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	good := PlatformBackupVersionRefV2{ObjectKey: value.ReceiptObjectKey, VersionID: value.ReceiptVersionID}
	if plan, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{value}, []PlatformBackupVersionRefV2{good}); err != nil || len(plan.Keep) != 1 {
		t.Fatalf("existing protected plan=%+v err=%v", plan, err)
	}
	foreign := PlatformBackupVersionRefV2{ObjectKey: "open-card/backups/" + remoteDigest("other") + "/backup-retention-v2-protected.receipt.json", VersionID: "receipt-v1"}
	missing := good
	missing.VersionID = "receipt-v2"
	data := PlatformBackupVersionRefV2{ObjectKey: value.Receipt.DataObjectKey, VersionID: value.Receipt.DataVersionID}
	for name, refs := range map[string][]PlatformBackupVersionRefV2{"foreign": {foreign}, "missing": {missing}, "data": {data}} {
		t.Run(name, func(t *testing.T) {
			if _, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{value}, refs); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestPlanPlatformBackupRetentionV2DuplicatesAndEmptyPlan(t *testing.T) {
	installation := remoteDigest("duplicate-installation")
	value := platformRetentionV2Committed(t, installation, "backup-retention-v2-duplicate", "receipt-v1", "data-v1", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	plan, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{value, value}, nil)
	if err != nil || !reflect.DeepEqual(plan.Keep, []PlatformBackupRetentionTargetV2{platformRetentionV2Target(value)}) || len(plan.Delete) != 0 {
		t.Fatalf("exact duplicate plan=%+v err=%v", plan, err)
	}

	changedDataVersion := value
	changedDataVersion.Receipt.DataVersionID = "data-v2"
	var marshalErr error
	changedDataVersion.ReceiptContent, marshalErr = MarshalPlatformBackupRemoteReceiptV2(changedDataVersion.Receipt)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	changedDataVersion.ReceiptSHA256, changedDataVersion.ReceiptSize = sha256Hex(changedDataVersion.ReceiptContent), int64(len(changedDataVersion.ReceiptContent))
	if err := changedDataVersion.Validate(); err != nil {
		t.Fatalf("changed version fixture invalid: %v", err)
	}
	if _, err := PlanPlatformBackupRetentionV2(installation, []PlatformBackupCommittedV2{value, changedDataVersion}, nil); !errors.Is(err, ErrRemoteBackupContract) {
		t.Fatalf("same data key with changed version err=%v", err)
	}

	empty, err := PlanPlatformBackupRetentionV2(installation, nil, nil)
	if err != nil || empty.Keep == nil || empty.Delete == nil || len(empty.Keep) != 0 || len(empty.Delete) != 0 {
		t.Fatalf("empty plan=%+v err=%v", empty, err)
	}
}

func TestPlatformBackupRetentionV2ExactRefAndTargetValidation(t *testing.T) {
	installation := remoteDigest("ref-installation")
	value := platformRetentionV2Committed(t, installation, "backup-retention-v2-ref", "receipt-v1", "data-v1", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	target := platformRetentionV2Target(value)
	if err := target.Validate(); err != nil {
		t.Fatalf("valid target: %v", err)
	}
	for name, ref := range map[string]PlatformBackupVersionRefV2{
		"malformed receipt key": {ObjectKey: "open-card/backups/not-a-sha/backup-retention-v2-ref.receipt.json", VersionID: "receipt-v1"},
		"malformed data key":    {ObjectKey: "open-card/backups/" + installation + "/backup-retention-v2-ref.data", VersionID: "data-v1"},
		"bad version grammar":   {ObjectKey: value.ReceiptObjectKey, VersionID: "receipt version"},
		"null version":          {ObjectKey: value.Receipt.DataObjectKey, VersionID: "null"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ref.Validate(); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("ref=%+v err=%v", ref, err)
			}
		})
	}
	for name, mutate := range map[string]func(*PlatformBackupRetentionTargetV2){
		"receipt/data backup mismatch": func(value *PlatformBackupRetentionTargetV2) {
			value.Data.ObjectKey = platformBackupDataObjectKeyV2(installation, "backup-retention-v2-other")
		},
		"malformed receipt version": func(value *PlatformBackupRetentionTargetV2) { value.Receipt.VersionID = "bad version" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := target
			mutate(&invalid)
			if err := invalid.Validate(); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("target=%+v err=%v", invalid, err)
			}
		})
	}
}

func TestPlanPlatformBackupRetentionV2RejectsMalformedForeignAndConflictingCommitted(t *testing.T) {
	installation := remoteDigest("invalid-installation")
	good := platformRetentionV2Committed(t, installation, "backup-retention-v2-invalid", "receipt-v1", "data-v1", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	malformed := good
	malformed.Receipt.DataVersionID = ""
	foreign := platformRetentionV2Committed(t, remoteDigest("foreign-installation"), "backup-retention-v2-foreign", "receipt-v1", "data-v2", good.Receipt.CreatedAt)
	conflictingReceiptVersion := good
	conflictingReceiptVersion.ReceiptVersionID = "receipt-v2"
	conflictingData := good
	conflictingData.Receipt.CreatedAt = conflictingData.Receipt.CreatedAt.Add(time.Second)
	conflictingData.ReceiptContent, _ = MarshalPlatformBackupRemoteReceiptV2(conflictingData.Receipt)
	conflictingData.ReceiptSHA256, conflictingData.ReceiptSize = sha256Hex(conflictingData.ReceiptContent), int64(len(conflictingData.ReceiptContent))
	for name, values := range map[string][]PlatformBackupCommittedV2{
		"malformed": {malformed}, "foreign": {foreign}, "multiple receipt versions": {good, conflictingReceiptVersion}, "duplicate data identity": {good, conflictingData},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PlanPlatformBackupRetentionV2(installation, values, nil); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
