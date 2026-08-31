package install

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	platformBackupRetentionDailyV2  = 7
	platformBackupRetentionWeeklyV2 = 4
)

// PlatformBackupVersionRefV2 identifies one immutable version of either a
// V2 companion receipt or its encrypted data object. It intentionally does
// not reuse RemoteBackupVersionRef: V2 retention must also address receipt
// objects, which end in .receipt.json rather than .ocbkp.
type PlatformBackupVersionRefV2 struct {
	ObjectKey string
	VersionID string
}

// Validate checks that this is an exact, version-qualified V2 backup object
// reference. A target additionally verifies the receipt/data pair binding.
func (r PlatformBackupVersionRefV2) Validate() error {
	if !validRemoteBackupVersionID(r.VersionID) || !validPlatformBackupV2ObjectKey(r.ObjectKey) {
		return ErrRemoteBackupContract
	}
	return nil
}

// PlatformBackupRetentionTargetV2 keeps the receipt and encrypted data version
// together. A future executor must delete Receipt first, then the exact Data
// version, so a data object is never visible through a remaining receipt.
type PlatformBackupRetentionTargetV2 struct {
	BackupID  string
	CreatedAt time.Time
	Receipt   PlatformBackupVersionRefV2
	Data      PlatformBackupVersionRefV2
}

func (t PlatformBackupRetentionTargetV2) Validate() error {
	installation, backupID, ok := platformBackupReceiptIdentityV2(t.Receipt.ObjectKey)
	if !ok || t.BackupID != backupID || t.CreatedAt.IsZero() || t.CreatedAt.Location() != time.UTC ||
		t.Receipt.Validate() != nil || t.Data.Validate() != nil ||
		t.Data.ObjectKey != platformBackupDataObjectKeyV2(installation, backupID) {
		return ErrRemoteBackupContract
	}
	return nil
}

// PlatformBackupRetentionPlanV2 is a pure retention decision. It contains no
// store, credential, receipt content, or deletion operation.
type PlatformBackupRetentionPlanV2 struct {
	Keep   []PlatformBackupRetentionTargetV2
	Delete []PlatformBackupRetentionTargetV2
}

// PlanPlatformBackupRetentionV2 selects the newest committed backup for seven
// distinct UTC days and four distinct ISO weeks. Protected receipt references
// must be exact committed V2 receipts for installationSHA256. The function is
// pure and deliberately does not call DeleteVersion or any remote API. A valid
// empty input returns deterministic, non-nil empty Keep and Delete slices.
func PlanPlatformBackupRetentionV2(installationSHA256 string, committed []PlatformBackupCommittedV2, protected []PlatformBackupVersionRefV2) (PlatformBackupRetentionPlanV2, error) {
	if !validSHA(installationSHA256) {
		return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
	}

	byReceipt := make(map[PlatformBackupVersionRefV2]PlatformBackupCommittedV2, len(committed))
	receiptVersions := make(map[string]PlatformBackupVersionRefV2, len(committed))
	dataOwners := make(map[PlatformBackupVersionRefV2]PlatformBackupVersionRefV2, len(committed))
	for _, value := range committed {
		if value.Validate() != nil || value.Receipt.SourceInstallationIDSHA256 != installationSHA256 {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		receipt := PlatformBackupVersionRefV2{ObjectKey: value.ReceiptObjectKey, VersionID: value.ReceiptVersionID}
		data := PlatformBackupVersionRefV2{ObjectKey: value.Receipt.DataObjectKey, VersionID: value.Receipt.DataVersionID}
		target := PlatformBackupRetentionTargetV2{BackupID: value.Receipt.BackupID, CreatedAt: value.Receipt.CreatedAt, Receipt: receipt, Data: data}
		if target.Validate() != nil {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		if existing, ok := receiptVersions[receipt.ObjectKey]; ok && existing != receipt {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		if existing, ok := byReceipt[receipt]; ok && !samePlatformBackupCommittedV2(existing, value) {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		if owner, ok := dataOwners[data]; ok && owner != receipt {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		byReceipt[receipt] = value
		receiptVersions[receipt.ObjectKey] = receipt
		dataOwners[data] = receipt
	}

	protectedSet := make(map[PlatformBackupVersionRefV2]struct{}, len(protected))
	for _, ref := range protected {
		installation, _, ok := platformBackupReceiptIdentityV2(ref.ObjectKey)
		if ref.Validate() != nil || !ok || installation != installationSHA256 {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		if _, ok := byReceipt[ref]; !ok {
			return PlatformBackupRetentionPlanV2{}, ErrRemoteBackupContract
		}
		protectedSet[ref] = struct{}{}
	}

	values := make([]PlatformBackupCommittedV2, 0, len(byReceipt))
	for _, value := range byReceipt {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if !left.Receipt.CreatedAt.Equal(right.Receipt.CreatedAt) {
			return left.Receipt.CreatedAt.After(right.Receipt.CreatedAt)
		}
		if left.ReceiptObjectKey != right.ReceiptObjectKey {
			return left.ReceiptObjectKey < right.ReceiptObjectKey
		}
		return left.ReceiptVersionID < right.ReceiptVersionID
	})

	keep := make(map[PlatformBackupVersionRefV2]struct{}, len(values))
	days, weeks := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range values {
		ref := PlatformBackupVersionRefV2{ObjectKey: value.ReceiptObjectKey, VersionID: value.ReceiptVersionID}
		utc := value.Receipt.CreatedAt.UTC()
		day := utc.Format("2006-01-02")
		if len(days) < platformBackupRetentionDailyV2 {
			if _, ok := days[day]; !ok {
				days[day] = struct{}{}
				keep[ref] = struct{}{}
			}
		}
		year, week := utc.ISOWeek()
		weekKey := strconv.Itoa(year) + "-" + strconv.Itoa(week)
		if len(weeks) < platformBackupRetentionWeeklyV2 {
			if _, ok := weeks[weekKey]; !ok {
				weeks[weekKey] = struct{}{}
				keep[ref] = struct{}{}
			}
		}
	}
	for ref := range protectedSet {
		keep[ref] = struct{}{}
	}

	plan := PlatformBackupRetentionPlanV2{
		Keep:   make([]PlatformBackupRetentionTargetV2, 0, len(keep)),
		Delete: make([]PlatformBackupRetentionTargetV2, 0, len(byReceipt)-len(keep)),
	}
	for ref, value := range byReceipt {
		target := PlatformBackupRetentionTargetV2{
			BackupID: value.Receipt.BackupID, CreatedAt: value.Receipt.CreatedAt,
			Receipt: ref,
			Data:    PlatformBackupVersionRefV2{ObjectKey: value.Receipt.DataObjectKey, VersionID: value.Receipt.DataVersionID},
		}
		if _, ok := keep[ref]; ok {
			plan.Keep = append(plan.Keep, target)
		} else {
			plan.Delete = append(plan.Delete, target)
		}
	}
	sortPlatformBackupRetentionTargetsV2(plan.Keep)
	sortPlatformBackupRetentionTargetsV2(plan.Delete)
	return plan, nil
}

func validPlatformBackupV2ObjectKey(key string) bool {
	if prefix := platformBackupPrefixForDataKey(key); prefix != "" {
		return true
	}
	_, _, ok := platformBackupReceiptIdentityV2(key)
	return ok
}

func platformBackupReceiptIdentityV2(key string) (installationSHA256, backupID string, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || !validPlatformBackupPrefix(strings.Join(parts[:2], "/")) || !validSHA(parts[2]) || !strings.HasSuffix(parts[3], ".receipt.json") {
		return "", "", false
	}
	backupID = strings.TrimSuffix(parts[3], ".receipt.json")
	return parts[2], backupID, validBackupID(backupID)
}

func platformBackupDataObjectKeyV2(installationSHA256, backupID string) string {
	return "open-card/backups/" + installationSHA256 + "/" + backupID + ".ocbkp"
}

func samePlatformBackupCommittedV2(left, right PlatformBackupCommittedV2) bool {
	return left.Receipt == right.Receipt && left.ReceiptObjectKey == right.ReceiptObjectKey && left.ReceiptVersionID == right.ReceiptVersionID &&
		left.ReceiptSHA256 == right.ReceiptSHA256 && left.ReceiptSize == right.ReceiptSize && string(left.ReceiptContent) == string(right.ReceiptContent)
}

func sortPlatformBackupRetentionTargetsV2(values []PlatformBackupRetentionTargetV2) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Receipt.ObjectKey != values[j].Receipt.ObjectKey {
			return values[i].Receipt.ObjectKey < values[j].Receipt.ObjectKey
		}
		if values[i].Receipt.VersionID != values[j].Receipt.VersionID {
			return values[i].Receipt.VersionID < values[j].Receipt.VersionID
		}
		if values[i].Data.ObjectKey != values[j].Data.ObjectKey {
			return values[i].Data.ObjectKey < values[j].Data.ObjectKey
		}
		return values[i].Data.VersionID < values[j].Data.VersionID
	})
}
