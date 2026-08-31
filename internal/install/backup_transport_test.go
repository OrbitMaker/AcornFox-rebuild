package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type remoteStoreFake struct {
	object       RemoteBackupObject
	body         []byte
	putErr       error
	headErr      error
	getErr       error
	headOverride *RemoteBackupObject
	getOverride  *RemoteBackupObject
	getBody      []byte
	lastExpected RemoteBackupExpectedObject
	puts         int
	heads        int
	gets         int
	lastHeadKey  string
	lastGetKey   string
	lastGetVer   string
}

func (s *remoteStoreFake) PutIfAbsent(_ context.Context, expected RemoteBackupExpectedObject, source io.Reader) (RemoteBackupObject, error) {
	s.puts++
	s.lastExpected = expected
	if s.putErr != nil {
		return RemoteBackupObject{}, s.putErr
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return RemoteBackupObject{}, err
	}
	if s.object.VersionID == "" {
		s.object = RemoteBackupObject{ObjectKey: expected.ObjectKey, VersionID: "version-1", SHA256: expected.SHA256, Size: expected.Size}
		s.body = append([]byte(nil), body...)
	}
	return s.object, nil
}

func (s *remoteStoreFake) Head(_ context.Context, key string) (RemoteBackupObject, error) {
	s.heads++
	s.lastHeadKey = key
	if s.headErr != nil {
		return RemoteBackupObject{}, s.headErr
	}
	if s.headOverride != nil {
		return *s.headOverride, nil
	}
	return s.object, nil
}

func (s *remoteStoreFake) Get(_ context.Context, key, version string) (io.ReadCloser, RemoteBackupObject, error) {
	s.gets++
	s.lastGetKey, s.lastGetVer = key, version
	if s.getErr != nil {
		return nil, RemoteBackupObject{}, s.getErr
	}
	object := s.object
	if s.getOverride != nil {
		object = *s.getOverride
	}
	body := s.body
	if s.getBody != nil {
		body = s.getBody
	}
	return io.NopCloser(bytes.NewReader(body)), object, nil
}

func (s *remoteStoreFake) List(context.Context, string) ([]RemoteBackupObject, error) {
	return nil, errors.New("not used")
}
func (s *remoteStoreFake) DeleteVersion(context.Context, string, string) error {
	return errors.New("not used")
}

func remoteDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func remoteContext(t *testing.T, backupID string) BackupEncryptionContext {
	t.Helper()
	key, err := RemoteBackupObjectKey("production", backupID)
	if err != nil {
		t.Fatal(err)
	}
	return BackupEncryptionContext{
		BackupID: backupID, BackupMetadataSHA256: remoteDigest("metadata"), SourceActivationID: "activation-remote-1",
		SourceActivationJSONSHA256: remoteDigest("activation"), ReleaseID: "release-remote-1", ReleaseManifestSHA256: remoteDigest("manifest"),
		ObjectKey: key, KeyVersion: "key-v1",
	}
}

func remotePublishRequest(t *testing.T, backupID string) (RemoteBackupPublishRequest, []byte, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	context := remoteContext(t, backupID)
	var encrypted bytes.Buffer
	receipt, err := EncryptBackup(&encrypted, bytes.NewReader([]byte("remote encrypted backup payload")), key, context, bytes.NewReader(bytes.Repeat([]byte{9}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	return RemoteBackupPublishRequest{
		Object: bytes.NewReader(encrypted.Bytes()), CreatedAt: time.Date(2026, 8, 31, 2, 3, 4, 0, time.UTC),
		EncryptionContext: context, EncryptionReceipt: receipt,
	}, encrypted.Bytes(), key
}

func TestPublishRemoteBackupFirstAndIdenticalReplay(t *testing.T) {
	request, body, key := remotePublishRequest(t, "backup-remote-first")
	store := &remoteStoreFake{}
	destination := &bytes.Buffer{}
	scratch := remoteScratch(t)
	request.DecryptionCheck = &RemoteBackupDecryptionCheck{Key: key, Scratch: scratch, Destination: destination}
	first, err := PublishRemoteBackup(context.Background(), store, request)
	if err != nil || first.Validate() != nil || first.VersionID != "version-1" || !bytes.Equal(store.body, body) || destination.String() != "remote encrypted backup payload" {
		t.Fatalf("receipt=%+v err=%v body=%q plaintext=%q", first, err, store.body, destination.String())
	}
	if store.lastExpected.Validate() != nil || store.lastExpected.ObjectKey != first.ObjectKey || store.lastExpected.SHA256 != first.EncryptedObjectSHA256 || store.lastExpected.Size != first.EncryptedObjectSize {
		t.Fatalf("conditional-create identity=%+v", store.lastExpected)
	}
	if store.lastHeadKey != first.ObjectKey || store.lastGetKey != first.ObjectKey || store.lastGetVer != first.VersionID {
		t.Fatalf("version-qualified readback head=%q get=%q version=%q", store.lastHeadKey, store.lastGetKey, store.lastGetVer)
	}
	store.putErr = errors.New("store retry token must not leak")
	replayRequest, _, _ := remotePublishRequest(t, "backup-remote-first")
	replayRequest.ExpectedExisting = &first
	replay, err := PublishRemoteBackup(context.Background(), store, replayRequest)
	if err != nil || replay != first || store.puts != 2 || store.heads < 3 {
		t.Fatalf("replay=%+v err=%v puts=%d heads=%d", replay, err, store.puts, store.heads)
	}
	if store.lastHeadKey != first.ObjectKey || store.lastGetKey != first.ObjectKey || store.lastGetVer != first.VersionID {
		t.Fatalf("replay lost version-qualified readback head=%q get=%q version=%q", store.lastHeadKey, store.lastGetKey, store.lastGetVer)
	}
	wrongVersion := first
	wrongVersion.VersionID = "version-foreign"
	replayRequest.ExpectedExisting = &wrongVersion
	if _, err := PublishRemoteBackup(context.Background(), store, replayRequest); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("version identity err=%v", err)
	}
}

func TestPublishRemoteBackupRejectsConflictsAndHeadMismatch(t *testing.T) {
	request, _, _ := remotePublishRequest(t, "backup-remote-conflict")
	store := &remoteStoreFake{putErr: errors.New("backend credential value")}
	store.object = RemoteBackupObject{ObjectKey: request.EncryptionContext.ObjectKey, VersionID: "version-1", SHA256: remoteDigest("other"), Size: 5}
	if _, err := PublishRemoteBackup(context.Background(), store, request); !errors.Is(err, ErrRemoteBackupTransport) || strings.Contains(err.Error(), "credential") {
		t.Fatalf("conflict err=%v", err)
	}
	request, _, _ = remotePublishRequest(t, "backup-remote-head")
	store = &remoteStoreFake{}
	bad := RemoteBackupObject{ObjectKey: request.EncryptionContext.ObjectKey, VersionID: "version-2", SHA256: remoteDigest("other"), Size: 5}
	store.headOverride = &bad
	if _, err := PublishRemoteBackup(context.Background(), store, request); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("head mismatch err=%v", err)
	}
}

func TestPublishRemoteBackupRejectsRemoteTamperAndTruncationWithoutPlaintext(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"tamper": func(body []byte) []byte {
			value := append([]byte(nil), body...)
			value[len(value)-1] ^= 1
			return value
		},
		"truncate": func(body []byte) []byte { return append([]byte(nil), body[:len(body)-1]...) },
	} {
		t.Run(name, func(t *testing.T) {
			request, body, key := remotePublishRequest(t, "backup-remote-"+name)
			store := &remoteStoreFake{getBody: mutate(body)}
			destination := &bytes.Buffer{}
			request.DecryptionCheck = &RemoteBackupDecryptionCheck{Key: key, Scratch: remoteScratch(t), Destination: destination}
			if _, err := PublishRemoteBackup(context.Background(), store, request); !errors.Is(err, ErrRemoteBackupTransport) || destination.Len() != 0 {
				t.Fatalf("err=%v plaintext=%q", err, destination.String())
			}
		})
	}
}

func TestRemoteBackupV1StrictJSONAndSecretFreeReceipt(t *testing.T) {
	request, _, _ := remotePublishRequest(t, "backup-remote-json")
	store := &remoteStoreFake{}
	receipt, err := PublishRemoteBackup(context.Background(), store, request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalRemoteBackupV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRemoteBackupV1(raw)
	if err != nil || parsed != receipt {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	drift := parsed
	drift.EncryptedObjectSize++
	if drift.Validate() == nil {
		t.Fatal("top-level object evidence drift accepted")
	}
	drift = parsed
	drift.EncryptionReceipt.PlaintextSHA256 = remoteDigest("other-plaintext")
	if drift.Validate() == nil {
		t.Fatal("encryption receipt digest drift accepted")
	}
	rebuilt, err := parsed.EncryptionContext()
	if err != nil || rebuilt != request.EncryptionContext {
		t.Fatalf("rebuilt context=%+v err=%v", rebuilt, err)
	}
	var restored bytes.Buffer
	if err := DecryptBackup(&restored, remoteScratch(t), bytes.NewReader(store.body), bytes.Repeat([]byte{7}, 32), rebuilt, parsed.EncryptionReceipt); err != nil || restored.String() != "remote encrypted backup payload" {
		t.Fatalf("receipt-only decrypt=%q err=%v", restored.String(), err)
	}
	for name, mutation := range map[string][]byte{
		"duplicate": append([]byte(`{"schema_version":1,`), raw[1:]...),
		"missing":   bytes.Replace(raw, []byte(`"version_id":"version-1",`), nil, 1),
		"unknown":   append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
		"null":      bytes.Replace(raw, []byte(`"version_id":"`), []byte(`"version_id":null,"old_version":"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRemoteBackupV1(mutation); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, forbidden := range []string{"password", "postgresql://", "token", "credential", "signed", "authorization"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("receipt leaked %q: %s", forbidden, raw)
		}
	}
}

func TestRemoteBackupObjectKeyAndLocalObjectValidation(t *testing.T) {
	if got, err := RemoteBackupObjectKey("production", "backup-remote-key"); err != nil || got != "open-card/backups/production/backup-remote-key.ocbkp" {
		t.Fatalf("key=%q err=%v", got, err)
	}
	request, _, _ := remotePublishRequest(t, "backup-remote-local")
	request.Object = bytes.NewReader([]byte("not the encrypted receipt"))
	if _, err := PublishRemoteBackup(context.Background(), &remoteStoreFake{}, request); !errors.Is(err, ErrRemoteBackupContract) {
		t.Fatalf("local mismatch err=%v", err)
	}
	for _, version := range []string{"", "null", "version/escape", "https://signed", strings.Repeat("a", 257)} {
		if validRemoteBackupVersionID(version) {
			t.Fatalf("unsafe version accepted: %q", version)
		}
	}
}

func remoteScratch(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "remote-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func retentionReceipt(t *testing.T, backupID, version string, createdAt time.Time) RemoteBackupV1 {
	t.Helper()
	key, err := RemoteBackupObjectKey("retention", backupID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := BackupEncryptionReceipt{SchemaVersion: 1, Cipher: "AES-256-GCM-CHUNKED", ObjectSHA256: remoteDigest("object-" + backupID), ObjectSize: 1, HeaderSHA256: remoteDigest("header-" + backupID), PlaintextSHA256: remoteDigest("plain-" + backupID), PlaintextSize: 1, ChunkCount: 1}
	receiptSHA, err := BackupEncryptionReceiptSHA256(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return RemoteBackupV1{SchemaVersion: 1, BackupID: backupID, CreatedAt: createdAt.UTC(), ObjectKey: key, VersionID: version,
		BackupMetadataSHA256: remoteDigest("metadata-" + backupID), EncryptedObjectSHA256: remoteDigest("object-" + backupID), EncryptedObjectSize: 1,
		EncryptionReceipt: receipt, EncryptionReceiptSHA256: receiptSHA,
		KeyVersion: "key-v1", SourceActivationID: "activation-retention", SourceActivationJSONSHA256: remoteDigest("activation"), ReleaseID: "release-retention", ReleaseManifestSHA256: remoteDigest("manifest")}
}

func TestPlanRemoteBackupRetentionBoundariesProtectionAndDeterminism(t *testing.T) {
	base := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC) // Monday, ISO 2025-W02.
	var receipts []RemoteBackupV1
	for day := 0; day < 40; day++ {
		receipts = append(receipts, retentionReceipt(t, fmt.Sprintf("backup-retention-%02d", day), "version-1", base.AddDate(0, 0, -day)))
	}
	protected := RemoteBackupVersionRef{ObjectKey: receipts[30].ObjectKey, VersionID: receipts[30].VersionID}
	plan, err := PlanRemoteBackupRetention(receipts, []RemoteBackupVersionRef{protected})
	if err != nil {
		t.Fatal(err)
	}
	// Overlap is intentional: the newest daily object may also represent its
	// ISO week. With a Monday base, weekly representatives are days 0,1,8,15.
	// The seven daily representatives are 0..6, and day 30 is protected.
	keepDays := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 8: true, 15: true, 30: true}
	var wantKeep, wantDelete []RemoteBackupVersionRef
	for day, receipt := range receipts {
		ref := RemoteBackupVersionRef{ObjectKey: receipt.ObjectKey, VersionID: receipt.VersionID}
		if keepDays[day] {
			wantKeep = append(wantKeep, ref)
		} else {
			wantDelete = append(wantDelete, ref)
		}
	}
	sortVersionRefs(wantKeep)
	sortVersionRefs(wantDelete)
	if !reflect.DeepEqual(plan.Keep, wantKeep) || !reflect.DeepEqual(plan.Delete, wantDelete) || !containsVersionRef(plan.Keep, protected) {
		t.Fatalf("plan=%+v want_keep=%+v want_delete=%+v", plan, wantKeep, wantDelete)
	}
	shuffled := append([]RemoteBackupV1(nil), receipts...)
	for left, right := 0, len(shuffled)-1; left < right; left, right = left+1, right-1 {
		shuffled[left], shuffled[right] = shuffled[right], shuffled[left]
	}
	again, err := PlanRemoteBackupRetention(shuffled, []RemoteBackupVersionRef{protected})
	if err != nil || !reflect.DeepEqual(plan, again) {
		t.Fatalf("again=%+v err=%v", again, err)
	}
	// The exact set above crosses the ISO-year boundary (2025-W01 to
	// 2024-W52/W51), proving ISO rather than calendar-year buckets.
	if year, week := receipts[8].CreatedAt.ISOWeek(); year != 2024 || week != 52 {
		t.Fatalf("ISO rollover not exercised: %d-W%02d", year, week)
	}
}

func TestPlanRemoteBackupRetentionSameBucketTieAndUTCBoundary(t *testing.T) {
	at := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
	first := retentionReceipt(t, "backup-retention-tie-a", "version-1", at)
	second := retentionReceipt(t, "backup-retention-tie-b", "version-1", at)
	plan, err := PlanRemoteBackupRetention([]RemoteBackupV1{second, first}, nil)
	firstRef := RemoteBackupVersionRef{ObjectKey: first.ObjectKey, VersionID: first.VersionID}
	secondRef := RemoteBackupVersionRef{ObjectKey: second.ObjectKey, VersionID: second.VersionID}
	if err != nil || !reflect.DeepEqual(plan.Keep, []RemoteBackupVersionRef{firstRef}) || !reflect.DeepEqual(plan.Delete, []RemoteBackupVersionRef{secondRef}) {
		t.Fatalf("tie plan=%+v err=%v", plan, err)
	}
	west := retentionReceipt(t, "backup-retention-west", "version-1", time.Date(2024, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -2*3600)))
	east := retentionReceipt(t, "backup-retention-east", "version-1", time.Date(2025, 1, 1, 0, 30, 0, 0, time.FixedZone("east", 2*3600)))
	boundary, err := PlanRemoteBackupRetention([]RemoteBackupV1{west, east}, nil)
	if err != nil || len(boundary.Keep) != 2 || len(boundary.Delete) != 0 || west.CreatedAt.Day() != 1 || east.CreatedAt.Day() != 31 {
		t.Fatalf("UTC boundary plan=%+v west=%s east=%s err=%v", boundary, west.CreatedAt, east.CreatedAt, err)
	}
}

func TestPlanRemoteBackupRetentionRejectsMalformedAndConflictingDuplicates(t *testing.T) {
	good := retentionReceipt(t, "backup-retention-duplicate", "version-1", time.Now().UTC())
	bad := good
	bad.EncryptedObjectSHA256 = "bad"
	if _, err := PlanRemoteBackupRetention([]RemoteBackupV1{bad}, nil); !errors.Is(err, ErrRemoteBackupContract) {
		t.Fatalf("malformed err=%v", err)
	}
	conflict := good
	conflict.EncryptedObjectSHA256 = remoteDigest("changed")
	if _, err := PlanRemoteBackupRetention([]RemoteBackupV1{good, conflict}, nil); !errors.Is(err, ErrRemoteBackupContract) {
		t.Fatalf("conflict err=%v", err)
	}
	otherVersion := good
	otherVersion.VersionID = "version-2"
	if _, err := PlanRemoteBackupRetention([]RemoteBackupV1{good, otherVersion}, nil); !errors.Is(err, ErrRemoteBackupContract) {
		t.Fatalf("key version conflict err=%v", err)
	}
}

func containsVersionRef(values []RemoteBackupVersionRef, want RemoteBackupVersionRef) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sortedVersionRefs(values []RemoteBackupVersionRef) bool {
	return reflect.DeepEqual(values, append([]RemoteBackupVersionRef(nil), values...)) && sortVersionRefCheck(values)
}

func sortVersionRefCheck(values []RemoteBackupVersionRef) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].ObjectKey > values[index].ObjectKey || values[index-1].ObjectKey == values[index].ObjectKey && values[index-1].VersionID > values[index].VersionID {
			return false
		}
	}
	return true
}
