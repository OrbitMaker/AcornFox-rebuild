package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sort"
	"testing"
	"time"
)

type platformPublicationFake struct {
	objects        map[string]PlatformBackupStoreObject
	bodies         map[string][]byte
	putErr         error
	closeErr       error
	getBody        map[string][]byte
	extra          []PlatformBackupStoreObject
	puts           int
	lastListPrefix string
}

func newPlatformPublicationFake() *platformPublicationFake {
	return &platformPublicationFake{objects: map[string]PlatformBackupStoreObject{}, bodies: map[string][]byte{}, getBody: map[string][]byte{}}
}
func platformPublicationRef(key, version string) string { return key + "\x00" + version }
func (s *platformPublicationFake) PutReconciled(_ context.Context, expected PlatformBackupExpectedObject, source io.Reader) (PlatformBackupStoreObject, error) {
	s.puts++
	if s.putErr != nil {
		return PlatformBackupStoreObject{}, s.putErr
	}
	if object, ok := s.objects[expected.ObjectKey]; ok {
		return object, nil
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return PlatformBackupStoreObject{}, err
	}
	version := "data-version-1"
	if bytes.HasSuffix([]byte(expected.ObjectKey), []byte(".receipt.json")) {
		version = "receipt-version-1"
	}
	object := PlatformBackupStoreObject{ObjectKey: expected.ObjectKey, VersionID: version, SHA256: expected.SHA256, Size: expected.Size}
	s.objects[expected.ObjectKey], s.bodies[platformPublicationRef(expected.ObjectKey, version)] = object, body
	return object, nil
}
func (s *platformPublicationFake) HeadCurrentVersion(_ context.Context, key string) (PlatformBackupStoreObject, error) {
	object, ok := s.objects[key]
	if !ok {
		return PlatformBackupStoreObject{}, errors.New("missing")
	}
	return object, nil
}
func (s *platformPublicationFake) Get(_ context.Context, key, version string) (io.ReadCloser, PlatformBackupStoreObject, error) {
	object, ok := s.objects[key]
	if !ok || object.VersionID != version {
		return nil, PlatformBackupStoreObject{}, errors.New("missing")
	}
	body := s.bodies[platformPublicationRef(key, version)]
	if overridden, ok := s.getBody[platformPublicationRef(key, version)]; ok {
		body = overridden
	}
	return platformPublicationReadCloser{Reader: bytes.NewReader(body), err: s.closeErr}, object, nil
}
func (s *platformPublicationFake) ListVersions(_ context.Context, prefix string) ([]PlatformBackupStoreObject, error) {
	s.lastListPrefix = prefix
	values := make([]PlatformBackupStoreObject, 0, len(s.objects))
	for key, object := range s.objects {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			values = append(values, object)
		}
	}
	values = append(values, s.extra...)
	sort.Slice(values, func(i, j int) bool { return values[i].ObjectKey < values[j].ObjectKey })
	return values, nil
}
func (s *platformPublicationFake) DeleteVersion(context.Context, string, string) error {
	return errors.New("not used")
}

type platformPublicationReadCloser struct {
	*bytes.Reader
	err error
}

func (r platformPublicationReadCloser) Close() error { return r.err }

func platformPublicationRequest(t *testing.T) (PlatformBackupPublishRequest, []byte) {
	t.Helper()
	packageRaw, cryptoContext := platformCryptoFixture(t)
	key := bytes.Repeat([]byte{7}, 32)
	var encrypted bytes.Buffer
	receipt, err := EncryptPlatformBackup(&encrypted, bytes.NewReader(packageRaw), key, cryptoContext, bytes.NewReader(bytes.Repeat([]byte{3}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	return PlatformBackupPublishRequest{Encrypted: bytes.NewReader(encrypted.Bytes()), EncryptionContext: cryptoContext, EncryptionReceipt: receipt, CreatedAt: time.Date(2026, 8, 31, 3, 4, 5, 0, time.UTC), DecryptionCheck: &PlatformBackupDecryptionCheck{Key: key, Scratch: backupScratch(t)}}, encrypted.Bytes()
}

func TestPublishPlatformBackupCommitsOnlyAfterCanonicalReceiptReadback(t *testing.T) {
	request, encrypted := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	if receipt := platformRemoteReceipt(request, PlatformBackupStoreObject{ObjectKey: request.EncryptionContext.ObjectKey, VersionID: "data-version-1", SHA256: request.EncryptionReceipt.ObjectSHA256, Size: request.EncryptionReceipt.ObjectSize}); receipt.Validate() != nil {
		t.Fatalf("preflight receipt invalid: %+v", receipt)
	}
	committed, err := PublishPlatformBackup(context.Background(), store, request)
	if err != nil || committed.Validate() != nil || committed.Receipt.DataVersionID != "data-version-1" || committed.ReceiptVersionID != "receipt-version-1" {
		t.Fatalf("committed=%+v err=%v", committed, err)
	}
	if got := store.bodies[platformPublicationRef(request.EncryptionContext.ObjectKey, "data-version-1")]; !bytes.Equal(got, encrypted) {
		t.Fatal("data object was not streamed unchanged")
	}
	if strings := string(committed.ReceiptContent); bytes.Contains([]byte(strings), []byte("postgresql://")) || bytes.Contains([]byte(strings), []byte("password")) {
		t.Fatalf("receipt leaked plaintext or secret: %s", strings)
	}
	replayRequest, _ := platformPublicationRequest(t)
	replayRequest.ExpectedExisting = &committed
	// Replay is a version-qualified read-only verification path; no ambiguous
	// create reconciliation is allowed after a durable local commit exists.
	store.putErr = errors.New("backend credential must not escape")
	putsBeforeReplay := store.puts
	replay, err := PublishPlatformBackup(context.Background(), store, replayRequest)
	if err != nil || store.puts != putsBeforeReplay || !reflect.DeepEqual(replay, committed) || !bytes.Equal(replay.ReceiptContent, committed.ReceiptContent) {
		t.Fatalf("replay=%+v err=%v puts=%d", replay, err, store.puts)
	}
	wrongVersion := committed
	wrongVersion.Receipt.DataVersionID = "foreign-data-version"
	wrongVersion.ReceiptContent, err = MarshalPlatformBackupRemoteReceiptV2(wrongVersion.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion.ReceiptSHA256, wrongVersion.ReceiptSize = sha256Hex(wrongVersion.ReceiptContent), int64(len(wrongVersion.ReceiptContent))
	replayRequest.ExpectedExisting = &wrongVersion
	if _, err := PublishPlatformBackup(context.Background(), store, replayRequest); !errors.Is(err, ErrRemoteBackupTransport) || store.puts != putsBeforeReplay {
		t.Fatalf("invalid data version err=%v puts=%d", err, store.puts)
	}
	mismatched := committed
	mismatched.Receipt.ReleaseID = "release-prevalidation-other"
	mismatched.ReceiptContent, err = MarshalPlatformBackupRemoteReceiptV2(mismatched.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.ReceiptSHA256, mismatched.ReceiptSize = sha256Hex(mismatched.ReceiptContent), int64(len(mismatched.ReceiptContent))
	replayRequest.ExpectedExisting = &mismatched
	if _, err := PublishPlatformBackup(context.Background(), store, replayRequest); !errors.Is(err, ErrRemoteBackupContract) || store.puts != putsBeforeReplay {
		t.Fatalf("expected prevalidation err=%v puts=%d", err, store.puts)
	}
	wrongReceiptVersion := committed
	wrongReceiptVersion.ReceiptVersionID = "receipt-version-foreign"
	replayRequest.ExpectedExisting = &wrongReceiptVersion
	if _, err := PublishPlatformBackup(context.Background(), store, replayRequest); !errors.Is(err, ErrRemoteBackupTransport) || store.puts != putsBeforeReplay {
		t.Fatalf("invalid receipt version err=%v puts=%d", err, store.puts)
	}
	discovered, err := DiscoverCommittedPlatformBackups(context.Background(), store, request.EncryptionContext.SourceInstallationIDSHA256)
	if err != nil || len(discovered) != 1 || discovered[0].ReceiptVersionID != committed.ReceiptVersionID {
		t.Fatalf("discovered=%+v err=%v", discovered, err)
	}
}

func TestPublishPlatformBackupRejectsReceiptTamperAndLeavesNoCommittedResult(t *testing.T) {
	request, _ := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	receiptKey := platformBackupReceiptObjectKey(request.EncryptionContext)
	// The readback fake mutates only after the receipt has been written. The
	// data object may remain for recovery, but visibility is never returned.
	store.getBody[platformPublicationRef(receiptKey, "receipt-version-1")] = []byte("tampered")
	if committed, err := PublishPlatformBackup(context.Background(), store, request); !errors.Is(err, ErrRemoteBackupTransport) || committed.ReceiptVersionID != "" {
		t.Fatalf("committed=%+v err=%v", committed, err)
	}
}

func TestPublishPlatformBackupSanitizesReadbackCloseError(t *testing.T) {
	request, _ := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	store.closeErr = errors.New("backend credential must not escape")
	if _, err := PublishPlatformBackup(context.Background(), store, request); !errors.Is(err, ErrRemoteBackupTransport) || bytes.Contains([]byte(err.Error()), []byte("credential")) {
		t.Fatalf("close err=%v", err)
	}
}

func TestPlatformBackupRemoteReceiptV2StrictAndDiscoveryRejectsMultipleVersions(t *testing.T) {
	request, _ := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	committed, err := PublishPlatformBackup(context.Background(), store, request)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"unknown":  append(append([]byte(nil), committed.ReceiptContent[:len(committed.ReceiptContent)-1]...), []byte(`,"unknown":true}`)...),
		"trailing": append(append([]byte(nil), committed.ReceiptContent...), []byte(" {}")...),
		"null":     bytes.Replace(committed.ReceiptContent, []byte(`"data_version_id":"`), []byte(`"data_version_id":null,"old":"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlatformBackupRemoteReceiptV2(raw); !errors.Is(err, ErrRemoteBackupContract) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	store.extra = append(store.extra, PlatformBackupStoreObject{ObjectKey: committed.ReceiptObjectKey, VersionID: "receipt-version-2", SHA256: committed.ReceiptSHA256, Size: committed.ReceiptSize})
	// Non-receipt data objects are ignored, but a malformed receipt object is a
	// hard conflict rather than a silently selected candidate.
	if _, err := DiscoverCommittedPlatformBackups(context.Background(), store, request.EncryptionContext.SourceInstallationIDSHA256); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("multiple receipt err=%v", err)
	}
}

func TestDiscoverCommittedPlatformBackupsRejectsUnknownManagedObjectAndOversizedReceipt(t *testing.T) {
	request, _ := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	committed, err := PublishPlatformBackup(context.Background(), store, request)
	if err != nil {
		t.Fatal(err)
	}
	unknownKey := "open-card/backups/" + request.EncryptionContext.SourceInstallationIDSHA256 + "/unexpected.bin"
	store.extra = append(store.extra, PlatformBackupStoreObject{ObjectKey: unknownKey, VersionID: "unknown-version-1", SHA256: remoteDigest("unknown"), Size: 1})
	if _, err := DiscoverCommittedPlatformBackups(context.Background(), store, request.EncryptionContext.SourceInstallationIDSHA256); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("unknown managed object err=%v", err)
	}
	store.extra = nil
	oversized := store.objects[committed.ReceiptObjectKey]
	oversized.Size = platformBackupRemoteReceiptMaxSize + 1
	store.objects[committed.ReceiptObjectKey] = oversized
	if _, err := DiscoverCommittedPlatformBackups(context.Background(), store, request.EncryptionContext.SourceInstallationIDSHA256); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("oversized receipt err=%v", err)
	}
}

func TestDiscoverCommittedPlatformBackupsRejectsCrossInstallationLeak(t *testing.T) {
	request, _ := platformPublicationRequest(t)
	store := newPlatformPublicationFake()
	committed, err := PublishPlatformBackup(context.Background(), store, request)
	if err != nil {
		t.Fatal(err)
	}
	otherInstallation := remoteDigest("other-installation")
	store.extra = append(store.extra, PlatformBackupStoreObject{
		ObjectKey: "open-card/backups/" + otherInstallation + "/" + committed.Receipt.BackupID + ".receipt.json",
		VersionID: "receipt-version-other", SHA256: committed.ReceiptSHA256, Size: committed.ReceiptSize,
	})
	if _, err := DiscoverCommittedPlatformBackups(context.Background(), store, request.EncryptionContext.SourceInstallationIDSHA256); !errors.Is(err, ErrRemoteBackupTransport) {
		t.Fatalf("cross-installation leak err=%v", err)
	}
	if store.lastListPrefix != platformBackupInstallationPrefix(request.EncryptionContext.SourceInstallationIDSHA256) {
		t.Fatalf("listed broad namespace %q", store.lastListPrefix)
	}
}
