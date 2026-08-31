package tencentcos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

type fakeAPI struct {
	status      VersioningStatus
	statusErr   error
	statusCalls int
	put         ObjectVersion
	putErr      error
	putCalls    int
	putBody     []byte
	putReadSize int
	head        map[string]ObjectVersion
	headErr     error
	headCalls   int
	get         ObjectVersion
	getStream   io.ReadCloser
	getErr      error
	getCalls    int
	list        []VersionPage
	listErr     error
	listCalls   int
	markers     [][2]string
	deleteErr   error
	deleteCalls int
	deleteKey   string
	deleteVer   string
}

func (f *fakeAPI) VersioningStatus(context.Context) (VersioningStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}
func (f *fakeAPI) Put(_ context.Context, _ string, body io.Reader, _ int64, _ string) (ObjectVersion, error) {
	f.putCalls++
	if f.putReadSize > 0 {
		buffer := make([]byte, f.putReadSize)
		n, _ := body.Read(buffer)
		f.putBody = append([]byte(nil), buffer[:n]...)
	} else {
		f.putBody, _ = io.ReadAll(body)
	}
	return f.put, f.putErr
}
func (f *fakeAPI) Head(_ context.Context, key, versionID string) (ObjectVersion, error) {
	f.headCalls++
	if f.headErr != nil {
		return ObjectVersion{}, f.headErr
	}
	if value, ok := f.head[key+"\x00"+versionID]; ok {
		return value, nil
	}
	return ObjectVersion{}, ErrNotFound
}
func (f *fakeAPI) Get(context.Context, string, string) (io.ReadCloser, ObjectVersion, error) {
	f.getCalls++
	return f.getStream, f.get, f.getErr
}
func (f *fakeAPI) ListVersions(_ context.Context, _ string, keyMarker, versionMarker string, max int) (VersionPage, error) {
	if max != maxListPageSize {
		return VersionPage{}, errors.New("unexpected list size")
	}
	f.markers = append(f.markers, [2]string{keyMarker, versionMarker})
	if f.listErr != nil {
		return VersionPage{}, f.listErr
	}
	if f.listCalls >= len(f.list) {
		return VersionPage{}, errors.New("unexpected list call")
	}
	page := f.list[f.listCalls]
	f.listCalls++
	return page, nil
}
func (f *fakeAPI) DeleteVersion(_ context.Context, key, versionID string) error {
	f.deleteCalls++
	f.deleteKey, f.deleteVer = key, versionID
	return f.deleteErr
}

func digest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func testStore(t *testing.T, api *fakeAPI) (*Adapter, install.BackupConfigV1, string) {
	t.Helper()
	installation := digest("installation")
	config := install.BackupConfigV1{SchemaVersion: 1, InstallationIDSHA256: installation, Provider: "tencent-cos", Bucket: "open-card-backups-1234567890", Region: "ap-shanghai", Endpoint: "https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn", Prefix: "open-card/backups", CredentialProvider: "cvm-instance-role"}
	store, err := NewTaskBackupObjectStore(context.Background(), config, installation, api)
	if err != nil {
		t.Fatal(err)
	}
	return store, config, installation
}

func expected(t *testing.T, config install.BackupConfigV1, id string) install.RemoteBackupExpectedObject {
	t.Helper()
	key, err := config.ObjectKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return install.RemoteBackupExpectedObject{ObjectKey: key, SHA256: digest("payload"), Size: 7}
}

func version(expected install.RemoteBackupExpectedObject, id string) ObjectVersion {
	return ObjectVersion{Key: expected.ObjectKey, VersionID: id, SHA256: expected.SHA256, Size: expected.Size}
}

func TestPutIfAbsentCreatesAndIdempotentlyFindsOneExactVersion(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-create")
	created := version(want, "v1")
	api.put = created
	api.head = map[string]ObjectVersion{want.ObjectKey + "\x00v1": created}
	api.list = []VersionPage{{}, {Versions: []ObjectVersion{created}}}
	got, err := store.PutIfAbsent(context.Background(), want, strings.NewReader("payload"))
	if err != nil || got.VersionID != "v1" || api.putCalls != 1 || string(api.putBody) != "payload" {
		t.Fatalf("got=%+v err=%v calls=%d body=%q", got, err, api.putCalls, api.putBody)
	}

	api.listCalls, api.putCalls = 0, 0
	api.list = []VersionPage{{Versions: []ObjectVersion{created}}}
	got, err = store.PutIfAbsent(context.Background(), want, strings.NewReader("payload"))
	if err != nil || got.VersionID != "v1" || api.putCalls != 0 {
		t.Fatalf("idempotent got=%+v err=%v puts=%d", got, err, api.putCalls)
	}
}

func TestPutIfAbsentReconcilesUnknownPutAndRejectsAmbiguity(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, putErr: errors.New("https://secret.invalid/token")}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-reconcile")
	stored := version(want, "v1")
	api.head = map[string]ObjectVersion{want.ObjectKey + "\x00v1": stored}
	api.list = []VersionPage{{}, {Versions: []ObjectVersion{stored}}}
	got, err := store.PutIfAbsent(context.Background(), want, strings.NewReader("payload"))
	if err != nil || got.VersionID != "v1" || strings.Contains(errString(err), "secret") {
		t.Fatalf("reconcile got=%+v err=%v", got, err)
	}

	api.listCalls = 0
	api.list = []VersionPage{{Versions: []ObjectVersion{stored, version(want, "v2")}}}
	if _, err := store.PutIfAbsent(context.Background(), want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
		t.Fatalf("multiple versions err=%v", err)
	}
	api.listCalls = 0
	api.list = []VersionPage{{Versions: []ObjectVersion{{Key: want.ObjectKey, VersionID: "v3", IsDeleteMarker: true}}}}
	if _, err := store.PutIfAbsent(context.Background(), want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
		t.Fatalf("delete marker err=%v", err)
	}
}

func TestVersioningAndMetadataFailuresAreNeutral(t *testing.T) {
	for _, status := range []VersioningStatus{"Suspended", ""} {
		api := &fakeAPI{status: status}
		store, config, _ := testStore(t, api)
		want := expected(t, config, "backup-cos-status")
		if _, err := store.PutIfAbsent(context.Background(), want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
			t.Fatalf("status %q err=%v", status, err)
		}
	}
	api := &fakeAPI{status: VersioningEnabled}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-bad-metadata")
	api.head = map[string]ObjectVersion{want.ObjectKey + "\x00": {Key: want.ObjectKey, VersionID: "null", SHA256: want.SHA256, Size: want.Size}}
	if _, err := store.Head(context.Background(), want.ObjectKey); !errors.Is(err, ErrTransport) {
		t.Fatalf("null version err=%v", err)
	}
	if _, err := store.PutIfAbsent(context.Background(), want, nil); !errors.Is(err, ErrContract) {
		t.Fatalf("nil body err=%v", err)
	}
	if _, err := store.PutIfAbsent(context.Background(), install.RemoteBackupExpectedObject{}, strings.NewReader("x")); !errors.Is(err, ErrContract) {
		t.Fatalf("bad expected err=%v", err)
	}
}

func TestListExhaustsBothMarkersAndRejectsProgressOrDuplicates(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled}
	store, config, installation := testStore(t, api)
	one := expected(t, config, "backup-cos-list-a")
	two := expected(t, config, "backup-cos-list-b")
	v1, v2 := version(one, "v2"), version(two, "v1")
	api.list = []VersionPage{{Versions: []ObjectVersion{v1}, IsTruncated: true, NextKeyMarker: one.ObjectKey, NextVersionIDMarker: "v2"}, {Versions: []ObjectVersion{v2}}}
	prefix := config.Prefix + "/" + installation + "/"
	objects, err := store.List(context.Background(), prefix)
	if err != nil || len(objects) != 2 || objects[0].ObjectKey != one.ObjectKey || len(api.markers) != 2 || api.markers[1] != [2]string{one.ObjectKey, "v2"} {
		t.Fatalf("objects=%+v err=%v markers=%+v", objects, err, api.markers)
	}

	api.listCalls, api.markers = 0, nil
	api.list = []VersionPage{{IsTruncated: true, NextKeyMarker: "k", NextVersionIDMarker: "v"}, {IsTruncated: true, NextKeyMarker: "k", NextVersionIDMarker: "v"}}
	if _, err := store.List(context.Background(), prefix); !errors.Is(err, ErrTransport) {
		t.Fatalf("cycle err=%v", err)
	}
	api.listCalls = 0
	api.list = []VersionPage{{Versions: []ObjectVersion{v1}, IsTruncated: true, NextKeyMarker: "k", NextVersionIDMarker: "v"}, {Versions: []ObjectVersion{v1}}}
	if _, err := store.List(context.Background(), prefix); !errors.Is(err, ErrTransport) {
		t.Fatalf("duplicate err=%v", err)
	}
	api.listCalls, api.markers = 0, nil
	api.list = []VersionPage{{Versions: []ObjectVersion{v1}, IsTruncated: true, NextKeyMarker: one.ObjectKey, NextVersionIDMarker: ""}, {Versions: []ObjectVersion{v2}}}
	if _, err := store.List(context.Background(), prefix); err != nil || len(api.markers) != 2 || api.markers[1] != [2]string{one.ObjectKey, ""} {
		t.Fatalf("empty version marker err=%v markers=%+v", err, api.markers)
	}
}

type closingReader struct {
	io.Reader
	closed bool
}

func (r *closingReader) Close() error { r.closed = true; return nil }

func TestGetClosesInvalidStreamAndDeleteProvesExactAbsence(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-get")
	stored := version(want, "v1")
	badStream := &closingReader{Reader: bytes.NewReader(nil)}
	api.get, api.getStream = ObjectVersion{Key: want.ObjectKey, VersionID: "v2", SHA256: want.SHA256, Size: want.Size}, badStream
	if _, _, err := store.Get(context.Background(), want.ObjectKey, "v1"); !errors.Is(err, ErrTransport) || !badStream.closed {
		t.Fatalf("get err=%v closed=%v", err, badStream.closed)
	}
	api.head = map[string]ObjectVersion{}
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, stored.VersionID); err != nil || api.deleteKey != want.ObjectKey || api.deleteVer != "v1" {
		t.Fatalf("delete err=%v key=%q version=%q", err, api.deleteKey, api.deleteVer)
	}
	api.head[want.ObjectKey+"\x00v1"] = stored
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, stored.VersionID); !errors.Is(err, ErrTransport) {
		t.Fatalf("unproven deletion err=%v", err)
	}
	api.head = map[string]ObjectVersion{}
	api.deleteErr = ErrNotFound
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, stored.VersionID); err != nil {
		t.Fatalf("already absent replay err=%v", err)
	}
	api.head[want.ObjectKey+"\x00v1"] = stored
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, stored.VersionID); !errors.Is(err, ErrTransport) {
		t.Fatalf("delete notfound with present head err=%v", err)
	}
}

func TestGetAndDeleteRejectUnsafeVersionRefsWithoutBackendCalls(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-version-ref")
	for _, versionID := range []string{"version space", "version?query", "version:port", "version/slash"} {
		if _, _, err := store.Get(context.Background(), want.ObjectKey, versionID); !errors.Is(err, ErrContract) {
			t.Fatalf("Get(%q) err=%v", versionID, err)
		}
		if err := store.DeleteVersion(context.Background(), want.ObjectKey, versionID); !errors.Is(err, ErrContract) {
			t.Fatalf("DeleteVersion(%q) err=%v", versionID, err)
		}
	}
	if api.statusCalls != 0 || api.getCalls != 0 || api.deleteCalls != 0 || api.headCalls != 0 {
		t.Fatalf("unsafe refs reached backend: status=%d get=%d delete=%d head=%d", api.statusCalls, api.getCalls, api.deleteCalls, api.headCalls)
	}
}

func TestCancelledContextAndBackendTextDoNotEscape(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, statusErr: errors.New("https://bucket.example/credential=secret")}
	store, config, _ := testStore(t, api)
	want := expected(t, config, "backup-cos-cancel")
	if _, err := store.Head(context.Background(), want.ObjectKey); !errors.Is(err, ErrTransport) || strings.Contains(errString(err), "secret") {
		t.Fatalf("backend error leaked: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PutIfAbsent(ctx, want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
		t.Fatalf("cancel err=%v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func testPlatformStore(t *testing.T, api *fakeAPI) (*PlatformAdapter, install.BackupConfigV1, string) {
	t.Helper()
	_, config, installation := testStore(t, api)
	store, err := NewTaskPlatformBackupVersionedStore(context.Background(), config, installation, api)
	if err != nil {
		t.Fatal(err)
	}
	return store, config, installation
}

func platformExpected(t *testing.T, config install.BackupConfigV1, id string, receipt bool) install.PlatformBackupExpectedObject {
	t.Helper()
	key, err := config.ObjectKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if receipt {
		key = strings.TrimSuffix(key, ".ocbkp") + ".receipt.json"
	}
	return install.PlatformBackupExpectedObject{ObjectKey: key, SHA256: digest("payload"), Size: int64(len("payload"))}
}
func platformVersion(expected install.PlatformBackupExpectedObject, id string) ObjectVersion {
	return ObjectVersion{Key: expected.ObjectKey, VersionID: id, SHA256: expected.SHA256, Size: expected.Size}
}

func TestPlatformAdapterAcceptsDataAndReceiptOnlyAndReconcilesExactVersion(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, head: map[string]ObjectVersion{}}
	store, config, _ := testPlatformStore(t, api)
	for _, receipt := range []bool{false, true} {
		want := platformExpected(t, config, "backup-platform-adapter", receipt)
		stored := platformVersion(want, map[bool]string{false: "data-v1", true: "receipt-v1"}[receipt])
		api.put, api.putErr, api.head = stored, nil, map[string]ObjectVersion{want.ObjectKey + "\x00" + stored.VersionID: stored}
		api.listCalls, api.putCalls = 0, 0
		api.list = []VersionPage{{}, {Versions: []ObjectVersion{stored}}}
		got, err := store.PutReconciled(context.Background(), want, strings.NewReader("payload"))
		if err != nil || got.ObjectKey != want.ObjectKey || got.VersionID != stored.VersionID || api.putCalls != 1 {
			t.Fatalf("receipt=%v got=%+v err=%v puts=%d", receipt, got, err, api.putCalls)
		}
	}
	bad := platformExpected(t, config, "backup-platform-bad", false)
	bad.ObjectKey = strings.TrimSuffix(bad.ObjectKey, ".ocbkp") + ".other"
	if _, err := store.PutReconciled(context.Background(), bad, strings.NewReader("payload")); !errors.Is(err, ErrContract) {
		t.Fatalf("unmanaged key err=%v", err)
	}
}

func TestPlatformAdapterRejectsSuccessfulPutUnlessCOSConsumedExactDeclaredBytes(t *testing.T) {
	for name, test := range map[string]struct {
		source  string
		mutate  func(*install.PlatformBackupExpectedObject)
		partial int
	}{
		"mismatched": {source: "payload", mutate: func(value *install.PlatformBackupExpectedObject) { value.SHA256 = digest("different") }},
		"short":      {source: "short"},
		"partial":    {source: "payload", partial: 3},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{status: VersioningEnabled, head: map[string]ObjectVersion{}, putReadSize: test.partial}
			store, config, _ := testPlatformStore(t, api)
			want := platformExpected(t, config, "backup-platform-evidence", false)
			if test.mutate != nil {
				test.mutate(&want)
			}
			api.put = platformVersion(want, "data-v1")
			api.list = []VersionPage{{}}
			if _, err := store.PutReconciled(context.Background(), want, strings.NewReader(test.source)); !errors.Is(err, ErrTransport) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestPlatformAdapterAmbiguousPutHeadAndExactGetAreFailClosed(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, putErr: errors.New("https://bucket/credential=secret"), head: map[string]ObjectVersion{}}
	store, config, _ := testPlatformStore(t, api)
	want := platformExpected(t, config, "backup-platform-ambiguous", false)
	stored := platformVersion(want, "data-v1")
	api.list = []VersionPage{{}, {Versions: []ObjectVersion{stored, platformVersion(want, "data-v2")}}}
	if _, err := store.PutReconciled(context.Background(), want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
		t.Fatalf("ambiguous put err=%v", err)
	}
	api.head[want.ObjectKey+"\x00"] = ObjectVersion{Key: want.ObjectKey, VersionID: "data-v1", IsDeleteMarker: true}
	if _, err := store.HeadCurrentVersion(context.Background(), want.ObjectKey); !errors.Is(err, ErrTransport) {
		t.Fatalf("delete current err=%v", err)
	}
	badStream := &closingReader{Reader: bytes.NewReader(nil)}
	api.get, api.getStream = ObjectVersion{Key: want.ObjectKey, VersionID: "other", SHA256: want.SHA256, Size: want.Size}, badStream
	if _, _, err := store.Get(context.Background(), want.ObjectKey, "data-v1"); !errors.Is(err, ErrTransport) || !badStream.closed {
		t.Fatalf("exact get err=%v closed=%v", err, badStream.closed)
	}
}

func TestPlatformAdapterListsExactInstallationNamespaceAndPagination(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled}
	store, config, installation := testPlatformStore(t, api)
	data := platformExpected(t, config, "backup-platform-list-data", false)
	receipt := platformExpected(t, config, "backup-platform-list-receipt", true)
	v1, v2 := platformVersion(data, "data-v1"), platformVersion(receipt, "receipt-v1")
	api.list = []VersionPage{{Versions: []ObjectVersion{v1}, IsTruncated: true, NextKeyMarker: data.ObjectKey, NextVersionIDMarker: ""}, {Versions: []ObjectVersion{v2}}}
	prefix := config.Prefix + "/" + installation
	objects, err := store.ListVersions(context.Background(), prefix)
	if err != nil || len(objects) != 2 || len(api.markers) != 2 || api.markers[1] != [2]string{data.ObjectKey, ""} {
		t.Fatalf("objects=%+v err=%v markers=%+v", objects, err, api.markers)
	}
	api.listCalls, api.markers = 0, nil
	foreign := v1
	foreign.Key = config.Prefix + "/" + digest("other-installation") + "/backup-platform-list-data.ocbkp"
	api.list = []VersionPage{{Versions: []ObjectVersion{foreign}}}
	if _, err := store.ListVersions(context.Background(), prefix); !errors.Is(err, ErrTransport) {
		t.Fatalf("cross namespace err=%v", err)
	}
}

func TestPlatformAdapterDeleteRequiresExactAbsenceAndSanitizesBackendError(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, head: map[string]ObjectVersion{}}
	store, config, _ := testPlatformStore(t, api)
	want := platformExpected(t, config, "backup-platform-delete", true)
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, "receipt-v1"); err != nil || api.deleteKey != want.ObjectKey || api.deleteVer != "receipt-v1" {
		t.Fatalf("delete err=%v key=%q version=%q", err, api.deleteKey, api.deleteVer)
	}
	api.deleteErr = ErrNotFound
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, "receipt-v1"); err != nil {
		t.Fatalf("not-found delete replay err=%v", err)
	}
	api.deleteErr = errors.New("https://bucket/credential=secret")
	if err := store.DeleteVersion(context.Background(), want.ObjectKey, "receipt-v1"); !errors.Is(err, ErrTransport) || strings.Contains(errString(err), "secret") {
		t.Fatalf("redaction err=%v", err)
	}
}

func TestPlatformAdapterP2ContextVersioningCurrentAndStreamBoundaries(t *testing.T) {
	api := &fakeAPI{status: VersioningEnabled, head: map[string]ObjectVersion{}}
	store, config, _ := testPlatformStore(t, api)
	want := platformExpected(t, config, "backup-platform-boundaries", false)
	if _, err := store.HeadCurrentVersion(nil, want.ObjectKey); !errors.Is(err, ErrTransport) || api.statusCalls != 0 {
		t.Fatalf("nil context err=%v status=%d", err, api.statusCalls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.HeadCurrentVersion(ctx, want.ObjectKey); !errors.Is(err, ErrTransport) || api.statusCalls != 0 {
		t.Fatalf("cancelled context err=%v status=%d", err, api.statusCalls)
	}
	api.status = "Suspended"
	if _, err := store.HeadCurrentVersion(context.Background(), want.ObjectKey); !errors.Is(err, ErrTransport) {
		t.Fatalf("disabled versioning err=%v", err)
	}
	api.status = VersioningEnabled
	stored := platformVersion(want, "data-v1")
	api.head[want.ObjectKey+"\x00"] = stored
	got, err := store.HeadCurrentVersion(context.Background(), want.ObjectKey)
	if err != nil || got.VersionID != stored.VersionID {
		t.Fatalf("current=%+v err=%v", got, err)
	}
	api.listCalls = 0
	api.list = []VersionPage{{Versions: []ObjectVersion{{Key: want.ObjectKey, VersionID: "delete-v1", IsDeleteMarker: true}}}}
	if _, err := store.PutReconciled(context.Background(), want, strings.NewReader("payload")); !errors.Is(err, ErrTransport) {
		t.Fatalf("delete marker list err=%v", err)
	}
	badStream := &closingReader{Reader: bytes.NewReader(nil)}
	api.getStream, api.getErr = badStream, errors.New("backend credential must not escape")
	if _, _, err := store.Get(context.Background(), want.ObjectKey, "data-v1"); !errors.Is(err, ErrTransport) || !badStream.closed || strings.Contains(errString(err), "credential") {
		t.Fatalf("get error err=%v closed=%v", err, badStream.closed)
	}
}
