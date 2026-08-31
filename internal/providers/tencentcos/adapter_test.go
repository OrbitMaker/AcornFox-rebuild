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
	f.putBody, _ = io.ReadAll(body)
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
