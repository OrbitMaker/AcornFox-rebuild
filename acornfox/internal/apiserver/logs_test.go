package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

type batchRunner struct {
	*fakeRunner
	records   []runner.LogRecord
	boundary  int
	lastSince string
}

func (r *batchRunner) LogBatch(_ context.Context, _, _ string, _ int, since string) (runner.LogBatchResponse, error) {
	r.lastSince = since
	return runner.LogBatchResponse{Records: r.records, BoundaryOffset: r.boundary}, nil
}

func logBatchServer(t *testing.T) (http.Handler, *fakeStore, *batchRunner) {
	t.Helper()
	store := newFakeStore()
	_, _, _ = store.EnsureApp(context.Background(), "shop")
	_, _ = store.UpdateApp(context.Background(), "shop", func(a *state.App) error { a.CurrentDeployment = "0123456789ab"; return nil })
	run := &batchRunner{fakeRunner: newFakeRunner()}
	h := New(Config{Store: store, Kicker: &fakeKicker{}, Runner: run, UploadDir: t.TempDir()})
	return h, store, run
}

func decodeLogBatch(t *testing.T, wbody string) logBatchView {
	t.Helper()
	var value logBatchView
	if err := json.Unmarshal([]byte(wbody), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestLogsCursorPreservesIdenticalRecordsAtBoundary(t *testing.T) {
	h, _, run := logBatchServer(t)
	stamp := "2026-09-30T10:00:00.123456789Z"
	run.records = []runner.LogRecord{{Timestamp: stamp, Text: "same"}, {Timestamp: stamp, Text: "same"}, {Timestamp: stamp, Text: "same"}}
	w := do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2", nil, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	first := decodeLogBatch(t, w.Body.String())
	if len(first.Lines) != 2 || !first.HasMore {
		t.Fatalf("first=%+v", first)
	}
	w = do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2&cursor="+first.Cursor, nil, nil)
	second := decodeLogBatch(t, w.Body.String())
	if len(second.Lines) != 1 || second.HasMore || second.Lines[0] != "same" {
		t.Fatalf("second=%+v", second)
	}
	w = do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2&cursor="+second.Cursor, nil, nil)
	if got := decodeLogBatch(t, w.Body.String()); len(got.Lines) != 0 {
		t.Fatalf("duplicate replay=%+v", got)
	}
	run.records = append(run.records, runner.LogRecord{Timestamp: stamp, Text: "same"})
	w = do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2&cursor="+second.Cursor, nil, nil)
	if got := decodeLogBatch(t, w.Body.String()); len(got.Lines) != 1 {
		t.Fatalf("identical new event lost=%+v", got)
	}
}

func TestLogsInitialTailUsesWholeBoundaryCount(t *testing.T) {
	h, _, run := logBatchServer(t)
	stamp := "2026-09-30T10:00:00Z"
	run.records = []runner.LogRecord{{Timestamp: stamp, Text: "same"}, {Timestamp: stamp, Text: "same"}}
	run.boundary = 5
	first := decodeLogBatch(t, do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2", nil, nil).Body.String())
	run.boundary = 0
	run.records = append(run.records, run.records[0], run.records[0], run.records[0])
	second := decodeLogBatch(t, do(t, h, "GET", "/v1/apps/shop/log-batch?tail=2&cursor="+first.Cursor, nil, nil).Body.String())
	if len(second.Lines) != 0 {
		t.Fatalf("initial suffix replayed: %+v", second)
	}
}

func TestLogsRedactAddonRawRootAndRemovedCredentials(t *testing.T) {
	h, store, run := logBatchServer(t)
	_ = store.SetEnv(context.Background(), state.EnvVar{App: "shop", Key: "SECRET", Value: "multiline\nsecret", Secret: true})
	credentials, err := state.NewAddonCredentials("shop", state.AddonMySQL, "af-shop-addon-mysql", 3306)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := credentials.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	store.removedAddons = map[string]state.Addon{"shop/mysql": {App: "shop", Kind: state.AddonMySQL, Credentials: raw}}
	stamp := "2026-09-30T10:00:00Z"
	run.records = []runner.LogRecord{
		{Timestamp: stamp, Text: credentials.URL},
		{Timestamp: stamp, Text: credentials.Password + " " + credentials.RootPassword},
		{Timestamp: stamp, Text: "multiline"}, {Timestamp: stamp, Text: "secret"},
	}
	w := do(t, h, "GET", "/v1/apps/shop/log-batch", nil, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, secret := range []string{credentials.Password, credentials.RootPassword, credentials.URL, "multiline", "secret"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked secret %q", secret)
		}
	}
	// The original /logs endpoint uses the same safe redaction path.
	run.logLines[runner.ContainerName("shop", "0123456789ab")] = []string{credentials.Password, credentials.RootPassword}
	w = do(t, h, "GET", "/v1/apps/shop/logs", nil, nil)
	if strings.Contains(w.Body.String(), credentials.Password) || strings.Contains(w.Body.String(), credentials.RootPassword) {
		t.Fatal("legacy logs leaked credentials")
	}
}

func TestLogsCursorDeploymentResetAndSinceValidation(t *testing.T) {
	h, store, run := logBatchServer(t)
	stamp := "2026-09-30T10:00:00Z"
	run.records = []runner.LogRecord{{Timestamp: stamp, Text: "one"}}
	first := decodeLogBatch(t, do(t, h, "GET", "/v1/apps/shop/log-batch", nil, nil).Body.String())
	_, _ = store.UpdateApp(context.Background(), "shop", func(a *state.App) error { a.CurrentDeployment = "abcdefabcdef"; return nil })
	second := decodeLogBatch(t, do(t, h, "GET", "/v1/apps/shop/log-batch?cursor="+first.Cursor, nil, nil).Body.String())
	if !second.Reset || len(second.Lines) != 1 {
		t.Fatalf("reset=%+v", second)
	}
	for _, query := range []string{"since=yesterday", "tail=0", "cursor=broken"} {
		w := do(t, h, "GET", "/v1/apps/shop/log-batch?"+query, nil, nil)
		if w.Code != 400 {
			t.Fatalf("query %s: %d", query, w.Code)
		}
	}
	w := do(t, h, "GET", "/v1/apps/shop/log-batch?since=2026-09-30T10:00:00Z", nil, nil)
	if w.Code != 200 || run.lastSince != "2026-09-30T09:59:59.999999999Z" {
		t.Fatalf("since=%q status=%d", run.lastSince, w.Code)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(first.Cursor)
	var cursor logCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.Offset != 1 {
		t.Fatalf("cursor=%s err=%v", decoded, err)
	}
}

func TestLogsFailClosedWhenStoredCredentialsCorrupt(t *testing.T) {
	h, store, _ := logBatchServer(t)
	store.addons = map[string]state.Addon{"shop/redis": {App: "shop", Kind: state.AddonRedis, Credentials: []byte("invalid")}}
	for _, path := range []string{"/v1/apps/shop/logs", "/v1/apps/shop/log-batch"} {
		w := do(t, h, "GET", path, nil, nil)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "redaction_unavailable") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}
