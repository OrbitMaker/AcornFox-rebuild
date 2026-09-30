package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLogBatchWireAndRedeployKey(t *testing.T) {
	var keys []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redeploy") {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			_ = json.NewEncoder(w).Encode(map[string]any{"deployment_id": "0123456789ab"})
			return
		}
		if r.URL.Path != "/v1/apps/shop/log-batch" || r.URL.Query().Get("tail") != "500" || r.URL.Query().Get("cursor") != "boundary" || r.URL.Query().Get("since") != "2026-09-30T10:00:00Z" {
			t.Errorf("request=%s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(LogBatch{Lines: []string{"same", "same"}, Cursor: "next", HasMore: true})
	}))
	defer backend.Close()
	c := newDirectClient(t, backend)
	batch, err := c.LogBatch(context.Background(), "shop", 500, "2026-09-30T10:00:00Z", "boundary")
	if err != nil || len(batch.Lines) != 2 || batch.Cursor != "next" || !batch.HasMore {
		t.Fatalf("batch=%+v err=%v", batch, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Redeploy(context.Background(), "shop"); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || len(keys[0]) != 32 || keys[0] == keys[1] {
		t.Fatalf("keys=%v", keys)
	}
}

func TestLogPollingSharesSSHAndCancellationClosesCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake SSH uses Unix process pipes")
	}
	withFakeSSH(t)
	blocked := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "block" {
			close(blocked)
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/v1/status" {
			_ = json.NewEncoder(w).Encode(map[string]any{"api_version": APIVersion})
			return
		}
		_ = json.NewEncoder(w).Encode(LogBatch{Lines: []string{"same", "same"}, Cursor: "next"})
	}))
	defer backend.Close()
	countFile := filepath.Join(t.TempDir(), "count")
	t.Setenv("FAKE_SSH_MODE", "proxy")
	t.Setenv("FAKE_SSH_ADDR", strings.TrimPrefix(backend.URL, "http://"))
	t.Setenv("FAKE_SSH_COUNT", countFile)
	c, err := Connect(context.Background(), Target{SSH: "devbox"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		if _, err := c.LogBatch(context.Background(), "shop", 100, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal("polling blocked status:", err)
	}
	if launches := processLaunches(t, countFile); launches != 1 {
		t.Fatalf("launched %d SSH processes", launches)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.LogBatch(ctx, "shop", 100, "", "block"); done <- err }()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("log request cancellation blocked")
	}
	// Close deliberately terminates the SSH process after cancellation.
	// The subprocess wait status may be signal: killed; the CLI ignores it.
	_ = c.Close()
	// A later CLI command gets a new transport and remains usable.
	next, err := Connect(context.Background(), Target{SSH: "devbox"})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := next.Status(context.Background()); err != nil {
		t.Fatal("next command blocked:", err)
	}
}
