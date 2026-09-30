package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

type followingAPI struct {
	*fakeAPI
	batch func(context.Context, string, int, string, string) (client.LogBatch, error)
}

func (f *followingAPI) LogBatch(ctx context.Context, app string, tail int, since, cursor string) (client.LogBatch, error) {
	return f.batch(ctx, app, tail, since, cursor)
}

func TestLogsPositionalAppAndTrailingFlags(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatal(err)
	}
	var got string
	var tail int
	h.api.logsFn = func(_ context.Context, name string, n int) ([]string, error) {
		got = name
		tail = n
		return []string{"same", "same"}, nil
	}
	code, out, errOut := h.run("logs", "shop", "--tail", "500")
	if code != exitOK || got != "shop" || tail != 500 || strings.Count(out, "same") != 2 {
		t.Fatalf("code=%d app=%s tail=%d out=%s err=%s", code, got, tail, out, errOut)
	}
}

func TestLogsFollowKeepsDuplicatesAndCancelsBlockedRequest(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	second := make(chan struct{})
	calls := 0
	api := &followingAPI{fakeAPI: h.api, batch: func(ctx context.Context, app string, tail int, since, cursor string) (client.LogBatch, error) {
		calls++
		if app != "shop" || tail != 100 {
			t.Errorf("request %s %d", app, tail)
		}
		if calls == 1 {
			if cursor != "" {
				t.Error("unexpected initial cursor")
			}
			return client.LogBatch{Lines: []string{"same", "same"}, Cursor: "boundary", HasMore: true}, nil
		}
		if cursor != "boundary" {
			t.Errorf("cursor=%s", cursor)
		}
		close(second)
		<-ctx.Done()
		return client.LogBatch{}, ctx.Err()
	}}
	h.connect = func(context.Context, client.Target) (client.API, error) { return api, nil }
	type result struct {
		code int
		out  string
	}
	done := make(chan result, 1)
	go func() {
		var out, errBuf bytes.Buffer
		code := MainWithConnector(ctx, []string{"logs", "shop", "-f"}, io.NopCloser(bytes.NewReader(nil)), &out, &errBuf, func(string) string { return "" }, h.connect, h.configDir, h.workDir)
		done <- result{code, out.String()}
	}()
	select {
	case <-second:
	case <-time.After(3 * time.Second):
		t.Fatal("follow did not request next page")
	}
	cancel()
	select {
	case got := <-done:
		if got.code != exitOK || strings.Count(got.out, "same") != 2 || !h.api.closed {
			t.Fatalf("result=%+v closed=%v", got, h.api.closed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow cancellation blocked")
	}
}

func TestLogsSinceUsesTimestampAndRejectsInvalidInput(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	api := &followingAPI{fakeAPI: h.api, batch: func(_ context.Context, app string, tail int, since, cursor string) (client.LogBatch, error) {
		if since != "2026-09-30T10:00:00Z" || app != "shop" {
			t.Errorf("since=%s app=%s", since, app)
		}
		return client.LogBatch{Lines: []string{"recent"}}, nil
	}}
	h.connect = func(context.Context, client.Target) (client.API, error) { return api, nil }
	if code, out, _ := h.run("logs", "shop", "--since", "2026-09-30T10:00:00Z"); code != exitOK || !strings.Contains(out, "recent") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if code, _, _ := h.run("logs", "shop", "--since", "yesterday"); code != exitUsage {
		t.Fatalf("invalid since code=%d", code)
	}
}
