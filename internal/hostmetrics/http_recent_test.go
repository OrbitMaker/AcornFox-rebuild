package hostmetrics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSnapshotHTTPHandler(t *testing.T) {
	sampler := NewSampler(Config{OS: "linux"})
	handler := NewHTTPHandler(sampler)

	// 1. Success without query
	req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.SchemaVersion != 1 {
		t.Fatalf("expected schema_version 1, got %d", resp.SchemaVersion)
	}

	// 2. Reject query parameters
	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics?foo=bar", nil)
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for query params on snapshot, got %d", badRec.Code)
	}

	// 3. Reject non-GET
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/host/metrics", nil)
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", postRec.Code)
	}
	if postRec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("expected Allow: GET, got %q", postRec.Header().Get("Allow"))
	}
}

func TestRecentHTTPHandler(t *testing.T) {
	now := time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC)
	sampler := NewSampler(Config{
		OS:  "linux",
		Now: func() time.Time { return now },
	})
	handler := NewRecentHTTPHandler(sampler)

	// 1. Default limit (no query)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics/recent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var recentResp RecentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &recentResp); err != nil {
		t.Fatalf("failed to decode recent response: %v", err)
	}
	if recentResp.SchemaVersion != 1 {
		t.Fatalf("expected schema_version 1, got %d", recentResp.SchemaVersion)
	}
	if recentResp.Capacity != 360 {
		t.Fatalf("expected capacity 360, got %d", recentResp.Capacity)
	}
	if recentResp.RetentionSeconds != 1800 {
		t.Fatalf("expected retention_seconds 1800, got %d", recentResp.RetentionSeconds)
	}
	if recentResp.Points == nil {
		t.Fatal("expected empty slice [] for points, got nil")
	}

	// 2. Valid limits
	validLimits := []string{"1", "60", "360"}
	for _, l := range validLimits {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics/recent?limit="+l, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("limit=%s expected 200, got %d", l, w.Code)
		}
	}

	// 3. Invalid limits & invalid queries -> 400
	invalidQueries := []string{
		"limit=0",
		"limit=-1",
		"limit=361",
		"limit=abc",
		"limit=",
		"limit=01",
		"limit=+10",
		"unknown=1",
		"limit=10&limit=20",
		"limit=10&foo=bar",
		"limit=%",
	}
	for _, q := range invalidQueries {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics/recent?"+q, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("query %q expected 400, got %d body=%s", q, w.Code, w.Body.String())
		}
	}

	// 4. Method not allowed
	wPost := httptest.NewRecorder()
	handler.ServeHTTP(wPost, httptest.NewRequest(http.MethodPost, "/api/v1/acornfox/host/metrics/recent", nil))
	if wPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", wPost.Code)
	}
	if wPost.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("expected Allow: GET, got %q", wPost.Header().Get("Allow"))
	}
}

func TestRecentHTTPHandlerNilOrUnsupported(t *testing.T) {
	// Nil sampler
	nilHandler := NewRecentHTTPHandler(nil)
	rec := httptest.NewRecorder()
	nilHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics/recent", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for nil sampler, got %d", rec.Code)
	}
	var nilResp RecentResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &nilResp)
	if nilResp.Availability != Unavailable || len(nilResp.Points) != 0 {
		t.Fatalf("unexpected nil sampler response: %+v", nilResp)
	}

	// Unsupported OS
	darwinHandler := NewRecentHTTPHandler(NewSampler(Config{OS: "darwin"}))
	recDarwin := httptest.NewRecorder()
	darwinHandler.ServeHTTP(recDarwin, httptest.NewRequest(http.MethodGet, "/api/v1/acornfox/host/metrics/recent", nil))
	if recDarwin.Code != http.StatusOK {
		t.Fatalf("expected 200 for darwin sampler, got %d", recDarwin.Code)
	}
	var darwinResp RecentResponse
	_ = json.Unmarshal(recDarwin.Body.Bytes(), &darwinResp)
	if darwinResp.Availability != Unsupported || len(darwinResp.Points) != 0 {
		t.Fatalf("unexpected unsupported response: %+v", darwinResp)
	}
}

func TestSamplerDoneLifecycle(t *testing.T) {
	sampler := NewSampler(Config{OS: "linux"})

	// Before Start, Done() is nil
	if sampler.Done() != nil {
		t.Fatal("expected Done() to be nil before Start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sampler.Start(ctx)

	done := sampler.Done()
	if done == nil {
		t.Fatal("expected non-nil Done() channel after Start")
	}

	select {
	case <-done:
		t.Fatal("Done() channel should not be closed while ctx is active")
	default:
	}

	cancel()

	select {
	case <-done:
		// OK - closed as expected
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sampler Done() channel to close")
	}
}

func TestSamplerConcurrentStartAndDone(t *testing.T) {
	for i := 0; i < 20; i++ {
		sampler := NewSampler(Config{OS: "linux"})
		ctx, cancel := context.WithCancel(context.Background())
		startWg := sync.WaitGroup{}
		startWg.Add(2)

		go func() {
			defer startWg.Done()
			sampler.Start(ctx)
		}()

		var doneChan <-chan struct{}
		go func() {
			defer startWg.Done()
			for j := 0; j < 50; j++ {
				if ch := sampler.Done(); ch != nil {
					doneChan = ch
					break
				}
				time.Sleep(100 * time.Microsecond)
			}
		}()

		startWg.Wait()
		cancel()
		if doneChan == nil {
			doneChan = sampler.Done()
		}
		if doneChan != nil {
			select {
			case <-doneChan:
			case <-time.After(2 * time.Second):
				t.Fatal("concurrent test timed out waiting for Done()")
			}
		}
	}
}
