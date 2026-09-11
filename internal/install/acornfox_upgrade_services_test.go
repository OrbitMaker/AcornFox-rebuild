package install

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyLocalReady(t *testing.T) {
	// 1. Success cases: valid states "uninitialized" and "initialized"
	for _, state := range []string{"uninitialized", "initialized"} {
		t.Run("success-state-"+state, func(t *testing.T) {
			var health18481Calls int32
			var setup8080Calls int32

			server18481 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&health18481Calls, 1)
				if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
					return
				}
				http.NotFound(w, r)
			}))
			defer server18481.Close()

			caddy8080 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&setup8080Calls, 1)
				if r.URL.Path == "/api/v1/acornfox/setup" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"state":"` + state + `"}`))
					return
				}
				http.NotFound(w, r)
			}))
			defer caddy8080.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := verifyLocalReadyWithTimeout(ctx, 2*time.Second, server18481.URL, caddy8080.URL)
			if err != nil {
				t.Fatalf("expected state %q to succeed, got %v", state, err)
			}
			if atomic.LoadInt32(&health18481Calls) < 2 {
				t.Fatalf("expected >= 2 health/ready calls, got %d", health18481Calls)
			}
			if atomic.LoadInt32(&setup8080Calls) < 1 {
				t.Fatalf("expected >= 1 setup call, got %d", setup8080Calls)
			}
		})
	}

	// 2. Retry recovery from transient 503 on 18481
	t.Run("retry-recovery", func(t *testing.T) {
		var transientCount int32
		transientServer18481 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&transientCount, 1)
			if count < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer transientServer18481.Close()

		caddy8080 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/acornfox/setup" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"initialized"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer caddy8080.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := verifyLocalReadyWithTimeout(ctx, 2*time.Second, transientServer18481.URL, caddy8080.URL)
		if err != nil {
			t.Fatalf("expected retry recovery to succeed, got %v", err)
		}
	})

	// 3. Negative setup responses: each must have a fresh timeout context and verify requests actually reached the setup endpoint
	negativeCases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "setup-unavailable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"unavailable"}`))
			},
		},
		{
			name: "setup-returns-html",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Welcome to AcornFox</body></html>`))
			},
		},
		{
			name: "setup-redirects",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/login", http.StatusFound)
			},
		},
		{
			name: "setup-oversized-body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"uninitialized","padding":"` + strings.Repeat("a", 5000) + `"}`))
			},
		},
		{
			name: "setup-unknown-field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"initialized","extra":"field"}`))
			},
		},
		{
			name: "setup-duplicate-key",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"uninitialized","state":"initialized"}`))
			},
		},
		{
			name: "setup-trailing-json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"state":"initialized"}{"extra":"object"}`))
			},
		},
	}

	for _, tc := range negativeCases {
		t.Run("negative-"+tc.name, func(t *testing.T) {
			// Ready 18481 server
			server18481 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))
			defer server18481.Close()

			var setupCalls int32
			caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/acornfox/setup" {
					atomic.AddInt32(&setupCalls, 1)
					tc.handler(w, r)
					return
				}
				http.NotFound(w, r)
			}))
			defer caddyServer.Close()

			// Fresh timeout context for each negative test case
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()

			err := verifyLocalReadyWithTimeout(ctx, 250*time.Millisecond, server18481.URL, caddyServer.URL)
			if err == nil {
				t.Fatalf("%s expected failure, got nil", tc.name)
			}

			// Assert that requests actually hit the setup endpoint >= 1
			hits := atomic.LoadInt32(&setupCalls)
			if hits < 1 {
				t.Fatalf("%s did not hit setup endpoint (calls=%d), invalid negative test", tc.name, hits)
			}
		})
	}

	// 4. Cancelled before start: asserts zero requests are made
	t.Run("cancelled-before-start", func(t *testing.T) {
		var serverCalls int32
		var caddyCalls int32

		server18481 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&serverCalls, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server18481.Close()

		caddy8080 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&caddyCalls, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer caddy8080.Close()

		ctxCancelled, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancelled

		err := verifyLocalReadyWithTimeout(ctxCancelled, 250*time.Millisecond, server18481.URL, caddy8080.URL)
		if err == nil {
			t.Fatal("expected error on cancelled context, got nil")
		}
		if atomic.LoadInt32(&serverCalls) != 0 {
			t.Fatalf("expected 0 calls to 18481 server on cancelled context, got %d", serverCalls)
		}
		if atomic.LoadInt32(&caddyCalls) != 0 {
			t.Fatalf("expected 0 calls to 8080 caddy on cancelled context, got %d", caddyCalls)
		}
	})
}
