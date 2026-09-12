package desktopupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type checkHandler struct {
	envelope []byte
	mode     string
}

func (h *checkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch h.mode {
	case "redirect":
		if r.URL.Path == "/index.json" {
			http.Redirect(w, r, "/v2/index.json", http.StatusFound)
			return
		}
		if r.URL.Path == "/v2/index.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(h.envelope)
			return
		}
	case "disallowed-redirect":
		http.Redirect(w, r, "https://disallowed.example.com/index.json", http.StatusFound)
		return
	case "http-redirect":
		http.Redirect(w, r, "http://downloads.example.com/index.json", http.StatusFound)
		return
	case "loop-redirect":
		http.Redirect(w, r, "/index.json", http.StatusFound)
		return
	case "oversize":
		w.Header().Set("Content-Type", "application/json")
		w.Write(make([]byte, MaxIndexEnvelopeBytes+64))
		return
	case "slow":
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.Write([]byte("{}"))
		return
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Write(h.envelope)
		return
	}
}

func newCheckFixtureWithHandler(t *testing.T, handler *checkHandler) hostFixture {
	t.Helper()
	root, e := filepath.EvalSymlinks(createTestParentDir(t))
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	data, m := hostTestBundle(t, "1.1.0", strings.Repeat("a", 64))
	host := "downloads.example.com"
	server, client := setupTestTLSServer(t, host, handler)
	t.Cleanup(server.Close)

	policy := &HostPolicy{
		PublicKey:    pub,
		IndexURL:     "https://" + host + "/index.json",
		OS:           "linux",
		Arch:         "amd64",
		Channel:      "stable",
		AllowedHosts: []string{host},
	}
	initial := HostInstallation{
		Version:         "1.0.0",
		SlotSHA256:      strings.Repeat("1", 64),
		BackendBinding: strings.Repeat("a", 64),
	}
	f := hostFake{path: filepath.Join(t.TempDir(), "world.json")}
	f.write(hostWorld{
		Instance: strings.Repeat("e", 64),
		Binding:  initial.BackendBinding,
		Slot:     initial.SlotSHA256,
		Attempts: map[string]bool{},
	})
	c, e := NewHostController(HostControllerOptions{
		Root:            root,
		InstanceID:      strings.Repeat("e", 64),
		Initial:         initial,
		Policy:          policy,
		Backend:         f,
		Runtime:         f,
		HTTPClient:      client,
		DownloadTimeout: 10 * time.Second,
		Now:             func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) },
	})
	if e != nil {
		t.Fatal(e)
	}
	c.diskSpaceCheck = func(string) (uint64, error) { return 1 << 40, nil }
	env := createTestEnvelope(t, priv, IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://" + host + "/bundle",
			SHA256:         hostSHA(data),
			Size:           int64(len(data)),
			BackendBinding: m.Backend.ToBinding,
		}},
	})
	handler.envelope = env
	return hostFixture{c: c, world: f, private: priv, payload: data, manifest: m, envelope: env}
}

func preinitializeHostFixture(t *testing.T, f *hostFixture) {
	t.Helper()
	s, _, e := f.c.open(context.Background())
	if e != nil {
		t.Fatal("preinitialize open failed", e)
	}
	s.close()
	w := f.world.read()
	w.Calls = 0
	f.world.write(w)
}

func TestHostCheckAndSelectPolicyNilReturnsNotConfiguredWithoutNetwork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-configured")
	c, err := NewHostController(HostControllerOptions{Root: root, Policy: nil})
	if err != nil {
		t.Fatal(err)
	}
	status, err := c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatal("expected nil error on policy nil, got", err)
	}
	if status.State != "not-configured" {
		t.Fatalf("expected state not-configured, got %q", status.State)
	}
}

func TestHostCheckAndSelectMissingStateFailsClosedWithoutCreatingState(t *testing.T) {
	var networkHit int32
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	origTransport := f.c.options.HTTPClient.Transport
	f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&networkHit, 1)
		return origTransport.RoundTrip(req)
	})

	// Do NOT preinitialize: root directory / state.json does not exist.
	status, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrHostUninitialized) {
		t.Fatalf("expected ErrHostUninitialized, got status=%+v, err=%v", status, err)
	}
	if atomic.LoadInt32(&networkHit) != 0 {
		t.Fatal("network was accessed when state was uninitialized")
	}
	if f.world.read().Calls != 0 {
		t.Fatal("backend/runtime was invoked on missing state")
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHostCheckAndSelectPendingOrCleanupReturnsErrHostPendingWithZeroHooks(t *testing.T) {
	for _, kind := range []string{"pending", "cleanup", "collectSlots"} {
		t.Run(kind, func(t *testing.T) {
			var networkHit int32
			h := &checkHandler{}
			f := newCheckFixtureWithHandler(t, h)
			origTransport := f.c.options.HTTPClient.Transport
			f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&networkHit, 1)
				return origTransport.RoundTrip(req)
			})

			switch kind {
			case "pending":
				if _, err := f.c.Select(context.Background(), f.envelope, false); err != nil {
					t.Fatal(err)
				}
			case "cleanup":
				preinitializeHostFixture(t, &f)
				s, state, err := f.c.openExistingDriver(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				state.Cleanup = []HostStageCleanup{{
					ID:       strings.Repeat("c", 64),
					Identity: "identity",
					SHA256:   strings.Repeat("2", 64),
					Size:     1024,
				}}
				if err := s.save(&state); err != nil {
					s.close()
					t.Fatal(err)
				}
				s.close()
			case "collectSlots":
				preinitializeHostFixture(t, &f)
				s, state, err := f.c.openExistingDriver(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				state.CollectSlots = true
				if err := s.save(&state); err != nil {
					s.close()
					t.Fatal(err)
				}
				s.close()
			}

			w := f.world.read()
			w.Calls = 0
			f.world.write(w)

			status, err := f.c.CheckAndSelect(context.Background())
			if !errors.Is(err, ErrHostPending) {
				t.Fatalf("expected ErrHostPending, got %v", err)
			}
			if atomic.LoadInt32(&networkHit) != 0 {
				t.Fatal("network was hit despite pending/cleanup state")
			}
			if f.world.read().Calls != 0 {
				t.Fatal("backend/runtime hook was invoked despite pending/cleanup state")
			}
			if kind == "pending" && status.Snapshot.Pending == nil {
				t.Fatal("pending offer was cleared")
			}
		})
	}
}

func TestHostCheckAndSelectHTTPSRetrievalAndRedirects(t *testing.T) {
	h := &checkHandler{mode: "redirect"}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	// 1. Normal HTTPS retrieval via valid redirect on allowed host
	status, err := f.c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatalf("CheckAndSelect failed: %v", err)
	}
	if status.State != "selected" || status.Snapshot.Pending == nil {
		t.Fatalf("expected selected state with pending offer, got %+v", status)
	}
	if status.Snapshot.Pending.Candidate.Version != "1.1.0" {
		t.Fatalf("expected candidate 1.1.0, got %s", status.Snapshot.Pending.Candidate.Version)
	}
	if f.world.read().Calls != 0 {
		t.Fatal("backend/runtime was called during check")
	}

	// 2. Disallowed redirect host
	h.mode = "disallowed-redirect"
	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.Pending = nil
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrURLNotAllowed) {
		t.Fatalf("expected ErrURLNotAllowed, got %v", err)
	}

	// 3. HTTP redirect
	h.mode = "http-redirect"
	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrURLNotAllowed) {
		t.Fatalf("expected ErrURLNotAllowed on http redirect, got %v", err)
	}

	// 4. Too many redirects
	h.mode = "loop-redirect"
	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrURLNotAllowed) {
		t.Fatalf("expected ErrURLNotAllowed on loop redirect, got %v", err)
	}
}

func TestHostCheckAndSelectSignedNewerAndNoUpdate(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	// 1. Signed newer version (1.1.0, seq 1 > installed 1.0.0, seq 0)
	status, err := f.c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if status.State != "selected" || status.Snapshot.Pending == nil {
		t.Fatalf("expected selected state with pending offer, got %+v", status)
	}
	if status.Snapshot.Catalog.Sequence != 1 {
		t.Fatalf("expected catalog sequence 1, got %d", status.Snapshot.Catalog.Sequence)
	}
	firstPendingID := status.Snapshot.Pending.ID

	// 2. Repeated check cannot replace existing pending offer
	repeatedStatus, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrHostPending) {
		t.Fatalf("expected ErrHostPending on repeated check, got %v", err)
	}
	if repeatedStatus.Snapshot.Pending.ID != firstPendingID {
		t.Fatal("existing pending offer was replaced")
	}

	// 3. Reset pending, advance installed version to 1.1.0, sequence 1
	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.Pending = nil
	state.Installed.Version = "1.1.0"
	state.Installed.AppliedSequence = 1
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	// Server now serves same version 1.1.0 with higher sequence 2 (no update)
	noUpdateEnv := createTestEnvelope(t, f.private, IndexPayload{
		Channel:   "stable",
		Sequence:  2,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://downloads.example.com/bundle",
			SHA256:         hostSHA(f.payload),
			Size:           int64(len(f.payload)),
			BackendBinding: f.manifest.Backend.ToBinding,
		}},
	})
	h.envelope = noUpdateEnv

	noUpdateStatus, err := f.c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on no update, got %v", err)
	}
	if noUpdateStatus.State != "idle" || noUpdateStatus.Snapshot.Pending != nil {
		t.Fatalf("expected idle without pending offer, got %+v", noUpdateStatus)
	}
	if noUpdateStatus.Snapshot.Catalog.Sequence != 2 {
		t.Fatalf("catalog floor was not updated to 2, got %d", noUpdateStatus.Snapshot.Catalog.Sequence)
	}
	if f.world.read().Calls != 0 {
		t.Fatal("backend/runtime hook was called")
	}
}

func TestHostCheckAndSelectCatalogFloorAndEquivocation(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	// Set catalog floor to sequence 5
	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state.Catalog = HostCatalogFloor{Sequence: 5, PayloadSHA256: strings.Repeat("a", 64)}
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	// 1. Sequence rollback (seq 4 < 5)
	h.envelope = createTestEnvelope(t, f.private, IndexPayload{
		Channel:   "stable",
		Sequence:  4,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://downloads.example.com/bundle",
			SHA256:         hostSHA(f.payload),
			Size:           int64(len(f.payload)),
			BackendBinding: f.manifest.Backend.ToBinding,
		}},
	})
	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrSequenceRollback) {
		t.Fatalf("expected ErrSequenceRollback, got %v", err)
	}

	// 2. Equivocation (seq 5 with different payload hash)
	h.envelope = createTestEnvelope(t, f.private, IndexPayload{
		Channel:   "stable",
		Sequence:  5,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://downloads.example.com/bundle",
			SHA256:         hostSHA(f.payload),
			Size:           int64(len(f.payload)),
			BackendBinding: f.manifest.Backend.ToBinding,
		}},
	})
	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrSequenceRollback) {
		t.Fatalf("expected ErrSequenceRollback on equivocation, got %v", err)
	}
}

func TestHostCheckAndSelectBadSignature(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	tampered := append([]byte(nil), f.envelope...)
	tampered[len(tampered)-5] ^= 0x55
	h.envelope = tampered

	_, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrSignatureMismatch) && !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected signature or envelope error, got %v", err)
	}
}

func TestHostCheckAndSelectPlatformAndChannelMismatch(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	// Channel mismatch (beta channel envelope served to stable controller)
	h.envelope = createTestEnvelope(t, f.private, IndexPayload{
		Channel:   "beta",
		Sequence:  1,
		Version:   "1.1.0-beta.1",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://downloads.example.com/bundle",
			SHA256:         hostSHA(f.payload),
			Size:           int64(len(f.payload)),
			BackendBinding: f.manifest.Backend.ToBinding,
		}},
	})
	_, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrChannelMismatch) {
		t.Fatalf("expected ErrChannelMismatch, got %v", err)
	}

	// Platform mismatch (only darwin/arm64 artifact present, controller is linux/amd64)
	h.envelope = createTestEnvelope(t, f.private, IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "darwin",
			Arch:           "arm64",
			URL:            "https://downloads.example.com/bundle",
			SHA256:         hostSHA(f.payload),
			Size:           int64(len(f.payload)),
			BackendBinding: f.manifest.Backend.ToBinding,
		}},
	})
	_, err = f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform on platform mismatch, got %v", err)
	}
}

func TestHostCheckAndSelectOversizeAndCancellation(t *testing.T) {
	h := &checkHandler{mode: "oversize"}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	// Oversize
	_, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected ErrInvalidEnvelope, got %v", err)
	}

	// Pre-cancellation
	h.mode = "slow"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.c.CheckAndSelect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

type cancelOnEOFBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnEOFBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.cancel()
	}
	return n, err
}

func (b *cancelOnEOFBody) Close() error {
	return b.ReadCloser.Close()
}

type cancelOnCloseOnlyBody struct {
	data   []byte
	offset int
	cancel context.CancelFunc
}

func (b *cancelOnCloseOnlyBody) Read(p []byte) (int, error) {
	if b.offset < len(b.data) {
		n := copy(p, b.data[b.offset:])
		b.offset += n
		return n, nil
	}
	return 0, io.EOF
}

func (b *cancelOnCloseOnlyBody) Close() error {
	b.cancel()
	return nil
}

type deadlineExceededAfterReadBody struct {
	data   []byte
	offset int
}

func (b *deadlineExceededAfterReadBody) Read(p []byte) (int, error) {
	if b.offset < len(b.data) {
		n := copy(p, b.data[b.offset:])
		b.offset += n
		return n, nil
	}
	// All envelope bytes delivered with nil error; sleep past the 50ms deadline
	// then return EOF without read error.
	time.Sleep(100 * time.Millisecond)
	return 0, io.EOF
}

func (b *deadlineExceededAfterReadBody) Close() error {
	return nil
}

func TestHostCheckAndSelectCancellationDuringBodyCompletionRejectsDurableSelection(t *testing.T) {
	// Deterministic regression test for P2 finding:
	// A complete valid envelope is delivered over HTTPS, but the context is cancelled
	// on the final body read (EOF). CheckAndSelect must return context.Canceled and
	// both Catalog floor and Pending state must remain completely unchanged.
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origTransport := f.c.options.HTTPClient.Transport
	f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := origTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Body = &cancelOnEOFBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	})

	status, err := f.c.CheckAndSelect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Re-load snapshot from disk under lock to verify state was NOT durably modified
	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	if state.Catalog.Sequence != 0 {
		t.Fatalf("catalog floor was updated despite cancellation: seq=%d", state.Catalog.Sequence)
	}
	if state.Pending != nil {
		t.Fatalf("pending offer was created despite cancellation: %+v", state.Pending)
	}
	if status.Snapshot != nil && status.Snapshot.Pending != nil {
		t.Fatal("returned status contains pending offer")
	}
}

func TestHostCheckAndSelectCancellationOnBodyCloseRejectsDurableSelection(t *testing.T) {
	// Deterministic regression test for P2 finding:
	// The envelope is fully read without error, but context cancellation occurs on resp.Body.Close().
	// CheckAndSelect must return context.Canceled and state must remain completely unchanged.
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origTransport := f.c.options.HTTPClient.Transport
	f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := origTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Body = &cancelOnCloseOnlyBody{data: f.envelope, cancel: cancel}
		return resp, nil
	})

	status, err := f.c.CheckAndSelect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	if state.Catalog.Sequence != 0 {
		t.Fatalf("catalog floor was updated despite cancellation: seq=%d", state.Catalog.Sequence)
	}
	if state.Pending != nil {
		t.Fatalf("pending offer was created despite cancellation: %+v", state.Pending)
	}
	if status.Snapshot != nil && status.Snapshot.Pending != nil {
		t.Fatal("returned status contains pending offer")
	}
}

func TestHostCheckAndSelectInternalDeadlineExceededAfterCompleteBodyRejectsDurableSelection(t *testing.T) {
	// Deterministic regression test for P2 finding at internal timeout boundary:
	// Parent context is healthy, but the full body completes after the internal DownloadTimeout (50ms)
	// has expired, returning nil read error. CheckAndSelect must return context.DeadlineExceeded
	// and neither catalog floor nor pending state may be modified.
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	f.c.options.DownloadTimeout = 50 * time.Millisecond
	origTransport := f.c.options.HTTPClient.Transport
	f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := origTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Body = &deadlineExceededAfterReadBody{data: f.envelope}
		return resp, nil
	})

	status, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	s, state, err := f.c.openExistingDriver(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	if state.Catalog.Sequence != 0 {
		t.Fatalf("catalog floor was updated despite internal deadline expiration: seq=%d", state.Catalog.Sequence)
	}
	if state.Pending != nil {
		t.Fatalf("pending offer was created despite internal deadline expiration: %+v", state.Pending)
	}
	if status.Snapshot != nil && status.Snapshot.Pending != nil {
		t.Fatal("returned status contains pending offer")
	}
}

func TestHostCheckAndSelectCookieJarAndHeaderIsolation(t *testing.T) {
	var initialCookie, redirectedCookie string
	var initialAuth, redirectedAuth string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			initialCookie = r.Header.Get("Cookie")
			initialAuth = r.Header.Get("Authorization")
			http.Redirect(w, r, "/v2/index.json", http.StatusFound)
			return
		}
		if r.URL.Path == "/v2/index.json" {
			redirectedCookie = r.Header.Get("Cookie")
			redirectedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.Write(fEnvelope)
			return
		}
		http.NotFound(w, r)
	})

	host := "downloads.example.com"
	server, client := setupTestTLSServer(t, host, handler)
	t.Cleanup(server.Close)

	root, _ := filepath.EvalSymlinks(createTestParentDir(t))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, m := hostTestBundle(t, "1.1.0", strings.Repeat("a", 64))
	policy := &HostPolicy{
		PublicKey:    pub,
		IndexURL:     "https://" + host + "/index.json",
		OS:           "linux",
		Arch:         "amd64",
		Channel:      "stable",
		AllowedHosts: []string{host},
	}
	initial := HostInstallation{
		Version:         "1.0.0",
		SlotSHA256:      strings.Repeat("1", 64),
		BackendBinding: strings.Repeat("a", 64),
	}
	fake := hostFake{path: filepath.Join(t.TempDir(), "world.json")}
	fake.write(hostWorld{
		Instance: strings.Repeat("e", 64),
		Binding:  initial.BackendBinding,
		Slot:     initial.SlotSHA256,
		Attempts: map[string]bool{},
	})

	// Configure client with populated CookieJar
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://" + host)
	jar.SetCookies(u, []*http.Cookie{{Name: "session-secret", Value: "sensitive-token-xyz"}})

	c, err := NewHostController(HostControllerOptions{
		Root:            root,
		InstanceID:      strings.Repeat("e", 64),
		Initial:         initial,
		Policy:          policy,
		Backend:         fake,
		Runtime:         fake,
		HTTPClient:      &http.Client{Jar: jar, Transport: client.Transport},
		DownloadTimeout: 10 * time.Second,
		Now:             func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	env := createTestEnvelope(t, priv, IndexPayload{
		Channel:   "stable",
		Sequence:  1,
		Version:   "1.1.0",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Artifacts: []Artifact{{
			OS:             "linux",
			Arch:           "amd64",
			URL:            "https://" + host + "/bundle",
			SHA256:         hostSHA(data),
			Size:           int64(len(data)),
			BackendBinding: m.Backend.ToBinding,
		}},
	})
	fEnvelope = env

	// Preinitialize
	s, _, e := c.open(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	s.close()

	status, err := c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatalf("CheckAndSelect failed: %v", err)
	}
	if status.State != "selected" {
		t.Fatalf("expected selected, got %s", status.State)
	}

	if initialCookie != "" || redirectedCookie != "" {
		t.Fatalf("cookie jar leaked to request: initial=%q, redirected=%q", initialCookie, redirectedCookie)
	}
	if initialAuth != "" || redirectedAuth != "" {
		t.Fatalf("authorization header present: initial=%q, redirected=%q", initialAuth, redirectedAuth)
	}
}

var fEnvelope []byte

func TestHostCheckAndSelectTimeoutDuringHeadersAndBody(t *testing.T) {
	t.Run("headers-timeout", func(t *testing.T) {
		h := &checkHandler{mode: "slow"}
		f := newCheckFixtureWithHandler(t, h)
		preinitializeHostFixture(t, &f)

		f.c.options.DownloadTimeout = 50 * time.Millisecond
		start := time.Now()
		_, err := f.c.CheckAndSelect(context.Background())
		elapsed := time.Since(start)

		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrDownloadFailed) {
			t.Fatalf("expected deadline exceeded or download failed, got %v", err)
		}
		// Server sleeps 2s; client timeout of 50ms must cut off promptly without waiting for the server
		if elapsed > 800*time.Millisecond {
			t.Fatalf("client did not cut off promptly, took %v", elapsed)
		}
	})

	t.Run("body-timeout", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			w.Write(fEnvelope)
		})
		host := "downloads.example.com"
		server, client := setupTestTLSServer(t, host, handler)
		t.Cleanup(server.Close)

		root, _ := filepath.EvalSymlinks(createTestParentDir(t))
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		data, m := hostTestBundle(t, "1.1.0", strings.Repeat("a", 64))
		policy := &HostPolicy{
			PublicKey:    pub,
			IndexURL:     "https://" + host + "/index.json",
			OS:           "linux",
			Arch:         "amd64",
			Channel:      "stable",
			AllowedHosts: []string{host},
		}
		initial := HostInstallation{
			Version:         "1.0.0",
			SlotSHA256:      strings.Repeat("1", 64),
			BackendBinding: strings.Repeat("a", 64),
		}
		fake := hostFake{path: filepath.Join(t.TempDir(), "world.json")}
		fake.write(hostWorld{
			Instance: strings.Repeat("e", 64),
			Binding:  initial.BackendBinding,
			Slot:     initial.SlotSHA256,
			Attempts: map[string]bool{},
		})
		c, err := NewHostController(HostControllerOptions{
			Root:            root,
			InstanceID:      strings.Repeat("e", 64),
			Initial:         initial,
			Policy:          policy,
			Backend:         fake,
			Runtime:         fake,
			HTTPClient:      client,
			DownloadTimeout: 50 * time.Millisecond,
			Now:             func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		fEnvelope = createTestEnvelope(t, priv, IndexPayload{
			Channel:   "stable",
			Sequence:  1,
			Version:   "1.1.0",
			ExpiresAt: "2026-10-01T00:00:00Z",
			Artifacts: []Artifact{{
				OS:             "linux",
				Arch:           "amd64",
				URL:            "https://" + host + "/bundle",
				SHA256:         hostSHA(data),
				Size:           int64(len(data)),
				BackendBinding: m.Backend.ToBinding,
			}},
		})
		s, _, e := c.open(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		s.close()

		start := time.Now()
		_, err = c.CheckAndSelect(context.Background())
		elapsed := time.Since(start)

		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrDownloadFailed) {
			t.Fatalf("expected deadline exceeded or download failed, got %v", err)
		}
		if elapsed > 800*time.Millisecond {
			t.Fatalf("client did not cut off promptly on stalled body, took %v", elapsed)
		}
	})
}

func TestHostCheckAndSelectErrorRedaction(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	sensitiveURL := "https://internal.secret.corp:8443/api?token=supersecret123"
	f.c.options.HTTPClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection to %s failed: sensitive diagnostic error", sensitiveURL)
	})

	_, err := f.c.CheckAndSelect(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "internal.secret.corp") || strings.Contains(errMsg, "supersecret123") {
		t.Fatalf("error leaked sensitive URL or credentials: %s", errMsg)
	}
	if !errors.Is(err, ErrDownloadFailed) {
		t.Fatalf("expected ErrDownloadFailed, got %v", err)
	}
}

type instrumentedWorld struct {
	hostFake
	observeCalls         int32
	ensureUpgradeCalls   int32
	collectInactiveCalls int32
	discardPreparedCalls int32
	currentSlotCalls     int32
	prepareCalls         int32
	activateCalls        int32
	probeCalls           int32
}

func (w *instrumentedWorld) Observe(ctx context.Context, id string) (BackendObservation, error) {
	atomic.AddInt32(&w.observeCalls, 1)
	return w.hostFake.Observe(ctx, id)
}
func (w *instrumentedWorld) EnsureUpgrade(ctx context.Context, i HostUpgradeIntent, b *VerifiedHostBundle) error {
	atomic.AddInt32(&w.ensureUpgradeCalls, 1)
	return w.hostFake.EnsureUpgrade(ctx, i, b)
}
func (w *instrumentedWorld) CollectInactive(ctx context.Context, keep []string) error {
	atomic.AddInt32(&w.collectInactiveCalls, 1)
	return nil
}
func (w *instrumentedWorld) DiscardPrepared(ctx context.Context, id string) error {
	atomic.AddInt32(&w.discardPreparedCalls, 1)
	return w.hostFake.DiscardPrepared(ctx, id)
}
func (w *instrumentedWorld) CurrentSlot(ctx context.Context) (string, error) {
	atomic.AddInt32(&w.currentSlotCalls, 1)
	return w.hostFake.CurrentSlot(ctx)
}
func (w *instrumentedWorld) Prepare(ctx context.Context, b *VerifiedHostBundle, old string) error {
	atomic.AddInt32(&w.prepareCalls, 1)
	return w.hostFake.Prepare(ctx, b, old)
}
func (w *instrumentedWorld) Activate(ctx context.Context, id, old, next string) error {
	atomic.AddInt32(&w.activateCalls, 1)
	return w.hostFake.Activate(ctx, id, old, next)
}
func (w *instrumentedWorld) Probe(ctx context.Context, slot, backend string) error {
	atomic.AddInt32(&w.probeCalls, 1)
	return w.hostFake.Probe(ctx, slot, backend)
}

func TestHostCheckAndSelectZeroHooksInstrumented(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	inst := &instrumentedWorld{hostFake: f.world}
	f.c.options.Backend = inst
	f.c.options.Runtime = inst

	status, err := f.c.CheckAndSelect(context.Background())
	if err != nil {
		t.Fatalf("CheckAndSelect failed: %v", err)
	}
	if status.State != "selected" {
		t.Fatalf("expected selected, got %s", status.State)
	}

	if atomic.LoadInt32(&inst.observeCalls) != 0 ||
		atomic.LoadInt32(&inst.ensureUpgradeCalls) != 0 ||
		atomic.LoadInt32(&inst.collectInactiveCalls) != 0 ||
		atomic.LoadInt32(&inst.discardPreparedCalls) != 0 ||
		atomic.LoadInt32(&inst.currentSlotCalls) != 0 ||
		atomic.LoadInt32(&inst.prepareCalls) != 0 ||
		atomic.LoadInt32(&inst.activateCalls) != 0 ||
		atomic.LoadInt32(&inst.probeCalls) != 0 {
		t.Fatalf("runtime/backend hooks were called during CheckAndSelect: %+v", inst)
	}
}

func TestHostCheckAndSelectPolicyDriftFailsClosed(t *testing.T) {
	h := &checkHandler{}
	f := newCheckFixtureWithHandler(t, h)
	preinitializeHostFixture(t, &f)

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.c.options.Policy.PublicKey = otherPub

	_, err := f.c.CheckAndSelect(context.Background())
	if !errors.Is(err, ErrHostConflict) {
		t.Fatalf("expected ErrHostConflict on policy drift, got %v", err)
	}
}

func TestExistingSelectMaintainsExistingBootstrapAndCleanup(t *testing.T) {
	// 1. Proves that existing public Select semantics are completely preserved:
	// It still bootstraps missing state via c.open.
	f := newHostFixture(t)
	status, err := f.c.Select(context.Background(), f.envelope, false)
	if err != nil {
		t.Fatalf("Select failed to bootstrap and select: %v", err)
	}
	if status.State != "selected" || status.Snapshot.Pending == nil {
		t.Fatalf("expected selected state, got %+v", status)
	}

	// 2. Proves that existing public Select still processes and collects pre-existing Cleanup records.
	f2 := newHostFixture(t)
	s, state, err := f2.c.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stageID := strings.Repeat("d", 64)
	stageDir := filepath.Join(f2.c.options.Root, "download-"+stageID)
	if err := os.Mkdir(stageDir, 0700); err != nil {
		s.close()
		t.Fatal(err)
	}
	payloadPath := filepath.Join(stageDir, StagePayloadFileName)
	if err := os.WriteFile(payloadPath, []byte("old staged payload"), 0600); err != nil {
		s.close()
		t.Fatal(err)
	}
	key, err := hostDirectoryKey(stageDir)
	if err != nil {
		s.close()
		t.Fatal(err)
	}
	state.Cleanup = []HostStageCleanup{{
		ID:       stageID,
		Identity: key,
		SHA256:   hostSHA([]byte("old staged payload")),
		Size:     int64(len("old staged payload")),
	}}
	if err := s.save(&state); err != nil {
		s.close()
		t.Fatal(err)
	}
	s.close()

	// Select should run collect, delete the stage directory, and clear Cleanup!
	status2, err := f2.c.Select(context.Background(), f2.envelope, false)
	if err != nil {
		t.Fatalf("Select failed with cleanup: %v", err)
	}
	if len(status2.Snapshot.Cleanup) != 0 {
		t.Fatal("Cleanup was not collected by Select")
	}
	if _, err := os.Lstat(stageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stage directory was not deleted by Select cleanup")
	}
}
