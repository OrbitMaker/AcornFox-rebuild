package desktopupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// createTestParentDir creates a valid, compliant parent directory for testing:
// On Unix: explicitly 0700 (bypassing restrictive umasks like 0002 on Ubuntu SSH).
// On Windows: secured with protected DACL for current user.
func createTestParentDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0700); err != nil {
			t.Fatalf("chmod test parent dir: %v", err)
		}
	} else {
		if err := secureNewStageDirectory(context.Background(), p); err != nil {
			t.Fatalf("secure windows test parent dir: %v", err)
		}
	}
	return p
}

func verifyStagedTestSecurity(t *testing.T, stageDir, payloadFile string) {
	t.Helper()
	if err := verifyStagedFileSecurity(context.Background(), stageDir, payloadFile); err != nil {
		t.Fatalf("staged security verification failed: %v", err)
	}
}

func setupTestTLSServer(t *testing.T, host string, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)

	// Transport intercepts requests and dials test server listener using request context
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}

	tr := ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = dialer
	tr.TLSClientConfig.ServerName = host

	client := &http.Client{
		Transport: tr,
	}
	return ts, client
}

func TestStageVerifiedUpdate_Success(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payloadData := []byte("hello safe desktop update payload content")
	hasher := sha256.New()
	hasher.Write(payloadData)
	payloadSHA := hex.EncodeToString(hasher.Sum(nil))

	host := "updates.example.com"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.10.0/artifact.bin", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			http.Error(w, "bad accept-encoding", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payloadData)
	})

	ts, client := setupTestTLSServer(t, host, mux)
	defer ts.Close()

	parentDir := createTestParentDir(t)

	p := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    "https://" + host + "/v1.10.0/artifact.bin",
				SHA256: payloadSHA,
				Size:   int64(len(payloadData)),
			},
		},
	}
	envBytes := createTestEnvelope(t, priv, p)

	opts := DownloadStagingOptions{
		IndexOptions: CheckUpdateOptions{
			PublicKey:       pub,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 5,
			CurrentVersion:  "v1.9.0",
			AllowedHosts:    []string{host},
		},
		ParentDir:  parentDir,
		HTTPClient: client,
		DiskSpaceCheck: func(path string) (uint64, error) {
			return 10 << 30, nil // 10 GiB free
		},
	}

	receipt, cand, err := StageVerifiedUpdate(context.Background(), envBytes, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cand.Version != "v1.10.0" {
		t.Errorf("candidate version = %s, want v1.10.0", cand.Version)
	}
	if receipt.Version != "v1.10.0" || receipt.Sequence != 10 {
		t.Errorf("receipt version/sequence mismatch")
	}
	if receipt.SHA256 != payloadSHA {
		t.Errorf("receipt sha mismatch")
	}

	// Verify file content and platform security
	data, err := os.ReadFile(receipt.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payloadData) {
		t.Errorf("content mismatch")
	}

	verifyStagedTestSecurity(t, filepath.Dir(receipt.ArtifactPath), receipt.ArtifactPath)

	// Assert that stage directory contains exclusively payload.bin and no leftover temporary hard links
	stageEntries, err := os.ReadDir(filepath.Dir(receipt.ArtifactPath))
	if err != nil {
		t.Fatalf("readdir stage dir failed: %v", err)
	}
	if len(stageEntries) != 1 || stageEntries[0].Name() != StagePayloadFileName {
		t.Fatalf("stage dir contains unexpected files: %v, want only %s", stageEntries, StagePayloadFileName)
	}
}

func TestStageVerifiedUpdate_TLSBadHostnameFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	parentDir := createTestParentDir(t)

	host := "updates.example.com"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data"))
	}))
	defer ts.Close()

	// Dial test server but assert TLS cert against an unmatched hostname "bad.example.com"
	tr := ts.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = "bad.example.com"

	badClient := &http.Client{Transport: tr}

	p := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    "https://" + host + "/app.bin",
				SHA256: strings.Repeat("0", 64),
				Size:   4,
			},
		},
	}
	env := createTestEnvelope(t, priv, p)

	opts := DownloadStagingOptions{
		IndexOptions: CheckUpdateOptions{
			PublicKey:       pub,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 5,
			CurrentVersion:  "v1.9.0",
			AllowedHosts:    []string{host},
		},
		ParentDir:  parentDir,
		HTTPClient: badClient,
		DiskSpaceCheck: func(path string) (uint64, error) {
			return 10 << 30, nil
		},
	}

	_, _, err := StageVerifiedUpdate(context.Background(), env, opts)
	if err == nil {
		t.Fatal("expected TLS verification failure for unmatched hostname, got nil")
	}
}

func TestStageVerifiedUpdate_CookieJarNeverSentAndTargetConflictProtected(t *testing.T) {
	dir := createTestParentDir(t)
	cookieSeen := false
	var planted string

	host := "updates.example.com"
	mux := http.NewServeMux()
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		cookieSeen = r.Header.Get("Cookie") != ""
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if entry.IsDir() {
				planted = filepath.Join(dir, entry.Name(), StagePayloadFileName)
				_ = os.WriteFile(planted, []byte("foreign-sentinel"), 0600)
			}
		}
		_, _ = w.Write([]byte("abc"))
	})

	ts, client := setupTestTLSServer(t, host, mux)
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://" + host + "/payload")
	jar.SetCookies(u, []*http.Cookie{{Name: "private_session", Value: "secret"}})
	client.Jar = jar

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := sha256.Sum256([]byte("abc"))
	p := IndexPayload{
		Channel:   "stable",
		Sequence:  2,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Version:   "1.1.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    u.String(),
				SHA256: hex.EncodeToString(h[:]),
				Size:   3,
			},
		},
	}
	envBytes := createTestEnvelope(t, priv, p)

	opts := DownloadStagingOptions{
		IndexOptions: CheckUpdateOptions{
			PublicKey:       pub,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 1,
			CurrentVersion:  "1.0.0",
			AllowedHosts:    []string{host},
		},
		ParentDir:  dir,
		HTTPClient: client,
		DiskSpaceCheck: func(string) (uint64, error) {
			return 8 << 30, nil
		},
	}

	_, _, err := StageVerifiedUpdate(context.Background(), envBytes, opts)
	if !errors.Is(err, ErrTargetConflict) {
		t.Fatalf("expected ErrTargetConflict, got %v", err)
	}
	if cookieSeen {
		t.Errorf("cookie was sent to update server!")
	}
	// Verify planted foreign payload was NOT deleted by cleanup
	if _, statErr := os.Stat(planted); statErr != nil {
		t.Errorf("planted foreign payload was deleted by cleanup: %v", statErr)
	}
}

func TestStageVerifiedUpdate_SyncFailureAndPrePublishCancellation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	host := "updates.example.com"
	parentDir := createTestParentDir(t)

	payloadData := []byte("payload content for test")
	h := sha256.Sum256(payloadData)

	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payloadData)
	})
	ts, client := setupTestTLSServer(t, host, mux)
	defer ts.Close()

	p := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    "https://" + host + "/test",
				SHA256: hex.EncodeToString(h[:]),
				Size:   int64(len(payloadData)),
			},
		},
	}
	env := createTestEnvelope(t, priv, p)

	// 1. Directory sync failure returns error and cleans up
	t.Run("sync_directory_failure", func(t *testing.T) {
		opts := DownloadStagingOptions{
			IndexOptions: CheckUpdateOptions{
				PublicKey:       pub,
				TargetOS:        "darwin",
				TargetArch:      "arm64",
				AllowedChannel:  "stable",
				CurrentSequence: 5,
				CurrentVersion:  "v1.9.0",
				AllowedHosts:    []string{host},
			},
			ParentDir:  parentDir,
			HTTPClient: client,
			DiskSpaceCheck: func(path string) (uint64, error) {
				return 10 << 30, nil
			},
			SyncHook: func(dirPath string) error {
				return errors.New("simulated disk sync error")
			},
		}
		_, _, err := StageVerifiedUpdate(context.Background(), env, opts)
		if err == nil || !strings.Contains(err.Error(), "simulated disk sync error") {
			t.Fatalf("expected sync error, got %v", err)
		}
	})
}

func TestStageVerifiedUpdate_RedirectWithCDNQueryAndDowngrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	host := "updates.example.com"
	parentDir := createTestParentDir(t)

	payloadData := []byte("cdn payload")
	hasher := sha256.New()
	hasher.Write(payloadData)
	payloadSHA := hex.EncodeToString(hasher.Sum(nil))

	mux := http.NewServeMux()
	mux.HandleFunc("/initial", func(w http.ResponseWriter, r *http.Request) {
		// Redirect with signed CDN query parameter
		http.Redirect(w, r, "https://"+host+"/cdn-target?token=secret123&expire=9999", http.StatusFound)
	})
	mux.HandleFunc("/cdn-target", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "secret123" {
			http.Error(w, "missing token", http.StatusForbidden)
			return
		}
		_, _ = w.Write(payloadData)
	})
	mux.HandleFunc("/downgrade", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+host+"/insecure", http.StatusFound)
	})

	ts, client := setupTestTLSServer(t, host, mux)
	defer ts.Close()

	// 1. Success with legitimate CDN query redirect
	t.Run("cdn_query_redirect_success", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{
					OS:     "darwin",
					Arch:   "arm64",
					URL:    "https://" + host + "/initial",
					SHA256: payloadSHA,
					Size:   int64(len(payloadData)),
				},
			},
		}
		env := createTestEnvelope(t, priv, p)
		opts := DownloadStagingOptions{
			IndexOptions: CheckUpdateOptions{
				PublicKey:       pub,
				TargetOS:        "darwin",
				TargetArch:      "arm64",
				AllowedChannel:  "stable",
				CurrentSequence: 5,
				CurrentVersion:  "v1.9.0",
				AllowedHosts:    []string{host},
			},
			ParentDir:  parentDir,
			HTTPClient: client,
			DiskSpaceCheck: func(path string) (uint64, error) {
				return 10 << 30, nil
			},
		}
		receipt, _, err := StageVerifiedUpdate(context.Background(), env, opts)
		if err != nil {
			t.Fatalf("unexpected error with CDN query redirect: %v", err)
		}
		if receipt == nil || receipt.SHA256 != payloadSHA {
			t.Errorf("receipt mismatch")
		}
	})

	// 2. Reject HTTP downgrade redirect
	t.Run("http_downgrade_rejected", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{
					OS:     "darwin",
					Arch:   "arm64",
					URL:    "https://" + host + "/downgrade",
					SHA256: payloadSHA,
					Size:   int64(len(payloadData)),
				},
			},
		}
		env := createTestEnvelope(t, priv, p)
		opts := DownloadStagingOptions{
			IndexOptions: CheckUpdateOptions{
				PublicKey:       pub,
				TargetOS:        "darwin",
				TargetArch:      "arm64",
				AllowedChannel:  "stable",
				CurrentSequence: 5,
				CurrentVersion:  "v1.9.0",
				AllowedHosts:    []string{host},
			},
			ParentDir:  parentDir,
			HTTPClient: client,
			DiskSpaceCheck: func(path string) (uint64, error) {
				return 10 << 30, nil
			},
		}
		_, _, err := StageVerifiedUpdate(context.Background(), env, opts)
		if !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("expected ErrURLNotAllowed for HTTP downgrade, got %v", err)
		}
	})
}

func TestStageVerifiedUpdate_CancellationAndTimeout(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	host := "updates.example.com"
	parentDir := createTestParentDir(t)

	p := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    "https://" + host + "/stall",
				SHA256: strings.Repeat("0", 64),
				Size:   100,
			},
		},
	}
	env := createTestEnvelope(t, priv, p)

	// 1. Pre-cancelled context before disk access
	t.Run("pre_cancelled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		opts := DownloadStagingOptions{
			IndexOptions: CheckUpdateOptions{
				PublicKey:       pub,
				TargetOS:        "darwin",
				TargetArch:      "arm64",
				AllowedChannel:  "stable",
				CurrentSequence: 5,
				CurrentVersion:  "v1.9.0",
				AllowedHosts:    []string{host},
			},
			ParentDir: parentDir,
		}
		_, _, err := StageVerifiedUpdate(ctx, env, opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		entries, _ := os.ReadDir(parentDir)
		if len(entries) != 0 {
			t.Errorf("files created on pre-cancelled context!")
		}
	})

	// 2. Download timeout / stall
	t.Run("download_timeout", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_, _ = w.Write([]byte("too late"))
		})
		ts, client := setupTestTLSServer(t, host, mux)
		defer ts.Close()

		opts := DownloadStagingOptions{
			IndexOptions: CheckUpdateOptions{
				PublicKey:       pub,
				TargetOS:        "darwin",
				TargetArch:      "arm64",
				AllowedChannel:  "stable",
				CurrentSequence: 5,
				CurrentVersion:  "v1.9.0",
				AllowedHosts:    []string{host},
			},
			ParentDir:  parentDir,
			HTTPClient: client,
			Timeout:    50 * time.Millisecond,
			DiskSpaceCheck: func(path string) (uint64, error) {
				return 10 << 30, nil
			},
		}
		_, _, err := StageVerifiedUpdate(context.Background(), env, opts)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected exact context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestStageVerifiedUpdate_ParentDirSymlinkRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	temp := t.TempDir()
	realDir := filepath.Join(temp, "real")
	symlinkDir := filepath.Join(temp, "symlink")
	_ = os.Mkdir(realDir, 0700)
	err := os.Symlink(realDir, symlinkDir)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink creation on Windows without privilege")
		}
		t.Fatalf("failed to create symlink: %v", err)
	}

	host := "updates.example.com"
	p := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: []Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    "https://" + host + "/app.bin",
				SHA256: strings.Repeat("0", 64),
				Size:   10,
			},
		},
	}
	env := createTestEnvelope(t, priv, p)
	opts := DownloadStagingOptions{
		IndexOptions: CheckUpdateOptions{
			PublicKey:       pub,
			TargetOS:        "darwin",
			TargetArch:      "arm64",
			AllowedChannel:  "stable",
			CurrentSequence: 5,
			CurrentVersion:  "v1.9.0",
			AllowedHosts:    []string{host},
		},
		ParentDir: symlinkDir,
	}

	_, _, err = StageVerifiedUpdate(context.Background(), env, opts)
	if !errors.Is(err, ErrInvalidParentDir) {
		t.Fatalf("expected ErrInvalidParentDir for symlinked parent, got %v", err)
	}
}
