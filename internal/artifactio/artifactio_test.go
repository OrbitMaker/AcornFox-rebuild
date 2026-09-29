package artifactio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memorySink struct {
	members map[string]*memoryMember
}

type memoryMember struct {
	bytes.Buffer
	mode   uint32
	synced bool
	closed bool
}

func (m *memoryMember) Sync() error  { m.synced = true; return nil }
func (m *memoryMember) Close() error { m.closed = true; return nil }

func (s *memorySink) OpenMember(name string, mode uint32) (ArchiveMember, error) {
	if s.members == nil {
		s.members = make(map[string]*memoryMember)
	}
	mem := &memoryMember{mode: mode}
	s.members[name] = mem
	return mem, nil
}

func TestDownloadArtifactStream_Validation(t *testing.T) {
	const serverHost = "example.com"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/valid.bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("hello verified artifact staging"))
		case "/short.bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("short"))
		case "/oversize.bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("this payload is definitely longer than expected"))
		case "/redirect-bad-host":
			http.Redirect(w, r, "https://evil.invalid/bad.bin", http.StatusFound)
		case "/redirect-bad-host-with-token":
			http.Redirect(w, r, "https://evil.invalid/bad.bin?token=secrettoken12345", http.StatusFound)
		case "/redirect-userinfo":
			http.Redirect(w, r, "https://user:pass@"+serverHost+"/bad.bin", http.StatusFound)
		case "/redirect-fragment":
			http.Redirect(w, r, "https://"+serverHost+"/bad.bin#frag", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewTLSServer(handler)
	defer server.Close()

	tr := server.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = serverHost

	validBytes := []byte("hello verified artifact staging")
	validSum := sha256.Sum256(validBytes)
	validSHA := hex.EncodeToString(validSum[:])

	cases := []struct {
		name        string
		path        string
		size        int64
		sha         string
		hosts       []string
		cancelCtx   bool
		wantErr     error
		errContains string
		forbidden   string
	}{
		{
			name:  "valid download",
			path:  "/valid.bin",
			size:  int64(len(validBytes)),
			sha:   validSHA,
			hosts: []string{serverHost},
		},
		{
			name:        "digest mismatch",
			path:        "/valid.bin",
			size:        int64(len(validBytes)),
			sha:         strings.Repeat("a", 64),
			hosts:       []string{serverHost},
			wantErr:     ErrDigestMismatch,
			errContains: "sha256 mismatch",
		},
		{
			name:        "short stream",
			path:        "/short.bin",
			size:        int64(len(validBytes)),
			sha:         validSHA,
			hosts:       []string{serverHost},
			wantErr:     ErrSizeMismatch,
			errContains: "less than expected size",
		},
		{
			name:        "oversize stream",
			path:        "/oversize.bin",
			size:        10,
			sha:         validSHA,
			hosts:       []string{serverHost},
			wantErr:     ErrSizeMismatch,
			errContains: "exceeded expected size",
		},
		{
			name:    "host not allowed",
			path:    "/valid.bin",
			size:    int64(len(validBytes)),
			sha:     validSHA,
			hosts:   []string{"other.invalid"},
			wantErr: ErrURLNotAllowed,
		},
		{
			name:    "redirect bad host",
			path:    "/redirect-bad-host",
			size:    10,
			sha:     validSHA,
			hosts:   []string{serverHost},
			wantErr: ErrURLNotAllowed,
		},
		{
			name:      "redirect bad host with token does not leak token",
			path:      "/redirect-bad-host-with-token",
			size:      10,
			sha:       validSHA,
			hosts:     []string{serverHost},
			wantErr:   ErrURLNotAllowed,
			forbidden: "secrettoken12345",
		},
		{
			name:    "redirect userinfo",
			path:    "/redirect-userinfo",
			size:    10,
			sha:     validSHA,
			hosts:   []string{serverHost},
			wantErr: ErrURLNotAllowed,
		},
		{
			name:    "redirect fragment",
			path:    "/redirect-fragment",
			size:    10,
			sha:     validSHA,
			hosts:   []string{serverHost},
			wantErr: ErrURLNotAllowed,
		},
		{
			name:      "context canceled",
			path:      "/valid.bin",
			size:      int64(len(validBytes)),
			sha:       validSHA,
			hosts:     []string{serverHost},
			cancelCtx: true,
			wantErr:   context.Canceled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if tc.cancelCtx {
				cancel()
			}

			var buf bytes.Buffer
			opts := DownloadOptions{
				URL:            "https://" + serverHost + tc.path,
				AllowedHosts:   tc.hosts,
				Out:            &buf,
				ExpectedSize:   tc.size,
				ExpectedSHA256: tc.sha,
				Transport:      tr,
			}

			err := DownloadArtifactStream(ctx, opts)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !bytes.Equal(buf.Bytes(), validBytes) {
					t.Fatalf("content mismatch: got %q, want %q", buf.String(), string(validBytes))
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", tc.wantErr, err)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tc.errContains, err.Error())
				}
				if tc.forbidden != "" && strings.Contains(err.Error(), tc.forbidden) {
					t.Fatalf("error leaked forbidden token %q: %v", tc.forbidden, err)
				}
			}
		})
	}
}

func TestArchivePrimitves(t *testing.T) {
	// VerifyArchiveMember
	sink := &memorySink{}
	memData := []byte("member file bytes")
	memSHA := sha256.Sum256(memData)
	memHex := hex.EncodeToString(memSHA[:])

	if err := VerifyArchiveMember(bytes.NewReader(memData), int64(len(memData)), nil, memHex, sink, "test.txt", 0644); err != nil {
		t.Fatalf("verify archive member failed: %v", err)
	}
	if mem, ok := sink.members["test.txt"]; !ok || !bytes.Equal(mem.Bytes(), memData) || !mem.synced || !mem.closed {
		t.Fatalf("sink did not record verified member properly")
	}

	// Parameter validation bounds before sink
	if err := VerifyArchiveMember(nil, 10, nil, "", nil, "file.txt", 0644); err == nil {
		t.Fatal("expected nil reader error")
	}
	if err := VerifyArchiveMember(bytes.NewReader([]byte("a")), -1, nil, "", nil, "file.txt", 0644); err == nil {
		t.Fatal("expected negative size error")
	}
	if err := VerifyArchiveMember(bytes.NewReader([]byte("ab")), 2, []byte("a"), "", nil, "manifest", 0644); err == nil || err.Error() != "archive manifest size mismatch" {
		t.Fatalf("expected archive manifest size mismatch without panic, got %v", err)
	}
}
