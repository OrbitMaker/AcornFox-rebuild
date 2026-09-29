//go:build linux

package peer

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serve(t *testing.T, allowUID uint32) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.sock")
	l, err := Listen(path, 0, allowUID)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

func TestOnlyExpectedUIDsConnect(t *testing.T) {
	self := uint32(os.Getuid())
	if self == 0 {
		t.Skip("requires a non-root test account")
	}
	path := serve(t, self)
	req, _ := http.NewRequest(http.MethodGet, "http://unix/", nil)
	if _, body, err := NewClient(path, self, time.Second).Do(req); err != nil || string(body) != "ok" {
		t.Fatalf("matching peer rejected: %v %q", err, body)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://unix/", nil)
	if _, _, err := NewClient(path, self+1, time.Second).Do(req); err == nil {
		t.Fatal("client accepted a server running as an unexpected uid")
	}
	other := serve(t, self+1)
	req, _ = http.NewRequest(http.MethodGet, "http://unix/", nil)
	if _, _, err := NewClient(other, self, time.Second).Do(req); err == nil {
		t.Fatal("server accepted a client running as an unexpected uid")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, %v", info.Mode(), err)
	}
}

func TestListenRefusesNonSocketAndRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0, 1000); err == nil {
		t.Fatal("regular file was replaced by a socket")
	}
	if _, err := Listen(filepath.Join(t.TempDir(), "s"), 0, 0); err == nil {
		t.Fatal("root peer uid was accepted")
	}
}
