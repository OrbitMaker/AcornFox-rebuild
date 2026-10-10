package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The --local target reaches the trusted socket through a unix:// URL.
func TestUnixURLAndPublicConsoleWire(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "afpc") // short path: macOS limits socket paths
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotEnable map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/public-console", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"enabled":true,"domain":"panel.example.com","url":"https://panel.example.com"}`))
	})
	mux.HandleFunc("POST /v1/public-console/verify", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"domain":"panel.example.com","verify_id":"v1","path":"/p","token":"t","ips":{"ipv4":["203.0.113.10"]},"expires_in":1800}`))
	})
	mux.HandleFunc("POST /v1/public-console/enable", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotEnable)
		_, _ = w.Write([]byte(`{"domain":"panel.example.com","url":"https://panel.example.com","password":"pw"}`))
	})
	mux.HandleFunc("DELETE /v1/public-console", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"disabled":true,"was_enabled":true}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	ctx := context.Background()
	c, err := Connect(ctx, Target{URL: "unix://" + sock})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.PublicConsoleStatus(ctx)
	if err != nil || !st.Enabled || st.Domain != "panel.example.com" {
		t.Fatalf("status = %+v %v", st, err)
	}
	v, err := c.PublicConsoleVerify(ctx, "panel.example.com")
	if err != nil || v.VerifyID != "v1" || v.IPs.V4[0] != "203.0.113.10" {
		t.Fatalf("verify = %+v %v", v, err)
	}
	res, err := c.PublicConsoleEnable(ctx, "panel.example.com", "v1", true)
	if err != nil || res.Password != "pw" || gotEnable["verify_id"] != "v1" || gotEnable["reset_password"] != true {
		t.Fatalf("enable = %+v %v %v", res, err, gotEnable)
	}
	was, err := c.PublicConsoleDisable(ctx)
	if err != nil || !was {
		t.Fatalf("disable = %v %v", was, err)
	}
}
