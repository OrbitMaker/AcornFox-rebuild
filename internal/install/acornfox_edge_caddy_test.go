//go:build !windows

package install

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestAcornFoxEdgeRealCaddyHeldSSEStopsWithinBudget(t *testing.T) {
	binary := os.Getenv("ACORNFOX_TEST_CADDY")
	if binary == "" {
		if os.Getenv("ACORNFOX_REQUIRE_CADDY") == "1" {
			t.Fatal("verified Caddy path required")
		}
		t.Skip("set ACORNFOX_TEST_CADDY to verified native Caddy 2.11.4")
	}
	version, err := exec.Command(binary, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "v2.11.4 ") {
		t.Fatal("requires pinned Caddy 2.11.4")
	}
	for _, grace := range []string{"5s", ""} {
		t.Run("grace="+grace, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: held\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			t.Cleanup(backend.Close)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			listener.Close()
			root := t.TempDir()
			httpApp := map[string]any{"servers": map[string]any{"events": map[string]any{"listen": []string{address}, "automatic_https": map[string]any{"disable": true}, "routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": strings.TrimPrefix(backend.URL, "http://")}}}}}}}}}
			if grace != "" {
				httpApp["grace_period"] = grace
			}
			raw, _ := json.Marshal(map[string]any{"admin": map[string]any{"disabled": true}, "apps": map[string]any{"http": httpApp}})
			config := filepath.Join(root, "edge.json")
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			logFile, err := os.Create(filepath.Join(root, "caddy.log"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { logFile.Close() })
			command := exec.Command(binary, "run", "--config", config)
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "XDG_DATA_HOME=" + root, "XDG_CONFIG_HOME=" + root}
			command.Stdout = logFile
			command.Stderr = logFile
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			var exited atomic.Bool
			wait := make(chan error, 1)
			go func() { wait <- command.Wait(); exited.Store(true) }()
			t.Cleanup(func() {
				if !exited.Load() {
					_ = command.Process.Kill()
				}
				select {
				case <-wait:
				case <-time.After(3 * time.Second):
				}
			})
			client := &http.Client{Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: time.Second}}
			t.Cleanup(client.CloseIdleConnections)
			var response *http.Response
			ready := time.Now().Add(5 * time.Second)
			for time.Now().Before(ready) {
				response, err = client.Get("http://" + address + "/events")
				if err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil || response == nil {
				t.Fatal("Caddy SSE unavailable")
			}
			defer response.Body.Close()
			line, err := bufio.NewReader(response.Body).ReadString('\n')
			if err != nil || line != "data: held\n" {
				t.Fatal("SSE not held")
			}
			stopped, quit := false, false
			runner := func(_ context.Context, path string, args ...string) ([]byte, error) {
				if path != "/usr/bin/systemctl" {
					t.Fatal("wrong transport")
				}
				switch args[0] {
				case "show":
					if exited.Load() {
						return edgeStopState("inactive", "dead", 0), nil
					}
					if stopped {
						return edgeStopState("deactivating", "stop-sigterm", command.Process.Pid), nil
					}
					return edgeStopState("active", "running", command.Process.Pid), nil
				case "stop":
					stopped = true
					if exited.Load() {
						return nil, nil
					}
					return nil, command.Process.Signal(syscall.SIGTERM)
				case "kill":
					if strings.Join(args, " ") != "kill --kill-whom=main --signal=QUIT acornfox-edge.service" {
						t.Fatal("unbounded signal target")
					}
					quit = true
					return nil, command.Process.Signal(syscall.SIGQUIT)
				default:
					return nil, fmt.Errorf("unexpected command")
				}
			}
			start := time.Now()
			err = stopAcornFoxEdge(context.Background(), runner, grace == "", acornFoxEdgeStopBudget, 50*time.Millisecond)
			elapsed := time.Since(start)
			if err != nil || !exited.Load() || elapsed >= acornFoxEdgeStopBudget {
				t.Fatal("held SSE prevented stop", err, elapsed)
			}
			if grace == "5s" && (quit || elapsed < 4*time.Second) {
				t.Fatal("bounded grace profile did not drain normally", elapsed, quit)
			}
			if grace == "" && (!quit || elapsed >= 5*time.Second) {
				t.Fatal("legacy fallback not exercised", elapsed, quit)
			}
			logBytes, _ := os.ReadFile(filepath.Join(root, "caddy.log"))
			if bytes.Contains(logBytes, []byte("panic")) {
				t.Fatal("Caddy panicked")
			}
			t.Logf("grace=%q held_sse=true stopped=true quit_fallback=%t elapsed=%s", grace, quit, elapsed)
		})
	}
}
