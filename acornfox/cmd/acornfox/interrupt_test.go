//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestCLIInterruptHelper(t *testing.T) {
	if os.Getenv("ACORNFOX_TEST_INTERRUPT_HELPER") != "1" {
		return
	}
	os.Exit(run([]string{"--app", "sample", "logs", "-f", "--tail", "1"}, os.Stdin, os.Stdout, os.Stderr))
}

func TestCLIInterruptCancelsLogFollow(t *testing.T) {
	ready := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/sample/log-batch" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"lines": []string{"following"}, "cursor": "cursor", "has_more": false})
		once.Do(func() { close(ready) })
	}))
	defer server.Close()

	home := t.TempDir()
	config := filepath.Join(home, "config")
	if err := os.MkdirAll(filepath.Join(config, "acornfox"), 0o700); err != nil {
		t.Fatal(err)
	}
	// os.UserConfigDir uses HOME on macOS and XDG_CONFIG_HOME on Linux.
	macConfig := filepath.Join(home, "Library", "Application Support", "acornfox")
	if err := os.MkdirAll(macConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"default": "test", "targets": map[string]any{
		"test": map[string]any{"name": "test", "url": server.URL},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(config, "acornfox"), macConfig} {
		if err := os.WriteFile(filepath.Join(dir, "targets.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIInterruptHelper$")
	cmd.Env = append(os.Environ(), "ACORNFOX_TEST_INTERRUPT_HELPER=1", "HOME="+home, "XDG_CONFIG_HOME="+config)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		waited = true
		t.Fatalf("CLI exited before following: %v; output=%s", err, output.String())
	case <-time.After(10 * time.Second):
		t.Fatal("CLI never reached log polling")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatalf("Ctrl+C must unwind log following cleanly: %v; output=%s", err, output.String())
		}
		if cmd.ProcessState.ExitCode() != 0 {
			t.Fatal("unexpected exit " + strconv.Itoa(cmd.ProcessState.ExitCode()))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CLI did not exit after Ctrl+C")
	}
}
