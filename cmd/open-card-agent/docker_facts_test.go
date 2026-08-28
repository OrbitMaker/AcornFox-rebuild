package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDockerFactsReaderUsesOnlyReadOnlyVersionAndInfo(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "oc-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	socketPath := filepath.Join(tempDir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	paths := []string{}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		paths = append(paths, request.Method+" "+request.URL.Path)
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/version":
			_ = json.NewEncoder(writer).Encode(map[string]any{"Version": "29.1.3", "ApiVersion": "1.52", "Os": "linux", "Arch": "amd64"})
		case "/info":
			_ = json.NewEncoder(writer).Encode(map[string]any{"OperatingSystem": "Ubuntu", "Architecture": "x86_64", "NCPU": 8, "MemTotal": 16 << 30, "Containers": 4, "ContainersRunning": 2, "ContainersPaused": 0, "ContainersStopped": 2, "RegistryConfig": map[string]any{"IndexConfigs": map[string]any{"private.example": map[string]any{"Mirrors": []string{"secret"}}}}})
		default:
			http.Error(writer, "unexpected endpoint", http.StatusForbidden)
		}
	})}
	go server.Serve(listener)
	defer server.Close()

	reader, err := NewUnixDockerFactsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := reader.ReadFacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if facts.ServerVersion != "29.1.3" || facts.CPUs != 8 || facts.MemoryBytes != 16<<30 || facts.ContainersRunning != 2 {
		t.Fatalf("unexpected Docker facts: %#v", facts)
	}
	encoded, _ := json.Marshal(facts)
	if string(encoded) == "" || strings.Contains(string(encoded), "private.example") || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "RegistryConfig") {
		t.Fatalf("Docker facts leaked non-allowlisted info: %s", encoded)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "GET /version" || paths[1] != "GET /info" {
		t.Fatalf("reader called non-allowlisted Docker endpoints: %#v", paths)
	}
}
