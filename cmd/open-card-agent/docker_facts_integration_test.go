//go:build integration

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestAgentReadsRealDockerFactsWithoutMutation(t *testing.T) {
	socketPath := os.Getenv("OPEN_CARD_DOCKER_SOCKET")
	if socketPath == "" {
		t.Fatal("OPEN_CARD_DOCKER_SOCKET is required")
	}
	reader, err := NewUnixDockerFactsReader(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	facts, err := reader.ReadFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if facts.ServerVersion == "" || facts.APIVersion == "" || facts.CPUs <= 0 || facts.MemoryBytes <= 0 || facts.Containers < facts.ContainersRunning {
		t.Fatalf("incomplete real Docker facts: %#v", facts)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("docker_facts=%s", encoded)
}
