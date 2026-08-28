package main

import (
	"context"
	"testing"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
)

func TestOutboundHandlerRoutesM4RestartThroughTypedExecutorAndReplays(t *testing.T) {
	runtime := newM4RuntimeFake()
	handler := NewOutboundHandlerWithRuntime("instance_m4", "node_m4", staticDockerFacts{}, runtime)
	task := m4Task(t, v1.TaskRestart, "outbound-m4-restart", contracts.RestartRequest{DeploymentID: "dep_m4", ServiceName: "worker", Operation: m4Operation("outbound-m4-restart")})
	first, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil || len(first) != 4 || len(second) != 4 || len(runtime.restarts) != 1 {
		t.Fatalf("M4 restart was not typed/idempotent: first=%#v second=%#v err=%v restarts=%d", first, second, err, len(runtime.restarts))
	}
	if first[1].Kind != v1.KindLogChunk || first[2].Kind != v1.KindObservation || first[3].Kind != v1.KindTaskResult {
		t.Fatalf("M4 outbound envelope order=%#v", first)
	}
}
