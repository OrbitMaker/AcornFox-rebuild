package controllers

import (
	"encoding/json"
	"testing"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
)

func TestM4ReplacementTaskDefersOnlyTypedAggregateReplacementPayloads(t *testing.T) {
	encode := func(kind v1.TaskKind, marker string) json.RawMessage {
		parameters, err := json.Marshal(map[string]string{"m4_payload_type": marker})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(AgentTaskSpec{Kind: kind, Parameters: parameters})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	for name, tc := range map[string]struct {
		payload json.RawMessage
		want    bool
	}{
		"redeploy":       {encode(v1.TaskDeploy, "service_group.redeploy"), true},
		"rollback":       {encode(v1.TaskRollback, "service_group.rollback"), true},
		"wrong kind":     {encode(v1.TaskRestart, "service_group.redeploy"), false},
		"unknown marker": {encode(v1.TaskDeploy, "service_group.unrecognized"), false},
		"invalid":        {json.RawMessage(`{"kind":"deploy","parameters":{}}`), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := m4ReplacementTask(tc.payload); got != tc.want {
				t.Fatalf("m4ReplacementTask()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestM4CandidateCleanupDefersParentOnlyForExactVolumePreservingPayload(t *testing.T) {
	encode := func(request contracts.DestroyRequest) json.RawMessage {
		parameters, _ := json.Marshal(request)
		payload, _ := json.Marshal(AgentTaskSpec{Kind: v1.TaskDestroyGroup, Parameters: parameters})
		return payload
	}
	valid := contracts.DestroyRequest{DeploymentID: "dep_candidate", PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: "m4-cleanup:op:dep_candidate", Actor: "test"}}
	if !m4DeferredTask(encode(valid)) {
		t.Fatal("exact candidate cleanup did not defer parent terminal")
	}
	for _, mutate := range []func(*contracts.DestroyRequest){func(v *contracts.DestroyRequest) { v.DeploymentID = "" }, func(v *contracts.DestroyRequest) { v.PreserveVolumes = false }, func(v *contracts.DestroyRequest) { v.ConfirmationToken = "delete" }, func(v *contracts.DestroyRequest) { v.Operation.IdempotencyKey = "m4-retire:old" }} {
		copy := valid
		mutate(&copy)
		if m4DeferredTask(encode(copy)) {
			t.Fatalf("unsafe cleanup payload deferred parent: %+v", copy)
		}
	}
}

func TestAgentDispatcherAllowlistIncludesAggregateTaskKinds(t *testing.T) {
	for _, kind := range []v1.TaskKind{v1.TaskDeployGroup, v1.TaskDestroyGroup, v1.TaskDestroyVolume, v1.TaskObserve, v1.TaskDeploy, v1.TaskLogs, v1.TaskRestart, v1.TaskScale, v1.TaskRollback, v1.TaskDestroy} {
		if !dispatchableAgentTaskKind(kind) {
			t.Fatalf("allowlisted kind rejected: %q", kind)
		}
	}
	if dispatchableAgentTaskKind("shell") {
		t.Fatal("arbitrary shell task accepted")
	}
	for _, kind := range dispatchableAgentTaskKinds() {
		if !dispatchableAgentTaskKind(v1.TaskKind(kind)) {
			t.Fatalf("dispatcher claim filter contains non-dispatchable kind %q", kind)
		}
	}
}

func TestAgentTaskWireIdempotencyUsesExactCleanupAndWrappedOperation(t *testing.T) {
	directParameters, _ := json.Marshal(contracts.DestroyRequest{DeploymentID: "dep_candidate", PreserveVolumes: true, Operation: contracts.OperationContext{IdempotencyKey: "m4-cleanup:rollout:candidate"}})
	directPayload, _ := json.Marshal(AgentTaskSpec{Kind: v1.TaskDestroyGroup, Parameters: directParameters})
	if got := agentTaskWireIdempotency(directPayload, "parent-key"); got != "m4-cleanup:rollout:candidate" {
		t.Fatalf("cleanup wire key=%q", got)
	}
	wrappedParameters, _ := json.Marshal(map[string]any{"m4_payload_type": "service_group.rollback", "request": map[string]any{"operation": contracts.OperationContext{IdempotencyKey: "rollback-candidate-key"}}})
	wrappedPayload, _ := json.Marshal(AgentTaskSpec{Kind: v1.TaskRollback, Parameters: wrappedParameters})
	if got := agentTaskWireIdempotency(wrappedPayload, "parent-key"); got != "rollback-candidate-key" {
		t.Fatalf("wrapped wire key=%q", got)
	}
	legacyPayload, _ := json.Marshal(AgentTaskSpec{Kind: v1.TaskObserve, Parameters: json.RawMessage(`{"scope":"node_docker_facts"}`)})
	if got := agentTaskWireIdempotency(legacyPayload, "parent-key"); got != "parent-key" {
		t.Fatalf("legacy wire key=%q", got)
	}
}
