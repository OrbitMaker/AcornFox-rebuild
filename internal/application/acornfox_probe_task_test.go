package application

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
)

func TestBuildAcornFoxProbeTaskPlanBindsOnlyAcceptedLoopbackFact(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/healthz", "probe-once")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0).UTC()
	current := contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124", ObservedAt: now}
	first, err := BuildAcornFoxProbeTaskPlan(request, current, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildAcornFoxProbeTaskPlan(request, current, now.Add(time.Minute))
	if err != nil || first.TaskID != second.TaskID || first.Operation.ID != second.Operation.ID || first.Operation.IdempotencyKey != request.IdempotencyKey {
		t.Fatalf("probe task was not restart-safe: first=%#v second=%#v err=%v", first, second, err)
	}
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(first.Payload, &task); err != nil || task.Kind != v1.TaskObserve {
		t.Fatalf("unexpected durable task: %s %v", first.Payload, err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(task.Parameters, &wire); err != nil || string(wire["acornfox_probe_payload_type"]) != `"probe"` || len(wire) != 2 {
		t.Fatalf("probe parameters lost strict marker: %s %v", task.Parameters, err)
	}
	for _, forbidden := range []string{"127.0.0.1", "39124", "target", "address"} {
		if strings.Contains(string(first.Payload), forbidden) {
			t.Fatalf("durable task leaked a runtime target %q: %s", forbidden, first.Payload)
		}
	}
}

func TestBuildAcornFoxProbeTaskPlanRejectsMismatchedOrNonLoopbackFacts(t *testing.T) {
	fact := acornFoxRuntimeFact(t)
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolTCP, "", "probe-once")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, _ := contracts.AcornFoxRuntimeDeploymentID(fact)
	now := time.Unix(1700000000, 0).UTC()
	for _, current := range []contracts.AcornFoxRuntimeObservation{
		{DeploymentID: "dep_other", ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124", ObservedAt: now},
		{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "10.0.0.1:39124", ObservedAt: now},
		{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "example.com:39124", ObservedAt: now},
	} {
		if _, err := BuildAcornFoxProbeTaskPlan(request, current, now); err == nil {
			t.Fatalf("unsafe runtime fact became a probe task: %#v", current)
		}
	}
}
