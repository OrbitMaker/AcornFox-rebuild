package standalone

import (
	"context"
	"errors"
	"github.com/acornfox/acornfox/internal/contracts"
	"io"
	"testing"
	"time"
)

func TestBoundedObservationBusyAndImmutableLogTarget(t *testing.T) {
	runner := &fakeRunner{}
	p := testProvider(t, runner, &fixedPorts{port: 39124})
	req := testRequest("observe-read")
	op := contracts.OperationContext{IdempotencyKey: "read-only"}
	calls := 0
	runner.run = func(args []string, out io.Writer) error {
		calls++
		if args[0] != "logs" || args[len(args)-1] != testContainerID {
			t.Fatal("bounded log used mutable container name")
		}
		_, err := io.WriteString(out, "owned log\n")
		return err
	}
	p.states[req.DeploymentID] = &runtimeState{service: "web", container: "replaceable-name", containerID: testContainerID}
	unlock := p.lockDeployment(req.DeploymentID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if _, err := p.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: op}, req.Spec); err == nil || time.Since(start) > 500*time.Millisecond || calls != 0 {
		t.Fatal("busy read waited or reached engine")
	}
	if _, err := p.ReadAcornFoxLogs(ctx, contracts.LogsRequest{DeploymentID: req.DeploymentID, ServiceName: "web", Tail: 1, Operation: op}); err == nil || calls != 0 {
		t.Fatal("busy logs waited or reached engine")
	}
	unlock()
	p.mu.Lock()
	if _, err := p.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: op}, req.Spec); err == nil || calls != 0 {
		t.Fatal("global state lock blocked or reached engine")
	}
	if _, err := p.ReadAcornFoxLogs(ctx, contracts.LogsRequest{DeploymentID: req.DeploymentID, ServiceName: "web", Tail: 1, Operation: op}); err == nil || calls != 0 {
		t.Fatal("global state lock blocked logs")
	}
	p.mu.Unlock()
	logs, err := p.ReadAcornFoxLogs(ctx, contracts.LogsRequest{DeploymentID: req.DeploymentID, ServiceName: "web", Tail: 1, Operation: op})
	if err != nil || len(logs.Records) != 1 || calls != 1 {
		t.Fatalf("immutable log target: %v", err)
	}
	p.states[req.DeploymentID].containerID = "short"
	if _, err = p.ReadAcornFoxLogs(ctx, contracts.LogsRequest{DeploymentID: req.DeploymentID, ServiceName: "web", Tail: 1, Operation: op}); err == nil || calls != 1 {
		t.Fatal("unbound CID reached logs")
	}
	canceled, done := context.WithCancel(context.Background())
	done()
	if _, err = p.ObserveDeploymentSnapshot(canceled, contracts.ObserveRequest{DeploymentID: req.DeploymentID, Operation: op}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read lost context cause")
	}
}
