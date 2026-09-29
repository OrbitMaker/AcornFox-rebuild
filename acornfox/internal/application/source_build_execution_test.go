package application

import (
	"context"
	"encoding/json"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"testing"
)

// Actual durable two-stage consumption is exercised by the SQLite fixture.
// This narrower guard test checks that unsupported control tasks cannot reach
// the composer/client even if a repository supplies one contrary to Kinds.
func TestSourceBuildWorkerRejectsUnapprovedControlTask(t *testing.T) {
	tasks := &sourceTaskGuardFixture{task: appcontracts.Task{ID: "task_control", OperationID: "op_control", CoreGeneration: 1, LeaseGeneration: 1, Payload: json.RawMessage(`{"kind":"source.cancel","intent_id":"intent_control","application_id":"app_control"}`)}}
	client := &sourceClientGuardFixture{}
	worker, err := NewSourceBuildExecutionWorker(SourceBuildExecutionWorkerConfig{WorkerID: "worker", Store: sourceStoreGuardFixture{}, TaskRepo: tasks, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := worker.PollOnce(context.Background()); !claimed || err == nil || client.calls != 0 {
		t.Fatalf("unapproved control dispatched: %v %v", claimed, err)
	}
	if len(tasks.request.Kinds) != 2 || tasks.request.Kinds[0] != "source.prepare" || tasks.request.Kinds[1] != "source.build" {
		t.Fatal("worker claimed outside its exact capabilities")
	}
	if _, err := NewSourceBuildExecutionWorker(SourceBuildExecutionWorkerConfig{WorkerID: "worker", Store: sourceStoreGuardFixture{}, TaskRepo: tasks}); err == nil {
		t.Fatal("missing client accepted")
	}
}

type sourceStoreGuardFixture struct {
	appcontracts.SourceBuildFactsStore
}
type sourceTaskGuardFixture struct {
	appcontracts.TaskRepository
	task    appcontracts.Task
	request appcontracts.ClaimTaskRequest
}

func (f *sourceTaskGuardFixture) ClaimTask(_ context.Context, r appcontracts.ClaimTaskRequest) (appcontracts.Task, bool, error) {
	f.request = r
	return f.task, true, nil
}

type sourceClientGuardFixture struct{ calls int }

func (f *sourceClientGuardFixture) ExecuteSourceBuild(context.Context, []byte) (appcontracts.SourceBuildExecutionReceipt, error) {
	f.calls++
	return appcontracts.SourceBuildExecutionReceipt{}, nil
}
