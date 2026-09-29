package application

import (
	"context"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"testing"
	"time"
)

type lifecycleWorkerStore struct {
	appcontracts.ImageLifecycleStore
	binding   appcontracts.ImageLifecycleBinding
	committed bool
	unknown   bool
	failed    bool
	received  appcontracts.ImageLifecycleAuthorityInput
}

func (s *lifecycleWorkerStore) BeginImageLifecycle(context.Context, appcontracts.BeginImageExecutionInput) (appcontracts.ImageLifecycleBinding, error) {
	return s.binding, nil
}
func (s *lifecycleWorkerStore) CommitImageLifecycleResult(_ context.Context, in appcontracts.CommitImageLifecycleInput) error {
	s.committed = true
	s.received = in.ImageLifecycleAuthorityInput
	return nil
}
func (s *lifecycleWorkerStore) RecordImageLifecycleUnknown(_ context.Context, in appcontracts.ImageLifecycleOutcomeInput) error {
	s.unknown = true
	s.received = in.ImageLifecycleAuthorityInput
	return nil
}
func (s *lifecycleWorkerStore) FailImageLifecycle(_ context.Context, in appcontracts.ImageLifecycleOutcomeInput) error {
	s.failed = true
	s.received = in.ImageLifecycleAuthorityInput
	return nil
}

type lifecycleWorkerClient struct {
	err       error
	binding   appcontracts.ImageLifecycleBinding
	authority appcontracts.ImageLifecycleAuthorityInput
}

func (c *lifecycleWorkerClient) ExecuteLifecycle(_ context.Context, b appcontracts.ImageLifecycleBinding, a appcontracts.ImageLifecycleAuthorityInput) (appcontracts.ImageLifecycleResult, error) {
	c.binding = b
	c.authority = a
	return appcontracts.ImageLifecycleResult{}, c.err
}
func TestImageLifecycleWorkerFreshCommandDispatchAndUnknown(t *testing.T) {
	for _, action := range []appcontracts.ImageLifecycleAction{appcontracts.ImageLifecycleStop, appcontracts.ImageLifecycleStart, appcontracts.ImageLifecycleRestart} {
		t.Run(string(action), func(t *testing.T) {
			deployStore := &fakeExecutionStore{}
			deployClient := &fakeContainerClient{}
			lifecycleStore := &lifecycleWorkerStore{binding: appcontracts.ImageLifecycleBinding{OperationID: domain.ID("op_new_command"), TaskID: domain.ID("task_command"), DeploymentID: domain.ID("dep_same"), ReleaseID: domain.ID("rel_same"), DeployOperationID: domain.ID("op_old_deploy"), PlanDigest: "sha256:fixture", ContainerID: "same-cid", Action: action, RecoveryRequired: true}}
			lifecycleClient := &lifecycleWorkerClient{}
			if action == appcontracts.ImageLifecycleRestart {
				lifecycleClient.err = appcontracts.ErrOutcomeUnknown
			}
			repo := &fakeExecutionTaskRepo{claimed: appcontracts.Task{ID: lifecycleStore.binding.TaskID, OperationID: lifecycleStore.binding.OperationID, CoreGeneration: 7, LeaseGeneration: 9, Payload: []byte(`{"kind":"image.lifecycle"}`)}, hasTask: true}
			worker, err := NewImageExecutionWorker(ImageExecutionWorkerConfig{WorkerID: "fresh-worker", Store: deployStore, Client: deployClient, TaskRepo: repo, LifecycleStore: lifecycleStore, LifecycleClient: lifecycleClient, LeaseDuration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			handled, err := worker.PollOnce(context.Background())
			if err != nil || !handled {
				t.Fatalf("poll %v %v", handled, err)
			}
			if deployStore.committedHit || deployStore.unknownHit || deployStore.failedHit {
				t.Fatal("lifecycle borrowed deploy outcome")
			}
			a := lifecycleClient.authority
			if a.OperationID != lifecycleStore.binding.OperationID || a.OperationID == lifecycleStore.binding.DeployOperationID || a.CoreGeneration != 7 || a.LeaseGeneration != 9 || a.Action != action || !lifecycleClient.binding.RecoveryRequired {
				t.Fatal("fresh command authority or recovery flag lost")
			}
			if action == appcontracts.ImageLifecycleRestart {
				if !lifecycleStore.unknown || lifecycleStore.committed {
					t.Fatal("unknown restart incorrectly became success")
				}
			} else if !lifecycleStore.committed {
				t.Fatal("successful command not committed")
			}
		})
	}
}
