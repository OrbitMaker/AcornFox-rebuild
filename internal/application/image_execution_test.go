package application

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type fakeExecutionTaskRepo struct {
	claimed  appcontracts.Task
	hasTask  bool
	renewed  bool
	failCall bool
}

func (f *fakeExecutionTaskRepo) ClaimTask(ctx context.Context, req appcontracts.ClaimTaskRequest) (appcontracts.Task, bool, error) {
	if !f.hasTask {
		return appcontracts.Task{}, false, nil
	}
	f.hasTask = false
	return f.claimed, true, nil
}

func (f *fakeExecutionTaskRepo) RenewTask(ctx context.Context, req appcontracts.TaskMutationRequest) error {
	f.renewed = true
	return nil
}

func (f *fakeExecutionTaskRepo) CompleteTask(ctx context.Context, req appcontracts.TaskMutationRequest) error {
	return nil
}

func (f *fakeExecutionTaskRepo) FailTask(ctx context.Context, req appcontracts.FailTaskRequest) (appcontracts.TaskState, error) {
	f.failCall = true
	return appcontracts.TaskFailed, nil
}

func (f *fakeExecutionTaskRepo) CancelTask(ctx context.Context, req appcontracts.TaskMutationRequest) error {
	return nil
}

func (f *fakeExecutionTaskRepo) GetTask(ctx context.Context, id domain.ID) (appcontracts.Task, error) {
	return f.claimed, nil
}

type fakeExecutionStore struct {
	binding      appcontracts.ImageExecutionBinding
	beginErr     error
	committed    appcontracts.CommitImageExecutionResultInput
	committedHit bool
	failedHit    bool
	unknownHit   bool
}

func (f *fakeExecutionStore) BeginImageExecution(ctx context.Context, input appcontracts.BeginImageExecutionInput) (appcontracts.ImageExecutionBinding, error) {
	if f.beginErr != nil {
		return appcontracts.ImageExecutionBinding{}, f.beginErr
	}
	return f.binding, nil
}

func (f *fakeExecutionStore) AuthorizeImageExecution(ctx context.Context, input appcontracts.AuthorizeImageExecutionInput) (appcontracts.AuthorityBindingFacts, error) {
	return appcontracts.AuthorityBindingFacts{PlanDigest: input.PlanDigest}, nil
}

func (f *fakeExecutionStore) CommitImageExecutionResult(ctx context.Context, input appcontracts.CommitImageExecutionResultInput) error {
	f.committed = input
	f.committedHit = true
	return nil
}

func (f *fakeExecutionStore) FailImageExecution(ctx context.Context, input appcontracts.FailImageExecutionInput) error {
	f.failedHit = true
	return nil
}

func (f *fakeExecutionStore) RecordImageExecutionUnknown(ctx context.Context, input appcontracts.RecordImageExecutionUnknownInput) error {
	f.unknownHit = true
	return nil
}

func (f *fakeExecutionStore) ReadImageObservationBinding(ctx context.Context, operationID, deploymentID domain.ID) (appcontracts.ImageObservationBinding, error) {
	return appcontracts.ImageObservationBinding{
		ApplicationID:  f.binding.ApplicationID,
		EnvironmentID:  f.binding.EnvironmentID,
		ReleaseID:      f.binding.ReleaseID,
		ApprovedPort:   f.binding.Plan.CanonicalInput.Port,
		PlanDigest:     f.binding.Plan.PlanDigest,
		Repository:     f.binding.Plan.ResolvedImage.Repository,
		Digest:         f.binding.Plan.ResolvedImage.Digest,
		OperationState: "running",
	}, nil
}

type fakeContainerClient struct {
	result    appcontracts.CommitImageExecutionResultInput
	err       error
	obsResult appcontracts.ImageExecutionResult
	obsErr    error
}

func (f *fakeContainerClient) ExecuteDeployment(ctx context.Context, binding appcontracts.ImageExecutionBinding) (appcontracts.CommitImageExecutionResultInput, error) {
	if f.err != nil {
		return appcontracts.CommitImageExecutionResultInput{}, f.err
	}
	return f.result, nil
}

func (f *fakeContainerClient) ObserveDeployment(ctx context.Context, deploymentID domain.ID, operationID domain.ID) (appcontracts.ImageExecutionResult, error) {
	if f.obsErr != nil {
		return appcontracts.ImageExecutionResult{}, f.obsErr
	}
	if f.obsResult.Status != "" {
		return f.obsResult, nil
	}
	return appcontracts.ImageExecutionResult{Status: "running", Running: true, ObservedAt: time.Now().UTC(), HostPort: 39898}, nil
}

func TestImageExecutionWorker_SuccessfulExecution(t *testing.T) {
	taskID := domain.ID("tsk_exec_001")
	opID := domain.ID("op_exec_001")
	depID := domain.ID("dep_exec_001")
	relID := domain.ID("rel_exec_001")

	repo := &fakeExecutionTaskRepo{
		hasTask: true,
		claimed: appcontracts.Task{
			ID:              taskID,
			OperationID:     opID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			State:           appcontracts.TaskLeased,
		},
	}

	store := &fakeExecutionStore{
		binding: appcontracts.ImageExecutionBinding{
			TaskID:          taskID,
			OperationID:     opID,
			DeploymentID:    depID,
			ReleaseID:       relID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	client := &fakeContainerClient{
		result: appcontracts.CommitImageExecutionResultInput{
			TaskID:          taskID,
			OperationID:     opID,
			DeploymentID:    depID,
			ReleaseID:       relID,
			ContainerID:     "cid-12345",
			HostPort:        39898,
			ContainerPort:   9898,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	worker, err := NewImageExecutionWorker(ImageExecutionWorkerConfig{
		WorkerID: "worker-test",
		Store:    store,
		TaskRepo: repo,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewImageExecutionWorker: %v", err)
	}

	handled, err := worker.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce failed: %v", err)
	}
	if !handled {
		t.Fatal("expected task to be handled")
	}

	if !store.committedHit {
		t.Fatal("expected CommitImageExecutionResult to be called")
	}
	if store.committed.ContainerID != "cid-12345" || store.committed.HostPort != 39898 {
		t.Fatalf("unexpected committed input: %+v", store.committed)
	}
	if store.failedHit {
		t.Fatal("expected FailImageExecution NOT to be called")
	}
}

func TestImageExecutionWorker_ClientFailureCallsFail(t *testing.T) {
	taskID := domain.ID("tsk_exec_002")
	opID := domain.ID("op_exec_002")

	repo := &fakeExecutionTaskRepo{
		hasTask: true,
		claimed: appcontracts.Task{
			ID:              taskID,
			OperationID:     opID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	store := &fakeExecutionStore{
		binding: appcontracts.ImageExecutionBinding{
			TaskID:          taskID,
			OperationID:     opID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	client := &fakeContainerClient{
		err: errors.New("docker daemon unreachable"),
	}

	worker, err := NewImageExecutionWorker(ImageExecutionWorkerConfig{
		WorkerID: "worker-test",
		Store:    store,
		TaskRepo: repo,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewImageExecutionWorker: %v", err)
	}

	handled, err := worker.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce failed: %v", err)
	}
	if !handled {
		t.Fatal("expected task to be handled")
	}

	if store.committedHit {
		t.Fatal("expected CommitImageExecutionResult NOT to be called")
	}
	if !store.failedHit {
		t.Fatal("expected FailImageExecution to be called on client failure")
	}
}

func TestImageExecutionWorker_UnknownOutcomeReconcilesViaObserve(t *testing.T) {
	taskID := domain.ID("tsk_exec_unk1")
	opID := domain.ID("op_exec_unk1")
	depID := domain.ID("dep_exec_unk1")

	repo := &fakeExecutionTaskRepo{
		hasTask: true,
		claimed: appcontracts.Task{
			ID:              taskID,
			OperationID:     opID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	store := &fakeExecutionStore{
		binding: appcontracts.ImageExecutionBinding{
			TaskID:          taskID,
			OperationID:     opID,
			DeploymentID:    depID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
			Plan: appcontracts.ImagePlan{
				CanonicalInput: appcontracts.CanonicalExecutionInput{Port: 9898},
			},
		},
	}

	now := time.Now().UTC()
	client := &fakeContainerClient{
		err: fmt.Errorf("%w: response EOF after dispatch", appcontracts.ErrOutcomeUnknown),
		obsResult: appcontracts.ImageExecutionResult{
			Status:         "running",
			Running:        true,
			ContainerID:    "cid-reconciled",
			ContainerName:  "acornfox-runtime-c1",
			ImageID:        "sha256:5b85a3c2678f134440c9502b406b7d6fb8fa83842f1f513f5fb4ebcbe5e638b9",
			ManifestDigest: "sha256:72611294759dc6b304d1f3efa2d4b1de212ce422866244f31bc29f731e3b2079",
			Artifact: appcontracts.StorageArtifactReceipt{
				StorageRef:    "image/test",
				ContentDigest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
				SizeBytes:     1024,
			},
			HostPort:      39898,
			ContainerPort: 9898,
			ObservedAt:    now,
		},
	}

	worker, err := NewImageExecutionWorker(ImageExecutionWorkerConfig{
		WorkerID: "worker-test",
		Store:    store,
		TaskRepo: repo,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewImageExecutionWorker: %v", err)
	}

	handled, err := worker.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce failed: %v", err)
	}
	if !handled {
		t.Fatal("expected task to be handled")
	}

	if !store.committedHit {
		t.Fatal("expected CommitImageExecutionResult to be called on reconciled observe")
	}
	if store.committed.ContainerID != "cid-reconciled" || store.committed.HostPort != 39898 {
		t.Fatalf("unexpected committed input: %+v", store.committed)
	}
	if store.failedHit || store.unknownHit {
		t.Fatal("expected neither Fail nor RecordUnknown on successful observe reconcile")
	}
}

func TestImageExecutionWorker_UnknownOutcomeRecordsUnknown(t *testing.T) {
	taskID := domain.ID("tsk_exec_unk2")
	opID := domain.ID("op_exec_unk2")
	depID := domain.ID("dep_exec_unk2")

	repo := &fakeExecutionTaskRepo{
		hasTask: true,
		claimed: appcontracts.Task{
			ID:              taskID,
			OperationID:     opID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	store := &fakeExecutionStore{
		binding: appcontracts.ImageExecutionBinding{
			TaskID:          taskID,
			OperationID:     opID,
			DeploymentID:    depID,
			CoreGeneration:  1,
			LeaseGeneration: 1,
		},
	}

	client := &fakeContainerClient{
		err:    fmt.Errorf("%w: unexpected peer disconnect", appcontracts.ErrOutcomeUnknown),
		obsErr: errors.New("observe failed: docker daemon still unreachable"),
	}

	worker, err := NewImageExecutionWorker(ImageExecutionWorkerConfig{
		WorkerID: "worker-test",
		Store:    store,
		TaskRepo: repo,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewImageExecutionWorker: %v", err)
	}

	handled, err := worker.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce failed: %v", err)
	}
	if !handled {
		t.Fatal("expected task to be handled")
	}

	if store.committedHit {
		t.Fatal("expected CommitImageExecutionResult NOT to be called")
	}
	if store.failedHit {
		t.Fatal("expected FailImageExecution NOT to be called on unknown outcome")
	}
	if !store.unknownHit {
		t.Fatal("expected RecordImageExecutionUnknown to be called when observe cannot confirm")
	}
}
