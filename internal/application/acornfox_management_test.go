package application

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

type fakeManagementStore struct {
	mu              sync.Mutex
	commands        map[domain.ID]AcornFoxManagementResult
	commandsByKey   map[string]domain.ID
	digests         map[domain.ID]string
	targets         map[domain.ID]*AcornFoxManagementTarget
	leases          map[domain.ID]*AcornFoxManagementCommandLease
	pauseReceipts   map[string]AcornFoxPauseReceipt
	retainedVolumes map[domain.ID][]contracts.AcornFoxRetainedVolumeReceipt
	evidence        map[string]struct{}
	taskStates      map[domain.ID]string
	taskEvents      map[domain.ID]json.RawMessage
	now             time.Time
}

func newFakeManagementStore() *fakeManagementStore {
	return &fakeManagementStore{
		commands:        map[domain.ID]AcornFoxManagementResult{},
		commandsByKey:   map[string]domain.ID{},
		digests:         map[domain.ID]string{},
		targets:         map[domain.ID]*AcornFoxManagementTarget{},
		leases:          map[domain.ID]*AcornFoxManagementCommandLease{},
		pauseReceipts:   map[string]AcornFoxPauseReceipt{},
		retainedVolumes: map[domain.ID][]contracts.AcornFoxRetainedVolumeReceipt{},
		evidence:        map[string]struct{}{},
		taskStates:      map[domain.ID]string{},
		taskEvents:      map[domain.ID]json.RawMessage{},
		now:             time.Unix(1000, 0).UTC(),
	}
}

func (f *fakeManagementStore) BeginManagementCommand(_ context.Context, req AcornFoxManagementRequest, digest string, now time.Time) (AcornFoxManagementResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	mapKey := req.ApplicationID.String() + ":" + req.IdempotencyKey
	if existingID, ok := f.commandsByKey[mapKey]; ok {
		cmd := f.commands[existingID]
		storedDigest := f.digests[existingID]
		if digest != storedDigest {
			return AcornFoxManagementResult{}, false, ErrManagementCommandConflict
		}
		return cmd, true, nil
	}

	cmdID := domain.ID("cmd_" + req.IdempotencyKey)
	var targets []AcornFoxManagementTarget
	if !req.DeploymentID.Empty() {
		tgtID := domain.ID("tgt_" + req.DeploymentID.String())
		target := AcornFoxManagementTarget{
			ID:                    tgtID,
			CommandID:             cmdID,
			DeploymentID:          req.DeploymentID,
			Revision:              1,
			RoutePhase:            "initial",
			OriginalDesiredPublic: true,
			Status:                "pending",
			CreatedAt:             now,
			UpdatedAt:             now,
		}
		targets = append(targets, target)
		f.targets[tgtID] = &target
	}

	res := AcornFoxManagementResult{
		CommandID:     cmdID,
		ApplicationID: req.ApplicationID,
		Action:        req.Action,
		Phase:         "accepted",
		Targets:       targets,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	f.commands[cmdID] = res
	f.commandsByKey[mapKey] = cmdID
	f.digests[cmdID] = digest
	f.leases[cmdID] = &AcornFoxManagementCommandLease{
		CommandID:     cmdID,
		ApplicationID: req.ApplicationID,
		Action:        req.Action,
		Phase:         "accepted",
		PhaseVersion:  1,
		Targets:       targets,
	}
	return res, false, nil
}

func (f *fakeManagementStore) ClaimManagementCommandLeases(_ context.Context, owner string, lease time.Duration, _ int, now time.Time) ([]AcornFoxManagementCommandLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AcornFoxManagementCommandLease
	for id, l := range f.leases {
		if l.Phase == "completed" || l.Phase == "failed" {
			continue
		}
		token := "tok_" + id.String()
		expires := now.Add(lease)
		l.Owner = owner
		l.Token = token
		l.ExpiresAt = expires
		out = append(out, *l)
	}
	return out, nil
}

func (f *fakeManagementStore) GetManagementCommand(_ context.Context, _, commandID domain.ID) (AcornFoxManagementResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	res, ok := f.commands[commandID]
	if !ok {
		return AcornFoxManagementResult{}, domain.NewError(domain.ErrNotFound, "command not found")
	}
	return res, nil
}

func (f *fakeManagementStore) UpdateManagementCommandPhase(_ context.Context, lease AcornFoxManagementCommandLease, expectedPhase, newPhase, failureReason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.leases[lease.CommandID]
	if !ok || l.Token != lease.Token || l.Owner != lease.Owner || l.PhaseVersion != lease.PhaseVersion || l.Phase != expectedPhase {
		return ErrManagementLeaseLost
	}
	l.Phase = newPhase
	l.PhaseVersion++
	if newPhase == "completed" || newPhase == "failed" {
		l.Owner = ""
		l.Token = ""
	}
	cmd := f.commands[lease.CommandID]
	cmd.Phase = newPhase
	cmd.FailureReason = failureReason
	f.commands[lease.CommandID] = cmd
	return nil
}

func (f *fakeManagementStore) UpdateManagementTarget(_ context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, expectedRevision int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.targets[target.ID]
	if !ok || t.Revision != expectedRevision {
		return ErrManagementTargetConflict
	}
	target.Revision = expectedRevision + 1
	*t = target
	return nil
}

func (f *fakeManagementStore) EnqueueTargetTask(_ context.Context, lease AcornFoxManagementCommandLease, target AcornFoxManagementTarget, task AcornFoxQueuedTask) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.targets[target.ID]
	if !ok || t.Revision != target.Revision {
		return ErrManagementTargetConflict
	}
	t.RuntimeTaskID = task.TaskID
	t.Status = "running"
	t.Revision++
	f.taskStates[task.TaskID] = "running"
	return nil
}

func (f *fakeManagementStore) GetValidatedManagementDestroyEvidence(_ context.Context, _ AcornFoxManagementCommandLease, target AcornFoxManagementTarget) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.taskStates[target.RuntimeTaskID] != "completed" {
		return nil, errors.New("task not completed")
	}
	evt, ok := f.taskEvents[target.RuntimeTaskID]
	if !ok {
		return nil, errors.New("destroy observation event missing")
	}
	var obs struct {
		TargetRef string `json:"target_ref"`
		Status    string `json:"status"`
		Details   struct {
			RetainedVolumes []contracts.AcornFoxRetainedVolumeReceipt `json:"retained_volumes"`
		} `json:"details"`
	}
	if err := json.Unmarshal(evt, &obs); err != nil || obs.Status != "stopped" {
		return nil, errors.New("invalid observation")
	}
	return obs.Details.RetainedVolumes, nil
}

func (f *fakeManagementStore) GetTaskState(_ context.Context, taskID domain.ID) (string, string, json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.taskStates[taskID]
	if !ok {
		return "", "", nil, domain.NewError(domain.ErrNotFound, "task not found")
	}
	return st, "", f.taskEvents[taskID], nil
}

func (f *fakeManagementStore) SavePauseReceipt(_ context.Context, _ AcornFoxManagementCommandLease, _ AcornFoxManagementTarget, receipt AcornFoxPauseReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pauseReceipts[receipt.DeploymentID.String()] = receipt
	return nil
}

func (f *fakeManagementStore) GetPauseReceipt(_ context.Context, _, deploymentID domain.ID) (AcornFoxPauseReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.pauseReceipts[deploymentID.String()]
	return r, ok, nil
}

func (f *fakeManagementStore) ConsumePauseReceipt(_ context.Context, _ AcornFoxManagementCommandLease, target AcornFoxManagementTarget, expectedEpoch int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.pauseReceipts[target.DeploymentID.String()]
	if !ok || r.Consumed || r.PauseEpoch != expectedEpoch {
		return errors.New("pause receipt conflict")
	}
	r.Consumed = true
	f.pauseReceipts[target.DeploymentID.String()] = r
	return nil
}

func (f *fakeManagementStore) FinalizeArchive(_ context.Context, lease AcornFoxManagementCommandLease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.leases[lease.CommandID]
	if !ok || l.Token != lease.Token {
		return ErrManagementLeaseLost
	}
	l.Phase = "completed"
	cmd := f.commands[lease.CommandID]
	cmd.Phase = "completed"
	f.commands[lease.CommandID] = cmd
	return nil
}

func (f *fakeManagementStore) GetRetainedVolumes(_ context.Context, appID domain.ID) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retainedVolumes[appID], nil
}

func TestManagementP2StopStartRequiresExplicitDeploymentID(t *testing.T) {
	store := newFakeManagementStore()
	svc := &AcornFoxManagementService{Store: store}

	// 1. Stop without DeploymentID rejected
	_, err := svc.Stop(context.Background(), AcornFoxManagementRequest{
		ApplicationID:  "app_1",
		DeploymentID:   "",
		IdempotencyKey: "key-1",
		Actor:          "admin",
	})
	if err == nil {
		t.Fatal("expected error for Stop without DeploymentID")
	}

	// 2. Start without DeploymentID rejected
	_, err = svc.Start(context.Background(), AcornFoxManagementRequest{
		ApplicationID:  "app_1",
		DeploymentID:   "",
		IdempotencyKey: "key-2",
		Actor:          "admin",
	})
	if err == nil {
		t.Fatal("expected error for Start without DeploymentID")
	}

	// 3. Archive with DeploymentID rejected
	_, err = svc.Archive(context.Background(), AcornFoxManagementRequest{
		ApplicationID:  "app_1",
		DeploymentID:   "dep_should_be_empty",
		IdempotencyKey: "key-3",
		Actor:          "admin",
	})
	if err == nil {
		t.Fatal("expected error for Archive with DeploymentID")
	}

	// 4. Same key with different deployment must conflict
	_, err = svc.Stop(context.Background(), AcornFoxManagementRequest{
		ApplicationID:  "app_1",
		DeploymentID:   "dep_1",
		IdempotencyKey: "key-conflict-test",
		Actor:          "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Stop(context.Background(), AcornFoxManagementRequest{
		ApplicationID:  "app_1",
		DeploymentID:   "dep_2", // changed deployment with same key
		IdempotencyKey: "key-conflict-test",
		Actor:          "admin",
	})
	if err == nil || !errors.Is(err, ErrManagementCommandConflict) {
		t.Fatalf("expected conflict for same key with different deployment, got: %v", err)
	}
}

func TestTargetSetDigestStability(t *testing.T) {
	targetsA := []string{"dep_2:rel_2:cfg_b:1", "dep_1:rel_1:cfg_a:1"}
	targetsB := []string{"dep_1:rel_1:cfg_a:1", "dep_2:rel_2:cfg_b:1"}
	digestA := TargetSetDigest(targetsA)
	digestB := TargetSetDigest(targetsB)
	if digestA != digestB {
		t.Fatalf("target set digest must be order-independent: %s != %s", digestA, digestB)
	}
}
