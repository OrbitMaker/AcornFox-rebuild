package standalone

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestRuntimeGatePausedPausingResumingRejectsRestartAndRecreate(t *testing.T) {
	phases := []string{"paused", "pausing", "resuming"}
	for _, phase := range phases {
		t.Run("phase_"+phase, func(t *testing.T) {
			runner := newLifecycleDockerRunner(testContainerID)
			ports := &fixedPorts{port: 39130}
			provider, _ := setupLifecycleTestDeployment(t, runner, ports)
			depID := domain.ID("dep_1234567890abcdef")
			now := time.Unix(200, 0).UTC()

			// Configure legal schema 3 state per phase
			provider.mu.Lock()
			st := provider.states[depID]
			st.phase = phase
			st.schemaVersion = "3"
			st.networkID = strings.Repeat("a", 64)
			runner.networkID = st.networkID

			switch phase {
			case "paused":
				st.deployment.Status = domain.DeploymentPaused
				st.actions = map[string]runtimeAction{}
				runner.running = false
			case "pausing":
				st.deployment.Status = domain.DeploymentRuntimeReady
				stopHash := actionIdentity("stop", "op-pausing-started")
				st.actions = map[string]runtimeAction{
					stopHash: {
						identityHash:        stopHash,
						action:              "stop",
						fingerprint:         st.fingerprint,
						status:              "started",
						previousContainerID: runner.containerID,
						at:                  now,
					},
				}
				runner.running = true
			case "resuming":
				st.deployment.Status = domain.DeploymentPaused
				startHash := actionIdentity("start", "op-resuming-started")
				st.actions = map[string]runtimeAction{
					startHash: {
						identityHash:        startHash,
						action:              "start",
						fingerprint:         st.fingerprint,
						status:              "started",
						previousContainerID: runner.containerID,
						at:                  now,
					},
				}
				runner.running = false
			}

			if err := provider.persistState(st); err != nil {
				provider.mu.Unlock()
				t.Fatalf("persist %s state: %v", phase, err)
			}
			provider.mu.Unlock()

			filePath := provider.durableStatePath(depID)
			bytesBefore, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatal(err)
			}

			runner.mu.Lock()
			callsBefore := len(runner.calls)
			runner.mu.Unlock()

			// 1. Fresh Restart must return ErrConflict
			err = provider.Restart(context.Background(), contracts.RestartRequest{
				DeploymentID: depID,
				ServiceName:  "web",
				Operation:    contracts.OperationContext{IdempotencyKey: "restart-fresh-key"},
			})
			if err == nil || !isProviderCode(err, contracts.ErrConflict) {
				t.Fatalf("expected ErrConflict for Restart in phase %s, got: %v", phase, err)
			}

			// 2. Fresh Recreate must return ErrConflict
			recreateReq := testRequest("recreate-fresh-key")
			recreateReq.DeploymentID = depID
			_, err = provider.Recreate(context.Background(), recreateReq)
			if err == nil || !isProviderCode(err, contracts.ErrConflict) {
				t.Fatalf("expected ErrConflict for Recreate in phase %s, got: %v", phase, err)
			}

			// 3. Durable state bytes must remain 100% untouched
			bytesAfter, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytesBefore, bytesAfter) {
				t.Fatalf("durable state file mutated during rejected calls in phase %s", phase)
			}

			// 4. Zero Docker write mutations
			runner.mu.Lock()
			recentCalls := append([][]string(nil), runner.calls[callsBefore:]...)
			runner.mu.Unlock()
			for _, call := range recentCalls {
				if len(call) > 0 {
					switch call[0] {
					case "run", "restart", "start", "stop", "rm":
						t.Fatalf("unexpected docker mutation executed in phase %s: %v", phase, call)
					}
				}
			}
		})
	}
}

func TestRuntimeGateCompletedRestartThenStopThenReplayDoesNotUnpause(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	restartKey := "restart-key-1"
	if err := provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: restartKey},
	}); err != nil {
		t.Fatalf("initial restart failed: %v", err)
	}

	// Stop container -> paused
	stopKey := "stop-key-1"
	if err := provider.Stop(context.Background(), contracts.StopRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: stopKey},
	}); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	durablePaused, _, err := provider.readDurableState(depID)
	if err != nil || durablePaused.Phase != "paused" {
		t.Fatalf("expected durable phase paused, got: %v (err=%v)", durablePaused.Phase, err)
	}

	// Replay old completed restart key
	callsBefore := len(runner.callsFor("restart"))
	err = provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: restartKey},
	})
	if err != nil {
		t.Fatalf("completed restart replay should return nil, got: %v", err)
	}

	// Must NOT execute docker restart
	if len(runner.callsFor("restart")) != callsBefore {
		t.Fatal("replaying old restart key executed docker restart on paused container!")
	}

	// State must still be paused!
	durableAfter, _, err := provider.readDurableState(depID)
	if err != nil || durableAfter.Phase != "paused" {
		t.Fatalf("replaying old restart key changed state from paused to %s", durableAfter.Phase)
	}
}

func TestRuntimeGateCompletedRecreateThenStopThenReplayDoesNotUnpause(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	recreateKey := "recreate-key-1"
	req := testRequest(recreateKey)
	req.DeploymentID = depID
	recreateHash := actionIdentity("recreate", recreateKey)
	now := time.Unix(300, 0).UTC()

	// Initial active container has completed recreate
	provider.mu.Lock()
	st := provider.states[depID]
	st.actions[recreateHash] = runtimeAction{
		identityHash: recreateHash,
		action:       "recreate",
		fingerprint:  st.fingerprint,
		status:       "succeeded",
		at:           now,
	}
	_ = provider.persistState(st)
	provider.mu.Unlock()

	// Stop container -> paused
	stopKey := "stop-key-1"
	if err := provider.Stop(context.Background(), contracts.StopRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: stopKey},
	}); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	durablePaused, _, err := provider.readDurableState(depID)
	if err != nil || durablePaused.Phase != "paused" {
		t.Fatalf("expected durable phase paused, got: %v (err=%v)", durablePaused.Phase, err)
	}

	// Replay old completed recreate key on paused container
	runner.mu.Lock()
	callsBefore := len(runner.calls)
	runner.mu.Unlock()

	replayDep, err := provider.Recreate(context.Background(), req)
	if err != nil {
		t.Fatalf("completed recreate replay should return nil error, got: %v", err)
	}
	if replayDep.ID != depID {
		t.Fatalf("expected replayed deployment ID %s, got %s", depID, replayDep.ID)
	}

	// Container must still be stopped/paused!
	if runner.running {
		t.Fatal("replaying completed recreate revived or unpaused the container!")
	}

	// Zero new Docker write calls during replay
	runner.mu.Lock()
	recentCalls := append([][]string(nil), runner.calls[callsBefore:]...)
	runner.mu.Unlock()
	for _, call := range recentCalls {
		if len(call) > 0 {
			switch call[0] {
			case "run", "restart", "start", "stop", "rm":
				t.Fatalf("unexpected docker mutation executed during recreate replay: %v", call)
			}
		}
	}

	durableAfter, _, err := provider.readDurableState(depID)
	if err != nil || durableAfter.Phase != "paused" {
		t.Fatalf("replaying old recreate key changed state from paused to %s", durableAfter.Phase)
	}
}

func TestRuntimeGateActiveStartedMutexAndRecovery(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	keyA := "restart-key-A"
	hashA := actionIdentity("restart", keyA)
	now := time.Unix(400, 0).UTC()

	provider.mu.Lock()
	st := provider.states[depID]
	st.actions[hashA] = runtimeAction{
		identityHash:        hashA,
		action:              "restart",
		fingerprint:         st.fingerprint,
		status:              "started",
		previousContainerID: runner.containerID,
		previousStartedAt:   "2026-09-21T00:00:00Z",
		at:                  now,
	}
	_ = provider.persistState(st)
	provider.mu.Unlock()

	// 1. Another key B must be rejected while key A is started
	keyB := "restart-key-B"
	err := provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: keyB},
	})
	if err == nil || !isProviderCode(err, contracts.ErrConflict) {
		t.Fatalf("expected conflict for different key while mutation started, got: %v", err)
	}

	// 2. Same key A when container has updated StartedAt should recover to succeeded
	runner.containerStartedAt = "2026-09-21T00:01:00Z"
	err = provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: keyA},
	})
	if err != nil {
		t.Fatalf("expected key A to recover, got: %v", err)
	}

	durable, _, err := provider.readDurableState(depID)
	if err != nil {
		t.Fatal(err)
	}
	var recoveredAction *durableRuntimeAction
	for i := range durable.Actions {
		if durable.Actions[i].IdentityHash == hashA {
			recoveredAction = &durable.Actions[i]
			break
		}
	}
	if recoveredAction == nil || recoveredAction.Status != "succeeded" {
		t.Fatalf("expected action to be succeeded after recovery, got: %+v", recoveredAction)
	}
}

func TestRuntimeGateRestartRejectsIDMismatchOrMissingID(t *testing.T) {
	runner := newLifecycleDockerRunner(testContainerID)
	ports := &fixedPorts{port: 39130}
	provider, _ := setupLifecycleTestDeployment(t, runner, ports)
	depID := domain.ID("dep_1234567890abcdef")

	// Missing containerID
	provider.mu.Lock()
	st := provider.states[depID]
	savedID := st.containerID
	st.containerID = ""
	_ = provider.persistState(st)
	provider.mu.Unlock()

	err := provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: "restart-missing-id"},
	})
	if err == nil || !isProviderCode(err, contracts.ErrConflict) {
		t.Fatalf("expected ErrConflict for missing containerID, got: %v", err)
	}

	// Restore and test drifted container ID
	provider.mu.Lock()
	st.containerID = savedID
	_ = provider.persistState(st)
	provider.mu.Unlock()

	runner.driftID = true
	err = provider.Restart(context.Background(), contracts.RestartRequest{
		DeploymentID: depID,
		ServiceName:  "web",
		Operation:    contracts.OperationContext{IdempotencyKey: "restart-mismatched-id"},
	})
	if err == nil || !isProviderCode(err, contracts.ErrConflict) {
		t.Fatalf("expected ErrConflict for mismatched containerID, got: %v", err)
	}
}
