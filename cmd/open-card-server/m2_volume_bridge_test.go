package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m2VolumeBridgeStore struct {
	release domain.Release
	env     domain.ID
	queued  *postgres.EnqueueControllerTaskRequest
}

func (s *m2VolumeBridgeStore) GetCompleteRelease(context.Context, domain.ID) (domain.Release, error) {
	return s.release, nil
}
func (s *m2VolumeBridgeStore) GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error) {
	return s.env, nil
}
func (s *m2VolumeBridgeStore) EnqueueControllerTask(_ context.Context, request postgres.EnqueueControllerTaskRequest) (application.Event, error) {
	s.queued = &request
	return application.Event{}, nil
}

func TestM2VolumeBridgeQueuesAllowlistedAgentTaskWithoutRedactingConfirmationPhrase(t *testing.T) {
	store := &m2VolumeBridgeStore{release: domain.Release{ID: "release_volume", ApplicationID: "app_volume"}, env: "env_volume"}
	bridge := &m2AgentVolumeCommand{store: store, capabilities: func() contracts.CapabilitySet {
		return contracts.NewCapabilitySet(contracts.CapabilityRuntimeDestroyGroup)
	}, now: func() time.Time { return time.Unix(100, 0).UTC() }}
	command := M2VolumeDestroyCommand{ReleaseID: "release_volume", Claim: postgres.M2ServiceGroupVolumeClaim{ID: "claim_volume", Name: "data", SizeBytes: 4096, Retain: true}, PhysicalName: "opencard-task-volume-data", ConfirmationToken: "confirm-volume-destroy:opencard-task-volume-data", IdempotencyKey: "destroy-volume-bridge", Actor: "test", Deadline: time.Unix(200, 0).UTC()}
	if err := bridge.Destroy(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if store.queued == nil {
		t.Fatal("volume command did not enqueue an Agent task")
	}
	redacted, err := foundation.RedactJSON(store.queued.Payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	var task controllers.AgentTaskSpec
	if err := json.Unmarshal(redacted, &task); err != nil || task.Kind != v1.TaskDestroyVolume {
		t.Fatalf("queued task invalid: %#v err=%v", task, err)
	}
	var parameters struct {
		ConfirmationPhrase string `json:"confirmation_phrase"`
	}
	if err := json.Unmarshal(task.Parameters, &parameters); err != nil || parameters.ConfirmationPhrase != command.ConfirmationToken {
		t.Fatalf("non-secret confirmation phrase did not survive durable redaction: %#v err=%v", parameters, err)
	}
}
