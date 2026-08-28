package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m2AgentVolumeCommand translates one exact confirmed volume mutation into an
// allowlisted Agent task.  The server retains no Docker client or socket.
type m2AgentVolumeCommand struct {
	store interface {
		GetCompleteRelease(context.Context, domain.ID) (domain.Release, error)
		GetDefaultEnvironmentID(context.Context, domain.ID) (domain.ID, error)
		EnqueueControllerTask(context.Context, postgres.EnqueueControllerTaskRequest) (application.Event, error)
	}
	capabilities func() contracts.CapabilitySet
	now          func() time.Time
}

// Facts are intentionally asynchronous at the control-plane boundary.  A
// caller that explicitly asks for runtime volume facts receives unavailable
// rather than a persisted claim misrepresented as a live Docker observation.
func (c *m2AgentVolumeCommand) Facts(context.Context, M2VolumeDestroyCommand) (M2VolumeFacts, error) {
	return M2VolumeFacts{}, errors.New("runtime volume facts require an Agent observation task")
}

func (c *m2AgentVolumeCommand) Destroy(ctx context.Context, command M2VolumeDestroyCommand) error {
	if c == nil || c.store == nil || c.capabilities == nil || !c.capabilities().Has(contracts.CapabilityRuntimeDestroyGroup) {
		return errors.New("Agent volume destroy capability is unavailable")
	}
	release, err := c.store.GetCompleteRelease(ctx, command.ReleaseID)
	if err != nil {
		return err
	}
	environmentID, err := c.store.GetDefaultEnvironmentID(ctx, release.ApplicationID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if c.now != nil {
		now = c.now().UTC()
	}
	operation, err := domain.NewOperation(release.ApplicationID, environmentID, domain.OperationDestroy, "volume/"+command.Claim.ID.String(), command.IdempotencyKey, now)
	if err != nil {
		return err
	}
	operation.ID = m2ServerID("operation", command.IdempotencyKey, command.Claim.ID.String())
	providerRequest := struct {
		Volume             contracts.VolumeSpec       `json:"volume"`
		ConfirmationPhrase string                     `json:"confirmation_phrase"`
		Operation          contracts.OperationContext `json:"operation"`
	}{
		Volume:             contracts.VolumeSpec{Name: command.PhysicalName, MountPath: "/", SizeBytes: command.Claim.SizeBytes},
		ConfirmationPhrase: command.ConfirmationToken,
		Operation:          contracts.OperationContext{IdempotencyKey: command.IdempotencyKey, Actor: command.Actor, Deadline: command.Deadline},
	}
	parameters, err := json.Marshal(providerRequest)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(controllers.AgentTaskSpec{Kind: v1.TaskDestroyVolume, Parameters: parameters})
	if err != nil {
		return err
	}
	_, err = c.store.EnqueueControllerTask(ctx, postgres.EnqueueControllerTaskRequest{
		Operation: operation, TaskID: m2ServerID("task", command.IdempotencyKey, command.Claim.ID.String()), Payload: payload, MaxAttempts: 3, InitialPublishStatus: domain.PublishPreparing,
	})
	return err
}
