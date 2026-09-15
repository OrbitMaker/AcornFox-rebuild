package application

import (
	"context"
	"fmt"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxRuntimeService adapts one immutable single-service fact onto the
// existing RuntimeDriver. It owns no containers and deliberately keeps all
// Docker behavior in the standalone provider.
type AcornFoxRuntimeService struct {
	driver acornFoxLegacyRuntimeDriver
}

var _ contracts.AcornFoxRuntimeDriver = (*AcornFoxRuntimeService)(nil)

type acornFoxLegacyRuntimeDriver interface {
	Deploy(context.Context, contracts.DeployRequest) (domain.Deployment, error)
	Recreate(context.Context, contracts.DeployRequest) (domain.Deployment, error)
	Observe(context.Context, contracts.ObserveRequest) (contracts.RuntimeObservation, error)
	Restart(context.Context, contracts.RestartRequest) error
	Destroy(context.Context, contracts.DestroyRequest) error
}

func NewAcornFoxRuntimeService(driver acornFoxLegacyRuntimeDriver) (*AcornFoxRuntimeService, error) {
	if driver == nil {
		return nil, fmt.Errorf("runtime driver is unavailable")
	}
	return &AcornFoxRuntimeService{driver: driver}, nil
}

func (service *AcornFoxRuntimeService) Deploy(ctx context.Context, request contracts.AcornFoxRuntimeDeployRequest) (contracts.AcornFoxRuntimeDeployment, error) {
	if service == nil || service.driver == nil {
		return contracts.AcornFoxRuntimeDeployment{}, fmt.Errorf("runtime service is unavailable")
	}
	if err := request.Validate(); err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	materialize := service.driver.Deploy
	action := "deploy"
	if request.Recreate {
		materialize = service.driver.Recreate
		action = "redeploy"
	}
	return service.materialize(ctx, request.Fact, action, request.IdempotencyKey, materialize)
}

func (service *AcornFoxRuntimeService) materialize(ctx context.Context, fact contracts.AcornFoxRuntimeReleaseFact, action, callerKey string, materialize func(context.Context, contracts.DeployRequest) (domain.Deployment, error)) (contracts.AcornFoxRuntimeDeployment, error) {
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	operation, err := service.operation(fact, action, callerKey)
	if err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	deployment, err := materialize(ctx, contracts.DeployRequest{DeploymentID: deploymentID, Spec: contracts.RuntimeSpec{Configuration: fact.Configuration, ConfigDigest: fact.ConfigDigest, ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: fact.ReleaseID, ServiceName: fact.ServiceName, Image: fact.Image, Resources: legacyAcornFoxRuntimeResources(fact.Resources), Port: fact.ContainerPort}, Operation: operation})
	if err != nil {
		return contracts.AcornFoxRuntimeDeployment{}, err
	}
	if deployment.ID != deploymentID || deployment.ApplicationID != fact.ApplicationID || deployment.EnvironmentID != fact.EnvironmentID || deployment.ReleaseID != fact.ReleaseID || deployment.Status != domain.DeploymentRuntimeReady {
		return contracts.AcornFoxRuntimeDeployment{}, fmt.Errorf("runtime result is invalid")
	}
	return contracts.AcornFoxRuntimeDeployment{DeploymentID: deployment.ID, ApplicationID: deployment.ApplicationID, EnvironmentID: deployment.EnvironmentID, ReleaseID: deployment.ReleaseID, ServiceName: fact.ServiceName, Image: fact.Image, RuntimeState: string(deployment.Status), OperationID: operation.IdempotencyKey, RequestedResources: fact.Resources}, nil
}

func legacyAcornFoxRuntimeResources(resources contracts.AcornFoxRuntimeRequestedResources) contracts.ResourceLimits {
	return contracts.ResourceLimits{CPUMillis: resources.CPUMillis, MemoryBytes: resources.MemoryBytes, DiskBytes: resources.DiskReservationBytes, PIDs: resources.PIDs}
}

func (service *AcornFoxRuntimeService) Observe(ctx context.Context, reference contracts.AcornFoxRuntimeReference) (contracts.AcornFoxRuntimeObservation, error) {
	if service == nil || service.driver == nil {
		return contracts.AcornFoxRuntimeObservation{}, fmt.Errorf("runtime service is unavailable")
	}
	fact := reference.Fact
	if err := fact.Validate(); err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	operation, err := service.operation(fact, "read", "read")
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	observed, err := service.driver.Observe(ctx, contracts.ObserveRequest{DeploymentID: deploymentID, Operation: operation})
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	requested := legacyAcornFoxRuntimeResources(fact.Resources)
	if observed.DeploymentID != deploymentID || observed.ServiceName != fact.ServiceName || !observed.CgroupVerified || observed.Limits.CPUMillis != requested.CPUMillis || observed.Limits.MemoryBytes != requested.MemoryBytes || observed.Limits.PIDs != requested.PIDs {
		return contracts.AcornFoxRuntimeObservation{}, fmt.Errorf("runtime observation is invalid")
	}
	internalAddress := ""
	if fact.ContainerPort == 0 {
		if observed.HostPort != 0 {
			return contracts.AcornFoxRuntimeObservation{}, fmt.Errorf("runtime observation is invalid")
		}
	} else {
		internalAddress, err = contracts.AcornFoxRuntimeLoopbackAddress(observed.HostPort)
		if err != nil {
			return contracts.AcornFoxRuntimeObservation{}, fmt.Errorf("runtime observation is invalid")
		}
	}
	return contracts.AcornFoxRuntimeObservation{DeploymentID: observed.DeploymentID, ServiceName: observed.ServiceName, ContainerID: observed.ContainerID, RuntimeState: observed.Status, RestartCount: observed.RestartCount, InternalAddress: internalAddress, RequestedResources: fact.Resources, AppliedLimits: contracts.AcornFoxRuntimeAppliedLimits{CPUMillis: observed.Limits.CPUMillis, MemoryBytes: observed.Limits.MemoryBytes, PIDs: observed.Limits.PIDs}, Disk: contracts.AcornFoxRuntimeDiskFact{ReservationBytes: fact.Resources.DiskReservationBytes, AccountingReconciled: false, PerContainerEnforced: false}, ObservedAt: observed.ObservedAt.UTC()}, nil
}

func (service *AcornFoxRuntimeService) Restart(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil || service.driver == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	if err := request.Validate(); err != nil {
		return err
	}
	fact := request.Fact
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return err
	}
	operation, err := service.operation(fact, "restart", request.IdempotencyKey)
	if err != nil {
		return err
	}
	return service.driver.Restart(ctx, contracts.RestartRequest{DeploymentID: deploymentID, ServiceName: fact.ServiceName, Operation: operation})
}

func (service *AcornFoxRuntimeService) Destroy(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil || service.driver == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	if err := request.Validate(); err != nil {
		return err
	}
	fact := request.Fact
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(fact)
	if err != nil {
		return err
	}
	operation, err := service.operation(fact, "destroy", request.IdempotencyKey)
	if err != nil {
		return err
	}
	return service.driver.Destroy(ctx, contracts.DestroyRequest{DeploymentID: deploymentID, Operation: operation})
}

func (service *AcornFoxRuntimeService) operation(fact contracts.AcornFoxRuntimeReleaseFact, action, callerKey string) (contracts.OperationContext, error) {
	idempotencyKey, err := contracts.AcornFoxRuntimeOperationID(fact, action, callerKey)
	if err != nil {
		return contracts.OperationContext{}, err
	}
	return contracts.OperationContext{IdempotencyKey: idempotencyKey, Actor: "acornfox"}, nil
}
