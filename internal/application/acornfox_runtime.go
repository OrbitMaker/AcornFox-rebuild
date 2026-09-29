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

type acornFoxLifecycleRuntimeService struct {
	*AcornFoxRuntimeService
	lifecycle acornFoxLifecycleDriver
}

type acornFoxRetainedRuntimeService struct {
	*AcornFoxRuntimeService
	retained acornFoxRetainedVolumeDriver
}

type acornFoxLifecycleAndRetainedRuntimeService struct {
	*AcornFoxRuntimeService
	lifecycle acornFoxLifecycleDriver
	retained  acornFoxRetainedVolumeDriver
}

var (
	_ contracts.AcornFoxRuntimeDriver          = (*acornFoxLifecycleRuntimeService)(nil)
	_ contracts.AcornFoxLifecycleDriver        = (*acornFoxLifecycleRuntimeService)(nil)
	_ contracts.AcornFoxRuntimeDriver          = (*acornFoxRetainedRuntimeService)(nil)
	_ contracts.AcornFoxRetainedVolumeObserver = (*acornFoxRetainedRuntimeService)(nil)
	_ contracts.AcornFoxRuntimeDriver          = (*acornFoxLifecycleAndRetainedRuntimeService)(nil)
	_ contracts.AcornFoxLifecycleDriver        = (*acornFoxLifecycleAndRetainedRuntimeService)(nil)
	_ contracts.AcornFoxRetainedVolumeObserver = (*acornFoxLifecycleAndRetainedRuntimeService)(nil)
)

type acornFoxLegacyRuntimeDriver interface {
	Deploy(context.Context, contracts.DeployRequest) (domain.Deployment, error)
	Recreate(context.Context, contracts.DeployRequest) (domain.Deployment, error)
	Observe(context.Context, contracts.ObserveRequest) (contracts.RuntimeObservation, error)
	Restart(context.Context, contracts.RestartRequest) error
	Destroy(context.Context, contracts.DestroyRequest) error
}

type acornFoxLifecycleDriver interface {
	Stop(context.Context, contracts.StopRequest) error
	Start(context.Context, contracts.StartRequest) error
}

type acornFoxRetainedVolumeDriver interface {
	ObserveRetainedVolumes(context.Context, contracts.RuntimeSpec) ([]contracts.AcornFoxRetainedVolumeReceipt, error)
	RetainedVolumeObservationSupported() bool
}

func NewAcornFoxRuntimeService(driver acornFoxLegacyRuntimeDriver) (contracts.AcornFoxRuntimeDriver, error) {
	if driver == nil {
		return nil, fmt.Errorf("runtime driver is unavailable")
	}
	base := &AcornFoxRuntimeService{driver: driver}
	lifecycle, hasLifecycle := driver.(acornFoxLifecycleDriver)
	retained, hasRetainedRaw := driver.(acornFoxRetainedVolumeDriver)
	hasRetained := hasRetainedRaw && retained.RetainedVolumeObservationSupported()
	if hasLifecycle && hasRetained {
		return &acornFoxLifecycleAndRetainedRuntimeService{
			AcornFoxRuntimeService: base,
			lifecycle:              lifecycle,
			retained:               retained,
		}, nil
	}
	if hasLifecycle {
		return &acornFoxLifecycleRuntimeService{
			AcornFoxRuntimeService: base,
			lifecycle:              lifecycle,
		}, nil
	}
	if hasRetained {
		return &acornFoxRetainedRuntimeService{
			AcornFoxRuntimeService: base,
			retained:               retained,
		}, nil
	}
	return base, nil
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

func (service *acornFoxLifecycleRuntimeService) Stop(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	return stopLifecycle(service.AcornFoxRuntimeService, service.lifecycle, ctx, request)
}

func (service *acornFoxLifecycleRuntimeService) Start(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	return startLifecycle(service.AcornFoxRuntimeService, service.lifecycle, ctx, request)
}

func (service *acornFoxRetainedRuntimeService) ObserveRetainedVolumes(ctx context.Context, fact contracts.AcornFoxRuntimeReleaseFact) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	if service == nil {
		return nil, fmt.Errorf("runtime service is unavailable")
	}
	return observeRetained(service.retained, ctx, fact)
}

func (service *acornFoxLifecycleAndRetainedRuntimeService) Stop(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	return stopLifecycle(service.AcornFoxRuntimeService, service.lifecycle, ctx, request)
}

func (service *acornFoxLifecycleAndRetainedRuntimeService) Start(ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if service == nil {
		return fmt.Errorf("runtime service is unavailable")
	}
	return startLifecycle(service.AcornFoxRuntimeService, service.lifecycle, ctx, request)
}

func (service *acornFoxLifecycleAndRetainedRuntimeService) ObserveRetainedVolumes(ctx context.Context, fact contracts.AcornFoxRuntimeReleaseFact) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	if service == nil {
		return nil, fmt.Errorf("runtime service is unavailable")
	}
	return observeRetained(service.retained, ctx, fact)
}

func stopLifecycle(base *AcornFoxRuntimeService, lifecycle acornFoxLifecycleDriver, ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if base == nil || lifecycle == nil {
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
	operation, err := base.operation(fact, "stop", request.IdempotencyKey)
	if err != nil {
		return err
	}
	return lifecycle.Stop(ctx, contracts.StopRequest{DeploymentID: deploymentID, ServiceName: fact.ServiceName, Operation: operation})
}

func startLifecycle(base *AcornFoxRuntimeService, lifecycle acornFoxLifecycleDriver, ctx context.Context, request contracts.AcornFoxRuntimeActionRequest) error {
	if base == nil || lifecycle == nil {
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
	operation, err := base.operation(fact, "start", request.IdempotencyKey)
	if err != nil {
		return err
	}
	return lifecycle.Start(ctx, contracts.StartRequest{DeploymentID: deploymentID, ServiceName: fact.ServiceName, Operation: operation})
}

func observeRetained(retained acornFoxRetainedVolumeDriver, ctx context.Context, fact contracts.AcornFoxRuntimeReleaseFact) ([]contracts.AcornFoxRetainedVolumeReceipt, error) {
	if retained == nil {
		return nil, fmt.Errorf("retained volume observer is unavailable")
	}
	if fact.Configuration == nil || len(fact.Configuration.Volumes) == 0 {
		return nil, nil
	}
	spec := contracts.RuntimeSpec{
		ApplicationID: fact.ApplicationID,
		EnvironmentID: fact.EnvironmentID,
		ReleaseID:     fact.ReleaseID,
		ServiceName:   fact.ServiceName,
		Image:         fact.Image,
		Port:          fact.ContainerPort,
		Configuration: fact.Configuration,
		ConfigDigest:  fact.ConfigDigest,
	}
	return retained.ObserveRetainedVolumes(ctx, spec)
}

func (service *AcornFoxRuntimeService) operation(fact contracts.AcornFoxRuntimeReleaseFact, action, callerKey string) (contracts.OperationContext, error) {
	idempotencyKey, err := contracts.AcornFoxRuntimeOperationID(fact, action, callerKey)
	if err != nil {
		return contracts.OperationContext{}, err
	}
	return contracts.OperationContext{IdempotencyKey: idempotencyKey, Actor: "acornfox"}, nil
}
