package install

import (
	"context"
	"time"
)

const (
	productionServerHealthURL      = "http://127.0.0.1:8080/healthz"
	productionServerReadyURL       = "http://127.0.0.1:8080/readyz"
	productionEdgeHealthURL        = "http://127.0.0.1:18482/healthz"
	productionRestoredEdgeReadyURL = "http://127.0.0.1:2020/config/"
	productionHealthTimeout        = 30 * time.Second
	productionHealthInterval       = 250 * time.Millisecond
)

var restoreInternalStartOrder = []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent}

// UpgradeServiceProbeConfig contains the only health targets an upgrade
// adapter may use. ServiceController enforces their loopback endpoint policy.
type UpgradeServiceProbeConfig struct {
	ServerHealth      string
	ServerReady       string
	EdgeHealth        string
	RestoredEdgeReady string
}

// UpgradeServiceAdapter maps the fixed service-controller boundary into the
// engine's typed service driver.
type UpgradeServiceAdapter struct {
	controller       *ServiceController
	probes           UpgradeServiceProbeConfig
	restoredInternal ServiceSnapshotV1
	edgeValidator    *EdgeConfigValidator
	healthTimeout    time.Duration
	healthInterval   time.Duration
}

func ProductionUpgradeServiceAdapter() (*UpgradeServiceAdapter, error) {
	controller, err := ProductionServiceController()
	if err != nil {
		return nil, err
	}
	validator, err := ProductionEdgeConfigValidator()
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	adapter, err := TaskUpgradeServiceAdapterWithEdgeConfigValidator(controller, UpgradeServiceProbeConfig{
		ServerHealth:      productionServerHealthURL,
		ServerReady:       productionServerReadyURL,
		EdgeHealth:        productionEdgeHealthURL,
		RestoredEdgeReady: productionRestoredEdgeReadyURL,
	}, validator)
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	adapter.healthTimeout = productionHealthTimeout
	adapter.healthInterval = productionHealthInterval
	return adapter, nil
}

func TaskUpgradeServiceAdapter(controller *ServiceController, probes UpgradeServiceProbeConfig) (*UpgradeServiceAdapter, error) {
	return TaskUpgradeServiceAdapterWithEdgeConfigValidator(controller, probes, nil)
}

// TaskUpgradeServiceAdapterWithEdgeConfigValidator is the explicit task-only
// seam for Caddy validation tests. The production constructor supplies the
// fixed-root validator itself.
func TaskUpgradeServiceAdapterWithEdgeConfigValidator(controller *ServiceController, probes UpgradeServiceProbeConfig, validator *EdgeConfigValidator) (*UpgradeServiceAdapter, error) {
	if controller == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return &UpgradeServiceAdapter{controller: controller, probes: probes, edgeValidator: validator}, nil
}

func (a *UpgradeServiceAdapter) Close() error {
	if a == nil {
		return nil
	}
	controller := a.controller
	a.controller = nil
	if controller == nil {
		return nil
	}
	return controller.Close()
}

func (a *UpgradeServiceAdapter) Capture(ctx context.Context) (ServiceSnapshotV1, error) {
	if a == nil || a.controller == nil {
		return ServiceSnapshotV1{}, ErrServiceOutcomeUnknown
	}
	snapshot, err := a.controller.CaptureSnapshot(ctx)
	if err != nil {
		return ServiceSnapshotV1{}, err
	}
	return ServiceSnapshotV1{
		Edge:     unitSnapshot(snapshot[ServiceEdge]),
		Agent:    unitSnapshot(snapshot[ServiceAgent]),
		Server:   unitSnapshot(snapshot[ServiceServer]),
		Caddy:    unitSnapshot(snapshot[ServiceCaddy]),
		BuildKit: unitSnapshot(snapshot[ServiceBuildKit]),
	}, nil
}

func unitSnapshot(state ServiceState) UnitSnapshotV1 {
	return UnitSnapshotV1{Active: state.Active, Enabled: state.Enabled}
}

func (a *UpgradeServiceAdapter) Quiesce(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.controller.Quiesce(ctx, true, true)
}

func (a *UpgradeServiceAdapter) StartInternal(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.controller.StartInternal(ctx)
}

func (a *UpgradeServiceAdapter) HealthInternal(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	retryCtx, cancel := a.healthRetryContext(ctx)
	defer cancel()
	if err := a.probeHealth(retryCtx, a.probes.ServerHealth); err != nil {
		return err
	}
	return a.probeHealth(retryCtx, a.probes.ServerReady)
}

func (a *UpgradeServiceAdapter) StartEdge(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.controller.StartEdge(ctx)
}

func (a *UpgradeServiceAdapter) HealthEdge(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	retryCtx, cancel := a.healthRetryContext(ctx)
	defer cancel()
	return a.probeHealth(retryCtx, a.probes.EdgeHealth)
}

// HealthRestoredEdge checks the Caddy admin readiness endpoint that exists in
// the pinned RC0 baseline as well as current releases. Rollback must not probe
// the candidate-only 18482 listener while the old Edge configuration is
// authoritative again.
func (a *UpgradeServiceAdapter) HealthRestoredEdge(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	retryCtx, cancel := a.healthRetryContext(ctx)
	defer cancel()
	return a.probeHealth(retryCtx, a.probes.RestoredEdgeReady)
}

func (a *UpgradeServiceAdapter) healthRetryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if a == nil || a.healthTimeout <= 0 || a.healthInterval <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, a.healthTimeout)
}

func (a *UpgradeServiceAdapter) probeHealth(ctx context.Context, target string) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	if a.healthTimeout <= 0 || a.healthInterval <= 0 {
		_, err := a.controller.ProbeHealth(ctx, target)
		return err
	}
	for {
		if _, err := a.controller.ProbeHealth(ctx, target); err == nil {
			return nil
		}
		timer := time.NewTimer(a.healthInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ErrServiceOutcomeUnknown
		case <-timer.C:
		}
	}
}

func (a *UpgradeServiceAdapter) GuardEdge(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.controller.stop(ctx, ServiceEdge)
}

// ReloadServerUnit exposes only the controller's fixed canonical-unit reload;
// callers can provide the expected digest but cannot select a unit or path.
func (a *UpgradeServiceAdapter) ReloadServerUnit(ctx context.Context, expectedFragmentSHA256 string) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.controller.ReloadServerUnit(ctx, expectedFragmentSHA256)
}

// ValidateEdgeConfig accepts typed non-secret transition evidence and a
// prepared artifact. It derives every filesystem path and both Caddy argv
// forms from the transaction/release identities; neither callers nor journals
// carry an executable or config path.
func (a *UpgradeServiceAdapter) ValidateEdgeConfig(ctx context.Context, transition EdgeConfigTransitionV1, artifact ArtifactV1) (EdgeConfigValidationV1, error) {
	if a == nil || a.edgeValidator == nil || !transition.valid() || artifact.Path != edgeConfigPreparedArtifactPath(transition.TransactionID) || artifact.Size < 1 || artifact.SourceDatabase != "" || !validSHA(artifact.SHA256) || artifact.SHA256 != transition.InstalledAfterSHA256 {
		return EdgeConfigValidationV1{}, ErrServiceOutcomeUnknown
	}
	result, err := a.edgeValidator.validate(ctx, edgeConfigValidationInput{Transition: transition, ConfigSHA256: artifact.SHA256})
	if err != nil {
		return EdgeConfigValidationV1{}, ErrServiceOutcomeUnknown
	}
	validation := EdgeConfigValidationV1{ConfigSHA256: result.ConfigSHA256, CaddySHA256: result.CandidateCaddySHA256, EvidenceSHA256: result.EvidenceSHA256}
	if !validation.valid() || validation.ConfigSHA256 != transition.InstalledAfterSHA256 || validation.CaddySHA256 != transition.CandidateCaddySHA256 {
		return EdgeConfigValidationV1{}, ErrServiceOutcomeUnknown
	}
	return validation, nil
}

// RestoreSnapshot deliberately excludes Edge. The engine clears the upgrade
// marker before RestoreEdge, which is the sole edge activation path.
func (a *UpgradeServiceAdapter) RestoreSnapshot(ctx context.Context, snapshot ServiceSnapshotV1) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	for _, unit := range restoreInternalStartOrder {
		if err := a.restoreEnabled(ctx, unit, snapshotUnit(snapshot, unit)); err != nil {
			return err
		}
	}
	for _, unit := range []ServiceUnit{ServiceAgent, ServiceServer, ServiceCaddy, ServiceBuildKit} {
		if !snapshotUnit(snapshot, unit).Active {
			if err := a.controller.stop(ctx, unit); err != nil {
				return err
			}
		}
	}
	for _, unit := range restoreInternalStartOrder {
		if snapshotUnit(snapshot, unit).Active {
			if err := a.controller.start(ctx, unit); err != nil {
				return err
			}
		}
	}
	a.restoredInternal = snapshot
	return nil
}

func (a *UpgradeServiceAdapter) restoreEnabled(ctx context.Context, unit ServiceUnit, expected UnitSnapshotV1) error {
	enabled, err := a.controller.state(ctx, unit, "is-enabled")
	if err != nil {
		return err
	}
	if enabled == expected.Enabled {
		return nil
	}
	if expected.Enabled {
		return a.controller.action(ctx, "enable", unit)
	}
	return a.controller.action(ctx, "disable", unit)
}

// HealthRestoredInternal accepts deliberately inactive services. The server
// endpoints are only meaningful when the snapshot expected the server active.
func (a *UpgradeServiceAdapter) HealthRestoredInternal(ctx context.Context) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	if !a.restoredInternal.Server.Active {
		return nil
	}
	return a.HealthInternal(ctx)
}

// RestoreEdge applies enablement before the final active/inactive action.
// It never probes health: UpgradeEngine owns the one post-restore edge probe.
func (a *UpgradeServiceAdapter) RestoreEdge(ctx context.Context, snapshot ServiceSnapshotV1) error {
	if a == nil || a.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	if err := a.restoreEnabled(ctx, ServiceEdge, snapshot.Edge); err != nil {
		return err
	}
	if snapshot.Edge.Active {
		return a.StartEdge(ctx)
	}
	return a.GuardEdge(ctx)
}

func snapshotUnit(snapshot ServiceSnapshotV1, unit ServiceUnit) UnitSnapshotV1 {
	switch unit {
	case ServiceAgent:
		return snapshot.Agent
	case ServiceServer:
		return snapshot.Server
	case ServiceCaddy:
		return snapshot.Caddy
	case ServiceBuildKit:
		return snapshot.BuildKit
	case ServiceEdge:
		return snapshot.Edge
	default:
		return UnitSnapshotV1{}
	}
}

var _ UpgradeServiceDriver = (*UpgradeServiceAdapter)(nil)

type upgradeServiceDriverWithReload interface {
	UpgradeServiceDriver
	ReloadServerUnit(context.Context, string) error
}

var _ upgradeServiceDriverWithReload = (*UpgradeServiceAdapter)(nil)
