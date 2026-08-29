package install

import "context"

const (
	productionServerHealthURL = "http://127.0.0.1:8080/healthz"
	productionServerReadyURL  = "http://127.0.0.1:8080/readyz"
	productionEdgeHealthURL   = "http://127.0.0.1:18482/healthz"
)

var restoreInternalStartOrder = []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent}

// UpgradeServiceProbeConfig contains the only health targets an upgrade
// adapter may use. ServiceController enforces their loopback endpoint policy.
type UpgradeServiceProbeConfig struct {
	ServerHealth string
	ServerReady  string
	EdgeHealth   string
}

// UpgradeServiceAdapter maps the fixed service-controller boundary into the
// engine's typed service driver.
type UpgradeServiceAdapter struct {
	controller       *ServiceController
	probes           UpgradeServiceProbeConfig
	restoredInternal ServiceSnapshotV1
}

func ProductionUpgradeServiceAdapter() (*UpgradeServiceAdapter, error) {
	controller, err := ProductionServiceController()
	if err != nil {
		return nil, err
	}
	adapter, err := TaskUpgradeServiceAdapter(controller, UpgradeServiceProbeConfig{
		ServerHealth: productionServerHealthURL,
		ServerReady:  productionServerReadyURL,
		EdgeHealth:   productionEdgeHealthURL,
	})
	if err != nil {
		_ = controller.Close()
		return nil, err
	}
	return adapter, nil
}

func TaskUpgradeServiceAdapter(controller *ServiceController, probes UpgradeServiceProbeConfig) (*UpgradeServiceAdapter, error) {
	if controller == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return &UpgradeServiceAdapter{controller: controller, probes: probes}, nil
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
	if _, err := a.controller.ProbeHealth(ctx, a.probes.ServerHealth); err != nil {
		return err
	}
	_, err := a.controller.ProbeHealth(ctx, a.probes.ServerReady)
	return err
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
	_, err := a.controller.ProbeHealth(ctx, a.probes.EdgeHealth)
	return err
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
