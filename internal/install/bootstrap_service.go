package install

import "context"

var bootstrapInternalServiceOrder = []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent}

// BootstrapServiceAdapter binds the native-bootstrap service interface to the
// existing fixed systemctl and loopback-health controller. Callers cannot
// select a unit, executable, action, marker, or health target.
type BootstrapServiceAdapter struct {
	upgrade *UpgradeServiceAdapter
}

func ProductionBootstrapServiceAdapter() (*BootstrapServiceAdapter, error) {
	upgrade, err := ProductionUpgradeServiceAdapter()
	if err != nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return &BootstrapServiceAdapter{upgrade: upgrade}, nil
}

func TaskBootstrapServiceAdapter(upgrade *UpgradeServiceAdapter) (*BootstrapServiceAdapter, error) {
	if upgrade == nil || upgrade.controller == nil {
		return nil, ErrServiceOutcomeUnknown
	}
	return &BootstrapServiceAdapter{upgrade: upgrade}, nil
}

func (a *BootstrapServiceAdapter) Close() error {
	if a == nil || a.upgrade == nil {
		return nil
	}
	upgrade := a.upgrade
	a.upgrade = nil
	return upgrade.Close()
}

func (a *BootstrapServiceAdapter) GuardEdge(ctx context.Context) error {
	if a == nil || a.upgrade == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.upgrade.GuardEdge(ctx)
}

// EnableInternal reloads only the fixed unit set and proves every internal
// unit enabled before the engine may start it. It is idempotent on replay.
func (a *BootstrapServiceAdapter) EnableInternal(ctx context.Context) error {
	if a == nil || a.upgrade == nil || a.upgrade.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	if err := a.upgrade.controller.DaemonReload(ctx); err != nil {
		return ErrServiceOutcomeUnknown
	}
	for _, unit := range bootstrapInternalServiceOrder {
		if err := a.enable(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

func (a *BootstrapServiceAdapter) EnableEdge(ctx context.Context) error {
	if a == nil || a.upgrade == nil || a.upgrade.controller == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.enable(ctx, ServiceEdge)
}

func (a *BootstrapServiceAdapter) enable(ctx context.Context, unit ServiceUnit) error {
	enabled, err := a.upgrade.controller.state(ctx, unit, "is-enabled")
	if err != nil {
		return ErrServiceOutcomeUnknown
	}
	if !enabled {
		if err := a.upgrade.controller.action(ctx, "enable", unit); err != nil {
			return ErrServiceOutcomeUnknown
		}
	}
	enabled, err = a.upgrade.controller.state(ctx, unit, "is-enabled")
	if err != nil || !enabled {
		return ErrServiceOutcomeUnknown
	}
	return nil
}

func (a *BootstrapServiceAdapter) StartInternal(ctx context.Context) error {
	if a == nil || a.upgrade == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.upgrade.StartInternal(ctx)
}

func (a *BootstrapServiceAdapter) HealthInternal(ctx context.Context) error {
	if a == nil || a.upgrade == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.upgrade.HealthInternal(ctx)
}

func (a *BootstrapServiceAdapter) StartEdge(ctx context.Context) error {
	if a == nil || a.upgrade == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.upgrade.StartEdge(ctx)
}

func (a *BootstrapServiceAdapter) HealthEdge(ctx context.Context) error {
	if a == nil || a.upgrade == nil {
		return ErrServiceOutcomeUnknown
	}
	return a.upgrade.HealthEdge(ctx)
}

func (a *BootstrapServiceAdapter) Capture(ctx context.Context) (ServiceSnapshotV1, error) {
	if a == nil || a.upgrade == nil {
		return ServiceSnapshotV1{}, ErrServiceOutcomeUnknown
	}
	return a.upgrade.Capture(ctx)
}

var _ BootstrapServiceDriver = (*BootstrapServiceAdapter)(nil)
