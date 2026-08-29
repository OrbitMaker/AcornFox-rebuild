package install

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type ServiceUnit string

const (
	ServiceEdge     ServiceUnit = "open-card-edge"
	ServiceAgent    ServiceUnit = "open-card-agent"
	ServiceServer   ServiceUnit = "open-card-server"
	ServiceCaddy    ServiceUnit = "open-card-caddy"
	ServiceBuildKit ServiceUnit = "open-card-buildkit"
)

var ErrServiceOutcomeUnknown = errors.New("service control outcome is unknown")
var ErrEdgeMarkerPresent = errors.New("edge start is blocked by upgrade marker")

var serviceUnits = []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer, ServiceCaddy, ServiceBuildKit}

type ServiceState struct{ Active, Enabled bool }
type ServiceSnapshot map[ServiceUnit]ServiceState
type CommandResult struct {
	ExitCode int
	Output   string
	Err      error
}
type ServiceRunner interface {
	Run(context.Context, ...string) CommandResult
}
type markerProbe func() (bool, error)

type ServiceController struct {
	runner ServiceRunner
	marker markerProbe
	client *http.Client
}

type productionServiceRunner struct{}

func (productionServiceRunner) Run(ctx context.Context, argv ...string) CommandResult {
	if len(argv) == 0 || argv[0] != "systemctl" {
		return CommandResult{ExitCode: -1, Err: errors.New("unsafe command")}
	}
	result := exec.CommandContext(ctx, "/usr/bin/systemctl", argv[1:]...)
	output, err := result.CombinedOutput()
	if err == nil {
		return CommandResult{Output: string(output)}
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return CommandResult{ExitCode: exit.ExitCode(), Output: string(output), Err: err}
	}
	return CommandResult{ExitCode: -1, Output: string(output), Err: err}
}

func ProductionServiceController() (*ServiceController, error) {
	info, err := os.Lstat("/usr/bin/systemctl")
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("production systemctl is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return nil, errors.New("production systemctl is unsafe")
	}
	return &ServiceController{runner: productionServiceRunner{}, marker: func() (bool, error) {
		_, err := os.Lstat("/var/lib/open-card/upgrade-in-progress")
		if os.IsNotExist(err) {
			return false, nil
		}
		return err == nil, err
	}, client: &http.Client{Timeout: 5 * time.Second}}, nil
}

func TaskServiceController(runner ServiceRunner, marker markerProbe, client *http.Client) (*ServiceController, error) {
	if runner == nil || marker == nil {
		return nil, errors.New("task service controller dependencies are required")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ServiceController{runner: runner, marker: marker, client: client}, nil
}

func serviceName(unit ServiceUnit) string { return string(unit) + ".service" }
func known(unit ServiceUnit) bool {
	for _, value := range serviceUnits {
		if value == unit {
			return true
		}
	}
	return false
}

func (c *ServiceController) state(ctx context.Context, unit ServiceUnit, action string) (bool, error) {
	if c == nil || c.runner == nil || !known(unit) {
		return false, ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", action, "--quiet", serviceName(unit))
	allowedInactive := action == "is-active" && result.ExitCode == 3
	allowedDisabled := action == "is-enabled" && result.ExitCode == 1
	if result.Err != nil || (result.ExitCode != 0 && !allowedInactive && !allowedDisabled) {
		return false, fmt.Errorf("%w: %s", ErrServiceOutcomeUnknown, action)
	}
	return result.ExitCode == 0, nil
}

func (c *ServiceController) CaptureSnapshot(ctx context.Context) (ServiceSnapshot, error) {
	snapshot := make(ServiceSnapshot, len(serviceUnits))
	for _, unit := range serviceUnits {
		active, err := c.state(ctx, unit, "is-active")
		if err != nil {
			return nil, err
		}
		enabled, err := c.state(ctx, unit, "is-enabled")
		if err != nil {
			return nil, err
		}
		snapshot[unit] = ServiceState{Active: active, Enabled: enabled}
	}
	return snapshot, nil
}

func (c *ServiceController) action(ctx context.Context, action string, unit ServiceUnit) error {
	if c == nil || c.runner == nil || !known(unit) {
		return ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", action, serviceName(unit))
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: %s", ErrServiceOutcomeUnknown, action)
	}
	return nil
}

func (c *ServiceController) stop(ctx context.Context, unit ServiceUnit) error {
	active, err := c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if active {
		if err := c.action(ctx, "stop", unit); err != nil {
			return err
		}
	}
	active, err = c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("%w: stop remained active", ErrServiceOutcomeUnknown)
	}
	return nil
}

func (c *ServiceController) start(ctx context.Context, unit ServiceUnit) error {
	active, err := c.state(ctx, unit, "is-active")
	if err != nil {
		return err
	}
	if !active {
		if err := c.action(ctx, "start", unit); err != nil {
			return err
		}
	}
	active, err = c.state(ctx, unit, "is-active")
	if err != nil || !active {
		return fmt.Errorf("%w: start did not become active", ErrServiceOutcomeUnknown)
	}
	return nil
}

func (c *ServiceController) Quiesce(ctx context.Context, keepRouteCaddy, keepBuildKit bool) error {
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer} {
		if err := c.stop(ctx, unit); err != nil {
			return err
		}
	}
	if !keepRouteCaddy {
		if err := c.stop(ctx, ServiceCaddy); err != nil {
			return err
		}
	}
	if !keepBuildKit {
		if err := c.stop(ctx, ServiceBuildKit); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServiceController) StartInternal(ctx context.Context) error {
	for _, unit := range []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent} {
		if err := c.start(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServiceController) StartEdge(ctx context.Context) error {
	present, err := c.marker()
	if err != nil || present {
		return ErrEdgeMarkerPresent
	}
	return c.start(ctx, ServiceEdge)
}

func (c *ServiceController) RestoreSnapshot(ctx context.Context, snapshot ServiceSnapshot) error {
	for _, unit := range []ServiceUnit{ServiceEdge, ServiceAgent, ServiceServer, ServiceCaddy, ServiceBuildKit} {
		state, ok := snapshot[unit]
		if !ok {
			return ErrServiceOutcomeUnknown
		}
		if !state.Active {
			if err := c.stop(ctx, unit); err != nil {
				return err
			}
		}
		if state.Enabled {
			if err := c.action(ctx, "enable", unit); err != nil {
				return err
			}
		} else if err := c.action(ctx, "disable", unit); err != nil {
			return err
		}
	}
	for _, unit := range []ServiceUnit{ServiceBuildKit, ServiceCaddy, ServiceServer, ServiceAgent} {
		if snapshot[unit].Active {
			if err := c.start(ctx, unit); err != nil {
				return err
			}
		}
	}
	if snapshot[ServiceEdge].Active {
		return c.StartEdge(ctx)
	}
	return nil
}

func (c *ServiceController) DaemonReload(ctx context.Context) error {
	if c == nil || c.runner == nil {
		return ErrServiceOutcomeUnknown
	}
	result := c.runner.Run(ctx, "systemctl", "daemon-reload")
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: daemon-reload", ErrServiceOutcomeUnknown)
	}
	return nil
}

type HealthResult struct{ Code string }

func (c *ServiceController) ProbeHealth(ctx context.Context, rawURL string) (HealthResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || (parsed.Path != "/healthz" && parsed.Path != "/readyz") {
		return HealthResult{Code: "invalid_target"}, errors.New("health target is not approved")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || parsed.Port() == "" {
		return HealthResult{Code: "invalid_target"}, errors.New("health target is not loopback")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HealthResult{Code: "invalid_target"}, errors.New("health request is invalid")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return HealthResult{Code: "unhealthy"}, errors.New("health request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return HealthResult{Code: "unhealthy"}, errors.New("health response was not ready")
	}
	return HealthResult{Code: "healthy"}, nil
}
