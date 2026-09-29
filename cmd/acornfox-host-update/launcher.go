package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

var (
	// RequiredApplicationUnits are the core services managed across update slots.
	// acornfox-upgrade-safe.target, docker.service, and postgresql.service are NEVER stopped.
	RequiredApplicationUnits = []string{
		"acornfox-build-network.service",
		"acornfox-buildkit.service",
		"acornfox-runtime-network.service",
		"acornfox-caddy.service",
		"acornfox-server.service",
		"acornfox-agent.service",
	}

	// OptionalApplicationUnits are auxiliary services that preserve their enabled profile.
	OptionalApplicationUnits = []string{
		"acornfox-edge.service",
		"acornfox-healthcheck.timer",
		"acornfox-healthcheck.service",
	}

	ErrLauncherProbeTimeout = errors.New("launcher: local probe timed out")
	ErrLauncherStopTimeout  = errors.New("launcher: waiting for port 8080 release timed out")
	ErrLauncherUnitActive   = errors.New("launcher: managed unit still active after stop")
)

// UnitCommandRunner executes systemctl commands. Overridable in tests.
var unitCommandRunner = func(ctx context.Context, action string, unit string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", action, unit)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return cmd.Run()
}

// UnitStatusRunner checks if a unit is active. Returns true if active. Overridable in tests.
var unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}

// UnitEnabledRunner checks if an optional unit is enabled. Overridable in tests.
var unitEnabledRunner = func(ctx context.Context, unit string) (bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-enabled", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err == nil {
		state := strings.TrimSpace(string(output))
		return state == "enabled" || state == "enabled-runtime", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}

// PortProbeRunner checks if a TCP address is closed/released. Overridable in tests.
var portReleasedRunner = func(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			// Port is released
			return nil
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return ErrLauncherStopTimeout
}

// HTTPProbeRunner checks local readiness HTTP endpoints. Overridable in tests.
var httpProbeRunner = func(ctx context.Context, client *http.Client, target string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func parseSetupState(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var probe struct {
		State string `json:"state"`
	}
	dec.DisallowUnknownFields()
	if err := dec.Decode(&probe); err != nil {
		return "", err
	}
	if probe.State != "initialized" && probe.State != "uninitialized" {
		return "", fmt.Errorf("invalid setup state: %q", probe.State)
	}
	return probe.State, nil
}

// RunSlotStop gracefully stops acornfox application units without touching
// docker.service, postgresql.service, or acornfox-upgrade-safe.target.
// Fails closed if any required or optional unit fails to stop or remains active at the barrier.
func RunSlotStop(ctx context.Context) error {
	// 1. Query and stop optional units if active. Any query error or stop error blocks activation.
	for _, unit := range OptionalApplicationUnits {
		active, err := unitActiveRunner(ctx, unit)
		if err != nil {
			return fmt.Errorf("failed to query optional unit %q: %w", unit, err)
		}
		if active {
			if err := unitCommandRunner(ctx, "stop", unit); err != nil {
				return fmt.Errorf("failed to stop active optional unit %q: %w", unit, err)
			}
		}
	}

	// 2. Stop required units in reverse dependency order. Fail immediately on error.
	for i := len(RequiredApplicationUnits) - 1; i >= 0; i-- {
		unit := RequiredApplicationUnits[i]
		if err := unitCommandRunner(ctx, "stop", unit); err != nil {
			return fmt.Errorf("failed to stop required unit %q: %w", unit, err)
		}
	}

	// 3. Verify ALL required units are confirmed inactive
	for _, unit := range RequiredApplicationUnits {
		active, err := unitActiveRunner(ctx, unit)
		if err != nil {
			return fmt.Errorf("failed to inspect required unit %q: %w", unit, err)
		}
		if active {
			return fmt.Errorf("%w: required unit %q remains active", ErrLauncherUnitActive, unit)
		}
	}

	// 4. Verify ALL optional application units are confirmed inactive at the barrier
	for _, unit := range OptionalApplicationUnits {
		active, err := unitActiveRunner(ctx, unit)
		if err != nil {
			return fmt.Errorf("failed to inspect optional unit %q: %w", unit, err)
		}
		if active {
			return fmt.Errorf("%w: optional unit %q remains active", ErrLauncherUnitActive, unit)
		}
	}

	// 5. Wait for 8080 port release
	if err := portReleasedRunner(ctx, "127.0.0.1:8080", 30*time.Second); err != nil {
		return err
	}

	return nil
}

// RunSlotStart starts the required application units and restores enabled optional profile.
func RunSlotStart(ctx context.Context) error {
	// 1. Start required application units
	for _, unit := range RequiredApplicationUnits {
		if err := unitCommandRunner(ctx, "start", unit); err != nil {
			return fmt.Errorf("failed to start required unit %q: %w", unit, err)
		}
	}

	// 2. Restore optional units according to their existing enabled profile
	for _, unit := range OptionalApplicationUnits {
		enabled, err := unitEnabledRunner(ctx, unit)
		if err == nil && enabled {
			_ = unitCommandRunner(ctx, "start", unit)
		}
	}

	return nil
}

// RunSlotProbe verifies unit readiness and loopback HTTP probes against 18481 and 8080.
func RunSlotProbe(ctx context.Context) error {
	// 1. Verify required units are active
	for _, unit := range RequiredApplicationUnits {
		active, err := unitActiveRunner(ctx, unit)
		if err != nil || !active {
			return fmt.Errorf("required unit %q not active: err=%v", unit, err)
		}
	}

	// 2. Verify enabled optional units are active
	for _, unit := range OptionalApplicationUnits {
		enabled, err := unitEnabledRunner(ctx, unit)
		if err == nil && enabled {
			active, aErr := unitActiveRunner(ctx, unit)
			if aErr != nil || !active {
				return fmt.Errorf("enabled optional unit %q not active", unit)
			}
		}
	}

	// 3. Loopback HTTP endpoints probe
	deadline := time.Now().Add(45 * time.Second)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Probe 18481 /healthz
		code, _, err := httpProbeRunner(ctx, client, "http://127.0.0.1:18481/healthz")
		if err != nil || code != http.StatusOK {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		// Probe 18481 /readyz
		code, _, err = httpProbeRunner(ctx, client, "http://127.0.0.1:18481/readyz")
		if err != nil || code != http.StatusOK {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		// Probe 8080 /api/v1/acornfox/setup
		code, body, err := httpProbeRunner(ctx, client, "http://127.0.0.1:8080/api/v1/acornfox/setup")
		if err != nil || code != http.StatusOK {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if _, err := parseSetupState(body); err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		// All probes succeeded
		return nil
	}

	return ErrLauncherProbeTimeout
}

// HandleLauncherCommand dispatches slot-stop, slot-start, and slot-probe.
func HandleLauncherCommand(ctx context.Context, cmd string) error {
	switch strings.TrimSpace(cmd) {
	case "slot-stop":
		return RunSlotStop(ctx)
	case "slot-start":
		return RunSlotStart(ctx)
	case "slot-probe":
		return RunSlotProbe(ctx)
	default:
		return fmt.Errorf("unknown launcher subcommand: %q", cmd)
	}
}
