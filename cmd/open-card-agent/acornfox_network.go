package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/providers/standalone"
	"github.com/open-card/open-card/internal/runtimenetwork"
)

func bindInstalledRuntimeNetwork(config *standalone.Config, environment acornfoxenv.Environment) {
	if environment.Clean() {
		config.ExistingNetworkValidator = runtimenetwork.ValidateApplicationTopology
		config.DNS = runtimenetwork.PublicResolvers()
		config.RestoreActiveGuard = installedRuntimeGuardReady
	}
}

// Agent Requires/After orders this root-owned oneshot before recovery. Reading
// its successful state does not claim to detect later out-of-band nft changes.
func installedRuntimeGuardReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "acornfox-runtime-network.service", "--property=ActiveState,SubState,Result", "--no-pager")
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	raw, err := command.Output()
	if err != nil || !successfulRuntimeGuardState(string(raw)) {
		return errors.New("installed runtime network guard is not ready")
	}
	return nil
}

func successfulRuntimeGuardState(raw string) bool {
	want := map[string]string{"ActiveState": "active", "SubState": "exited", "Result": "success"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] || want[key] != value || value == "" {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}
