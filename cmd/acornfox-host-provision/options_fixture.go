//go:build fixture

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostprovision"
)

func isFixtureBuild() bool {
	return true
}

func getFixtureGuestTransport(fixtureDir string) desktopupdate.GuestTransport {
	stateFile := filepath.Join(fixtureDir, "backend-state.json")
	return func(ctx context.Context, command desktopupdate.GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
		raw, err := os.ReadFile(stateFile)
		if err != nil {
			return 1, fmt.Errorf("fixture guest transport: backend-state.json missing: %w", err)
		}
		var data struct {
			InstanceID   string `json:"instance_id"`
			Architecture string `json:"architecture"`
			Binding      string `json:"binding"`
			Ready        bool   `json:"ready"`
			Finalized    bool   `json:"finalized"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return 1, fmt.Errorf("fixture guest transport: backend-state.json malformed: %w", err)
		}
		args := command.Arguments()
		if len(args) > 0 && args[0] == "observe" {
			obs := desktopupdate.BackendObservation{
				LocalLoopback:    true,
				MigrationVersion: "0040",
				Architecture:     data.Architecture,
				InstanceID:       data.InstanceID,
				Binding:          data.Binding,
				Ready:            data.Ready,
				Finalized:        data.Finalized,
				AttemptState:     "absent",
			}
			obsRaw, _ := json.Marshal(obs)
			reply := struct {
				OK     bool            `json:"ok"`
				Code   string          `json:"code"`
				Result json.RawMessage `json:"result,omitempty"`
			}{
				OK:     true,
				Code:   "ok",
				Result: json.RawMessage(obsRaw),
			}
			out, _ := json.Marshal(reply)
			_, _ = stdout.Write(out)
			return 0, nil
		}
		return 1, fmt.Errorf("fixture guest transport: unsupported command %v", args)
	}
}

func runProvision(ctx context.Context, req hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
	fixtureDir := os.Getenv("ACORNFOX_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = "/tmp/acornfox-fixture"
	}
	paths := hostprovision.ProvisionPaths{
		BootstrapExecutable: filepath.Join(fixtureDir, "libexec", "acornfox-host-bootstrap"),
		BootstrapRoot:       filepath.Join(fixtureDir, "bootstrap"),
		LauncherPath:        filepath.Join(fixtureDir, "bootstrap", "launcher", "acornfox-host-launcher"),
		ControllerPath:      filepath.Join(fixtureDir, "bootstrap", "controller", "acornfox-host-update"),
		ConfigPath:          filepath.Join(fixtureDir, "host-runtime.json"),
		GuestInstancePath:   filepath.Join(fixtureDir, "guest-instance.json"),
		SlotsRoot:           filepath.Join(fixtureDir, "slots"),
		SlotsLock:           filepath.Join(fixtureDir, "slots", "lock"),
		ControllerRoot:      filepath.Join(fixtureDir, "controller"),
	}
	return hostprovision.ProvisionForFixture(ctx, req, hostprovision.FixtureOptions{
		AllowNonRoot:   true,
		Paths:          paths,
		GuestTransport: getFixtureGuestTransport(fixtureDir),
	})
}
