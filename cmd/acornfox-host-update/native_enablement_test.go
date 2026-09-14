//go:build linux

package main

import (
	"context"
	"flag"
	"os/exec"
	"strings"
	"testing"
)

var nativeSystemdEnablement = flag.Bool("native-systemd-enablement", false, "run against the explicitly provisioned Linux local-mode fixture")

func TestNativeOptionalUnitEnablement(t *testing.T) {
	if !*nativeSystemdEnablement {
		t.Skip("requires explicitly selected native Linux fixture")
	}
	cases := []struct {
		unit, state string
		enabled     bool
	}{
		{"acornfox-healthcheck.service", "static", false},
		{"acornfox-healthcheck.timer", "disabled", false},
		{"acornfox-server.service", "enabled", true},
	}
	for _, tc := range cases {
		t.Run(tc.unit, func(t *testing.T) {
			raw, _ := exec.Command("/usr/bin/systemctl", "is-enabled", tc.unit).Output()
			if strings.TrimSpace(string(raw)) != tc.state {
				t.Fatalf("native fixture state mismatch for %s", tc.unit)
			}
			got, err := unitEnabledRunner(context.Background(), tc.unit)
			if err != nil || got != tc.enabled {
				t.Fatalf("unit=%s want enabled=%v got=%v err=%v", tc.unit, tc.enabled, got, err)
			}
		})
	}
}
