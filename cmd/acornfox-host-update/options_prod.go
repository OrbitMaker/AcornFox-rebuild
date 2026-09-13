//go:build !fixture

package main

import "github.com/open-card/open-card/internal/hostconfig"

var BuildMarker = "PROD"

func getProductionControllerOptions() ControllerOptions {
	return ControllerOptions{
		ConfigPath:     hostconfig.DefaultHostRuntimeConfigPath,
		BootstrapRoot:  hostconfig.DefaultBootstrapRoot,
		SlotsRoot:      hostconfig.DefaultSlotsRoot,
		ControllerRoot: hostconfig.DefaultControllerRoot,
		GuestTransport: defaultGuestTransport(),
	}
}

func getLauncherEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
}

func traceAdmittedMarker(operation string) {}
