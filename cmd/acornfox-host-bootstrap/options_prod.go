//go:build !fixture

package main

import "github.com/open-card/open-card/internal/hostconfig"

func getProductionBootstrapOptions() BootstrapOptions {
	return BootstrapOptions{
		ConfigPath:     hostconfig.DefaultHostRuntimeConfigPath,
		BootstrapRoot:  hostconfig.DefaultBootstrapRoot,
		SlotsRoot:      hostconfig.DefaultSlotsRoot,
		InvocationLock: hostconfig.DefaultInvocationLockPath,
		AllowNonRoot:   false,
	}
}

func getChildEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
}
