package main

import (
	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/providers/standalone"
	"github.com/open-card/open-card/internal/runtimenetwork"
)

func bindInstalledRuntimeNetwork(config *standalone.Config, environment acornfoxenv.Environment) {
	if environment.Clean() {
		config.ExistingNetworkValidator = runtimenetwork.ValidateApplicationTopology
		config.DNS = runtimenetwork.PublicResolvers()
	}
}
