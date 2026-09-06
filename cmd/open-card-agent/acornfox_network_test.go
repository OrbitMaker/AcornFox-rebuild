package main

import (
	"reflect"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/providers/standalone"
)

func TestCleanAgentRequiresPreparedNetworkAndExplicitDNS(t *testing.T) {
	environment, err := acornfoxenv.Resolve(acornfoxenv.ProcessAgent, "acornfox", func(key string) (string, bool) {
		if key == "ACORNFOX_RUNTIME_MODE" {
			return "clean", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	config := standalone.Config{}
	bindInstalledRuntimeNetwork(&config, environment)
	if config.ExistingNetworkValidator == nil || !reflect.DeepEqual(config.DNS, []string{"223.5.5.5", "223.6.6.6"}) {
		t.Fatal("clean runtime can fall back to an unguarded/default-DNS network")
	}
	if config.ExistingNetworkValidator([]byte(`[]`)) == nil {
		t.Fatal("absent network accepted")
	}
	legacy, err := acornfoxenv.Resolve(acornfoxenv.ProcessAgent, "legacy", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	config = standalone.Config{}
	bindInstalledRuntimeNetwork(&config, legacy)
	if config.ExistingNetworkValidator != nil || config.DNS != nil {
		t.Fatal("legacy behavior changed")
	}
}
