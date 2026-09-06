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
	if config.RestoreActiveGuard == nil || config.ExistingNetworkValidator == nil || !reflect.DeepEqual(config.DNS, []string{"223.5.5.5", "223.6.6.6"}) {
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
	if config.RestoreActiveGuard != nil || config.ExistingNetworkValidator != nil || config.DNS != nil {
		t.Fatal("legacy behavior changed")
	}
}

func TestRuntimeGuardReadinessRequiresExactSuccessfulOneshot(t *testing.T) {
	for _, raw := range []string{"", "ActiveState=active\nSubState=running\nResult=success\n", "ActiveState=inactive\nSubState=dead\nResult=success\n", "ActiveState=active\nSubState=exited\nResult=exit-code\n", "ActiveState=active\nSubState=exited\n", "ActiveState=active\nSubState=exited\nResult=success\nResult=success\n"} {
		if successfulRuntimeGuardState(raw) {
			t.Fatalf("unsafe guard accepted: %q", raw)
		}
	}
	if !successfulRuntimeGuardState("Result=success\nSubState=exited\nActiveState=active\n") {
		t.Fatal("successful guard rejected")
	}
}
