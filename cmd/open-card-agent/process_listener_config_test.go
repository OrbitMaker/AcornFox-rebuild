package main

import (
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func agentListenerEnvironment(t *testing.T, address string, clean bool) acornfoxenv.Environment {
	t.Helper()
	values := map[string]string{}
	identity := "legacy"
	if clean {
		identity = "acornfox"
		values["ACORNFOX_RUNTIME_MODE"] = "clean"
		values["ACORNFOX_AGENT_ADDR"] = address
	} else {
		values["OPEN_CARD_AGENT_ADDR"] = address
	}
	environment, err := acornfoxenv.Resolve(acornfoxenv.ProcessAgent, identity, func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func TestCleanAgentListenerAddressIsClosed(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:8091"} {
		if got, err := resolveAgentListenerAddress(agentListenerEnvironment(t, address, true)); err != nil || got != "127.0.0.1:8091" {
			t.Fatalf("clean address=%q got=%q err=%v", address, got, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8091", "[::]:8091", "127.0.0.1:8092"} {
		if _, err := resolveAgentListenerAddress(agentListenerEnvironment(t, address, true)); err == nil || !strings.Contains(err.Error(), "AcornFox") || strings.Contains(err.Error(), address) {
			t.Fatalf("clean address %q result=%v", address, err)
		}
	}
}

func TestLegacyAgentListenerAddressRemainsUnchanged(t *testing.T) {
	if got, err := resolveAgentListenerAddress(agentListenerEnvironment(t, "", false)); err != nil || got != "127.0.0.1:8091" {
		t.Fatalf("legacy default=%q err=%v", got, err)
	}
	if got, err := resolveAgentListenerAddress(agentListenerEnvironment(t, "0.0.0.0:8091", false)); err != nil || got != "0.0.0.0:8091" {
		t.Fatalf("legacy override=%q err=%v", got, err)
	}
}
