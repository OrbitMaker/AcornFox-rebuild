package main

import (
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func serverListenerEnvironment(t *testing.T, values map[string]string, clean bool) acornfoxenv.Environment {
	t.Helper()
	if clean {
		values["ACORNFOX_RUNTIME_MODE"] = "clean"
	}
	environment, err := acornfoxenv.Resolve(acornfoxenv.ProcessServer, map[bool]string{true: "acornfox", false: "legacy"}[clean], func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func TestCleanServerAndGatewayListenerAddressesAreClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		server  string
		gateway string
		valid   bool
	}{
		{name: "defaults", valid: true},
		{name: "exact", server: "127.0.0.1:18481", gateway: "127.0.0.1:8092", valid: true},
		{name: "public", server: "0.0.0.0:18481"},
		{name: "ipv6", server: "[::]:18481"},
		{name: "old default", server: "127.0.0.1:8080"},
		{name: "other server port", server: "127.0.0.1:18482"},
		{name: "public gateway", gateway: "0.0.0.0:8092"},
		{name: "other gateway port", gateway: "127.0.0.1:8093"},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := serverListenerEnvironment(t, map[string]string{"ACORNFOX_SERVER_ADDR": test.server, "ACORNFOX_AGENT_GATEWAY_ADDR": test.gateway}, true)
			server, serverErr := resolveServerListenerAddress(environment)
			gateway, gatewayErr := resolveAgentGatewayListenerAddress(environment)
			if test.valid {
				if serverErr != nil || gatewayErr != nil || server != "127.0.0.1:18481" || gateway != test.gateway {
					t.Fatalf("server=%q gateway=%q errors=%v,%v", server, gateway, serverErr, gatewayErr)
				}
				return
			}
			err := serverErr
			if err == nil {
				err = gatewayErr
			}
			if err == nil || !strings.Contains(err.Error(), "AcornFox") || (test.server != "" && strings.Contains(err.Error(), test.server)) || (test.gateway != "" && strings.Contains(err.Error(), test.gateway)) {
				t.Fatalf("unsafe listener result server=%q gateway=%q errors=%v,%v", server, gateway, serverErr, gatewayErr)
			}
		})
	}
}

func TestLegacyServerListenerAddressesRemainUnchanged(t *testing.T) {
	defaults := serverListenerEnvironment(t, map[string]string{}, false)
	if address, err := resolveServerListenerAddress(defaults); err != nil || address != "127.0.0.1:8080" {
		t.Fatalf("default address=%q err=%v", address, err)
	}
	legacy := serverListenerEnvironment(t, map[string]string{"OPEN_CARD_SERVER_ADDR": "0.0.0.0:8080", "OPEN_CARD_AGENT_GATEWAY_ADDR": "0.0.0.0:8092"}, false)
	if address, err := resolveServerListenerAddress(legacy); err != nil || address != "0.0.0.0:8080" {
		t.Fatalf("legacy server address=%q err=%v", address, err)
	}
	if address, err := resolveAgentGatewayListenerAddress(legacy); err != nil || address != "0.0.0.0:8092" {
		t.Fatalf("legacy gateway address=%q err=%v", address, err)
	}
}
