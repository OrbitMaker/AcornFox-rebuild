package agenttransport

import (
	v1 "github.com/open-card/open-card/api/agent/v1"
	"testing"
)

func TestConfiguredRuntimeCapabilityNegotiation(t *testing.T) {
	for _, version := range []string{v1.ProtocolVersion, v1.PreviousProtocolVersion} {
		enabled, disabled := negotiateSessionCapabilities([]string{v1.AgentCapabilityAcornFoxRuntimeConfig}, version, nil)
		has := false
		for _, c := range enabled {
			if c == v1.AgentCapabilityAcornFoxRuntimeConfig {
				has = true
			}
		}
		if has != (version == v1.ProtocolVersion) {
			t.Fatal("configured runtime wrongly negotiated", version)
		}
		if version != v1.ProtocolVersion {
			found := false
			for _, c := range disabled {
				if c == v1.AgentCapabilityAcornFoxRuntimeConfig {
					found = true
				}
			}
			if !found {
				t.Fatal("legacy config capability not disabled")
			}
		}
	}
}
