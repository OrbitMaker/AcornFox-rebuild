package runtimenetwork

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestApplicationTopologyUsesTheCompleteFixedInspector(t *testing.T) {
	owner := strings.Repeat("b", 64)
	raw := networkFixture(owner)
	if err := ValidateApplicationTopology(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ name, old, next string }{
		{"invalid owner", owner, "caller-controlled"},
		{"foreign name", `"Name":"acornfox-network"`, `"Name":"other-network"`},
		{"foreign bridge", Bridge, "docker0"},
		{"wrong policy", originDigest(), strings.Repeat("f", 64)},
		{"unmanaged", `"open-card.managed":"true"`, `"open-card.managed":"false"`},
		{"IPv6", `"EnableIPv6":false`, `"EnableIPv6":true`},
		{"subnet", Subnet, "10.0.0.0/8"},
		{"gateway", Gateway, "10.203.254.2"},
		{"sibling access", `"com.docker.network.bridge.enable_icc":"false"`, `"com.docker.network.bridge.enable_icc":"true"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := bytes.Replace(raw, []byte(change.old), []byte(change.next), 1)
			if bytes.Equal(raw, altered) {
				t.Fatal("ineffective mutation")
			}
			if ValidateApplicationTopology(altered) == nil {
				t.Fatal("unsafe topology accepted")
			}
		})
	}
	for _, malformed := range []string{"", `[]`, `null`, `[{},{}]`, `[{"Name":"acornfox-network","Name":"other"}]`} {
		if ValidateApplicationTopology([]byte(malformed)) == nil {
			t.Fatal("malformed inspection accepted")
		}
	}
	// A different valid token is syntactically acceptable. This pure check
	// deliberately makes no claim about matching privileged persisted intent.
	if err := ValidateApplicationTopology(networkFixture(strings.Repeat("c", 64))); err != nil {
		t.Fatal(err)
	}
}

func TestPublicResolversReturnsAnIndependentFixedSlice(t *testing.T) {
	first := PublicResolvers()
	if !reflect.DeepEqual(first, []string{"223.5.5.5", "223.6.6.6"}) {
		t.Fatal(first)
	}
	first[0] = "127.0.0.1"
	second := PublicResolvers()
	if !reflect.DeepEqual(second, []string{"223.5.5.5", "223.6.6.6"}) {
		t.Fatal("caller changed public resolver policy")
	}
	for _, resolver := range second {
		if !bytes.Contains(policyCommands(strings.Repeat("a", 64)), []byte(resolver)) {
			t.Fatal("runtime firewall omitted resolver", resolver)
		}
	}
}
