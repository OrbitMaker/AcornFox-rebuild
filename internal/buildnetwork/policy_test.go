package buildnetwork

import (
	"bytes"
	"strings"
	"testing"
)

func TestProductionPolicyIsDistinctAndClosed(t *testing.T) {
	raw := CanonicalPolicy()
	policy, digest, err := ParsePolicy(raw)
	if err != nil || policy.Scope != "build-execution" || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal(policy, digest, err)
	}
	for _, bad := range [][]byte{append(raw, ' '), bytes.Replace(raw, []byte(`"deny_host_addresses":true`), []byte(`"deny_host_addresses":false`), 1), bytes.Replace(raw, []byte(`"scope":"build-execution"`), []byte(`"scope":"dependency-prefetch"`), 1)} {
		if _, _, err := ParsePolicy(bad); err == nil {
			t.Fatal("changed policy accepted")
		}
	}
}

func TestFirewallScopeBlocksHostAndPostDNATWithoutGlobalChanges(t *testing.T) {
	rules := HostRules()
	for _, want := range []string{`iifname "acornfox-bh" counter drop`, `iifname "acornfox-bh" ip daddr @denied_v4 counter drop`, `iifname "acornfox-bh" ip saddr 10.203.253.2 masquerade`} {
		if !strings.Contains(rules, want) {
			t.Fatal("missing scoped protection", want)
		}
	}
	for _, bad := range []string{"flush ruleset", "policy drop", "DOCKER"} {
		if strings.Contains(rules, bad) {
			t.Fatal("global firewall change", bad)
		}
	}
	if strings.Contains(WorkerRules(), "host network") || !strings.Contains(WorkerRules(), "policy drop") {
		t.Fatal("worker policy missing")
	}
}
