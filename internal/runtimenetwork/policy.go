// Package runtimenetwork prepares the fixed single-host runtime network.
// Its receipts describe local network configuration, not application or public
// acceptance. It never removes a network or its firewall.
package runtimenetwork

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/open-card/open-card/internal/buildnetwork"
)

const (
	Network     = "acornfox-network"
	Bridge      = "acornfox-r0"
	Subnet      = "10.203.254.0/24"
	Gateway     = "10.203.254.1"
	Table       = "acornfox_runtime_guard"
	StateRoot   = "/run/acornfox-runtime-network"
	IntentPath  = "/var/lib/acornfox/install/runtime-network.json"
	ownerLabel  = "acornfox.runtime-network.owner"
	policyLabel = "acornfox.runtime-network.policy"
)

var (
	ErrConflict    = errors.New("AcornFox runtime network ownership or policy conflict")
	ErrUnavailable = errors.New("AcornFox runtime network is unavailable")
)

type Receipt struct {
	SchemaVersion  int    `json:"schema_version"`
	PolicySHA256   string `json:"policy_sha256"`
	NetworkID      string `json:"network_id"`
	FirewallSHA256 string `json:"firewall_sha256"`
}

type object = map[string]any

func hashBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func digestOK(s string) bool      { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

// Each rule is scoped to this bridge. An accept in our base chain cannot
// override a later Docker drop. The input exception preserves responses to
// host-originated loopback published-port connections.
func policyObjects(owner string) []object {
	objects := []object{{"table": object{"family": "inet", "name": Table}}}
	chain := func(name string) {
		objects = append(objects, object{"chain": object{"family": "inet", "table": Table, "name": name, "type": "filter", "hook": name, "prio": -5, "policy": "accept"}})
	}
	meta := func(key string) object { return object{"meta": object{"key": key}} }
	payload := func(protocol, field string) object {
		return object{"payload": object{"protocol": protocol, "field": field}}
	}
	match := func(left any, op string, right any) object {
		return object{"match": object{"left": left, "op": op, "right": right}}
	}
	ingress := func() object { return match(meta("iifname"), "==", Bridge) }
	states := func() object {
		return match(object{"ct": object{"key": "state"}}, "==", object{"set": []string{"established", "related"}})
	}
	rule := func(chain, name, verdict string, expr ...object) {
		values := make([]object, 0, len(expr)+2)
		values = append(values, expr...)
		values = append(values, object{"counter": nil}, object{verdict: nil})
		objects = append(objects, object{"rule": object{"family": "inet", "table": Table, "chain": chain, "expr": values, "comment": "acornfox-runtime-v1:" + owner + ":" + name}})
	}
	// nft lists chain definitions before rules, even when commands interleave.
	chain("input")
	chain("forward")
	rule("input", "host_return", "accept", ingress(), states())
	rule("input", "host_denied", "drop", ingress())
	rule("forward", "ipv6_denied", "drop", ingress(), match(meta("nfproto"), "==", "ipv6"))
	rule("forward", "spoof_denied", "drop", ingress(), match(payload("ip", "saddr"), "!=", prefix(Subnet)))
	rule("forward", "return_allowed", "accept", ingress(), states())
	rule("forward", "same_bridge_denied", "drop", ingress(), match(meta("oifname"), "==", Bridge))
	for i, cidr := range buildnetwork.DefaultPolicy().DeniedIPv4 {
		// The ordinal is fixed by the canonical shared policy.
		name := "private_" + string(rune('a'+i)) + "_denied"
		rule("forward", name, "drop", ingress(), match(payload("ip", "daddr"), "==", prefix(cidr)))
	}
	for _, resolver := range PublicResolvers() {
		for _, protocol := range []string{"tcp", "udp"} {
			rule("forward", "dns_"+strings.ReplaceAll(resolver, ".", "_")+"_"+protocol, "accept", ingress(), match(payload("ip", "daddr"), "==", resolver), match(payload(protocol, "dport"), "==", 53))
		}
	}
	for _, port := range []int{80, 443} {
		name := "http_allowed"
		if port == 443 {
			name = "https_allowed"
		}
		rule("forward", name, "accept", ingress(), match(payload("tcp", "dport"), "==", port))
	}
	rule("forward", "other_egress_denied", "drop", ingress())
	return objects
}
func prefix(cidr string) object {
	p := netip.MustParsePrefix(cidr)
	return object{"prefix": object{"addr": p.Addr().String(), "len": p.Bits()}}
}
func originDigest() string {
	raw, _ := json.Marshal(object{"schema": "acornfox-runtime-network.v1", "network": Network, "bridge": Bridge, "subnet": Subnet, "gateway": Gateway, "ipv6": false, "options": dockerOptions(), "rules": policyObjects(strings.Repeat("0", 64))})
	return hashBytes(raw)
}
func policyFingerprint(owner string) (string, error) {
	raw, _ := json.Marshal(object{"nftables": policyObjects(owner)})
	return fingerprint(raw)
}
func policyCommands(owner string) []byte {
	commands := []object{}
	for i, obj := range policyObjects(owner) {
		verb := "add"
		if i == 0 {
			verb = "create"
		}
		commands = append(commands, object{verb: obj})
	}
	raw, _ := json.Marshal(object{"nftables": commands})
	return raw
}

func dockerOptions() map[string]string {
	return map[string]string{
		"com.docker.network.bridge.name":                 Bridge,
		"com.docker.network.bridge.enable_icc":           "false",
		"com.docker.network.bridge.enable_ip_masquerade": "true",
		"com.docker.network.bridge.host_binding_ipv4":    "127.0.0.1",
	}
}
func dockerLabels(owner string) map[string]string {
	return map[string]string{
		"open-card.managed": "true", "open-card.task-prefix": "acornfox", ownerLabel: owner, policyLabel: originDigest(),
	}
}

// PublicResolvers returns a fresh copy of the runtime policy's public IPv4
// DNS endpoints. Callers cannot mutate the policy through the returned slice.
func PublicResolvers() []string {
	return []string{"223.5.5.5", "223.6.6.6"}
}
