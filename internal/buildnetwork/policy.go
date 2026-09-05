// Package buildnetwork implements the installed single-host build network.
// It is separate from the source-specific, download-then-offline self-build
// proof policy: user Dockerfile build steps may retrieve public dependencies.
package buildnetwork

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

const (
	Namespace          = "acornfox-buildkit"
	HostLink           = "acornfox-bh"
	WorkerLink         = "acornfox-bw"
	Gateway            = "10.203.253.1"
	WorkerIP           = "10.203.253.2"
	RunRoot            = "/run/acornfox-build-policy"
	SocketPath         = RunRoot + "/attest.sock"
	PolicyPath         = "/etc/acornfox/build-network-policy.json"
	ResolverPath       = "/etc/acornfox/build-resolv.conf"
	BuildkitSocketPath = "/run/acornfox-buildkit/buildkitd.sock"
)

var ErrPolicy = errors.New("AcornFox build network policy is invalid")

type Policy struct {
	Schema               string   `json:"schema"`
	Product              string   `json:"product"`
	Scope                string   `json:"scope"`
	Resolvers            []string `json:"resolver_ipv4"`
	PublicTCPPorts       []int    `json:"public_tcp_ports"`
	DeniedIPv4           []string `json:"deny_ipv4_cidrs"`
	DenyIPv6             bool     `json:"deny_ipv6"`
	DenyHost             bool     `json:"deny_host_addresses"`
	DenyIngress          bool     `json:"deny_new_ingress"`
	NoAmbientCredentials bool     `json:"no_ambient_credentials"`
}

func DefaultPolicy() Policy {
	return Policy{
		Schema: "acornfox-build-network-policy.v1", Product: "acornfox", Scope: "build-execution",
		Resolvers: []string{"1.0.0.1", "1.1.1.1"}, PublicTCPPorts: []int{80, 443},
		DeniedIPv4: []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"},
		DenyIPv6:   true, DenyHost: true, DenyIngress: true, NoAmbientCredentials: true,
	}
}

func CanonicalPolicy() []byte {
	raw, _ := json.Marshal(DefaultPolicy())
	return append(raw, '\n')
}

func ParsePolicy(raw []byte) (Policy, string, error) {
	var policy Policy
	if len(raw) > 65536 || !bytes.Equal(raw, CanonicalPolicy()) || json.Unmarshal(raw, &policy) != nil || !reflect.DeepEqual(policy, DefaultPolicy()) {
		return policy, "", ErrPolicy
	}
	sum := sha256.Sum256(raw)
	return policy, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ResolverConfig() []byte {
	return []byte("nameserver 1.1.1.1\nnameserver 1.0.0.1\noptions timeout:2 attempts:2\n")
}

func RootlessProfile() []byte {
	return []byte("abi <abi/4.0>,\ninclude <tunables/global>\nprofile acornfox-rootlesskit /opt/acornfox/{current,releases/*}/bin/rootlesskit flags=(unconfined) {\n  userns,\n}\n")
}

// Rules are fixed generated input, never shell or nft fragments supplied by an
// application. The outer netns belongs to the initial user namespace, so a
// rootless BuildKit child cannot change these rules.
func WorkerRules() string {
	return `table inet acornfox_build {
 set denied_v4 { type ipv4_addr; flags interval; elements = { ` + strings.Join(DefaultPolicy().DeniedIPv4, ", ") + ` } }
 chain input { type filter hook input priority 0; policy drop;
  ct state established,related accept
  counter drop comment "new_ingress_denied"
 }
 chain output { type filter hook output priority 0; policy drop;
  meta nfproto ipv6 counter drop comment "ipv6_denied"
  ip daddr @denied_v4 counter drop comment "private_denied"
  ip daddr { 1.0.0.1, 1.1.1.1 } udp dport 53 counter accept comment "dns_udp_allowed"
  ip daddr { 1.0.0.1, 1.1.1.1 } tcp dport 53 counter accept comment "dns_tcp_allowed"
  tcp dport { 80, 443 } counter accept comment "public_web_allowed"
  counter drop comment "other_egress_denied"
 }
 chain forward { type filter hook forward priority 0; policy drop; }
}
`
}

func HostRules() string {
	return `table inet acornfox_build_guard {
 set denied_v4 { type ipv4_addr; flags interval; elements = { ` + strings.Join(DefaultPolicy().DeniedIPv4, ", ") + ` } }
 chain input { type filter hook input priority -5; policy accept;
  iifname "` + HostLink + `" counter drop comment "build_to_host_denied"
 }
 chain forward { type filter hook forward priority -5; policy accept;
  iifname "` + HostLink + `" meta nfproto ipv6 counter drop
  iifname "` + HostLink + `" ip saddr != ` + WorkerIP + ` counter drop
  iifname "` + HostLink + `" ip daddr @denied_v4 counter drop comment "post_dnat_private_denied"
 }
}
table ip acornfox_build_nat {
 chain postrouting { type nat hook postrouting priority 100; policy accept;
  iifname "` + HostLink + `" ip saddr ` + WorkerIP + ` masquerade
 }
}
`
}

func DockerRules() [][]string {
	return [][]string{
		{"-i", HostLink, "-s", WorkerIP + "/32", "-m", "comment", "--comment", "acornfox-build-egress-v1", "-j", "ACCEPT"},
		{"-o", HostLink, "-d", WorkerIP + "/32", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "acornfox-build-return-v1", "-j", "ACCEPT"},
	}
}
