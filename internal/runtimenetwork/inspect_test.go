package runtimenetwork

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestDockerInspectorRequiresExactManagedTopology(t *testing.T) {
	owner := strings.Repeat("b", 64)
	good := networkFixture(owner)
	if _, err := inspectNetwork(good, owner, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ from, to string }{
		{`"EnableIPv6":false`, `"EnableIPv6":true`},
		{`"Driver":"bridge"`, `"Driver":"host"`},
		{`"Gateway":"10.203.254.1"`, `"Gateway":"10.203.254.2"`},
		{`"Subnet":"10.203.254.0/24"`, `"Subnet":"10.0.0.0/8"`},
		{`"com.docker.network.bridge.enable_icc":"false"`, `"com.docker.network.bridge.enable_icc":"true"`},
		{`"com.docker.network.bridge.name":"acornfox-r0"`, `"com.docker.network.bridge.name":"docker0"`},
		{`"open-card.managed":"true"`, `"open-card.managed":"false"`},
		{`"Config":[{`, `"Config":[{"AuxiliaryAddresses":{"reserved":"10.203.254.2"},`},
	} {
		bad := bytes.Replace(good, []byte(change.from), []byte(change.to), 1)
		if bytes.Equal(bad, good) {
			t.Fatal("ineffective mutation", change)
		}
		if _, err := inspectNetwork(bad, owner, ""); err == nil {
			t.Fatal("accepted changed network", change)
		}
	}
	if _, err := inspectNetwork(good, strings.Repeat("c", 64), ""); err == nil {
		t.Fatal("foreign owner accepted")
	}
	for _, bad := range []string{`null`, `[]`, `[{"Id":"a","Id":"b"}]`} {
		if _, err := inspectNetwork([]byte(bad), owner, ""); err == nil {
			t.Fatal("bad JSON", bad)
		}
	}
}

func TestNFTFingerprintIgnoresOnlyCountersHandlesAndMetainfo(t *testing.T) {
	owner := strings.Repeat("d", 64)
	objects := policyObjects(owner)
	baseline, _ := json.Marshal(object{"nftables": objects})
	var emitted []map[string]any
	if json.Unmarshal(mustJSON(t, objects), &emitted) != nil {
		t.Fatal("decode")
	}
	for _, entry := range emitted {
		for _, v := range entry {
			v.(map[string]any)["handle"] = float64(99)
		}
		if rule, ok := entry["rule"].(map[string]any); ok {
			for _, expr := range rule["expr"].([]any) {
				e := expr.(map[string]any)
				if _, exists := e["counter"]; exists {
					e["counter"] = object{"packets": 102, "bytes": 4024}
				}
			}
		}
	}
	emitted = append([]map[string]any{{"metainfo": object{"version": "1.0.9", "release_name": "Old Doc Yak", "json_schema_version": 1}}}, emitted...)
	actual := mustJSON(t, object{"nftables": emitted})
	a, e := fingerprint(baseline)
	b, f := fingerprint(actual)
	if e != nil || f != nil || a != b {
		t.Fatalf("volatile nft metadata changed fingerprint: %v %v", e, f)
	}
	for _, change := range []struct{ from, to string }{
		{`"drop":null`, `"accept":null`},
		{`"prio":-5`, `"prio":5`},
		{`"223.5.5.5"`, `"8.8.8.8"`},
		{`"bytes":4024`, `"bytes":4024,"unexpected":true`},
	} {
		modified := bytes.Replace(actual, []byte(change.from), []byte(change.to), 1)
		if bytes.Equal(actual, modified) {
			t.Fatal("ineffective mutation")
		}
		got, err := fingerprint(modified)
		if err == nil && got == a {
			t.Fatal("ignored policy drift", change)
		}
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Evaluate representative packets against the generated rule expressions.
// The verdict is only this table's decision; Docker retains the final policy.
type packet struct {
	iif, oif, family, protocol, src, dst, state string
	port                                        int
}

func policyVerdict(t *testing.T, chain string, p packet) string {
	t.Helper()
	var entries []map[string]map[string]any
	if err := json.Unmarshal(mustJSON(t, policyObjects(strings.Repeat("a", 64))), &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		r, ok := entry["rule"]
		if !ok || r["chain"] != chain {
			continue
		}
		matched := true
		for _, expr := range r["expr"].([]any) {
			e := expr.(map[string]any)
			if m, ok := e["match"].(map[string]any); ok {
				left := m["left"].(map[string]any)
				var value any
				switch {
				case left["meta"] != nil:
					switch left["meta"].(map[string]any)["key"] {
					case "iifname":
						value = p.iif
					case "oifname":
						value = p.oif
					case "nfproto":
						value = p.family
					}
				case left["ct"] != nil:
					value = p.state
				case left["payload"] != nil:
					field := left["payload"].(map[string]any)
					if field["protocol"] == "ip" {
						if p.family != "ipv4" {
							matched = false
							continue
						}
						if field["field"] == "saddr" {
							value = p.src
						} else {
							value = p.dst
						}
					} else {
						if field["protocol"] != p.protocol {
							matched = false
							continue
						}
						value = float64(p.port)
					}
				}
				equal := false
				switch right := m["right"].(type) {
				case map[string]any:
					if values, ok := right["set"].([]any); ok {
						for _, v := range values {
							equal = equal || value == v
						}
					} else if prefix, ok := right["prefix"].(map[string]any); ok {
						addr, err := netip.ParseAddr(value.(string))
						network := netip.PrefixFrom(netip.MustParseAddr(prefix["addr"].(string)), int(prefix["len"].(float64)))
						equal = err == nil && network.Contains(addr)
					}
				default:
					equal = value == right
				}
				if m["op"] == "!=" {
					equal = !equal
				}
				matched = matched && equal
			}
			if matched {
				if _, ok := e["accept"]; ok {
					return "accept"
				}
				if _, ok := e["drop"]; ok {
					return "drop"
				}
			}
		}
	}
	return "accept"
}
func TestScopedRulesPreserveRepliesAndRejectRuntimeEscape(t *testing.T) {
	base := packet{iif: Bridge, oif: "eth0", family: "ipv4", protocol: "tcp", src: "10.203.254.2", dst: "93.184.216.34", state: "new", port: 443}
	for _, tc := range []struct {
		name, chain, want string
		change            func(*packet)
	}{
		{"public https", "forward", "accept", func(*packet) {}},
		{"public http", "forward", "accept", func(p *packet) { p.port = 80 }},
		{"public ssh", "forward", "drop", func(p *packet) { p.port = 22 }},
		{"public udp", "forward", "drop", func(p *packet) { p.protocol = "udp" }},
		{"metadata", "forward", "drop", func(p *packet) { p.dst = "169.254.169.254" }},
		{"post DNAT private", "forward", "drop", func(p *packet) { p.dst = "172.17.0.2" }},
		{"IPv6", "forward", "drop", func(p *packet) { p.family = "ipv6"; p.dst = "2606:4700::1111" }},
		{"spoof", "forward", "drop", func(p *packet) { p.src = "10.203.253.2" }},
		{"sibling", "forward", "drop", func(p *packet) { p.oif = Bridge; p.dst = "10.203.254.3" }},
		{"DNS UDP", "forward", "accept", func(p *packet) { p.dst = "223.5.5.5"; p.port = 53; p.protocol = "udp" }},
		{"DNS TCP", "forward", "accept", func(p *packet) { p.dst = "223.6.6.6"; p.port = 53 }},
		{"other DNS", "forward", "drop", func(p *packet) { p.dst = "8.8.8.8"; p.port = 53 }},
		{"published response", "forward", "accept", func(p *packet) { p.dst = "192.168.1.10"; p.port = 51234; p.state = "established" }},
		{"host IP", "input", "drop", func(p *packet) { p.dst = "10.203.254.1" }},
		{"public host alias", "input", "drop", func(*packet) {}},
		{"host published response", "input", "accept", func(p *packet) { p.dst = Gateway; p.port = 50000; p.state = "established" }},
		{"unrelated host ingress", "input", "accept", func(p *packet) { p.iif = "eth0"; p.port = 22 }},
		{"unrelated forwarding", "forward", "accept", func(p *packet) { p.iif = "docker0"; p.dst = "172.18.0.2"; p.port = 3306 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.change(&p)
			if got := policyVerdict(t, tc.chain, p); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
