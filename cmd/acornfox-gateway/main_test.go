package main

import "testing"

func TestGatewayFlagsRequireFixedBindingAndNoArbitraryAdmin(t *testing.T) {
	valid := []string{"--runtime-binding", "/run/acornfox/trust/runtime-binding.json", "--socket-gid", "981", "--caddy-admin-uid", "994", "--caddy-admin-gid", "981"}
	if c, err := parseFlags(valid); err != nil || c.socketGID != 981 || c.adminUID != 994 {
		t.Fatalf("fixed Gateway identities rejected: %v", err)
	}
	for _, flags := range [][]string{
		{"--runtime-binding", "/run/acornfox/trust/runtime-binding.json", "--socket-gid", "981", "--caddy-admin-uid", "994"},
		{"--runtime-binding", "/tmp/runtime-binding.json", "--socket-gid", "981", "--caddy-admin-uid", "994", "--caddy-admin-gid", "981"},
		{"--runtime-binding", "/run/acornfox/trust/runtime-binding.json", "--socket-gid", "981", "--caddy-admin-uid", "994", "--caddy-admin-gid", "995"},
		{"--runtime-binding", "/run/acornfox/trust/runtime-binding.json", "--socket-gid", "981", "--caddy-admin-uid", "994", "--caddy-admin-gid", "981", "--admin-url", "http://127.0.0.1:2019"},
	} {
		if _, err := parseFlags(flags); err == nil {
			t.Fatalf("unsafe Gateway configuration accepted: %v", flags)
		}
	}
}
