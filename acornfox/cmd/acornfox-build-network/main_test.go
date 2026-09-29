package main

import "testing"

func TestNativeBuildNetworkOnlyServesFixedCommands(t *testing.T) {
	for _, command := range []string{"serve", "cleanup"} {
		got, err := parseCommand([]string{command})
		if err != nil || got != command {
			t.Fatalf("fixed command %q rejected: %v", command, err)
		}
	}
	for _, args := range [][]string{nil, {"serve", "--policy", "/tmp/policy"}, {"cleanup", "extra"}, {"run"}} {
		if _, err := parseCommand(args); err == nil {
			t.Fatalf("untrusted build network command accepted: %v", args)
		}
	}
}
