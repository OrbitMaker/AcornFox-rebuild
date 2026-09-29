package main

import "testing"

func TestNativeStageAcceptsOnlyFixedBundleID(t *testing.T) {
	if got, err := parseNativeStageArgs([]string{"--bundle-id", "ur-20260928"}); err != nil || got != "ur-20260928" {
		t.Fatalf("private bundle ID rejected: %q %v", got, err)
	}
	for _, args := range [][]string{{}, {"--bundle-id", "../escape"}, {"--bundle-id", "/tmp/arbitrary"}, {"--bundle-id", "Upper"}, {"--bundle-id", "ur-good", "--facts-json", "fake.json"}, {"--bundle-id", "ur-good", "extra"}} {
		if _, err := parseNativeStageArgs(args); err == nil {
			t.Fatalf("unsafe stage flags accepted: %v", args)
		}
	}
}
