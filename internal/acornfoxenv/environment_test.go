package acornfoxenv

import (
	"strings"
	"testing"
)

func lookup(values map[string]string) Lookup {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func TestResolveLegacyAndCleanBoundary(t *testing.T) {
	legacy, err := Resolve("/opt/open-card-server", lookup(map[string]string{"OPEN_CARD_SERVER_ADDR": "127.0.0.1:1"}))
	if err != nil || legacy.Clean() || legacy.Get("OPEN_CARD_SERVER_ADDR") != "127.0.0.1:1" {
		t.Fatalf("legacy=%#v %v", legacy, err)
	}
	clean, err := Resolve("/opt/acornfox-server", lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": "clean", "ACORNFOX_SERVER_ADDR": "127.0.0.1:2"}))
	if err != nil || !clean.Clean() || clean.Get("OPEN_CARD_SERVER_ADDR") != "127.0.0.1:2" {
		t.Fatalf("clean=%#v %v", clean, err)
	}
	for _, values := range []map[string]string{{}, {"ACORNFOX_RUNTIME_MODE": "clean", "OPEN_CARD_SERVER_ADDR": "x"}, {"ACORNFOX_RUNTIME_MODE": "clean", "ACORNFOX_MIGRATION_COMPATIBILITY": "legacy"}} {
		if _, err := Resolve("acornfox-agent", lookup(values)); err == nil || strings.Contains(strings.ToLower(err.Error()), "open card") {
			t.Fatalf("invalid clean env accepted/leaked: %v", err)
		}
	}
	if _, err := Resolve("other", lookup(nil)); err == nil {
		t.Fatal("unknown executable accepted")
	}
}
