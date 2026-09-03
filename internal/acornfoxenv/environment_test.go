package acornfoxenv

import (
	"strings"
	"testing"
)

func lookup(values map[string]string) Lookup {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}

func TestResolveLegacyAndCleanBoundary(t *testing.T) {
	legacy, err := Resolve(ProcessServer, "legacy", lookup(map[string]string{"OPEN_CARD_SERVER_ADDR": "127.0.0.1:1", "ACORNFOX_PUBLIC_ROOT": "/srv"}))
	if err != nil || legacy.Clean() || legacy.Get(ServerAddr) != "127.0.0.1:1" || legacy.Get(PublicRoot) != "/srv" || legacy.ProductLabel() != "Open Card" {
		t.Fatalf("legacy=%#v %v", legacy, err)
	}
	clean, err := Resolve(ProcessServer, "acornfox", lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": "clean", "ACORNFOX_MIGRATION_COMPATIBILITY": "", "ACORNFOX_SERVER_ADDR": "127.0.0.1:2"}))
	if err != nil || !clean.Clean() || clean.Get(ServerAddr) != "127.0.0.1:2" || clean.Name(ServerAddr) != "ACORNFOX_SERVER_ADDR" || clean.ProductLabel() != "AcornFox" {
		t.Fatalf("clean=%#v %v", clean, err)
	}
	for _, values := range []map[string]string{{}, {"ACORNFOX_RUNTIME_MODE": "clean", "OPEN_CARD_SERVER_ADDR": "x"}, {"ACORNFOX_RUNTIME_MODE": "clean", "ACORNFOX_MIGRATION_COMPATIBILITY": "legacy"}} {
		if _, err := Resolve(ProcessAgent, "acornfox", lookup(values)); err == nil || strings.Contains(strings.ToLower(err.Error()), "open card") {
			t.Fatalf("invalid clean env accepted/leaked: %v", err)
		}
	}
	if _, err := Resolve(ProcessServer, "other", lookup(nil)); err == nil {
		t.Fatal("unknown identity accepted")
	}
}

func TestResolveIdentityCannotBeChangedByBinaryNameOrEnvironment(t *testing.T) {
	cleanValues := lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": "clean", "ACORNFOX_SERVER_ADDR": "127.0.0.1:2"})
	if legacy, err := Resolve(ProcessServer, "legacy", cleanValues); err != nil || legacy.Clean() || legacy.Get(ServerAddr) != "" {
		t.Fatalf("legacy identity was upgraded by configuration: %#v %v", legacy, err)
	}
	if _, err := Resolve(ProcessServer, "acornfox", lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": "clean", "OPEN_CARD_SERVER_ADDR": "x"})); err == nil {
		t.Fatal("clean identity accepted a legacy key")
	}
}

func TestKeySpecsAreCompleteAndNamesAreUnique(t *testing.T) {
	if len(specs) != int(MigrationCompatibility) {
		t.Fatalf("key specs=%d want=%d", len(specs), MigrationCompatibility)
	}
	names := map[string]Key{}
	for key := RuntimeMode; key <= MigrationCompatibility; key++ {
		spec := mustSpec(key)
		if spec.canonical == "" {
			t.Fatalf("key %d has no canonical name", key)
		}
		for _, name := range []string{spec.legacy, spec.canonical} {
			if name == "" {
				continue
			}
			if previous, exists := names[name]; exists && previous != key {
				t.Fatalf("name %q belongs to both %d and %d", name, previous, key)
			}
			names[name] = key
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown key was accepted")
		}
	}()
	_ = Environment{}.Get(MigrationCompatibility + 1)
}
