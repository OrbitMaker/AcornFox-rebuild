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
	if _, err := Resolve(ProcessServer, "legacy", cleanValues); err == nil {
		t.Fatal("legacy identity accepted clean runtime mode")
	}
	if _, err := Resolve(ProcessServer, "acornfox", lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": "clean", "OPEN_CARD_SERVER_ADDR": "x"})); err == nil {
		t.Fatal("clean identity accepted a legacy key")
	}
}

func TestResolveCapturesEachKnownNameOnceAndKeepsSnapshotValues(t *testing.T) {
	reads := map[string]int{}
	environment, err := Resolve(ProcessServer, "acornfox", func(name string) (string, bool) {
		reads[name]++
		if reads[name] > 1 {
			t.Fatalf("read %q more than once", name)
		}
		switch name {
		case "ACORNFOX_RUNTIME_MODE":
			return "clean", true
		case "ACORNFOX_MIGRATION_COMPATIBILITY":
			// A second read would observe a forbidden value. Resolution must use
			// this one captured value throughout mode and migration checks.
			return "", true
		case "ACORNFOX_SERVER_ADDR":
			return "127.0.0.1:8090", true
		default:
			return "", false
		}
	})
	if err != nil || environment.Get(RuntimeMode) != "clean" || environment.Get(ServerAddr) != "127.0.0.1:8090" {
		t.Fatalf("snapshot environment=%#v err=%v", environment, err)
	}
	if reads["ACORNFOX_MIGRATION_COMPATIBILITY"] != 1 {
		t.Fatalf("migration compatibility reads=%d want=1", reads["ACORNFOX_MIGRATION_COMPATIBILITY"])
	}
}

func TestResolveDoesNotReReadMigrationCompatibilityAfterItChanges(t *testing.T) {
	migrationReads := 0
	environment, err := Resolve(ProcessServer, "acornfox", func(name string) (string, bool) {
		switch name {
		case "ACORNFOX_RUNTIME_MODE":
			return "clean", true
		case "ACORNFOX_MIGRATION_COMPATIBILITY":
			migrationReads++
			if migrationReads == 1 {
				return "", true
			}
			return "enabled-after-snapshot", true
		default:
			return "", false
		}
	})
	if err != nil || !environment.Clean() || migrationReads != 1 {
		t.Fatalf("environment=%#v err=%v migration reads=%d", environment, err, migrationReads)
	}
}

func TestResolveRejectsIdentityModeMismatchAndUnknownCleanNames(t *testing.T) {
	for _, value := range []string{"", "clean", "other"} {
		if _, err := Resolve(ProcessAgent, "legacy", lookup(map[string]string{"ACORNFOX_RUNTIME_MODE": value})); err == nil {
			t.Fatalf("legacy accepted runtime mode %q", value)
		}
	}
	for _, unknown := range []map[string]string{{"OPEN_CARD_UNKNOWN": "x"}, {"ACORNFOX_UNKNOWN": "x"}} {
		environ := []string{"ACORNFOX_RUNTIME_MODE=clean"}
		for name, value := range unknown {
			environ = append(environ, name+"="+value)
		}
		if _, err := ResolveEnviron(ProcessServer, "acornfox", environ); err == nil {
			t.Fatalf("clean process accepted unknown name %q", environ[1])
		}
	}
	if _, err := ResolveEnviron(ProcessServer, "acornfox", []string{"ACORNFOX_RUNTIME_MODE=clean", "ACORNFOX_MIGRATION_COMPATIBILITY=", "ACORNFOX_PUBLIC_ROOT=/srv"}); err != nil {
		t.Fatalf("documented clean names rejected: %v", err)
	}
}

func TestKeySpecsAreCompleteAndNamesAreUnique(t *testing.T) {
	if len(specs) != int(AssistantToolsSocket) {
		t.Fatalf("key specs=%d want=%d", len(specs), AssistantToolsSocket)
	}
	names := map[string]Key{}
	for key := RuntimeMode; key <= AssistantToolsSocket; key++ {
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
	_ = Environment{}.Get(AssistantToolsSocket + 1)
}
