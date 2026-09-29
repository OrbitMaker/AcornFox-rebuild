package compatibility

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func compatibilityFixtureDir(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "tests", "fixtures", "compatibility")
}

func readFixtureObject(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(compatibilityFixtureDir(t), name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("fixture %q is not a JSON object: %v", name, err)
	}
	return object
}

func TestCompatibilityFixturesAreValidJSON(t *testing.T) {
	entries, err := os.ReadDir(compatibilityFixtureDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("compatibility fixture directory is empty")
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(compatibilityFixtureDir(t), entry.Name()))
		if err != nil {
			t.Errorf("read %s: %v", entry.Name(), err)
			continue
		}
		if !json.Valid(data) {
			t.Errorf("fixture %s is invalid JSON", entry.Name())
		}
	}
}

func TestCompatibilityFixturesHaveExpectedKeys(t *testing.T) {
	commonEnvelope := []string{"protocol", "version", "message_id", "instance_id", "node_id", "kind", "sent_at", "payload"}
	for _, name := range []string{
		"agent-envelope-v1-legacy.json",
		"agent-envelope-v1-current.json",
		"agent-envelope-v1-current-unknown-ordinary.json",
		"agent-envelope-v1-current-unknown-security.json",
		"agent-envelope-v1-current-missing-optional.json",
		"agent-envelope-v2-major-mismatch.json",
	} {
		object := readFixtureObject(t, name)
		for _, key := range commonEnvelope {
			if _, ok := object[key]; !ok {
				t.Errorf("fixture %s is missing envelope key %q", name, key)
			}
		}
	}

	for _, name := range []string{"sse-event-v1-old.json", "sse-event-v1-current.json", "outbox-payload-v1-old.json", "outbox-payload-v1-current.json"} {
		object := readFixtureObject(t, name)
		for _, key := range []string{"id", "operation_id", "application_id", "sequence", "occurred_at", "kind", "status"} {
			if _, ok := object[key]; !ok {
				t.Errorf("fixture %s is missing event key %q", name, key)
			}
		}
	}
	for _, name := range []string{"task-payload-v1-old.json", "task-payload-v1-current.json"} {
		object := readFixtureObject(t, name)
		for _, key := range []string{"kind", "parameters"} {
			if _, ok := object[key]; !ok {
				t.Errorf("fixture %s is missing task key %q", name, key)
			}
		}
	}
}

func TestCompatibilityFixturesEncodeVersionDifferences(t *testing.T) {
	cases := []struct {
		name        string
		version     string
		hasSequence bool
		hasDetails  bool
	}{
		{name: "agent-envelope-v1-legacy.json", version: "v1"},
		{name: "agent-envelope-v1-current.json", version: "1.1", hasSequence: true, hasDetails: true},
		{name: "agent-envelope-v1-current-missing-optional.json", version: "v1"},
		{name: "agent-envelope-v2-major-mismatch.json", version: "2.0"},
	}
	for _, tc := range cases {
		object := readFixtureObject(t, tc.name)
		var version string
		if err := json.Unmarshal(object["version"], &version); err != nil {
			t.Errorf("fixture %s version: %v", tc.name, err)
		}
		if version != tc.version {
			t.Errorf("fixture %s version=%q want %q", tc.name, version, tc.version)
		}
		if _, ok := object["agent_sequence"]; ok != tc.hasSequence {
			t.Errorf("fixture %s agent_sequence presence=%v want %v", tc.name, ok, tc.hasSequence)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(object["payload"], &payload); err != nil {
			t.Errorf("fixture %s payload: %v", tc.name, err)
			continue
		}
		if _, ok := payload["details"]; ok != tc.hasDetails {
			t.Errorf("fixture %s details presence=%v want %v", tc.name, ok, tc.hasDetails)
		}
	}

	for _, name := range []string{"sse-event-v1-old.json", "outbox-payload-v1-old.json", "task-payload-v1-old.json"} {
		if _, ok := readFixtureObject(t, name)["schema_version"]; ok {
			t.Errorf("legacy fixture %s unexpectedly has schema_version", name)
		}
	}
	for _, name := range []string{"sse-event-v1-current.json", "outbox-payload-v1-current.json", "task-payload-v1-current.json"} {
		object := readFixtureObject(t, name)
		if _, ok := object["schema_version"]; !ok {
			t.Errorf("current fixture %s is missing schema_version", name)
		}
	}
}
