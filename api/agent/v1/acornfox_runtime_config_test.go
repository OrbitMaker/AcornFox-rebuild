package v1

import (
	"encoding/json"
	"testing"
)

func TestAcornFoxRuntimeConfigCapabilityCannotReachLegacyAgent(t *testing.T) {
	for _, action := range []string{"deploy", "redeploy", "restart", "observe", "destroy"} {
		task := TaskRequest{Kind: TaskDeploy, Parameters: json.RawMessage(`{"acornfox_payload_type":"` + action + `","request":{"fact":{"schema_version":2,"config_digest":"sha256:accepted","configuration":{}}}}`)}
		if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxRuntimeConfig {
			t.Fatalf("%s selected %s", action, got)
		}
	}
	for _, fact := range []string{`{"configuration":{}}`, `{"schema_version":1}`, `{"schema_version":2,"config_digest":"x","configuration":null}`} {
		task := TaskRequest{Kind: TaskDeploy, Parameters: json.RawMessage(`{"acornfox_payload_type":"deploy","request":{"fact":` + fact + `}}`)}
		if RequiredCapabilityForTaskRequest(task) != "acornfox.unknown_configuration" {
			t.Fatal("invalid configuration routed to old agent")
		}
	}
}
