package v1

import (
	"encoding/json"
	"testing"
)

func TestRequiredCapabilityForTaskRequestPrefersProbeMarkerOverRuntimeMarker(t *testing.T) {
	task := TaskRequest{Kind: TaskObserve, Parameters: json.RawMessage(`{"acornfox_probe_payload_type":"probe","request":{}}`)}
	if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxProbe {
		t.Fatalf("probe capability = %q, want %q", got, AgentCapabilityAcornFoxProbe)
	}
	task.Parameters = json.RawMessage(`{"acornfox_probe_payload_type":"probe","acornfox_payload_type":"observe","request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxProbe {
		t.Fatalf("mixed marker did not preserve probe authority: %q", got)
	}
	task.Parameters = json.RawMessage(`{"acornfox_probe_payload_type":"shell","request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "acornfox_probe.unknown_payload" {
		t.Fatalf("unknown probe marker capability = %q", got)
	}
	task.Parameters = json.RawMessage(`{"nested":{"acornfox_probe_payload_type":"probe"}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "" {
		t.Fatalf("nested probe marker changed routing: %q", got)
	}
}
