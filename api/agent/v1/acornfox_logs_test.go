package v1

import (
	"encoding/json"
	"testing"
)

func TestRequiredCapabilityForTaskRequestPrefersLogsMarkerOverOtherAcornFoxMarkers(t *testing.T) {
	task := TaskRequest{Kind: TaskLogs, Parameters: json.RawMessage(`{"acornfox_log_payload_type":"logs","request":{}}`)}
	if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxLogs {
		t.Fatalf("logs capability = %q, want %q", got, AgentCapabilityAcornFoxLogs)
	}
	task.Parameters = json.RawMessage(`{"acornfox_log_payload_type":"logs","acornfox_probe_payload_type":"probe","acornfox_payload_type":"observe","request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxLogs {
		t.Fatalf("mixed marker did not preserve logs authority: %q", got)
	}
	task.Parameters = json.RawMessage(`{"acornfox_log_payload_type":"shell","request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "acornfox_logs.unknown_payload" {
		t.Fatalf("unknown logs marker capability = %q", got)
	}
	task.Parameters = json.RawMessage(`{"nested":{"acornfox_log_payload_type":"logs"}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "" {
		t.Fatalf("nested logs marker changed routing: %q", got)
	}
}
