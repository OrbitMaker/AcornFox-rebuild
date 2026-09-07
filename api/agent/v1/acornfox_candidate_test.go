package v1

import (
	"encoding/json"
	"testing"
)

func TestRequiredCapabilityForTaskRequestPrefersCandidateMarker(t *testing.T) {
	task := TaskRequest{Kind: TaskDeploy, Parameters: json.RawMessage(`{"acornfox_candidate_payload_type":"acornfox_candidate_validation_v1","acornfox_log_payload_type":"logs","acornfox_probe_payload_type":"probe","acornfox_payload_type":"deploy","request":{}}`)}
	if got := RequiredCapabilityForTaskRequest(task); got != AgentCapabilityAcornFoxCandidateValidation {
		t.Fatalf("candidate capability = %q, want %q", got, AgentCapabilityAcornFoxCandidateValidation)
	}
	task.Parameters = json.RawMessage(`{"acornfox_candidate_payload_type":"shell","request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "acornfox_candidate.unknown_payload" {
		t.Fatalf("unknown candidate marker capability = %q", got)
	}
	task.Parameters = json.RawMessage(`{"acornfox_candidate_payload_type":{},"request":{}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "acornfox_candidate.unknown_payload" {
		t.Fatalf("non-string candidate marker capability = %q", got)
	}
	task.Parameters = json.RawMessage(`{"nested":{"acornfox_candidate_payload_type":"acornfox_candidate_validation_v1"}}`)
	if got := RequiredCapabilityForTaskRequest(task); got != "" {
		t.Fatalf("nested candidate marker changed routing: %q", got)
	}
}
