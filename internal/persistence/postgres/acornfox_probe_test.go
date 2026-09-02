package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

func TestAcornFoxProbeObservationValidationFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	status := 204
	valid := acornFoxProbeObservationForTest(now)
	valid.HTTPStatus = &status
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid HTTP response rejected: %v", err)
	}
	for _, item := range []AcornFoxProbeObservation{
		func() AcornFoxProbeObservation {
			item := valid
			item.Protocol = contracts.AcornFoxProbeProtocolTCP
			item.HTTPStatus = nil
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeTimeout
			item.HTTPStatus = nil
			item.ErrorCode = contracts.AcornFoxProbeErrorTimeout
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeRefused
			item.HTTPStatus = nil
			item.ErrorCode = contracts.AcornFoxProbeErrorConnectionRefused
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeMalformedResponse
			item.HTTPStatus = nil
			item.ErrorCode = contracts.AcornFoxProbeErrorMalformedResponse
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeCancelled
			item.HTTPStatus = nil
			item.ErrorCode = contracts.AcornFoxProbeErrorCancelled
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeNotApplicable
			item.HTTPStatus = nil
			item.LatencyMS = 0
			return item
		}(),
	} {
		if err := item.Validate(); err != nil {
			t.Errorf("valid probe fact rejected: %+v: %v", item, err)
		}
	}
	for _, item := range []AcornFoxProbeObservation{
		func() AcornFoxProbeObservation { item := valid; item.ID = " "; return item }(),
		func() AcornFoxProbeObservation { item := valid; item.AgentSequence = 0; return item }(),
		func() AcornFoxProbeObservation {
			item := valid
			item.AgentSequence = acornFoxProbeMaxAgentSequence + 1
			return item
		}(),
		func() AcornFoxProbeObservation { item := valid; item.TargetClass = "public"; return item }(),
		func() AcornFoxProbeObservation {
			item := valid
			item.FactDigest = "sha256:" + strings.Repeat("A", 64)
			return item
		}(),
		func() AcornFoxProbeObservation { item := valid; value := 600; item.HTTPStatus = &value; return item }(),
		func() AcornFoxProbeObservation { item := valid; item.LatencyMS = 60_001; return item }(),
		func() AcornFoxProbeObservation { item := valid; item.HTTPStatus = nil; return item }(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Protocol = contracts.AcornFoxProbeProtocolTCP
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.ErrorCode = contracts.AcornFoxProbeErrorTimeout
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Protocol = contracts.AcornFoxProbeProtocolTCP
			item.Outcome = contracts.AcornFoxProbeOutcomeMalformedResponse
			item.HTTPStatus = nil
			item.ErrorCode = contracts.AcornFoxProbeErrorMalformedResponse
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeTimeout
			item.HTTPStatus = nil
			item.ErrorCode = "timeout but raw"
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeTimeout
			item.HTTPStatus = nil
			item.ErrorCode = ""
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeRefused
			item.HTTPStatus = nil
			item.ErrorCode = ""
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeMalformedResponse
			item.HTTPStatus = nil
			item.ErrorCode = ""
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeCancelled
			item.HTTPStatus = nil
			item.ErrorCode = ""
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeNotApplicable
			item.HTTPStatus = nil
			item.LatencyMS = 1
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeNotApplicable
			item.LatencyMS = 0
			return item
		}(),
		func() AcornFoxProbeObservation {
			item := valid
			item.Outcome = contracts.AcornFoxProbeOutcomeNotApplicable
			item.HTTPStatus = nil
			item.LatencyMS = 0
			item.ErrorCode = contracts.AcornFoxProbeErrorTimeout
			return item
		}(),
	} {
		if err := item.Validate(); err == nil {
			t.Errorf("invalid probe fact accepted: %+v", item)
		}
	}
}

func TestAcornFoxProbeObservationMigrationIsBoundedAndAppendOnly(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0027_acornfox_probe_observations.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, fragment := range []string{
		"create table if not exists acornfox_probe_observations",
		"unique (task_id, agent_sequence)",
		"sample_id text not null unique",
		"foreign key (task_id, agent_sequence) references task_agent_events(task_id, sequence)",
		"protocol in ('http', 'tcp')",
		"target_class = 'loopback'",
		"outcome in ('responded', 'timeout', 'refused', 'malformed_response', 'cancelled', 'not_applicable')",
		"http_status between 100 and 599",
		"http_status is not null",
		"protocol = 'http' or outcome <> 'malformed_response'",
		"acornfox_probe_observations_agent_event_fk",
		"acornfox_probe_observations_task_scope",
		"error_code is not null",
		"is distinct from expected_application_id",
		"latency_ms between 0 and 60000",
		"fact_digest ~ '^sha256:[a-f0-9]{64}$'",
		"acornfox_probe_observations_are_immutable",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("probe migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"url", "host", "response_body", "raw_error", "healthy boolean", "public boolean", "update deployments", "update m4_", "delete from"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("probe migration stores or mutates forbidden %q", forbidden)
		}
	}
}

func acornFoxProbeObservationForTest(now time.Time) AcornFoxProbeObservation {
	return AcornFoxProbeObservation{
		ID: "probe_1", SampleID: "sample_1", TaskID: "task_1", AgentSequence: 1,
		ApplicationID: "app_1", EnvironmentID: "env_1", ReleaseID: "release_1", DeploymentID: "deployment_1",
		ServiceName: "web", Protocol: contracts.AcornFoxProbeProtocolHTTP, TargetClass: contracts.AcornFoxProbeTargetClassLoopback,
		Outcome: contracts.AcornFoxProbeOutcomeResponded, LatencyMS: 5, ObservedAt: now,
		FactDigest: "sha256:" + strings.Repeat("a", 64),
	}
}
