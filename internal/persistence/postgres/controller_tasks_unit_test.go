package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestMapControllerOperationInsertError(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		constraint string
		wantCode   domain.ErrorCode
	}{
		{name: "one active operation", constraint: "operations_one_active_per_environment", wantCode: domain.ErrConflict},
		{name: "idempotency identity", constraint: "operations_environment_id_idempotency_key_key", wantCode: domain.ErrConflict},
		{name: "operation identity", constraint: "operations_pkey", wantCode: domain.ErrConflict},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := mapControllerOperationInsertError(&pgconn.PgError{ConstraintName: test.constraint})
			if !domain.IsCode(err, test.wantCode) {
				t.Fatalf("expected %s, got %v", test.wantCode, err)
			}
			if errors.Is(err, ErrEnvironmentOperationActive) != (test.constraint == "operations_one_active_per_environment") {
				t.Fatal("active operation conflict lost its distinct identity")
			}
		})
	}

	backend := errors.New("backend unavailable")
	if got := mapControllerOperationInsertError(backend); !errors.Is(got, backend) {
		t.Fatalf("unclassified backend error lost its cause: %v", got)
	}
}

func TestTaskOutcomeDoesNotReTransitionTerminalDeployment(t *testing.T) {
	for _, status := range []domain.DeploymentStatus{domain.DeploymentFailed, domain.DeploymentRolledBack, domain.DeploymentStopped} {
		deployment := domain.Deployment{Status: status}
		if err := transitionDeploymentForTaskOutcome(&deployment, domain.DeploymentFailed, time.Now()); err != nil {
			t.Fatalf("terminal %s rejected cleanup outcome: %v", status, err)
		}
		if deployment.Status != status {
			t.Fatalf("terminal %s was rewritten to %s", status, deployment.Status)
		}
	}
}

func TestTaskOutcomeStillEnforcesNonTerminalStateMachine(t *testing.T) {
	deployment := domain.Deployment{Status: domain.DeploymentDeploying}
	if err := transitionDeploymentForTaskOutcome(&deployment, domain.DeploymentFailed, time.Now()); err != nil {
		t.Fatal(err)
	}
	if deployment.Status != domain.DeploymentFailed {
		t.Fatalf("deployment status=%s", deployment.Status)
	}
}

func TestAcornFoxProbeTaskAndObservationParsingFailsClosed(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_probe", EnvironmentID: "env_probe", ReleaseID: "release_probe", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1024, PIDs: 10, DiskReservationBytes: 2048}, ContainerPort: 8080, AcceptedAt: now, Immutable: true}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, contracts.AcornFoxProbeProtocolHTTP, "/ready", "probe-once")
	if err != nil {
		t.Fatal(err)
	}
	parameters, _ := json.Marshal(map[string]any{"acornfox_probe_payload_type": "probe", "request": request})
	payload, _ := json.Marshal(map[string]any{"kind": v1.TaskObserve, "parameters": json.RawMessage(parameters)})
	parsed, marked, err := decodeAcornFoxProbeTaskPayload(payload)
	if err != nil || !marked || parsed != request {
		t.Fatalf("valid probe task was not recognized: parsed=%#v marked=%v err=%v", parsed, marked, err)
	}
	deploymentID, _ := contracts.AcornFoxRuntimeDeploymentID(fact)
	status := 503
	digest, err := contracts.AcornFoxProbeFactDigest(request, contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: fact.ServiceName, InternalAddress: "127.0.0.1:39124"}, contracts.AcornFoxProbeOutcomeResponded, &status)
	if err != nil {
		t.Fatal(err)
	}
	result := contracts.AcornFoxProbeResult{ApplicationID: fact.ApplicationID, EnvironmentID: fact.EnvironmentID, ReleaseID: fact.ReleaseID, DeploymentID: deploymentID, ServiceName: fact.ServiceName, Protocol: request.Protocol, TargetClass: "loopback", Outcome: contracts.AcornFoxProbeOutcomeResponded, HTTPStatus: &status, ObservedAt: now, FactDigest: digest}
	details, _ := json.Marshal(result)
	good := v1.Observation{TaskID: "task_probe", Sequence: 1, TargetRef: "deployment/" + deploymentID.String() + "/probe/web", Status: "unknown", Healthy: false, At: now, EvidenceRefs: []string{"acornfox-probe:" + digest}, Details: details}
	wire, _ := json.Marshal(good)
	if _, err := validateAcornFoxProbeAgentObservation(wire, "task_probe", 3, deploymentID, request); err != nil {
		t.Fatalf("valid probe observation rejected: %v", err)
	}
	for _, bad := range []json.RawMessage{
		mustJSON(t, func() v1.Observation { value := good; value.TaskID = "task_other"; return value }()),
		mustJSON(t, func() v1.Observation { value := good; value.Sequence = 2; return value }()),
		mustJSON(t, func() v1.Observation { value := good; value.Healthy = true; return value }()),
		mustJSON(t, func() v1.Observation {
			value := good
			value.EvidenceRefs = []string{"acornfox-probe:sha256:" + strings.Repeat("b", 64)}
			return value
		}()),
		mustJSON(t, func() v1.Observation {
			value := good
			value.EvidenceRefs = append(value.EvidenceRefs, "extra")
			return value
		}()),
		mustJSON(t, func() v1.Observation { value := good; value.At = now.Add(time.Second); return value }()),
	} {
		if _, err := validateAcornFoxProbeAgentObservation(bad, "task_probe", 3, deploymentID, request); err == nil {
			t.Fatalf("mismatched probe observation was accepted: %s", bad)
		}
	}
	badPayload := []byte(`{"kind":"observe","parameters":{"acornfox_probe_payload_type":"probe","request":{},"unexpected":true}}`)
	if _, marked, err := decodeAcornFoxProbeTaskPayload(badPayload); !marked || err == nil {
		t.Fatalf("malformed marked probe task fell through: marked=%v err=%v", marked, err)
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
