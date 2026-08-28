package v1

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
)

type m2WireFixture struct {
	envelope     Envelope
	capabilities []string
	registryRef  string
	afterDigest  string
}

func readM2WireFixture(t *testing.T, name, negotiated string) (m2WireFixture, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "m2", name))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var fixture m2WireFixture
	_ = json.Unmarshal(raw["capabilities"], &fixture.capabilities)
	_ = json.Unmarshal(raw["registry_reference"], &fixture.registryRef)
	_ = json.Unmarshal(raw["registry_digest_after_tag_update"], &fixture.afterDigest)
	for _, metadata := range []string{"capabilities", "registry_reference", "registry_digest_after_tag_update", "message_security"} {
		delete(raw, metadata)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	fixture.envelope, _, err = DecodeCompatibleEnvelope(encoded, negotiated)
	return fixture, err
}

func decodeM2DeployGroup(t *testing.T, envelope Envelope) (TaskRequest, contracts.DeployGroupRequest, error) {
	t.Helper()
	var task TaskRequest
	if err := json.Unmarshal(envelope.Payload, &task); err != nil {
		return TaskRequest{}, contracts.DeployGroupRequest{}, err
	}
	var request contracts.DeployGroupRequest
	if err := json.Unmarshal(task.Parameters, &request); err != nil {
		return TaskRequest{}, contracts.DeployGroupRequest{}, err
	}
	if err := request.Spec.Validate(); err != nil {
		return task, request, err
	}
	if task.Kind != TaskDeployGroup || task.IdempotencyKey != request.Operation.IdempotencyKey {
		return task, request, errors.New("aggregate runtime task identity mismatch")
	}
	return task, request, nil
}

func TestM2DeployGroupWireFixturesFailClosed(t *testing.T) {
	for _, name := range []string{"deploy-group-request-valid.json", "deploy-group-request-missing-optional.json"} {
		t.Run(name, func(t *testing.T) {
			fixture, err := readM2WireFixture(t, name, ProtocolVersion)
			if err != nil {
				t.Fatal(err)
			}
			if !containsWireCapability(fixture.capabilities, AgentCapabilityRuntimeDeployGroup) {
				t.Fatal("valid fixture omitted aggregate runtime capability")
			}
			if _, _, err := decodeM2DeployGroup(t, fixture.envelope); err != nil {
				t.Fatal(err)
			}
		})
	}

	if _, err := readM2WireFixture(t, "deploy-group-request-incompatible-major.json", ProtocolVersion); err == nil {
		t.Fatal("incompatible major fixture was accepted")
	}
	if _, err := readM2WireFixture(t, "deploy-group-request-unknown-security-field.json", ProtocolVersion); err == nil || !strings.Contains(err.Error(), "security-sensitive") {
		t.Fatalf("unknown security field was not rejected: %v", err)
	}

	old, err := readM2WireFixture(t, "deploy-group-request-old-agent-missing-capability.json", PreviousProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	var oldTask TaskRequest
	if err := json.Unmarshal(old.envelope.Payload, &oldTask); err != nil {
		t.Fatal(err)
	}
	if oldTask.Kind.RequiredCapability() == "" || containsWireCapability(old.capabilities, AgentCapabilityRuntimeDeployGroup) {
		t.Fatal("old Agent fixture could silently accept aggregate runtime")
	}

	for _, name := range []string{"deploy-group-request-duplicate-service.json", "deploy-group-request-plaintext-secret.json"} {
		t.Run(name, func(t *testing.T) {
			fixture, err := readM2WireFixture(t, name, ProtocolVersion)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := decodeM2DeployGroup(t, fixture.envelope); err == nil {
				t.Fatal("invalid aggregate runtime parameters were accepted")
			}
		})
	}

	drift, err := readM2WireFixture(t, "deploy-group-request-digest-tag-drift.json", ProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	_, driftRequest, err := decodeM2DeployGroup(t, drift.envelope)
	if err != nil {
		t.Fatal(err)
	}
	if drift.registryRef == "" || drift.afterDigest == "" || driftRequest.Spec.Services[0].Image.Digest == drift.afterDigest {
		t.Fatal("tag drift fixture does not prove immutable digest mismatch")
	}
}

func TestM2DeployGroupResultAndObservationFixturesValidate(t *testing.T) {
	for _, name := range []string{"deploy-group-result-valid.json", "deploy-group-observations-valid.json"} {
		fixture, err := readM2WireFixture(t, name, ProtocolVersion)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ValidateEnvelopePayload(fixture.envelope); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func containsWireCapability(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
