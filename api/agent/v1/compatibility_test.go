package v1

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/compatibility"
)

func compatibilityFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "tests", "fixtures", "compatibility", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compatibility fixture %q: %v", name, err)
	}
	return data
}

func TestCompatibilityLegacyEnvelopeNormalizesV1(t *testing.T) {
	envelope, report, err := DecodeCompatibleEnvelope(compatibilityFixture(t, "agent-envelope-v1-legacy.json"), PreviousProtocolVersion)
	if err != nil {
		t.Fatalf("decode legacy envelope: %v", err)
	}
	if envelope.Version != PreviousProtocolVersion || report.NegotiatedVersion != PreviousProtocolVersion {
		t.Fatalf("legacy envelope was not normalized: envelope=%#v report=%#v", envelope, report)
	}
	if envelope.Kind != KindTaskAck || envelope.AgentSequence != 0 {
		t.Fatalf("unexpected legacy envelope: %#v", envelope)
	}
	if !reflect.DeepEqual(report.MissingOptional, []string{"agent_sequence"}) {
		t.Fatalf("legacy missing-optional report=%v", report.MissingOptional)
	}
}

func TestCompatibilityNegotiatesCurrentAndNMinusOne(t *testing.T) {
	current, err := NegotiateProtocol(PreviousProtocolVersion, ProtocolVersion, SupportedAgentVersions)
	if err != nil {
		t.Fatalf("negotiate N/N-1 range: %v", err)
	}
	if current.Version.String() != ProtocolVersion || len(current.DisabledCapabilities) != 0 {
		t.Fatalf("current negotiation=%#v", current)
	}

	legacy, err := NegotiateProtocol(PreviousProtocolVersion, ProtocolVersion, []compatibility.Version{{Major: 1, Minor: 0}})
	if err != nil {
		t.Fatalf("negotiate N-1-only peer: %v", err)
	}
	if legacy.Version.String() != PreviousProtocolVersion || !reflect.DeepEqual(legacy.DisabledCapabilities, legacyDisabledCapabilities()) {
		t.Fatalf("N-1 negotiation=%#v", legacy)
	}

	omitted, err := NegotiateProtocol("", "", SupportedAgentVersions)
	if err != nil {
		t.Fatalf("negotiate omitted optional versions: %v", err)
	}
	if omitted.Version.String() != PreviousProtocolVersion {
		t.Fatalf("omitted-version negotiation=%#v", omitted)
	}
}

func TestCompatibilityReportsCompatibleMissingOptionalFields(t *testing.T) {
	envelope, report, err := DecodeCompatibleEnvelope(compatibilityFixture(t, "agent-envelope-v1-current-missing-optional.json"), PreviousProtocolVersion)
	if err != nil {
		t.Fatalf("decode missing-optional legacy observation: %v", err)
	}
	if envelope.Version != PreviousProtocolVersion || envelope.AgentSequence != 0 {
		t.Fatalf("unexpected normalized legacy observation: %#v", envelope)
	}
	want := []string{"agent_sequence", "observation_details"}
	if !reflect.DeepEqual(report.MissingOptional, want) {
		t.Fatalf("missing-optional report=%v want %v", report.MissingOptional, want)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["details"]; ok {
		t.Fatal("missing-optional fixture unexpectedly contains observation details")
	}
}

func TestCompatibilityReportsOrdinaryUnknownField(t *testing.T) {
	_, report, err := DecodeCompatibleEnvelope(compatibilityFixture(t, "agent-envelope-v1-current-unknown-ordinary.json"), ProtocolVersion)
	if err != nil {
		t.Fatalf("decode ordinary unknown field: %v", err)
	}
	if !reflect.DeepEqual(report.UnknownFields, []string{"display_name"}) {
		t.Fatalf("ordinary unknown fields=%v", report.UnknownFields)
	}
}

func TestCompatibilityRejectsSecurityLikeUnknownField(t *testing.T) {
	_, report, err := DecodeCompatibleEnvelope(compatibilityFixture(t, "agent-envelope-v1-current-unknown-security.json"), ProtocolVersion)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "security-sensitive") {
		t.Fatalf("security-like unknown field error=%v", err)
	}
	if len(report.UnknownFields) != 0 {
		t.Fatalf("security-like unknown field was reported as ordinary: %v", report.UnknownFields)
	}
}

func TestCompatibilityRejectsSecurityLikeUnknownPayloadField(t *testing.T) {
	var envelope map[string]any
	if err := json.Unmarshal(compatibilityFixture(t, "agent-envelope-v1-current.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	payload := envelope["payload"].(map[string]any)
	payload["auth_token"] = "must-not-be-ignored"
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeCompatibleEnvelope(encoded, ProtocolVersion); err == nil || !strings.Contains(strings.ToLower(err.Error()), "security-sensitive") {
		t.Fatalf("security-like payload field error=%v", err)
	}
}

func TestCompatibilityRejectsMissingAgentSequenceInCurrentProtocol(t *testing.T) {
	data := compatibilityFixture(t, "agent-envelope-v1-current-missing-optional.json")
	data = []byte(strings.Replace(string(data), `"version": "v1"`, `"version": "1.1"`, 1))
	_, _, err := DecodeCompatibleEnvelope(data, ProtocolVersion)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "sequence") {
		t.Fatalf("missing current-protocol Agent sequence error=%v", err)
	}
}

func TestCompatibilityRejectsMajorMismatch(t *testing.T) {
	if _, err := NegotiateProtocol("2.0", "2.0", SupportedAgentVersions); !errors.Is(err, compatibility.ErrIncompatibleMajor) {
		t.Fatalf("major mismatch error=%v", err)
	}
	majorTwo := compatibilityFixture(t, "agent-envelope-v2-major-mismatch.json")
	if _, _, err := DecodeCompatibleEnvelope(majorTwo, ProtocolVersion); err == nil {
		t.Fatal("major-two fixture was accepted by the 1.1 decoder")
	}
}

func TestCompatibilityDowngradeStripsCurrentOnlyFields(t *testing.T) {
	var envelope Envelope
	if err := json.Unmarshal(compatibilityFixture(t, "agent-envelope-v1-current.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	downgraded, report, err := DowngradeEnvelope(envelope, PreviousProtocolVersion)
	if err != nil {
		t.Fatalf("downgrade current envelope: %v", err)
	}
	if downgraded.Version != PreviousProtocolVersion || downgraded.AgentSequence != 0 {
		t.Fatalf("downgraded envelope=%#v", downgraded)
	}
	if !reflect.DeepEqual(report.DisabledCapabilities, legacyDisabledCapabilities()) {
		t.Fatalf("disabled capabilities=%v", report.DisabledCapabilities)
	}
	encoded, err := json.Marshal(downgraded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"agent_sequence"`) {
		t.Fatal("downgrade retained Agent sequence")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(downgraded.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["details"]; ok {
		t.Fatal("downgrade retained observation details")
	}
}

func TestCompatibilityDisabledCapabilitiesAreStable(t *testing.T) {
	negotiation, err := NegotiateProtocol(PreviousProtocolVersion, ProtocolVersion, []compatibility.Version{{Major: 1, Minor: 0}})
	if err != nil {
		t.Fatal(err)
	}
	want := legacyDisabledCapabilities()
	got := append([]string(nil), negotiation.DisabledCapabilities...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disabled capabilities=%v want %v", got, want)
	}
	if !containsString(AgentCapabilitiesByVersion[compatibility.Version{Major: 1, Minor: 1}], AgentCapabilityAcornFoxCandidateValidation) || !containsString(want, AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("candidate capability current=%v legacy-disabled=%v", AgentCapabilitiesByVersion[compatibility.Version{Major: 1, Minor: 1}], want)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
