package v1

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/compatibility"
)

var AgentCapabilitiesByVersion = map[compatibility.Version][]string{
	{Major: 1, Minor: 0}: {"mtls", "typed_tasks", "heartbeat"},
	{Major: 1, Minor: 1}: {"mtls", "typed_tasks", "heartbeat", "agent_sequence", "observation_details", AgentCapabilityAcornFoxRuntime, AgentCapabilityAcornFoxProbe, AgentCapabilityRuntimeDeployGroup, AgentCapabilityRuntimeObserveGroup, AgentCapabilityRuntimeRollbackGroup, AgentCapabilityRuntimeDestroyGroup, AgentCapabilityRuntimeRestartGroupService, AgentCapabilityRuntimeRestartGroup},
}

var SupportedAgentVersions = []compatibility.Version{{Major: 1, Minor: 1}, {Major: 1, Minor: 0}}

type CompatibilityReport struct {
	NegotiatedVersion    string   `json:"negotiated_version"`
	UnknownFields        []string `json:"unknown_fields,omitempty"`
	MissingOptional      []string `json:"missing_optional_fields,omitempty"`
	DisabledCapabilities []string `json:"disabled_capabilities,omitempty"`
}

func NormalizeProtocolVersion(raw string) (string, error) {
	version, err := compatibility.Parse(raw)
	if err != nil || version.Major != 1 || version.Minor < 0 || version.Minor > 1 {
		return "", compatibility.ErrNoCommonVersion
	}
	return version.String(), nil
}

func NegotiateProtocol(minimum, maximum string, supported []compatibility.Version) (compatibility.Negotiation, error) {
	if strings.TrimSpace(minimum) == "" && strings.TrimSpace(maximum) == "" {
		minimum, maximum = PreviousProtocolVersion, PreviousProtocolVersion
	}
	minVersion, err := compatibility.Parse(minimum)
	if err != nil {
		return compatibility.Negotiation{}, err
	}
	maxVersion, err := compatibility.Parse(maximum)
	if err != nil {
		return compatibility.Negotiation{}, err
	}
	return compatibility.Negotiate(minVersion, maxVersion, supported, AgentCapabilitiesByVersion)
}

func DecodeCompatibleEnvelope(data []byte, negotiatedVersion string) (Envelope, CompatibilityReport, error) {
	normalized, err := NormalizeProtocolVersion(negotiatedVersion)
	if err != nil {
		return Envelope{}, CompatibilityReport{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Envelope{}, CompatibilityReport{}, err
	}
	known := map[string]struct{}{"protocol": {}, "version": {}, "message_id": {}, "instance_id": {}, "node_id": {}, "kind": {}, "sent_at": {}, "idempotency_key": {}, "agent_sequence": {}, "payload": {}}
	report := CompatibilityReport{NegotiatedVersion: normalized}
	for field := range raw {
		if _, ok := known[field]; ok {
			continue
		}
		if securitySensitiveUnknownField(field) {
			return Envelope{}, report, errors.New("unknown security-sensitive Agent field: " + field)
		}
		report.UnknownFields = append(report.UnknownFields, field)
	}
	sort.Strings(report.UnknownFields)
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, report, err
	}
	envelopeVersion, err := NormalizeProtocolVersion(envelope.Version)
	if err != nil || envelopeVersion != normalized {
		return Envelope{}, report, errors.New("Agent envelope version does not match negotiation")
	}
	envelope.Version = normalized
	if normalized == PreviousProtocolVersion {
		report.DisabledCapabilities = legacyDisabledCapabilities()
		sort.Strings(report.DisabledCapabilities)
		if envelope.AgentSequence == 0 && isAgentTaskEvent(envelope.Kind) {
			report.MissingOptional = append(report.MissingOptional, "agent_sequence")
		}
		if envelope.Kind == KindObservation {
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				return Envelope{}, report, err
			}
			if _, ok := payload["details"]; !ok {
				report.MissingOptional = append(report.MissingOptional, "observation_details")
			}
		}
	} else if isAgentTaskEvent(envelope.Kind) && envelope.AgentSequence == 0 {
		return Envelope{}, report, errors.New("Agent sequence is required by protocol 1.1")
	}
	if err := inspectPayloadCompatibility(envelope, &report); err != nil {
		return Envelope{}, report, err
	}
	sort.Strings(report.MissingOptional)
	if err := ValidateEnvelopePayload(envelope); err != nil {
		return Envelope{}, report, err
	}
	return envelope, report, nil
}

func inspectPayloadCompatibility(envelope Envelope, report *CompatibilityReport) error {
	known := payloadFields(envelope.Kind)
	if len(known) == 0 {
		return nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return err
	}
	for field := range payload {
		if _, ok := known[field]; ok {
			continue
		}
		path := "payload." + field
		if securitySensitiveUnknownField(field) {
			return errors.New("unknown security-sensitive Agent field: " + path)
		}
		report.UnknownFields = append(report.UnknownFields, path)
	}
	sort.Strings(report.UnknownFields)
	return nil
}

func payloadFields(kind MessageKind) map[string]struct{} {
	fields := func(values ...string) map[string]struct{} {
		result := make(map[string]struct{}, len(values))
		for _, value := range values {
			result[value] = struct{}{}
		}
		return result
	}
	switch kind {
	case KindHello:
		return fields("instance_id", "node_id", "agent_version", "capabilities", "certificate_id")
	case KindHeartbeat:
		return fields("instance_id", "node_id", "sequence", "at", "load")
	case KindTaskRequest:
		return fields("task_id", "instance_id", "node_id", "kind", "idempotency_key", "lease_id", "parameters", "deadline")
	case KindTaskAck:
		return fields("task_id", "status", "reason")
	case KindTaskResult:
		return fields("task_id", "idempotency_key", "succeeded", "status", "error_code", "error_message", "evidence_refs")
	case KindCancelTask:
		return fields("task_id", "idempotency_key", "reason")
	case KindLogChunk:
		return fields("task_id", "sequence", "stream", "data", "final")
	case KindObservation:
		return fields("task_id", "sequence", "target_ref", "status", "healthy", "at", "evidence_refs", "details")
	default:
		return nil
	}
}

func DowngradeEnvelope(envelope Envelope, targetVersion string) (Envelope, CompatibilityReport, error) {
	normalized, err := NormalizeProtocolVersion(targetVersion)
	if err != nil {
		return Envelope{}, CompatibilityReport{}, err
	}
	report := CompatibilityReport{NegotiatedVersion: normalized}
	envelope.Version = normalized
	if normalized == PreviousProtocolVersion {
		report.DisabledCapabilities = legacyDisabledCapabilities()
		sort.Strings(report.DisabledCapabilities)
		envelope.AgentSequence = 0
		if envelope.Kind == KindObservation {
			var observation Observation
			if err := json.Unmarshal(envelope.Payload, &observation); err != nil {
				return Envelope{}, report, err
			}
			observation.Details = nil
			payload, err := json.Marshal(observation)
			if err != nil {
				return Envelope{}, report, err
			}
			envelope.Payload = payload
		}
	}
	if err := ValidateEnvelopePayload(envelope); err != nil {
		return Envelope{}, report, err
	}
	return envelope, report, nil
}

func legacyDisabledCapabilities() []string {
	values := []string{"agent_sequence", "observation_details", AgentCapabilityAcornFoxRuntime, AgentCapabilityAcornFoxProbe, AgentCapabilityRuntimeDeployGroup, AgentCapabilityRuntimeDestroyGroup, AgentCapabilityRuntimeObserveGroup, AgentCapabilityRuntimeRollbackGroup, AgentCapabilityRuntimeRestartGroupService, AgentCapabilityRuntimeRestartGroup}
	sort.Strings(values)
	return values
}

func isAgentTaskEvent(kind MessageKind) bool {
	switch kind {
	case KindTaskAck, KindTaskResult, KindLogChunk, KindObservation:
		return true
	default:
		return false
	}
}

func securitySensitiveUnknownField(field string) bool {
	field = strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(field))
	for _, marker := range []string{"auth", "security", "permission", "capability", "certificate", "credential", "secret", "token", "lease", "signature", "sequence"} {
		if strings.Contains(field, marker) {
			return true
		}
	}
	return false
}
