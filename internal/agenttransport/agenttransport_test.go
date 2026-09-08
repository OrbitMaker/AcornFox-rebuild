package agenttransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/compatibility"
)

func TestGatewayRequiresClientCertificate(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequestClientCert)
	withoutCertificate := fixture.clientWithoutCertificate(t)

	status, _ := postAgentJSON(t, withoutCertificate, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: testHello("missing-cert", "node-1", "")}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("missing client certificate status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestGatewayBindsHelloCertificateIDToMTLSPeer(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)

	wrong := testHello("instance-1", "node-1", "wrong-certificate")
	status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: wrong}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("mismatched certificate ID status = %d, want %d", status, http.StatusForbidden)
	}

	matching := testHello("instance-1", "node-1", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: matching}, &ConnectResponse{})
	if status != http.StatusOK {
		t.Fatalf("matching certificate ID status = %d, want %d", status, http.StatusOK)
	}
	connectResponse := response.(*ConnectResponse)
	if connectResponse.SessionID == "" {
		t.Fatal("matching certificate ID response omitted session")
	}
}

func TestGatewayLegacyOmissionNegotiatesOneZeroAndRejectsMajorTwo(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-version", "node-version", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello}, &ConnectResponse{})
	if status != http.StatusOK || response.(*ConnectResponse).NegotiatedVersion != v1.PreviousProtocolVersion {
		t.Fatalf("legacy omission status=%d response=%#v", status, response)
	}
	status, _ = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello, MinVersion: "2.0", MaxVersion: "2.0"}, nil)
	if status != http.StatusUpgradeRequired {
		t.Fatalf("major-two connect status=%d want=%d", status, http.StatusUpgradeRequired)
	}
}

func TestGatewayCapabilityGatesAggregateRuntimeWithoutDowngrade(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	groupTask := func(instanceID, nodeID, taskID string) v1.Envelope {
		return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, "message-"+taskID, v1.TaskRequest{
			TaskID: taskID, InstanceID: instanceID, NodeID: nodeID, Kind: v1.TaskDeployGroup,
			IdempotencyKey: "idem-" + taskID, LeaseID: "lease-" + taskID,
			Parameters: json.RawMessage(`{"schema_version":"1"}`), Deadline: time.Now().Add(time.Minute).UTC(),
		})
	}

	legacy := testHello("instance-no-group", "node-no-group", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: legacy, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityRuntimeDeployGroup) {
		t.Fatalf("missing capability was not explicit: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(legacy.InstanceID, legacy.NodeID, groupTask(legacy.InstanceID, legacy.NodeID, "task-no-group")); err == nil || !strings.Contains(err.Error(), "lacks required capability") {
		t.Fatalf("old Agent accepted aggregate task: %v", err)
	}

	capable := testHello("instance-group", "node-group", fixture.clientCertificate.SerialNumber.String())
	capable.Capabilities = append(capable.Capabilities, v1.AgentCapabilityRuntimeDeployGroup)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: capable, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityRuntimeDeployGroup) {
		t.Fatalf("aggregate capability was not negotiated: status=%d response=%#v", status, response)
	}
	if cursor, err := gateway.Enqueue(capable.InstanceID, capable.NodeID, groupTask(capable.InstanceID, capable.NodeID, "task-group")); err != nil || cursor != 1 {
		t.Fatalf("capable Agent rejected aggregate task: cursor=%d err=%v", cursor, err)
	}

	nMinusOne := testHello("instance-group-old-wire", "node-group-old-wire", fixture.clientCertificate.SerialNumber.String())
	nMinusOne.Capabilities = append(nMinusOne.Capabilities, v1.AgentCapabilityRuntimeDeployGroup)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: nMinusOne, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.PreviousProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityRuntimeDeployGroup) {
		t.Fatalf("N-1 aggregate capability was not disabled: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(nMinusOne.InstanceID, nMinusOne.NodeID, groupTask(nMinusOne.InstanceID, nMinusOne.NodeID, "task-group-old-wire")); err == nil || !strings.Contains(err.Error(), "protocol cannot accept") {
		t.Fatalf("aggregate task silently downgraded to N-1: %v", err)
	}
}

func TestGatewayNegotiatesAndGatesAcornFoxRuntimeOnlyOnCurrentProtocol(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	taskFor := func(instanceID, nodeID, taskID string) v1.Envelope {
		return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, "message-"+taskID, v1.TaskRequest{
			TaskID: taskID, InstanceID: instanceID, NodeID: nodeID, Kind: v1.TaskDeploy, IdempotencyKey: "idem-" + taskID, LeaseID: "lease-" + taskID,
			Parameters: json.RawMessage(`{"acornfox_payload_type":"deploy","request":{}}`), Deadline: time.Now().Add(time.Minute).UTC(),
		})
	}
	missing := testHello("instance-acorn-missing", "node-acorn-missing", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: missing, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxRuntime) {
		t.Fatalf("missing AcornFox capability was not explicit: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(missing.InstanceID, missing.NodeID, taskFor(missing.InstanceID, missing.NodeID, "acorn-missing")); err == nil || !strings.Contains(err.Error(), v1.AgentCapabilityAcornFoxRuntime) {
		t.Fatalf("Agent without AcornFox capability accepted task: %v", err)
	}

	capable := testHello("instance-acorn", "node-acorn", fixture.clientCertificate.SerialNumber.String())
	capable.Capabilities = append(capable.Capabilities, v1.AgentCapabilityAcornFoxRuntime)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: capable, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxRuntime) {
		t.Fatalf("AcornFox capability was not negotiated: status=%d response=%#v", status, response)
	}
	if cursor, err := gateway.Enqueue(capable.InstanceID, capable.NodeID, taskFor(capable.InstanceID, capable.NodeID, "acorn-current")); err != nil || cursor != 1 {
		t.Fatalf("current capable Agent rejected AcornFox task: cursor=%d err=%v", cursor, err)
	}

	legacy := testHello("instance-acorn-old", "node-acorn-old", fixture.clientCertificate.SerialNumber.String())
	legacy.Capabilities = append(legacy.Capabilities, v1.AgentCapabilityAcornFoxRuntime)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: legacy, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.PreviousProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxRuntime) || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxRuntime) {
		t.Fatalf("N-1 Agent did not fail closed for AcornFox runtime: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(legacy.InstanceID, legacy.NodeID, taskFor(legacy.InstanceID, legacy.NodeID, "acorn-old")); err == nil || !strings.Contains(err.Error(), "protocol cannot accept") {
		t.Fatalf("AcornFox task silently downgraded to N-1: %v", err)
	}
}

func TestGatewayNegotiatesAndGatesAcornFoxCandidateValidationOnlyOnCurrentProtocol(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	taskFor := func(instanceID, nodeID, taskID string) v1.Envelope {
		return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, "message-"+taskID, v1.TaskRequest{
			TaskID: taskID, InstanceID: instanceID, NodeID: nodeID, Kind: v1.TaskDeploy, IdempotencyKey: "idem-" + taskID, LeaseID: "lease-" + taskID,
			Parameters: json.RawMessage(`{"acornfox_candidate_payload_type":"acornfox_candidate_validation_v1","request":{}}`), Deadline: time.Now().Add(time.Minute).UTC(),
		})
	}
	missing := testHello("instance-candidate-missing", "node-candidate-missing", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: missing, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("missing candidate capability was not explicit: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(missing.InstanceID, missing.NodeID, taskFor(missing.InstanceID, missing.NodeID, "candidate-missing")); err == nil || !strings.Contains(err.Error(), v1.AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("Agent without candidate capability accepted task: %v", err)
	}

	capable := testHello("instance-candidate", "node-candidate", fixture.clientCertificate.SerialNumber.String())
	capable.Capabilities = append(capable.Capabilities, v1.AgentCapabilityAcornFoxCandidateValidation)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: capable, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxCandidateValidation) || containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("candidate capability was not negotiated: status=%d response=%#v", status, response)
	}
	if cursor, err := gateway.Enqueue(capable.InstanceID, capable.NodeID, taskFor(capable.InstanceID, capable.NodeID, "candidate-current")); err != nil || cursor != 1 {
		t.Fatalf("current capable Agent rejected candidate task: cursor=%d err=%v", cursor, err)
	}

	legacy := testHello("instance-candidate-old", "node-candidate-old", fixture.clientCertificate.SerialNumber.String())
	legacy.Capabilities = append(legacy.Capabilities, v1.AgentCapabilityAcornFoxCandidateValidation)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: legacy, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.PreviousProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxCandidateValidation) || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("N-1 Agent did not fail closed for candidate capability: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(legacy.InstanceID, legacy.NodeID, taskFor(legacy.InstanceID, legacy.NodeID, "candidate-old")); err == nil || !strings.Contains(err.Error(), "protocol cannot accept") {
		t.Fatalf("candidate task silently downgraded to N-1: %v", err)
	}
}

func TestGatewayNegotiatesAndGatesAcornFoxProbeOnlyOnCurrentProtocol(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	taskFor := func(instanceID, nodeID, taskID string) v1.Envelope {
		return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, "message-"+taskID, v1.TaskRequest{
			TaskID: taskID, InstanceID: instanceID, NodeID: nodeID, Kind: v1.TaskObserve, IdempotencyKey: "idem-" + taskID, LeaseID: "lease-" + taskID,
			Parameters: json.RawMessage(`{"acornfox_probe_payload_type":"probe","request":{}}`), Deadline: time.Now().Add(time.Minute).UTC(),
		})
	}
	missing := testHello("instance-probe-missing", "node-probe-missing", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: missing, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxProbe) {
		t.Fatalf("missing probe capability was not explicit: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(missing.InstanceID, missing.NodeID, taskFor(missing.InstanceID, missing.NodeID, "probe-missing")); err == nil || !strings.Contains(err.Error(), v1.AgentCapabilityAcornFoxProbe) {
		t.Fatalf("Agent without probe capability accepted task: %v", err)
	}

	capable := testHello("instance-probe", "node-probe", fixture.clientCertificate.SerialNumber.String())
	capable.Capabilities = append(capable.Capabilities, v1.AgentCapabilityAcornFoxProbe)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: capable, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxProbe) {
		t.Fatalf("probe capability was not negotiated: status=%d response=%#v", status, response)
	}
	if cursor, err := gateway.Enqueue(capable.InstanceID, capable.NodeID, taskFor(capable.InstanceID, capable.NodeID, "probe-current")); err != nil || cursor != 1 {
		t.Fatalf("current capable Agent rejected probe task: cursor=%d err=%v", cursor, err)
	}

	legacy := testHello("instance-probe-old", "node-probe-old", fixture.clientCertificate.SerialNumber.String())
	legacy.Capabilities = append(legacy.Capabilities, v1.AgentCapabilityAcornFoxProbe)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: legacy, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.PreviousProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxProbe) || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxProbe) {
		t.Fatalf("N-1 Agent did not fail closed for probe capability: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(legacy.InstanceID, legacy.NodeID, taskFor(legacy.InstanceID, legacy.NodeID, "probe-old")); err == nil || !strings.Contains(err.Error(), "protocol cannot accept") {
		t.Fatalf("probe task silently downgraded to N-1: %v", err)
	}
}

func TestGatewayNegotiatesAndGatesAcornFoxLogsOnlyOnCurrentProtocol(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	taskFor := func(instanceID, nodeID, taskID string) v1.Envelope {
		return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, "message-"+taskID, v1.TaskRequest{
			TaskID: taskID, InstanceID: instanceID, NodeID: nodeID, Kind: v1.TaskLogs, IdempotencyKey: "idem-" + taskID, LeaseID: "lease-" + taskID,
			Parameters: json.RawMessage(`{"acornfox_log_payload_type":"logs","request":{}}`), Deadline: time.Now().Add(time.Minute).UTC(),
		})
	}
	missing := testHello("instance-logs-missing", "node-logs-missing", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: missing, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxLogs) {
		t.Fatalf("missing logs capability was not explicit: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(missing.InstanceID, missing.NodeID, taskFor(missing.InstanceID, missing.NodeID, "logs-missing")); err == nil || !strings.Contains(err.Error(), v1.AgentCapabilityAcornFoxLogs) {
		t.Fatalf("Agent without logs capability accepted task: %v", err)
	}

	capable := testHello("instance-logs", "node-logs", fixture.clientCertificate.SerialNumber.String())
	capable.Capabilities = append(capable.Capabilities, v1.AgentCapabilityAcornFoxLogs)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: capable, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxLogs) {
		t.Fatalf("logs capability was not negotiated: status=%d response=%#v", status, response)
	}
	if cursor, err := gateway.Enqueue(capable.InstanceID, capable.NodeID, taskFor(capable.InstanceID, capable.NodeID, "logs-current")); err != nil || cursor != 1 {
		t.Fatalf("current capable Agent rejected logs task: cursor=%d err=%v", cursor, err)
	}

	legacy := testHello("instance-logs-old", "node-logs-old", fixture.clientCertificate.SerialNumber.String())
	legacy.Capabilities = append(legacy.Capabilities, v1.AgentCapabilityAcornFoxLogs)
	status, response = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: legacy, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.PreviousProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || containsCapability(response.(*ConnectResponse).EnabledCapabilities, v1.AgentCapabilityAcornFoxLogs) || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityAcornFoxLogs) {
		t.Fatalf("N-1 Agent did not fail closed for logs capability: status=%d response=%#v", status, response)
	}
	if _, err := gateway.Enqueue(legacy.InstanceID, legacy.NodeID, taskFor(legacy.InstanceID, legacy.NodeID, "logs-old")); err == nil || !strings.Contains(err.Error(), "protocol cannot accept") {
		t.Fatalf("logs task silently downgraded to N-1: %v", err)
	}
}

func TestGatewayRejectsGroupLogsBeforeDispatchWithoutDedicatedCapability(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-group-logs", "node-group-logs", fixture.clientCertificate.SerialNumber.String())
	hello.Capabilities = append(hello.Capabilities, v1.AgentCapabilityRuntimeObserveGroup)
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello, MinVersion: v1.ProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK || !containsCapability(response.(*ConnectResponse).DisabledCapabilities, v1.AgentCapabilityRuntimeLogsGroup) {
		t.Fatalf("missing group logs capability was not explicit: status=%d response=%#v", status, response)
	}
	parameters := json.RawMessage(`{"m4_payload_type":"service_group.logs","request":{"deployment_id":"dep_logs","service_name":"worker","tail":64,"operation":{"idempotency_key":"group-logs","actor":"collector"}}}`)
	task := v1.TaskRequest{TaskID: "task-group-logs", InstanceID: hello.InstanceID, NodeID: hello.NodeID, Kind: v1.TaskLogs, IdempotencyKey: "group-logs", LeaseID: "lease-group-logs", Parameters: parameters, Deadline: time.Now().Add(time.Minute).UTC()}
	envelope := makeAgentEnvelope(t, hello.InstanceID, hello.NodeID, v1.KindTaskRequest, "message-group-logs", task)
	if _, err := gateway.Enqueue(hello.InstanceID, hello.NodeID, envelope); err == nil || !strings.Contains(err.Error(), v1.AgentCapabilityRuntimeLogsGroup) {
		t.Fatalf("group logs reached Agent without dedicated capability: %v", err)
	}
}

func TestGatewayNegotiatesM4RestartCapabilitiesOnlyOnCurrentProtocol(t *testing.T) {
	advertised := []string{v1.AgentCapabilityRuntimeRestartGroupService, v1.AgentCapabilityRuntimeRestartGroup}
	enabled, disabled := negotiateSessionCapabilities(advertised, v1.ProtocolVersion, nil)
	for _, capability := range advertised {
		if !containsCapability(enabled, capability) || containsCapability(disabled, capability) {
			t.Fatalf("current protocol did not enable %s: enabled=%v disabled=%v", capability, enabled, disabled)
		}
	}
	enabled, disabled = negotiateSessionCapabilities(advertised, v1.PreviousProtocolVersion, nil)
	for _, capability := range advertised {
		if containsCapability(enabled, capability) || !containsCapability(disabled, capability) {
			t.Fatalf("N-1 protocol did not fail closed for %s: enabled=%v disabled=%v", capability, enabled, disabled)
		}
	}
}

func TestStrictGatewayRequiresPreRegisteredCertificateNodeBinding(t *testing.T) {
	gateway := NewStrictGateway(nil)
	now := time.Unix(1_724_467_200, 0).UTC()
	gateway.clock = func() time.Time { return now }
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-strict", "node-strict", fixture.clientCertificate.SerialNumber.String())
	status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("unregistered strict identity status = %d, want %d", status, http.StatusForbidden)
	}
	if err := gateway.RegisterIdentity(hello.CertificateID, hello.InstanceID, hello.NodeID); err != nil {
		t.Fatal(err)
	}
	status, _ = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello}, nil)
	if status != http.StatusOK {
		t.Fatalf("registered strict identity status = %d, want %d", status, http.StatusOK)
	}
	if status := gateway.NodeStatus(hello.InstanceID, hello.NodeID, now.Add(15*time.Second)); status != "online" {
		t.Fatalf("node status at heartbeat boundary = %s, want online", status)
	}
	if status := gateway.NodeStatus(hello.InstanceID, hello.NodeID, now.Add(15*time.Second+time.Nanosecond)); status != "unknown" {
		t.Fatalf("node status after three missed heartbeats = %s, want unknown", status)
	}
	wrongNode := hello
	wrongNode.NodeID = "node-other"
	status, _ = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: wrongNode}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("wrong registered node status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestGatewayBindsPollAndEventsToConnectedMTLSCertificate(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-session-owner", "node-session-owner", fixture.clientCertificate.SerialNumber.String())
	sessionID := connectGateway(t, fixture, hello)
	otherClient, _ := fixture.newClientCertificate(t, 4, "other-agent-client")

	status, _ := postAgentJSON(t, otherClient, fixture.server.URL+"/v1/agent/poll", PollRequest{SessionID: sessionID}, nil)
	if status != http.StatusConflict {
		t.Fatalf("cross-certificate poll status = %d, want %d", status, http.StatusConflict)
	}
	envelope := observationEnvelope(t, hello.InstanceID, hello.NodeID, "cross-certificate-event", "healthy")
	status, _ = postAgentJSON(t, otherClient, fixture.server.URL+"/v1/agent/events", EventBatch{SessionID: sessionID, Events: []v1.Envelope{envelope}}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("cross-certificate event status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestClientProcessesQueuedTaskAndSendsAgentEventsAndHeartbeat(t *testing.T) {
	sink := newRecordingAgentSink(16)
	gateway := NewGateway(sink)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-1", "node-1", fixture.clientCertificate.SerialNumber.String())
	connectGateway(t, fixture, hello)

	task := taskRequestEnvelope(t, hello.InstanceID, hello.NodeID, "task-1", "task-message-1")
	if cursor, err := gateway.Enqueue(hello.InstanceID, hello.NodeID, task); err != nil || cursor != 1 {
		t.Fatalf("enqueue task cursor = %d, err = %v; want cursor 1", cursor, err)
	}

	handler := &countingAgentHandler{
		outgoing: taskResultEnvelopes(t, hello.InstanceID, hello.NodeID, "task-1"),
		attempts: make(chan int, 1),
	}
	client := newTestAgentClient(fixture, hello, handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.Run(ctx) }()

	waitForAgentSignal(t, handler.attempts, "task handler")
	wantKinds := map[v1.MessageKind]bool{
		v1.KindTaskAck:     false,
		v1.KindLogChunk:    false,
		v1.KindObservation: false,
		v1.KindTaskResult:  false,
		v1.KindHeartbeat:   false,
	}
	for len(wantKinds) > 0 {
		select {
		case envelope := <-sink.events:
			if _, ok := wantKinds[envelope.Kind]; ok {
				wantKinds[envelope.Kind] = true
				if allAgentKindsSeen(wantKinds) {
					wantKinds = nil
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for agent event kinds; remaining=%v", missingAgentKinds(wantKinds))
		}
	}

	if got := client.Cursor(); got != 1 {
		t.Fatalf("client cursor = %d, want 1 after task events were accepted", got)
	}
	cancel()
	select {
	case err := <-runResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("client Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client Run did not stop after cancellation")
	}

	handler.mu.Lock()
	if handler.attemptCount != 1 {
		t.Fatalf("task handler attempts = %d, want 1", handler.attemptCount)
	}
	handler.mu.Unlock()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := countAgentKinds(sink.received); got[v1.KindTaskAck] != 1 || got[v1.KindLogChunk] != 1 || got[v1.KindObservation] != 1 || got[v1.KindTaskResult] != 1 || got[v1.KindHeartbeat] < 1 {
		t.Fatalf("unexpected agent event counts: %#v", got)
	}
}

func TestExpiredQueuedTaskIsSkippedWithoutExecutingAfterReconnect(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	task := v1.TaskRequest{TaskID: "task-expired", InstanceID: "instance-1", NodeID: "node-1", Kind: v1.TaskDeploy, IdempotencyKey: "expired", LeaseID: "lease-expired", Parameters: json.RawMessage(`{"deployment_id":"dep_1"}`), Deadline: now.Add(-time.Second)}
	payload, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	envelope := v1.Envelope{Kind: v1.KindTaskRequest, Payload: payload}
	if !expiredTaskEnvelope(envelope, now) {
		t.Fatal("expired durable task was not classified for safe transport skip")
	}
	task.Deadline = now.Add(time.Second)
	payload, _ = json.Marshal(task)
	envelope.Payload = payload
	if expiredTaskEnvelope(envelope, now) {
		t.Fatal("live task was classified as expired")
	}
}

func TestClientReconnectsWithSameSessionAndReplaysUnackedTask(t *testing.T) {
	sink := newRecordingAgentSink(16)
	gateway := NewGateway(sink)
	faults := &failFirstEventBatchHandler{gateway: gateway}
	fixture := newAgentTLSServer(t, faults, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-reconnect", "node-reconnect", fixture.clientCertificate.SerialNumber.String())
	initialSession := connectGateway(t, fixture, hello)
	task := taskRequestEnvelope(t, hello.InstanceID, hello.NodeID, "task-replay", "task-replay-message")
	if cursor, err := gateway.Enqueue(hello.InstanceID, hello.NodeID, task); err != nil || cursor != 1 {
		t.Fatalf("enqueue task cursor = %d, err = %v; want cursor 1", cursor, err)
	}

	handler := &countingAgentHandler{
		outgoing: taskResultEnvelopes(t, hello.InstanceID, hello.NodeID, "task-replay"),
		attempts: make(chan int, 2),
	}
	client := newTestAgentClient(fixture, hello, handler)
	client.MinBackoff = time.Millisecond
	client.MaxBackoff = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.Run(ctx) }()

	waitForAgentSignal(t, handler.attempts, "first task handler attempt")
	waitForAgentSignal(t, handler.attempts, "replayed task handler attempt")
	waitForAgentKind(t, sink.events, v1.KindHeartbeat, "heartbeat after replay")
	if got := client.Cursor(); got != 1 {
		t.Fatalf("client cursor = %d, want 1 after replay is acknowledged", got)
	}
	cancel()
	select {
	case err := <-runResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("client Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client Run did not stop after replay cancellation")
	}

	handler.mu.Lock()
	attempts := handler.attemptCount
	handler.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("task handler attempts = %d, want exactly 2", attempts)
	}

	gateway.mu.Lock()
	currentSession := gateway.byNode[nodeKey(hello.InstanceID, hello.NodeID)]
	sessionCount := len(gateway.sessions)
	var currentCursor uint64
	if session := gateway.sessions[currentSession]; session != nil {
		currentCursor = session.cursor
	}
	gateway.mu.Unlock()
	if currentSession != initialSession {
		t.Fatalf("reconnect session = %q, want original session %q", currentSession, initialSession)
	}
	if sessionCount != 1 || currentCursor != 1 {
		t.Fatalf("gateway sessions/cursor = %d/%d, want 1/1", sessionCount, currentCursor)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	counts := countAgentKinds(sink.received)
	if counts[v1.KindTaskAck] != 1 || counts[v1.KindLogChunk] != 1 || counts[v1.KindObservation] != 1 || counts[v1.KindTaskResult] != 1 {
		t.Fatalf("replayed task envelopes were not idempotent: %#v", counts)
	}
}

func TestGatewayAcceptsExactDuplicateAndRejectsConflictingMessageID(t *testing.T) {
	sink := newRecordingAgentSink(8)
	gateway := NewGateway(sink)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-idempotency", "node-idempotency", fixture.clientCertificate.SerialNumber.String())
	sessionID := connectGateway(t, fixture, hello)

	original := observationEnvelope(t, hello.InstanceID, hello.NodeID, "same-message", "healthy")
	batch := EventBatch{SessionID: sessionID, Events: []v1.Envelope{original}}
	if status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/events", batch, nil); status != http.StatusAccepted {
		t.Fatalf("first event status = %d, want %d", status, http.StatusAccepted)
	}
	if status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/events", batch, nil); status != http.StatusAccepted {
		t.Fatalf("exact duplicate status = %d, want %d", status, http.StatusAccepted)
	}

	conflict := original
	conflict.Payload = json.RawMessage(`{"task_id":"task-1","sequence":1,"target_ref":"deployment/1","status":"failed","healthy":false,"at":"2026-08-24T00:00:00Z"}`)
	if status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/events", EventBatch{SessionID: sessionID, Events: []v1.Envelope{conflict}}, nil); status != http.StatusConflict {
		t.Fatalf("conflicting duplicate status = %d, want %d", status, http.StatusConflict)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.received) != 1 {
		t.Fatalf("sink received %d events, want exactly 1 after duplicate replay", len(sink.received))
	}
}

func TestGatewayReportsOrdinaryUnknownEnvelopeFieldAndRejectsSecurityUnknown(t *testing.T) {
	gateway := NewGateway(newRecordingAgentSink(4))
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-unknown", "node-unknown", fixture.clientCertificate.SerialNumber.String())
	sessionID := connectGateway(t, fixture, hello)
	envelope := observationEnvelope(t, hello.InstanceID, hello.NodeID, "unknown-message-1", "healthy")
	envelope.AgentSequence = 1
	encoded, _ := json.Marshal(envelope)
	var ordinary map[string]any
	_ = json.Unmarshal(encoded, &ordinary)
	ordinary["display_name"] = "optional future field"
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/events", map[string]any{"session_id": sessionID, "events": []any{ordinary}}, &EventBatchResponse{})
	if status != http.StatusAccepted {
		t.Fatalf("ordinary unknown status=%d", status)
	}
	reports := response.(*EventBatchResponse).CompatibilityReports
	if len(reports) != 1 || !reflect.DeepEqual(reports[0].UnknownFields, []string{"display_name"}) {
		t.Fatalf("ordinary unknown report=%#v", reports)
	}
	security := map[string]any{}
	for key, value := range ordinary {
		security[key] = value
	}
	delete(security, "display_name")
	security["auth_token"] = "must-not-be-ignored"
	security["message_id"] = "unknown-message-2"
	status, _ = postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/events", map[string]any{"session_id": sessionID, "events": []any{security}}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("security unknown status=%d want=%d", status, http.StatusBadRequest)
	}
}

func TestGatewayRejectsExpiredReplayCursor(t *testing.T) {
	gateway := NewGateway(nil)
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-expired", "node-expired", fixture.clientCertificate.SerialNumber.String())
	sessionID := connectGateway(t, fixture, hello)
	for index := 0; index < maxQueueDepth+1; index++ {
		envelope := observationEnvelope(t, hello.InstanceID, hello.NodeID, fmt.Sprintf("message-%d", index), "healthy")
		if _, err := gateway.Enqueue(hello.InstanceID, hello.NodeID, envelope); err != nil {
			t.Fatalf("enqueue %d: %v", index, err)
		}
	}

	status, _ := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/poll", PollRequest{SessionID: sessionID, After: 0, WaitMS: 0}, nil)
	if status != http.StatusConflict {
		t.Fatalf("expired replay cursor status = %d, want %d", status, http.StatusConflict)
	}
}

func TestClientRejectsGappedPollCursor(t *testing.T) {
	gappedEnvelope := observationEnvelope(t, "instance-gap", "node-gap", "gap-message", "healthy")
	serverHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/agent/connect":
			writeGatewayJSON(writer, http.StatusOK, ConnectResponse{SessionID: "session-gap"})
		case "/v1/agent/poll":
			writeGatewayJSON(writer, http.StatusOK, PollResponse{Items: []QueuedEnvelope{{Cursor: 2, Envelope: gappedEnvelope}}})
		default:
			writeGatewayError(writer, http.StatusNotFound, "not_found", "not found")
		}
	})
	fixture := newAgentTLSServer(t, serverHandler, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-gap", "node-gap", fixture.clientCertificate.SerialNumber.String())
	client := newTestAgentClient(fixture, hello, &countingAgentHandler{})
	if err := client.normalize(); err != nil {
		t.Fatal(err)
	}
	if err := client.connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.NegotiatedVersion() != v1.PreviousProtocolVersion || !containsCapability(client.DisabledCapabilities(), v1.AgentCapabilityAcornFoxCandidateValidation) {
		t.Fatalf("legacy fallback did not disable candidate capability: version=%s disabled=%v", client.NegotiatedVersion(), client.DisabledCapabilities())
	}
	if err := client.pollOnce(context.Background()); err == nil {
		t.Fatal("expected gapped poll cursor to be rejected")
	}
	if got := client.Cursor(); got != 0 {
		t.Fatalf("client cursor after rejected gap = %d, want 0", got)
	}
}

func TestClientRejectsCandidateCapabilityEnabledByNMinusOneServer(t *testing.T) {
	for _, negotiated := range []string{"", v1.PreviousProtocolVersion} {
		t.Run("version-"+negotiated, func(t *testing.T) {
			serverHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v1/agent/connect" {
					writeGatewayError(writer, http.StatusNotFound, "not_found", "not found")
					return
				}
				writeGatewayJSON(writer, http.StatusOK, ConnectResponse{SessionID: "session-candidate-old", NegotiatedVersion: negotiated, EnabledCapabilities: []string{v1.AgentCapabilityAcornFoxCandidateValidation}})
			})
			fixture := newAgentTLSServer(t, serverHandler, tls.RequireAndVerifyClientCert)
			hello := testHello("instance-candidate-client-old", "node-candidate-client-old", fixture.clientCertificate.SerialNumber.String())
			hello.Capabilities = append(hello.Capabilities, v1.AgentCapabilityAcornFoxCandidateValidation)
			client := newTestAgentClient(fixture, hello, &countingAgentHandler{})
			if err := client.normalize(); err != nil {
				t.Fatal(err)
			}
			if err := client.connect(context.Background()); err == nil || !strings.Contains(err.Error(), "current-only capability") {
				t.Fatalf("N-1 candidate enable err=%v", err)
			}
		})
	}
}

func TestNewClientNegotiatesNMinusOneAndExplicitlyDowngradesEvents(t *testing.T) {
	sink := newRecordingAgentSink(16)
	gateway := NewGatewayForVersions(sink, []compatibility.Version{{Major: 1, Minor: 0}})
	fixture := newAgentTLSServer(t, gateway, tls.RequireAndVerifyClientCert)
	hello := testHello("instance-nminus1", "node-nminus1", fixture.clientCertificate.SerialNumber.String())
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK {
		t.Fatalf("N-1 connect status=%d", status)
	}
	connect := response.(*ConnectResponse)
	if connect.NegotiatedVersion != v1.PreviousProtocolVersion || !containsCapability(connect.DisabledCapabilities, v1.AgentCapabilityRuntimeDeployGroup) {
		t.Fatalf("N-1 negotiation=%#v", connect)
	}
	task := taskRequestEnvelope(t, hello.InstanceID, hello.NodeID, "task-nminus1", "task-message-nminus1")
	if _, err := gateway.Enqueue(hello.InstanceID, hello.NodeID, task); err != nil {
		t.Fatal(err)
	}
	outgoing := taskResultEnvelopes(t, hello.InstanceID, hello.NodeID, "task-nminus1")
	for index := range outgoing {
		outgoing[index].AgentSequence = uint64(index + 1)
	}
	var observation v1.Observation
	if err := json.Unmarshal(outgoing[2].Payload, &observation); err != nil {
		t.Fatal(err)
	}
	observation.Details = json.RawMessage(`{"new_field":"not-for-1.0"}`)
	outgoing[2].Payload, _ = json.Marshal(observation)
	directDowngrade, _, err := v1.DowngradeEnvelope(outgoing[2], v1.PreviousProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	var directObservation v1.Observation
	_ = json.Unmarshal(directDowngrade.Payload, &directObservation)
	if len(directObservation.Details) != 0 {
		t.Fatalf("direct downgrade retained details: %s", directObservation.Details)
	}
	handler := &countingAgentHandler{outgoing: outgoing, attempts: make(chan int, 2)}
	client := newTestAgentClient(fixture, hello, handler)
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- client.Run(ctx) }()
	waitForAgentSignal(t, handler.attempts, "N-1 task handler")
	if client.NegotiatedVersion() != v1.PreviousProtocolVersion || !containsCapability(client.DisabledCapabilities(), v1.AgentCapabilityRuntimeDeployGroup) {
		t.Fatalf("client did not expose capability degradation before events: version=%s disabled=%v", client.NegotiatedVersion(), client.DisabledCapabilities())
	}
	var receivedObservation v1.Envelope
	deadline := time.After(2 * time.Second)
	for receivedObservation.Kind == "" {
		select {
		case envelope := <-sink.events:
			if envelope.Kind == v1.KindObservation {
				receivedObservation = envelope
			}
		case <-deadline:
			t.Fatal("timed out waiting for downgraded observation")
		}
	}
	if receivedObservation.Version != v1.PreviousProtocolVersion || receivedObservation.AgentSequence != 0 {
		t.Fatalf("observation was not downgraded: %#v", receivedObservation)
	}
	observation = v1.Observation{}
	if err := json.Unmarshal(receivedObservation.Payload, &observation); err != nil {
		t.Fatal(err)
	}
	if len(observation.Details) != 0 {
		t.Fatalf("N-1 observation %s retained 1.1 details: %s", receivedObservation.MessageID, observation.Details)
	}
	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("client Run error=%v", err)
	}
}

func containsCapability(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type countingAgentHandler struct {
	mu           sync.Mutex
	attemptCount int
	attempts     chan int
	outgoing     []v1.Envelope
}

func (h *countingAgentHandler) HandleControlEnvelope(_ context.Context, envelope v1.Envelope) ([]v1.Envelope, error) {
	if envelope.Kind != v1.KindTaskRequest {
		return nil, fmt.Errorf("unexpected control envelope kind %q", envelope.Kind)
	}
	h.mu.Lock()
	h.attemptCount++
	attempt := h.attemptCount
	outgoing := append([]v1.Envelope(nil), h.outgoing...)
	h.mu.Unlock()
	if h.attempts != nil {
		h.attempts <- attempt
	}
	return outgoing, nil
}

type recordingAgentSink struct {
	mu       sync.Mutex
	received []v1.Envelope
	events   chan v1.Envelope
}

func newRecordingAgentSink(buffer int) *recordingAgentSink {
	return &recordingAgentSink{events: make(chan v1.Envelope, buffer)}
}

func (s *recordingAgentSink) RecordAgentEnvelope(_ context.Context, envelope v1.Envelope) error {
	s.mu.Lock()
	s.received = append(s.received, envelope)
	s.mu.Unlock()
	s.events <- envelope
	return nil
}

type failFirstEventBatchHandler struct {
	gateway *Gateway
	mu      sync.Mutex
	failed  bool
}

func (h *failFirstEventBatchHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/agent/events" {
		h.gateway.ServeHTTP(writer, request)
		return
	}
	h.mu.Lock()
	fail := !h.failed
	if fail {
		h.failed = true
	}
	h.mu.Unlock()
	if !fail {
		h.gateway.ServeHTTP(writer, request)
		return
	}
	// Let the gateway record the batch, then lose the response to emulate a
	// server error after the client sent an unacknowledged batch.
	recorder := httptest.NewRecorder()
	h.gateway.ServeHTTP(recorder, request)
	if recorder.Code < http.StatusOK || recorder.Code >= http.StatusMultipleChoices {
		recorder.Result().Body.Close()
		writer.WriteHeader(recorder.Code)
		return
	}
	writeGatewayError(writer, http.StatusServiceUnavailable, "temporary_failure", "event acknowledgement was lost")
}

type agentTLSFixture struct {
	server            *httptest.Server
	client            *http.Client
	roots             *x509.CertPool
	clientCertificate *x509.Certificate
	caCertificate     *x509.Certificate
	caKey             *ecdsa.PrivateKey
}

func newAgentTLSServer(t *testing.T, handler http.Handler, clientAuth tls.ClientAuthType) *agentTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Open Card agent test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	serverTLS, _ := issueAgentCertificate(t, caCertificate, caKey, 2, "agent-gateway", true, now.Add(-time.Minute), now.Add(time.Hour))
	clientTLS, clientCertificate := issueAgentCertificate(t, caCertificate, caKey, 3, "agent-client", false, now.Add(-time.Minute), now.Add(time.Hour))

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		ClientAuth:   clientAuth,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientTLS}, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &agentTLSFixture{
		server:            server,
		client:            &http.Client{Transport: transport},
		roots:             roots,
		clientCertificate: clientCertificate,
		caCertificate:     caCertificate,
		caKey:             caKey,
	}
}

func issueAgentCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, commonName string, server bool, notBefore, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCertificate, err := tls.X509KeyPair(pemCertificate(der), pemPrivateKey(keyDER))
	if err != nil {
		t.Fatal(err)
	}
	return tlsCertificate, certificate
}

func pemCertificate(der []byte) []byte {
	return pemEncode("CERTIFICATE", der)
}

func pemPrivateKey(der []byte) []byte {
	return pemEncode("PRIVATE KEY", der)
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func (f *agentTLSFixture) clientWithoutCertificate(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func (f *agentTLSFixture) newClientCertificate(t *testing.T, serial int64, commonName string) (*http.Client, *x509.Certificate) {
	t.Helper()
	now := time.Now().UTC()
	clientTLS, certificate := issueAgentCertificate(t, f.caCertificate, f.caKey, serial, commonName, false, now.Add(-time.Minute), now.Add(time.Hour))
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots, Certificates: []tls.Certificate{clientTLS}, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}, certificate
}

func newTestAgentClient(fixture *agentTLSFixture, hello v1.Hello, handler EnvelopeHandler) *Client {
	return &Client{
		BaseURL:    fixture.server.URL,
		HTTPClient: fixture.client,
		Hello:      hello,
		Handler:    handler,
		PollWait:   10 * time.Millisecond,
		MinBackoff: time.Millisecond,
		MaxBackoff: 10 * time.Millisecond,
		clock:      func() time.Time { return time.Unix(1_724_467_200, 0).UTC() },
	}
}

func testHello(instanceID, nodeID, certificateID string) v1.Hello {
	return v1.Hello{InstanceID: instanceID, NodeID: nodeID, AgentVersion: "test-agent", Capabilities: []string{"observe"}, CertificateID: certificateID}
}

func connectGateway(t *testing.T, fixture *agentTLSFixture, hello v1.Hello) string {
	t.Helper()
	status, response := postAgentJSON(t, fixture.client, fixture.server.URL+"/v1/agent/connect", ConnectRequest{Hello: hello, MinVersion: v1.PreviousProtocolVersion, MaxVersion: v1.ProtocolVersion}, &ConnectResponse{})
	if status != http.StatusOK {
		t.Fatalf("connect status = %d, want %d", status, http.StatusOK)
	}
	return response.(*ConnectResponse).SessionID
}

func taskRequestEnvelope(t *testing.T, instanceID, nodeID, taskID, messageID string) v1.Envelope {
	t.Helper()
	return makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskRequest, messageID, v1.TaskRequest{
		TaskID:         taskID,
		InstanceID:     instanceID,
		NodeID:         nodeID,
		Kind:           v1.TaskObserve,
		IdempotencyKey: "idem-" + taskID,
		LeaseID:        "lease-" + taskID,
		Parameters:     json.RawMessage(`{"target":"deployment/1"}`),
		Deadline:       time.Unix(1_800_000_000, 0).UTC(),
	})
}

func taskResultEnvelopes(t *testing.T, instanceID, nodeID, taskID string) []v1.Envelope {
	t.Helper()
	return []v1.Envelope{
		makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskAck, "ack-"+taskID, v1.TaskAck{TaskID: taskID, Status: v1.AckAccepted}),
		makeAgentEnvelope(t, instanceID, nodeID, v1.KindLogChunk, "log-"+taskID, v1.LogChunk{TaskID: taskID, Sequence: 1, Stream: v1.LogStreamStdout, Data: "observed\n", Final: true}),
		makeAgentEnvelope(t, instanceID, nodeID, v1.KindObservation, "observation-"+taskID, v1.Observation{TaskID: taskID, Sequence: 1, TargetRef: "deployment/1", Status: "healthy", Healthy: true, At: time.Unix(1_724_467_200, 0).UTC()}),
		makeAgentEnvelope(t, instanceID, nodeID, v1.KindTaskResult, "result-"+taskID, v1.TaskResult{TaskID: taskID, IdempotencyKey: "idem-" + taskID, Succeeded: true, Status: v1.TaskResultSucceeded}),
	}
}

func observationEnvelope(t *testing.T, instanceID, nodeID, messageID, status string) v1.Envelope {
	t.Helper()
	return makeAgentEnvelope(t, instanceID, nodeID, v1.KindObservation, messageID, v1.Observation{TaskID: "task-1", Sequence: 1, TargetRef: "deployment/1", Status: status, Healthy: status == "healthy", At: time.Unix(1_724_467_200, 0).UTC()})
}

func makeAgentEnvelope(t *testing.T, instanceID, nodeID string, kind v1.MessageKind, messageID string, payload any) v1.Envelope {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := v1.Envelope{Protocol: v1.ProtocolName, Version: v1.ProtocolVersion, MessageID: messageID, InstanceID: instanceID, NodeID: nodeID, Kind: kind, SentAt: time.Unix(1_724_467_200, 0).UTC(), Payload: encoded}
	if kind == v1.KindTaskAck || kind == v1.KindTaskResult || kind == v1.KindLogChunk || kind == v1.KindObservation {
		envelope.AgentSequence = 1
	}
	return envelope
}

func postAgentJSON(t *testing.T, client *http.Client, url string, input any, output any) (int, any) {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatalf("decode %s response: %v", response.Status, err)
		}
	} else {
		_, _ = io.Copy(io.Discard, response.Body)
	}
	return response.StatusCode, output
}

func allAgentKindsSeen(kinds map[v1.MessageKind]bool) bool {
	for _, seen := range kinds {
		if !seen {
			return false
		}
	}
	return true
}

func missingAgentKinds(kinds map[v1.MessageKind]bool) []v1.MessageKind {
	missing := make([]v1.MessageKind, 0)
	for kind, seen := range kinds {
		if !seen {
			missing = append(missing, kind)
		}
	}
	return missing
}

func countAgentKinds(events []v1.Envelope) map[v1.MessageKind]int {
	counts := make(map[v1.MessageKind]int)
	for _, event := range events {
		counts[event.Kind]++
	}
	return counts
}

func waitForAgentSignal[T any](t *testing.T, signal <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(2 * time.Second):
		var zero T
		t.Fatalf("timed out waiting for %s", name)
		return zero
	}
}

func waitForAgentKind(t *testing.T, events <-chan v1.Envelope, want v1.MessageKind, name string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Kind == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", name)
		}
	}
}
