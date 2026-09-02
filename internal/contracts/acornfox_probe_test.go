package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxProbeRequestNormalizesOnlyOriginFormHTTPPaths(t *testing.T) {
	reference := probeReference(t)
	request, err := NewAcornFoxProbeRequest(reference, AcornFoxProbeProtocolHTTP, "/ready/../healthz", "probe-1")
	if err != nil || request.HTTPPath != "/healthz" {
		t.Fatalf("normalized request=%+v err=%v", request, err)
	}
	for _, value := range []string{"https://example.test/x", "//example.test/x", "/x?q=1", "/x#fragment", "/x%2fy", " /x", "x"} {
		if _, err := NewAcornFoxProbeRequest(reference, AcornFoxProbeProtocolHTTP, value, "probe-1"); err == nil {
			t.Fatalf("unsafe path was accepted: %q", value)
		}
	}
	if err := (AcornFoxProbeRequest{Reference: reference, Protocol: AcornFoxProbeProtocolHTTP, HTTPPath: "/x/../y", IdempotencyKey: "probe-1"}).Validate(); err == nil {
		t.Fatal("unnormalized wire request was accepted")
	}
	if _, err := NewAcornFoxProbeRequest(reference, AcornFoxProbeProtocolTCP, "/", "probe-1"); err == nil {
		t.Fatal("tcp path was accepted")
	}
}

func TestAcornFoxProbeContractWireShapeAndDigestAreBounded(t *testing.T) {
	reference := probeReference(t)
	request, err := NewAcornFoxProbeRequest(reference, AcornFoxProbeProtocolHTTP, "/", "probe-1")
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := AcornFoxRuntimeDeploymentID(reference.Fact)
	if err != nil {
		t.Fatal(err)
	}
	observation := AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: reference.Fact.ServiceName, InternalAddress: "127.0.0.1:18080"}
	status := 503
	digest, err := AcornFoxProbeFactDigest(request, observation, AcornFoxProbeOutcomeResponded, &status)
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := AcornFoxProbeFactDigest(request, observation, AcornFoxProbeOutcomeResponded, &status); err != nil || repeated != digest {
		t.Fatalf("digest was not deterministic: %q %v", repeated, err)
	}
	result := AcornFoxProbeResult{ApplicationID: reference.Fact.ApplicationID, EnvironmentID: reference.Fact.EnvironmentID, ReleaseID: reference.Fact.ReleaseID, DeploymentID: deploymentID, ServiceName: reference.Fact.ServiceName, Protocol: AcornFoxProbeProtocolHTTP, TargetClass: AcornFoxProbeTargetClassLoopback, Outcome: AcornFoxProbeOutcomeResponded, HTTPStatus: &status, ObservedAt: time.Unix(5, 0).UTC(), FactDigest: digest}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Protocol       AcornFoxProbeProtocol `json:"protocol"`
		HTTPPath       string                `json:"http_path,omitempty"`
		IdempotencyKey string                `json:"idempotency_key"`
		Result         AcornFoxProbeResult   `json:"result"`
	}{request.Protocol, request.HTTPPath, request.IdempotencyKey, result})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"address", "host", "port", "url", "timeout", "network", "healthy", "public", "external", "dns", "tls", "body", "error_message"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("probe wire contract leaked %q: %s", forbidden, raw)
		}
	}
	if result.ErrorCode = "connection refused: secret"; result.Validate() == nil {
		t.Fatal("raw error text was accepted")
	}
	result.HTTPStatus = nil
	result.Protocol = AcornFoxProbeProtocolTCP
	result.Outcome = AcornFoxProbeOutcomeMalformedResponse
	result.ErrorCode = AcornFoxProbeErrorMalformedResponse
	if result.Validate() == nil {
		t.Fatal("TCP accepted an HTTP-only malformed response outcome")
	}
	if _, err := AcornFoxProbeFactDigest(AcornFoxProbeRequest{Reference: reference, Protocol: AcornFoxProbeProtocolTCP, IdempotencyKey: "probe-1"}, observation, AcornFoxProbeOutcomeMalformedResponse, nil); err == nil {
		t.Fatal("TCP malformed response digest was accepted")
	}
}

func probeReference(t *testing.T) AcornFoxRuntimeReference {
	t.Helper()
	fact := AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_probe",
		EnvironmentID: "env_probe",
		ReleaseID:     "rel_probe",
		ServiceName:   "web",
		Image:         domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("a", 64)},
		Resources:     AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, PIDs: 1, DiskReservationBytes: 1},
		ContainerPort: 8080,
		AcceptedAt:    time.Unix(1, 0).UTC(),
		Immutable:     true,
	}
	if err := fact.Validate(); err != nil {
		t.Fatal(err)
	}
	return AcornFoxRuntimeReference{Fact: fact}
}
