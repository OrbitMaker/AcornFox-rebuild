package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

func TestNewAcornFoxLogsRequestBindsOnlyImmutableRuntimeIdentity(t *testing.T) {
	fact := acornFoxLogsFact()
	since := time.Date(2026, 9, 2, 1, 2, 3, 0, time.FixedZone("local", 8*60*60))
	request, err := NewAcornFoxLogsRequest(AcornFoxRuntimeReference{Fact: fact}, since, AcornFoxLogsMaxTail, "logs-once")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := AcornFoxRuntimeDeploymentID(fact)
	if err != nil || request.DeploymentID != expected || request.ServiceName != fact.ServiceName || request.Since.Location() != time.UTC {
		t.Fatalf("logs request did not bind immutable runtime identity: %#v err=%v", request, err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"container", "command", "path", "address", "target"} {
		if strings.Contains(string(encoded), "\""+forbidden+"\"") {
			t.Fatalf("logs request leaked forbidden runtime control %q: %s", forbidden, encoded)
		}
	}
}

func TestAcornFoxLogsRequestRejectsUnboundIdentityAndInvalidBounds(t *testing.T) {
	fact := acornFoxLogsFact()
	request, err := NewAcornFoxLogsRequest(AcornFoxRuntimeReference{Fact: fact}, time.Time{}, 1, "logs-once")
	if err != nil {
		t.Fatal(err)
	}
	cases := []AcornFoxLogsRequest{
		func() AcornFoxLogsRequest { value := request; value.DeploymentID = "dep_other"; return value }(),
		func() AcornFoxLogsRequest { value := request; value.ServiceName = "other"; return value }(),
		func() AcornFoxLogsRequest { value := request; value.Tail = 0; return value }(),
		func() AcornFoxLogsRequest { value := request; value.Tail = AcornFoxLogsMaxTail + 1; return value }(),
		func() AcornFoxLogsRequest { value := request; value.IdempotencyKey = " "; return value }(),
		func() AcornFoxLogsRequest { value := request; value.Since = time.Now(); return value }(),
	}
	for _, value := range cases {
		if err := value.Validate(); err == nil {
			t.Fatalf("unsafe logs request was accepted: %#v", value)
		}
	}
}

func TestAcornFoxBoundedLogsAcceptsOnlyBoundedProvenancePreservingRecords(t *testing.T) {
	valid := AcornFoxBoundedLogs{Records: []AcornFoxLogRecord{
		{Stream: AcornFoxLogStreamStdout, Data: "ready\n"},
		{Stream: AcornFoxLogStreamStderr, Data: "warning\n"},
	}, SourceLimited: true}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid bounded logs rejected: %v", err)
	}
	for _, invalid := range []AcornFoxBoundedLogs{
		{Records: []AcornFoxLogRecord{{Stream: "combined", Data: "not proven\n"}}},
		{Records: []AcornFoxLogRecord{{Stream: AcornFoxLogStreamStdout, Data: ""}}},
		{Records: make([]AcornFoxLogRecord, AcornFoxLogsMaxRecords+1)},
		{Records: []AcornFoxLogRecord{{Stream: AcornFoxLogStreamStdout, Data: strings.Repeat("x", AcornFoxLogsMaxBytes+1)}}},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid bounded logs accepted: %#v", invalid)
		}
	}
}

func acornFoxLogsFact() AcornFoxRuntimeReleaseFact {
	return AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_logs", EnvironmentID: "env_logs", ReleaseID: "rel_logs", ServiceName: "web",
		Image:         domain.ImageDigest{Repository: "registry.example/acornfox", Digest: "sha256:" + strings.Repeat("a", 64)},
		Resources:     AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1 << 20, PIDs: 1, DiskReservationBytes: 1 << 20},
		ContainerPort: 8080, AcceptedAt: time.Unix(1, 0).UTC(), Immutable: true,
	}
}
