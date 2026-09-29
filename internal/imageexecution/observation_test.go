package imageexecution

import (
	"context"
	"encoding/json"
	"errors"
	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"strings"
	"testing"
	"time"
)

func TestManagedObservationBoundsAndBindingGlue(t *testing.T) {
	q := appcontracts.ImageObservationRequest{AdminID: "admin", DeploymentID: "dep", Logs: true, Tail: 64}
	if !q.Valid(time.Now().UTC()) {
		t.Fatal("valid bounds rejected")
	}
	q.Tail = 65
	if _, err := (*ContainerRuntime)(nil).ReadManagedImageObservation(context.Background(), q); err == nil {
		t.Fatal("invalid bounds reached authority")
	}
	q.Tail = 64
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (*ContainerRuntime)(nil).ReadManagedImageObservation(ctx, q); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context cause lost")
	}
	if _, err := (*ContainerRuntime)(nil).ReadManagedImageObservation(context.Background(), q); err == nil {
		t.Fatal("missing authority accepted")
	}
	a := appcontracts.ManagedImageObservationBinding{AdminID: "admin", Runtime: appcontracts.ImageLifecycleBinding{ContainerID: "cid"}}
	b := a
	b.Runtime.ContainerID = "foreign"
	if sameObservationBinding(a, b) {
		t.Fatal("drift accepted")
	}
	b = a
	b.AdminID = "other"
	if sameObservationBinding(a, b) {
		t.Fatal("owner drift accepted")
	}
	logs, limited := boundedObservationLogs(contracts.AcornFoxBoundedLogs{Records: []contracts.AcornFoxLogRecord{{Stream: "stderr", Data: "token=must-not-leak"}, {Stream: "stdout", Data: strings.Repeat("x", appcontracts.ImageObservationLogBytes)}}})
	if !limited || len(logs) != 1 || logs[0].Stream != "stderr" || strings.Contains(logs[0].Data, "must-not-leak") {
		t.Fatal("redaction/stream/byte glue failed")
	}
	if len(observationSlots) != 0 {
		t.Fatal("observation slot leaked")
	}
	state := appcontracts.ImageObservationResult{State: appcontracts.ImageLifecycleResult{Running: false, VerifiedIdentity: true, ContainerID: "cid", ImageID: "sha256:image", ManifestDigest: "sha256:manifest", HostPort: 39001, ContainerPort: 80, ObservedAt: time.Now().UTC()}}
	raw, _ := json.Marshal(state)
	if _, err := decodeManagedObservationResult(raw); err != nil {
		t.Fatalf("explicit stopped snapshot rejected: %v", err)
	}
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	delete(wire["state"].(map[string]any), "running")
	missing, _ := json.Marshal(wire)
	if _, err := decodeManagedObservationResult(missing); err == nil {
		t.Fatal("omitted running flag accepted")
	}
	state.State.EndpointReady = true
	raw, _ = json.Marshal(state)
	if _, err := decodeManagedObservationResult(raw); err == nil {
		t.Fatal("unprobed endpoint ready accepted")
	}
	state.State.EndpointReady = false
	state.State.ObservedAt = time.Time{}
	raw, _ = json.Marshal(state)
	if _, err := decodeManagedObservationResult(raw); err == nil {
		t.Fatal("missing observation time accepted")
	}
	state.State.ObservedAt = time.Now().UTC().Add(-time.Minute)
	raw, _ = json.Marshal(state)
	if _, err := decodeManagedObservationResult(raw); err == nil {
		t.Fatal("stale observation accepted")
	}

}
