package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestDecodeAcornFoxRuntimeTaskRejectsLegacyAndTamperedPayloads(t *testing.T) {
	fact := contracts.AcornFoxRuntimeReleaseFact{ApplicationID: "app_runtime", EnvironmentID: "env_runtime", ReleaseID: "release_runtime", ServiceName: "web", Image: domain.ImageDigest{Repository: "registry.example/acornfox", Digest: "sha256:" + strings.Repeat("a", 64)}, Resources: contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 64, DiskReservationBytes: 1 << 30}, ContainerPort: 8080, AcceptedAt: time.Unix(1, 0).UTC(), Immutable: true}
	parameters, err := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "delivery-key"}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(parameters)})
	if err != nil {
		t.Fatal(err)
	}
	request, marked, err := decodeAcornFoxRuntimeTask(payload)
	if err != nil || !marked || request.Fact != fact || request.IdempotencyKey != "delivery-key" {
		t.Fatalf("request=%#v marked=%v err=%v", request, marked, err)
	}
	tamperedParameters, err := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: fact, IdempotencyKey: "delivery-key", Recreate: true}})
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload, err := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(tamperedParameters)})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]json.RawMessage{
		"legacy":            json.RawMessage(`{"kind":"deploy","parameters":{"operation":{"idempotency_key":"legacy"}}}`),
		"wrong marker":      json.RawMessage(`{"kind":"deploy","parameters":{"acornfox_payload_type":"shell","request":{}}}`),
		"recreate mismatch": tamperedPayload,
	} {
		if _, marked, err := decodeAcornFoxRuntimeTask(raw); err == nil && marked {
			t.Fatalf("%s accepted", name)
		}
	}
}
