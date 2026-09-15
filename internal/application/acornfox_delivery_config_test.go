package application

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"testing"
)

func configuredDeliveryRequest(f *acornFoxDeliveryFixture) AcornFoxDeliveryCreateRequest {
	return AcornFoxDeliveryCreateRequest{ApplicationID: f.source.ApplicationID, SourceRevisionID: f.source.ID, ContainerPort: 8080, IdempotencyKey: "configured-deploy", Actor: "admin", Runtime: &contracts.AcornFoxRuntimeInput{AcornFoxRuntimeConfiguration: contracts.AcornFoxRuntimeConfiguration{Command: []string{"serve", "--quiet"}, Environment: []contracts.RuntimeEnvironmentVariable{{Name: "MODE", Value: "production"}}, Volumes: []contracts.AcornFoxRuntimeVolume{{Name: "data", MountPath: "/data", SizeBytes: 2 << 30}}}}}
}
func TestAcornFoxDeliveryRuntimeConfigPersistsAndReplays(t *testing.T) {
	f := newAcornFoxDeliveryFixture(t)
	f.service.RuntimeConfigurationGate = func(context.Context) error { return nil }
	request := configuredDeliveryRequest(f)
	result, err := f.service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		Parameters struct {
			Request contracts.AcornFoxRuntimeDeployRequest `json:"request"`
		} `json:"parameters"`
	}
	safe, err := foundation.RedactJSON(f.tasks[0].Payload, nil)
	if err != nil || json.Unmarshal(safe, &task) != nil {
		t.Fatal("task not persistable", err)
	}
	fact := task.Parameters.Request.Fact
	if fact.Validate() != nil || fact.SchemaVersion != 2 || fact.Configuration == nil || fact.Configuration.Command[0] != "serve" || fact.Configuration.Environment[0].Kind != contracts.RuntimeEnvironmentLiteral || fact.Resources.DiskReservationBytes != 3<<30 || fact.ConfigDigest != f.release.ConfigDigest {
		t.Fatal("runtime configuration not bound to release/task")
	}
	f.runtimeRequest = task.Parameters.Request
	f.service.RuntimeConfigurationGate = func(context.Context) error { return errors.New("agent now offline") }
	replay, err := f.service.Create(context.Background(), request)
	if err != nil || replay != result || f.buildProvider.calls != 1 {
		t.Fatal("accepted replay depended on live agent", err)
	}
	request.Runtime.Command = []string{"different"}
	if _, err := f.service.Create(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("same key accepted changed config", err)
	}
	restart, err := f.service.Restart(context.Background(), AcornFoxDeliveryActionRequest{ApplicationID: request.ApplicationID, DeploymentID: result.DeploymentID, IdempotencyKey: "restart-configured", Actor: "admin"})
	if err != nil || restart.TaskID.Empty() {
		t.Fatal("restart cannot reuse configured fact", err)
	}
	var action struct {
		Parameters struct {
			Request contracts.AcornFoxRuntimeActionRequest `json:"request"`
		} `json:"parameters"`
	}
	if json.Unmarshal(f.tasks[len(f.tasks)-1].Payload, &action) != nil || action.Parameters.Request.Fact.ConfigDigest != fact.ConfigDigest || action.Parameters.Request.Fact.Configuration.Command[0] != "serve" {
		t.Fatal("restart changed accepted configuration")
	}
}
func TestAcornFoxDeliveryRuntimeConfigRejectsBeforeBuild(t *testing.T) {
	for _, name := range []string{"unsupported agent", "invalid resources", "protected value", "secret unsupported"} {
		t.Run(name, func(t *testing.T) {
			f := newAcornFoxDeliveryFixture(t)
			req := configuredDeliveryRequest(f)
			f.service.RuntimeConfigurationGate = func(context.Context) error { return nil }
			switch name {
			case "unsupported agent":
				f.service.RuntimeConfigurationGate = nil
			case "invalid resources":
				req.Runtime.Resources = &contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, PIDs: 1, DiskReservationBytes: 1}
			case "protected value":
				req.Runtime.Environment[0].Name = "API_KEY"
			case "secret unsupported":
				req.Runtime.Secrets = []contracts.AcornFoxRuntimeSecretBinding{{Name: "key", Reference: domain.SecretReference{ID: "sec_1", Name: "key", Provider: "filesystem-secret"}}}
			}
			if _, err := f.service.Create(context.Background(), req); err == nil || f.buildProvider.calls != 0 || f.importCalls != 0 || len(f.tasks) != 0 {
				t.Fatal("rejected runtime input caused work", err)
			}
		})
	}
}
