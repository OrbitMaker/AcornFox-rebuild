package application

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestBuildAcornFoxLogsTaskPlanIsBoundedAndBucketReplaySafe(t *testing.T) {
	fact := acornFoxLogsRuntimeFact()
	request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, time.Unix(1_700_000_000, 0).UTC(), 5, "logs-once")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_090, 0).UTC()
	first, err := BuildAcornFoxLogsTaskPlan(request, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildAcornFoxLogsTaskPlan(request, now.Add(time.Second))
	if err != nil || first.TaskID != second.TaskID || first.Operation.ID != second.Operation.ID || first.Deadline != now.Add(AcornFoxLogsTaskDeadline) || first.MaxAttempts != AcornFoxLogsTaskAttempts {
		t.Fatalf("logs task was not bounded/replay-safe: first=%#v second=%#v err=%v", first, second, err)
	}
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(first.Payload, &task); err != nil || task.Kind != v1.TaskLogs {
		t.Fatalf("unexpected durable task: %s %v", first.Payload, err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(task.Parameters, &wire); err != nil || string(wire["acornfox_log_payload_type"]) != `"logs"` || len(wire) != 2 {
		t.Fatalf("logs parameters lost strict marker: %s %v", task.Parameters, err)
	}
	for _, forbidden := range []string{"command", "container", "path", "address", "target", "rollback", "scale", "group"} {
		if strings.Contains(string(first.Payload), `"`+forbidden+`"`) {
			t.Fatalf("durable logs task leaked %q: %s", forbidden, first.Payload)
		}
	}
}

func TestBuildAcornFoxLogsTaskPlanUsesNextInternalSchedulerBucket(t *testing.T) {
	fact := acornFoxLogsRuntimeFact()
	request, err := contracts.NewAcornFoxLogsRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, time.Time{}, 1, "logs-once")
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildAcornFoxLogsTaskPlan(request, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildAcornFoxLogsTaskPlan(request, time.Unix(1_700_000_030, 0).UTC())
	if err != nil || first.TaskID == second.TaskID || first.Operation.ID == second.Operation.ID {
		t.Fatalf("logs task did not advance its collection bucket: first=%#v second=%#v err=%v", first, second, err)
	}
}

func TestAcornFoxLogsCollectionSinceUsesSchedulerInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if got := AcornFoxLogsCollectionSince(now); !got.Equal(now.Add(-AcornFoxLogsCollectionInterval)) {
		t.Fatalf("collection since=%s interval=%s", got, AcornFoxLogsCollectionInterval)
	}
}

func acornFoxLogsRuntimeFact() contracts.AcornFoxRuntimeReleaseFact {
	return contracts.AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_logs", EnvironmentID: "env_logs", ReleaseID: "rel_logs", ServiceName: "web",
		Image:         domain.ImageDigest{Repository: "registry.example/acornfox", Digest: "sha256:" + strings.Repeat("a", 64)},
		Resources:     contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 1 << 20, PIDs: 1, DiskReservationBytes: 1 << 20},
		ContainerPort: 8080, AcceptedAt: time.Unix(1, 0).UTC(), Immutable: true,
	}
}
