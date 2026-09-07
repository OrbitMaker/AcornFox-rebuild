package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
)

func TestAcornFoxCandidateStrictDecodeRejectsAdditionalAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	spec := testAcornFoxCandidateSpec()
	runtime := newCandidateRuntimeFake(spec, now)
	executor := NewAcornFoxCandidateOutboundExecutor("instance-candidate", "node-candidate", runtime)
	executor.clock = func() time.Time { return now }
	valid := acornFoxCandidateTask(t, spec, "candidate-valid", now)

	cases := []struct {
		name       string
		parameters string
		kind       v1.TaskKind
	}{
		{name: "unknown wrapper field", parameters: `{"acornfox_candidate_payload_type":"acornfox_candidate_validation_v1","request":{},"command":"docker ps"}`, kind: v1.TaskDeploy},
		{name: "unknown request field", parameters: candidateParameters(t, spec, `,"host_path":"/tmp"`), kind: v1.TaskDeploy},
		{name: "resolved tag", parameters: strings.Replace(string(valid.Parameters), `"digest":"`, `"resolved_tag":"latest","digest":"`, 1), kind: v1.TaskDeploy},
		{name: "trailing json", parameters: string(valid.Parameters) + ` {"ignored":true}`, kind: v1.TaskDeploy},
		{name: "wrong marker", parameters: strings.Replace(string(valid.Parameters), acornFoxCandidatePayloadType, "deploy", 1), kind: v1.TaskDeploy},
		{name: "wrong kind", parameters: string(valid.Parameters), kind: v1.TaskObserve},
		{name: "normal deployment id", parameters: strings.Replace(string(valid.Parameters), spec.CandidateID.String(), "dep_normal", 1), kind: v1.TaskDeploy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := valid
			task.TaskID = "task-" + strings.ReplaceAll(tc.name, " ", "-")
			task.IdempotencyKey = "key-" + strings.ReplaceAll(tc.name, " ", "-")
			task.Kind = tc.kind
			task.Parameters = json.RawMessage(tc.parameters)
			result := executor.Execute(context.Background(), task)
			if result.Result.ErrorCode != "invalid_argument" || result.Result.Succeeded {
				t.Fatalf("unexpected rejected result: %#v", result.Result)
			}
		})
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("rejected input reached candidate runtime: %v", runtime.calls)
	}
}

func TestAcornFoxCandidateLifecycleIdentityAndHandlerReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	spec := testAcornFoxCandidateSpec()
	runtime := newCandidateRuntimeFake(spec, now)
	handler := WithAcornFoxCandidateRuntime(NewOutboundHandler("instance-candidate", "node-candidate", staticDockerFacts{}), runtime)
	handler.clock = func() time.Time { return now }
	handler.acornFoxCandidate.clock = func() time.Time { return now }
	task := acornFoxCandidateTask(t, spec, "candidate-replay", now)

	first, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"deploy", "observe", "probe", "destroy", "confirm_absent"}) {
		t.Fatalf("unexpected candidate lifecycle: %v", runtime.calls)
	}
	if len(first) != 4 || len(second) != len(first) {
		t.Fatalf("unexpected candidate event count: first=%d second=%d", len(first), len(second))
	}
	for index := range first {
		if first[index].MessageID != second[index].MessageID {
			t.Fatalf("replay changed event %d identity", index)
		}
	}
	var result v1.TaskResult
	if err := json.Unmarshal(first[len(first)-1].Payload, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Succeeded || result.Status != v1.TaskResultSucceeded || len(result.EvidenceRefs) != 2 {
		t.Fatalf("unexpected candidate result: %#v", result)
	}

	firstID, err := AcornFoxCandidateRuntimeID(spec)
	if err != nil || !strings.HasPrefix(firstID, "candidate_runtime_") {
		t.Fatalf("candidate runtime id = %q, err=%v", firstID, err)
	}
	changed := spec
	changed.Image.Digest = "sha256:" + strings.Repeat("b", 64)
	secondID, err := AcornFoxCandidateRuntimeID(changed)
	if err != nil || secondID == firstID {
		t.Fatalf("digest change did not change candidate identity: first=%q second=%q err=%v", firstID, secondID, err)
	}

	conflict := task
	conflict.TaskID = "task-conflict"
	conflict.Parameters = acornFoxCandidateTask(t, changed, task.IdempotencyKey, now).Parameters
	if _, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, conflict)); err == nil {
		t.Fatal("handler accepted conflicting input for candidate idempotency key")
	}
}

func TestAcornFoxCandidateCleansUpAfterProbeFailureAndCancellation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	spec := testAcornFoxCandidateSpec()

	t.Run("probe failure", func(t *testing.T) {
		runtime := newCandidateRuntimeFake(spec, now)
		runtime.probeErr = errors.New("probe refused")
		result := candidateExecutorAt(runtime, now).Execute(context.Background(), acornFoxCandidateTask(t, spec, "candidate-probe-failure", now))
		if result.Result.ErrorCode != "candidate_runtime_probe_failed" {
			t.Fatalf("probe failure code = %q", result.Result.ErrorCode)
		}
		if !reflect.DeepEqual(runtime.calls, []string{"deploy", "observe", "probe", "destroy", "confirm_absent"}) {
			t.Fatalf("probe failure cleanup calls = %v", runtime.calls)
		}
	})

	t.Run("cancelled probe", func(t *testing.T) {
		runtime := newCandidateRuntimeFake(spec, now)
		runtime.blockProbe = true
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := candidateExecutorAt(runtime, now).Execute(ctx, acornFoxCandidateTask(t, spec, "candidate-cancelled", now))
		if result.Result.ErrorCode != "candidate_runtime_cancelled" {
			t.Fatalf("cancel failure code = %q", result.Result.ErrorCode)
		}
		if !runtime.cleanupContextLive {
			t.Fatal("cleanup inherited cancelled task context")
		}
		if !reflect.DeepEqual(runtime.calls, []string{"deploy", "observe", "probe", "destroy", "confirm_absent"}) {
			t.Fatalf("cancel cleanup calls = %v", runtime.calls)
		}
	})
}

func TestAcornFoxCandidateFailsWhenAbsenceCannotBeConfirmed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	spec := testAcornFoxCandidateSpec()
	for _, tc := range []struct {
		name   string
		mutate func(*candidateRuntimeFake)
	}{
		{name: "present", mutate: func(runtime *candidateRuntimeFake) { runtime.absence.Absent = false }},
		{name: "wrong identity", mutate: func(runtime *candidateRuntimeFake) { runtime.absence.RuntimeID = "candidate_runtime_wrong" }},
		{name: "inventory failed", mutate: func(runtime *candidateRuntimeFake) { runtime.absenceErr = errors.New("daemon unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := newCandidateRuntimeFake(spec, now)
			tc.mutate(runtime)
			result := candidateExecutorAt(runtime, now).Execute(context.Background(), acornFoxCandidateTask(t, spec, "candidate-absence-"+tc.name, now))
			if result.Result.Succeeded || result.Result.ErrorCode != "candidate_runtime_absence_unconfirmed" {
				t.Fatalf("absence failure result = %#v", result.Result)
			}
		})
	}

	runtime := newCandidateRuntimeFake(spec, now)
	runtime.destroyErr = errors.New("destroy failed")
	result := candidateExecutorAt(runtime, now).Execute(context.Background(), acornFoxCandidateTask(t, spec, "candidate-destroy-failure", now))
	if result.Result.ErrorCode != "candidate_runtime_cleanup_failed" || !reflect.DeepEqual(runtime.calls, []string{"deploy", "observe", "probe", "destroy", "confirm_absent"}) {
		t.Fatalf("destroy failure did not preserve independent absence check: result=%#v calls=%v", result.Result, runtime.calls)
	}
}

func candidateExecutorAt(runtime AcornFoxCandidateRuntime, now time.Time) *AcornFoxCandidateOutboundExecutor {
	executor := NewAcornFoxCandidateOutboundExecutor("instance-candidate", "node-candidate", runtime)
	executor.clock = func() time.Time { return now }
	return executor
}

func testAcornFoxCandidateSpec() AcornFoxCandidateRuntimeSpec {
	return AcornFoxCandidateRuntimeSpec{
		CandidateID:   "candidate_fix_1",
		ApplicationID: "app_candidate",
		Image:         AcornFoxCandidateImage{Repository: "registry.example.test/acornfox/candidate", Digest: "sha256:" + strings.Repeat("a", 64)},
		ContainerPort: 8080,
		Resources:     AcornFoxCandidateRuntimeResources{CPUMillis: 500, MemoryBytes: 128 << 20, PIDs: 64, DiskReservationBytes: 256 << 20},
	}
}

func acornFoxCandidateTask(t *testing.T, spec AcornFoxCandidateRuntimeSpec, key string, now time.Time) v1.TaskRequest {
	t.Helper()
	request, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(acornFoxCandidateTaskPayload{PayloadType: acornFoxCandidatePayloadType, Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return v1.TaskRequest{TaskID: "task-" + key, InstanceID: "instance-candidate", NodeID: "node-candidate", Kind: v1.TaskDeploy, IdempotencyKey: key, LeaseID: "lease-" + key, Parameters: parameters, Deadline: now.Add(time.Minute)}
}

func candidateParameters(t *testing.T, spec AcornFoxCandidateRuntimeSpec, requestSuffix string) string {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	request := strings.TrimSuffix(string(raw), "}") + requestSuffix + "}"
	return `{"acornfox_candidate_payload_type":"` + acornFoxCandidatePayloadType + `","request":` + request + `}`
}

type candidateRuntimeFake struct {
	spec               AcornFoxCandidateRuntimeSpec
	observation        AcornFoxCandidateRuntimeObservation
	probe              AcornFoxCandidateRuntimeProbe
	absence            AcornFoxCandidateRuntimeAbsence
	calls              []string
	probeErr           error
	destroyErr         error
	absenceErr         error
	blockProbe         bool
	cleanupContextLive bool
}

func newCandidateRuntimeFake(spec AcornFoxCandidateRuntimeSpec, now time.Time) *candidateRuntimeFake {
	runtimeID, _ := AcornFoxCandidateRuntimeID(spec)
	observation := AcornFoxCandidateRuntimeObservation{RuntimeID: runtimeID, ContainerID: "container-candidate-1", RuntimeState: "running", Image: spec.Image, HostPort: 38080, AppliedResources: spec.Resources, ObservedAt: now.Add(time.Second)}
	return &candidateRuntimeFake{
		spec:        spec,
		observation: observation,
		probe:       AcornFoxCandidateRuntimeProbe{RuntimeID: runtimeID, ContainerID: observation.ContainerID, TargetClass: "loopback", Outcome: "responded", EvidenceRef: "candidate-probe:" + runtimeID, ObservedAt: now.Add(2 * time.Second)},
		absence:     AcornFoxCandidateRuntimeAbsence{RuntimeID: runtimeID, Absent: true, EvidenceRef: "candidate-absence:" + runtimeID, ObservedAt: now.Add(3 * time.Second)},
	}
}

func (r *candidateRuntimeFake) Deploy(_ context.Context, spec AcornFoxCandidateRuntimeSpec) error {
	r.calls = append(r.calls, "deploy")
	if spec != r.spec {
		return errors.New("unexpected candidate spec")
	}
	return nil
}

func (r *candidateRuntimeFake) Observe(_ context.Context, spec AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeObservation, error) {
	r.calls = append(r.calls, "observe")
	if spec != r.spec {
		return AcornFoxCandidateRuntimeObservation{}, errors.New("unexpected candidate spec")
	}
	return r.observation, nil
}

func (r *candidateRuntimeFake) Probe(ctx context.Context, spec AcornFoxCandidateRuntimeSpec, observation AcornFoxCandidateRuntimeObservation) (AcornFoxCandidateRuntimeProbe, error) {
	r.calls = append(r.calls, "probe")
	if spec != r.spec || observation != r.observation {
		return AcornFoxCandidateRuntimeProbe{}, errors.New("unexpected candidate probe input")
	}
	if r.blockProbe {
		<-ctx.Done()
		return AcornFoxCandidateRuntimeProbe{}, ctx.Err()
	}
	return r.probe, r.probeErr
}

func (r *candidateRuntimeFake) Destroy(ctx context.Context, spec AcornFoxCandidateRuntimeSpec) error {
	r.calls = append(r.calls, "destroy")
	r.cleanupContextLive = ctx.Err() == nil
	if spec != r.spec {
		return errors.New("unexpected candidate spec")
	}
	return r.destroyErr
}

func (r *candidateRuntimeFake) ConfirmAbsent(_ context.Context, spec AcornFoxCandidateRuntimeSpec) (AcornFoxCandidateRuntimeAbsence, error) {
	r.calls = append(r.calls, "confirm_absent")
	if spec != r.spec {
		return AcornFoxCandidateRuntimeAbsence{}, errors.New("unexpected candidate spec")
	}
	return r.absence, r.absenceErr
}
