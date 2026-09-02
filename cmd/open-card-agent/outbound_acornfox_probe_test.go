package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	acornfoxprobe "github.com/open-card/open-card/internal/probe"
)

func TestAcornFoxProbeOutboundExecutorUsesLiveRuntimeObservationForHTTPAndTCP(t *testing.T) {
	fact := testAcornFoxFact()
	t.Run("http", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/ready" {
				t.Fatalf("unexpected probe path %q", request.URL.Path)
			}
			writer.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		runtime := newProbeRuntime(t, fact, strings.TrimPrefix(server.URL, "http://"))
		prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), func() time.Time { return time.Unix(7, 0).UTC() })
		if err != nil {
			t.Fatal(err)
		}
		handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime, prober)
		handler.healthProbe = func(context.Context, int, time.Time) error { t.Fatal("probe called legacy health probe"); return nil }
		events := executeProbeTask(t, handler, acornFoxProbeTask(t, "probe-http", fact, contracts.AcornFoxProbeProtocolHTTP, "/ready"))
		result := assertAcornFoxProbeWire(t, events)
		if runtime.observeCalls != 1 || result.Protocol != contracts.AcornFoxProbeProtocolHTTP || result.Outcome != contracts.AcornFoxProbeOutcomeResponded || result.HTTPStatus == nil || *result.HTTPStatus != http.StatusNoContent {
			t.Fatalf("HTTP probe did not use current runtime observation: calls=%d result=%#v", runtime.observeCalls, result)
		}
	})

	t.Run("tcp", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan struct{}, 1)
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr == nil {
				accepted <- struct{}{}
				_ = connection.Close()
			}
		}()
		runtime := newProbeRuntime(t, fact, listener.Addr().String())
		prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime, prober)
		result := assertAcornFoxProbeWire(t, executeProbeTask(t, handler, acornFoxProbeTask(t, "probe-tcp", fact, contracts.AcornFoxProbeProtocolTCP, "")))
		if runtime.observeCalls != 1 || result.Protocol != contracts.AcornFoxProbeProtocolTCP || result.Outcome != contracts.AcornFoxProbeOutcomeResponded || result.HTTPStatus != nil {
			t.Fatalf("TCP probe did not use current runtime observation: calls=%d result=%#v", runtime.observeCalls, result)
		}
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("TCP probe did not dial the runtime-derived loopback address")
		}
	})
}

func TestAcornFoxProbeNoPortIsNotApplicableWithoutDial(t *testing.T) {
	fact := testAcornFoxFact()
	fact.ContainerPort = 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = connection.Close()
		}
	}()
	runtime := newProbeRuntime(t, fact, "")
	prober, err := acornfoxprobe.New(acornfoxprobe.DefaultConfig(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime, prober)
	result := assertAcornFoxProbeWire(t, executeProbeTask(t, handler, acornFoxProbeTask(t, "probe-no-port", fact, contracts.AcornFoxProbeProtocolHTTP, "/")))
	if runtime.observeCalls != 1 || result.Outcome != contracts.AcornFoxProbeOutcomeNotApplicable || result.LatencyMS != 0 {
		t.Fatalf("no-port probe result=%#v calls=%d", result, runtime.observeCalls)
	}
	select {
	case <-accepted:
		t.Fatal("no-port probe dialed an arbitrary listener")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAcornFoxProbeStrictRoutingRedactionAndReplay(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := newProbeRuntime(t, fact, "127.0.0.1:32001")
	prober := &fakeAcornFoxProber{}
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, contracts.NewFakeRuntimeDriver(true), nil, nil, runtime, prober)
	handler.healthProbe = func(context.Context, int, time.Time) error {
		t.Fatal("probe fell through to legacy health probe")
		return nil
	}
	valid := acornFoxProbeTask(t, "probe-replay", fact, contracts.AcornFoxProbeProtocolTCP, "")
	first := executeProbeTask(t, handler, valid)
	second := executeProbeTask(t, handler, valid)
	if runtime.observeCalls != 1 || prober.calls != 1 || len(first) != len(second) {
		t.Fatalf("probe replay repeated a live effect: runtime=%d prober=%d", runtime.observeCalls, prober.calls)
	}
	for index := range first {
		if first[index].MessageID != second[index].MessageID {
			t.Fatalf("probe replay changed event %d identity", index)
		}
	}

	cases := []struct {
		name string
		task v1.TaskRequest
	}{
		{name: "unknown probe marker", task: probeTaskWithIdentity(withProbeParameters(t, valid, `{"acornfox_probe_payload_type":"shell","request":{}}`), "probe-unknown")},
		{name: "wrong kind", task: probeTaskWithIdentity(probeTaskWithKind(valid, v1.TaskRestart), "probe-wrong-kind")},
		{name: "wrapper mixed runtime authority", task: probeTaskWithIdentity(withProbeParameters(t, valid, `{"acornfox_probe_payload_type":"probe","acornfox_payload_type":"observe","request":{}}`), "probe-mixed")},
		{name: "arbitrary target is unknown request field", task: probeTaskWithIdentity(withProbeParameters(t, valid, `{"acornfox_probe_payload_type":"probe","request":{"runtime_reference":{},"protocol":"tcp","idempotency_key":"probe-replay","target":"127.0.0.1:1"}}`), "probe-target")},
	}
	baselineRuntime, baselineProber := runtime.observeCalls, prober.calls
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := executeProbeTask(t, handler, tc.task)
			if len(events) != 2 {
				t.Fatalf("probe marker fell through: %#v", events)
			}
			var ack v1.TaskAck
			if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckRejected {
				t.Fatalf("probe task was not rejected: %#v err=%v", ack, err)
			}
		})
	}
	trailing := probeTaskWithIdentity(withProbeParameters(t, valid, `{"acornfox_probe_payload_type":"probe","request":{}} {"ignored":true}`), "probe-trailing")
	trailingEvents, err := handler.executeTask(context.Background(), trailing)
	if err != nil || len(trailingEvents) != 2 {
		t.Fatalf("trailing probe wrapper escaped strict rejection: events=%#v err=%v", trailingEvents, err)
	}
	var trailingAck v1.TaskAck
	if err := json.Unmarshal(trailingEvents[0].Payload, &trailingAck); err != nil || trailingAck.Status != v1.AckRejected {
		t.Fatalf("trailing probe wrapper was not rejected: %#v err=%v", trailingAck, err)
	}
	if runtime.observeCalls != baselineRuntime || prober.calls != baselineProber {
		t.Fatalf("rejected probe reached runtime/prober: runtime=%d prober=%d", runtime.observeCalls, prober.calls)
	}

	prober.err = errors.New("network secret=must-not-leak")
	errorTask := acornFoxProbeTask(t, "probe-redacted", fact, contracts.AcornFoxProbeProtocolTCP, "")
	events := executeProbeTask(t, handler, errorTask)
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), "must-not-leak") || !strings.Contains(string(raw), "probe_failed") {
		t.Fatalf("probe error leaked raw network detail: %s", raw)
	}
}

func TestComposeAcornFoxRuntimeWithProbeBuildsOnlyAfterReconcile(t *testing.T) {
	provider := &reconcileOrderingRuntime{RuntimeDriver: contracts.NewFakeRuntimeDriver(true)}
	builtAfterReconcile := false
	legacy, runtime, prober, capabilities, err := composeAcornFoxRuntimeWithProbe(context.Background(), provider, func() (acornFoxRuntimeProber, error) {
		builtAfterReconcile = provider.reconcileCalls == 1
		return &fakeAcornFoxProber{}, nil
	})
	if err != nil || !builtAfterReconcile || legacy != provider || runtime == nil || prober == nil || !compositionHasCapability(capabilities, v1.AgentCapabilityAcornFoxProbe) {
		t.Fatalf("probe composition order/capability failed: legacy=%#v runtime=%#v prober=%#v capabilities=%v reconciles=%d err=%v", legacy, runtime, prober, capabilities, provider.reconcileCalls, err)
	}
	failed := &reconcileOrderingRuntime{RuntimeDriver: contracts.NewFakeRuntimeDriver(true)}
	legacy, runtime, prober, capabilities, err = composeAcornFoxRuntimeWithProbe(context.Background(), failed, func() (acornFoxRuntimeProber, error) {
		return nil, errors.New("probe constructor failed")
	})
	if err == nil || failed.reconcileCalls != 1 || legacy != nil || runtime != nil || prober != nil || len(capabilities) != 0 {
		t.Fatalf("failed probe construction advertised capability: legacy=%#v runtime=%#v prober=%#v capabilities=%v err=%v", legacy, runtime, prober, capabilities, err)
	}
}

func TestAcornFoxProbeRejectsDigestNotBoundToLiveRuntimeObservation(t *testing.T) {
	fact := testAcornFoxFact()
	runtime := newProbeRuntime(t, fact, "127.0.0.1:32001")
	prober := &fakeAcornFoxProber{digestOverride: "sha256:" + strings.Repeat("0", 64)}
	handler := NewOutboundHandlerWithAcornFoxProbe("instance-acorn", "node-acorn", staticDockerFacts{}, nil, nil, nil, runtime, prober)
	events := executeProbeTask(t, handler, acornFoxProbeTask(t, "probe-unbound-digest", fact, contracts.AcornFoxProbeProtocolTCP, ""))
	if len(events) != 3 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindLogChunk || events[2].Kind != v1.KindTaskResult {
		t.Fatalf("unbound probe digest produced unexpected events: %#v", events)
	}
	var ack v1.TaskAck
	var result v1.TaskResult
	if err := json.Unmarshal(events[0].Payload, &ack); err != nil || ack.Status != v1.AckAccepted {
		t.Fatalf("valid request was not accepted before bounded validation failure: %#v err=%v", ack, err)
	}
	if err := json.Unmarshal(events[2].Payload, &result); err != nil || result.Succeeded || result.ErrorCode != "probe_result_invalid" {
		t.Fatalf("unbound probe digest was accepted: %#v err=%v", result, err)
	}
}

func executeProbeTask(t *testing.T, handler *OutboundHandler, task v1.TaskRequest) []v1.Envelope {
	t.Helper()
	events, err := handler.HandleControlEnvelope(context.Background(), controlTaskEnvelope(t, task))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func assertAcornFoxProbeWire(t *testing.T, events []v1.Envelope) contracts.AcornFoxProbeResult {
	t.Helper()
	if len(events) != 4 || events[0].Kind != v1.KindTaskAck || events[1].Kind != v1.KindLogChunk || events[2].Kind != v1.KindObservation || events[3].Kind != v1.KindTaskResult {
		t.Fatalf("unexpected probe events: %#v", events)
	}
	var observation v1.Observation
	if err := json.Unmarshal(events[2].Payload, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Healthy || observation.Status != "unknown" || !strings.Contains(observation.TargetRef, "/probe/") {
		t.Fatalf("probe wire claimed health or an invalid target: %#v", observation)
	}
	var result contracts.AcornFoxProbeResult
	if err := json.Unmarshal(observation.Details, &result); err != nil || result.Validate() != nil {
		t.Fatalf("probe wire details are not the exact bounded result: %#v err=%v", result, err)
	}
	if !observation.At.Equal(result.ObservedAt) || len(observation.EvidenceRefs) != 1 || observation.EvidenceRefs[0] != "acornfox-probe:"+result.FactDigest {
		t.Fatalf("probe wire did not bind timestamp/evidence to result: observation=%#v result=%#v", observation, result)
	}
	return result
}

func acornFoxProbeTask(t *testing.T, key string, fact contracts.AcornFoxRuntimeReleaseFact, protocol contracts.AcornFoxProbeProtocol, httpPath string) v1.TaskRequest {
	t.Helper()
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, protocol, httpPath, key)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := json.Marshal(struct {
		PayloadType string                         `json:"acornfox_probe_payload_type"`
		Request     contracts.AcornFoxProbeRequest `json:"request"`
	}{PayloadType: "probe", Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return v1.TaskRequest{TaskID: "task-" + key, InstanceID: "instance-acorn", NodeID: "node-acorn", Kind: v1.TaskObserve, IdempotencyKey: key, LeaseID: "lease-" + key, Parameters: parameters, Deadline: time.Now().Add(time.Minute).UTC()}
}

func withProbeParameters(t *testing.T, task v1.TaskRequest, parameters string) v1.TaskRequest {
	t.Helper()
	task.Parameters = json.RawMessage(parameters)
	return task
}

func probeTaskWithKind(task v1.TaskRequest, kind v1.TaskKind) v1.TaskRequest {
	task.Kind = kind
	return task
}

func probeTaskWithIdentity(task v1.TaskRequest, key string) v1.TaskRequest {
	task.TaskID = "task-" + key
	task.IdempotencyKey = key
	task.LeaseID = "lease-" + key
	return task
}

type probeRuntime struct {
	fact         contracts.AcornFoxRuntimeReleaseFact
	address      string
	observeCalls int
}

func newProbeRuntime(t *testing.T, fact contracts.AcornFoxRuntimeReleaseFact, address string) *probeRuntime {
	t.Helper()
	return &probeRuntime{fact: fact, address: address}
}

func (r *probeRuntime) Observe(_ context.Context, reference contracts.AcornFoxRuntimeReference) (contracts.AcornFoxRuntimeObservation, error) {
	if reference.Fact != r.fact {
		return contracts.AcornFoxRuntimeObservation{}, errors.New("unexpected probe reference")
	}
	id, err := contracts.AcornFoxRuntimeDeploymentID(reference.Fact)
	if err != nil {
		return contracts.AcornFoxRuntimeObservation{}, err
	}
	r.observeCalls++
	return contracts.AcornFoxRuntimeObservation{DeploymentID: id, ServiceName: reference.Fact.ServiceName, InternalAddress: r.address, RuntimeState: "running", ObservedAt: time.Unix(3, 0).UTC()}, nil
}

func (*probeRuntime) Deploy(context.Context, contracts.AcornFoxRuntimeDeployRequest) (contracts.AcornFoxRuntimeDeployment, error) {
	return contracts.AcornFoxRuntimeDeployment{}, errors.New("unexpected deploy")
}
func (*probeRuntime) Restart(context.Context, contracts.AcornFoxRuntimeActionRequest) error {
	return errors.New("unexpected restart")
}
func (*probeRuntime) Destroy(context.Context, contracts.AcornFoxRuntimeActionRequest) error {
	return errors.New("unexpected destroy")
}

type fakeAcornFoxProber struct {
	calls          int
	err            error
	digestOverride string
}

func (p *fakeAcornFoxProber) Probe(_ context.Context, request contracts.AcornFoxProbeRequest, observation contracts.AcornFoxRuntimeObservation) (contracts.AcornFoxProbeResult, error) {
	p.calls++
	if p.err != nil {
		return contracts.AcornFoxProbeResult{}, p.err
	}
	digest, err := contracts.AcornFoxProbeFactDigest(request, observation, contracts.AcornFoxProbeOutcomeResponded, nil)
	if err != nil {
		return contracts.AcornFoxProbeResult{}, err
	}
	if p.digestOverride != "" {
		digest = p.digestOverride
	}
	return contracts.AcornFoxProbeResult{ApplicationID: request.Reference.Fact.ApplicationID, EnvironmentID: request.Reference.Fact.EnvironmentID, ReleaseID: request.Reference.Fact.ReleaseID, DeploymentID: observation.DeploymentID, ServiceName: observation.ServiceName, Protocol: request.Protocol, TargetClass: "loopback", Outcome: contracts.AcornFoxProbeOutcomeResponded, ObservedAt: time.Unix(4, 0).UTC(), FactDigest: digest}, nil
}
