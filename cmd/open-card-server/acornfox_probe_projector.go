package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// projectAcornFoxProbeEvidence is deliberately before the M4 metric
// projection. The matching raw event and immutable fact have already been
// committed atomically by postgres.RecordAgentEvent, so this server projector
// must be a no-op even when metrics/logs are configured.
func (a *m4PostgresAdapter) projectAcornFoxProbeEvidence(_ context.Context, task postgres.ControllerTask, _ v1.Envelope) (bool, error) {
	_, marked, err := decodeServerAcornFoxProbeTask(task.Task.Payload)
	if err != nil {
		return marked, err
	}
	return marked, nil
}

func decodeServerAcornFoxProbeTask(payload json.RawMessage) (contracts.AcornFoxProbeRequest, bool, error) {
	var task struct {
		Kind       v1.TaskKind     `json:"kind"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := decodeServerProbeJSON(payload, &task); err != nil {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(task.Parameters, &fields) != nil {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	if _, marked := fields["acornfox_probe_payload_type"]; !marked {
		return contracts.AcornFoxProbeRequest{}, false, nil
	}
	var wrapper struct {
		PayloadType string                         `json:"acornfox_probe_payload_type"`
		Request     contracts.AcornFoxProbeRequest `json:"request"`
	}
	if task.Kind != v1.TaskObserve || decodeServerProbeJSON(task.Parameters, &wrapper) != nil || wrapper.PayloadType != "probe" || wrapper.Request.Validate() != nil {
		return contracts.AcornFoxProbeRequest{}, true, errors.New("AcornFox probe durable task is invalid")
	}
	return wrapper.Request, true, nil
}

func decodeServerProbeJSON(data []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
