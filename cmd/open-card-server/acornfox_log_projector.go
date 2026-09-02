package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// acornFoxLogProjector owns only AcornFox-marked TaskLogs evidence. It is
// deliberately separate from M4 so a clean single-service composition keeps
// durable logs when the commercial M4 operations subsystem is absent.
type acornFoxLogProjector struct {
	store *postgres.Store
	logs  *observability.LogStore
	clock func() time.Time
}

var _ controllers.AgentEvidenceProjector = (*acornFoxLogProjector)(nil)

func (p *acornFoxLogProjector) ProjectAgentEvidence(ctx context.Context, task postgres.ControllerTask, envelope v1.Envelope) error {
	request, marked, err := decodeServerAcornFoxLogsTask(task.Task.Payload)
	if err != nil || !marked {
		return err
	}
	if envelope.Kind != v1.KindLogChunk {
		return nil
	}
	if p == nil || p.store == nil || p.logs == nil {
		return errors.New("AcornFox logs projector is unavailable")
	}
	if task.DeploymentID != request.DeploymentID {
		return errors.New("AcornFox logs task deployment identity is invalid")
	}
	var chunk v1.LogChunk
	if err := json.Unmarshal(envelope.Payload, &chunk); err != nil {
		return err
	}
	if err := chunk.Validate(); err != nil || chunk.TaskID != task.Task.ID.String() {
		return errors.New("AcornFox logs evidence is invalid")
	}
	stream := "task-" + task.Task.ID.String() + "-" + fmt.Sprint(envelope.AgentSequence) + "-" + chunk.Stream
	prior, err := p.logs.Read(observability.LogCategoryRuntime, stream)
	if err != nil {
		return err
	}
	if len(prior) == 0 && chunk.Data != "" {
		if err := p.logs.Append(observability.LogCategoryRuntime, stream, []byte(chunk.Data)); err != nil {
			return err
		}
	}
	files, err := p.logs.List(observability.LogCategoryRuntime, stream)
	if err != nil {
		return err
	}
	now := p.now()
	for _, file := range files {
		contentDigest, size, err := acornFoxLogSegmentDigest(filepath.Join(p.logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
		if err != nil || size != file.Bytes {
			return errors.New("AcornFox runtime log segment integrity is unavailable")
		}
		indexID := m4AdapterID("acornfox-log", task.Task.ID.String()+":"+fmt.Sprint(envelope.AgentSequence)+":"+chunk.Stream+":"+fmt.Sprint(file.Sequence))
		var exists bool
		if err := p.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_log_indexes WHERE id=$1)`, indexID.String()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		truncation := postgres.LogTruncationComplete
		if chunk.Final && chunk.SourceLimited {
			truncation = postgres.LogTruncationSourceLimited
		}
		segmentOrder, err := acornFoxLogSegmentOrder(envelope.AgentSequence, file.Sequence)
		if err != nil {
			return err
		}
		if err := p.store.AppendLogIndex(ctx, postgres.LogIndex{
			ID:            indexID,
			ApplicationID: request.Reference.Fact.ApplicationID,
			ServiceName:   request.ServiceName,
			ReleaseID:     request.Reference.Fact.ReleaseID,
			DeploymentID:  request.DeploymentID,
			OperationID:   task.Operation.ID,
			LogTaskID:     task.Task.ID,
			Category:      postgres.LogIndexRuntime,
			LogStream:     postgres.LogStream(chunk.Stream),
			Truncation:    truncation,
			Path:          file.Path,
			Segment:       segmentOrder,
			ByteSize:      file.Bytes,
			ContentDigest: contentDigest,
			CreatedAt:     now,
		}, now); err != nil {
			return err
		}
	}
	return m4ReconcileOrdinaryLogIndexes(ctx, p.store, p.logs, now)
}

// Segment remains an internal ordering field. A task's Agent sequence is the
// authoritative event order; reserve the low range for a rare LogStore split
// of one bounded chunk so logical record reconstruction stays deterministic.
func acornFoxLogSegmentOrder(agentSequence uint64, fileSequence int) (int, error) {
	const splitRange = 100000
	if agentSequence == 0 || fileSequence < 0 || fileSequence >= splitRange {
		return 0, errors.New("AcornFox log segment order is invalid")
	}
	maximumInt := uint64(^uint(0) >> 1)
	if agentSequence > (maximumInt-uint64(fileSequence))/splitRange {
		return 0, errors.New("AcornFox log segment order overflows")
	}
	return int(agentSequence*splitRange + uint64(fileSequence)), nil
}

func (p *acornFoxLogProjector) now() time.Time {
	if p != nil && p.clock != nil {
		return p.clock().UTC()
	}
	return time.Now().UTC()
}

func decodeServerAcornFoxLogsTask(payload json.RawMessage) (contracts.AcornFoxLogsRequest, bool, error) {
	var task controllers.AgentTaskSpec
	if err := decodeAcornFoxLogsStrictJSON(payload, &task); err != nil {
		return contracts.AcornFoxLogsRequest{}, false, nil
	}
	var fields map[string]json.RawMessage
	if err := decodeAcornFoxLogsStrictJSON(task.Parameters, &fields); err != nil {
		return contracts.AcornFoxLogsRequest{}, false, nil
	}
	if _, marked := fields["acornfox_log_payload_type"]; !marked {
		return contracts.AcornFoxLogsRequest{}, false, nil
	}
	var wrapper struct {
		PayloadType string                        `json:"acornfox_log_payload_type"`
		Request     contracts.AcornFoxLogsRequest `json:"request"`
	}
	if task.Kind != v1.TaskLogs || decodeAcornFoxLogsStrictJSON(task.Parameters, &wrapper) != nil || wrapper.PayloadType != "logs" || wrapper.Request.Validate() != nil {
		return contracts.AcornFoxLogsRequest{}, true, errors.New("AcornFox logs durable task is invalid")
	}
	return wrapper.Request, true, nil
}

func decodeAcornFoxLogsStrictJSON(data []byte, into any) error {
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

// newAcornFoxAgentLogEnvelopeRedactor applies source provenance and local
// root redaction before DurableAgentSink writes raw Agent evidence. It only
// accepts a strict AcornFox TaskLogs wrapper, leaving every other task kind
// untouched. The same returned envelope is handed to the projector by the
// sink, so disk and task_agent_events cannot disagree about what was stored.
func newAcornFoxAgentLogEnvelopeRedactor(store acornFoxDeliveryLogReader, staticRoots ...string) controllers.AgentEnvelopeRedactor {
	return func(ctx context.Context, task postgres.ControllerTask, envelope v1.Envelope) (v1.Envelope, error) {
		if envelope.Kind != v1.KindLogChunk {
			return envelope, nil
		}
		request, marked, err := decodeServerAcornFoxLogsTask(task.Task.Payload)
		if err != nil || !marked {
			return envelope, err
		}
		if task.DeploymentID != request.DeploymentID || store == nil {
			return v1.Envelope{}, errors.New("AcornFox logs redaction task identity is invalid")
		}
		values, err := store.GetAcornFoxDeliveryLogRedactionValues(ctx, request.Reference.Fact.ApplicationID, request.DeploymentID)
		if err != nil {
			return v1.Envelope{}, err
		}
		values = append(values, staticRoots...)
		redacted, err := foundation.RedactJSON(envelope.Payload, values)
		if err != nil {
			return v1.Envelope{}, err
		}
		envelope.Payload = redacted
		return envelope, nil
	}
}
