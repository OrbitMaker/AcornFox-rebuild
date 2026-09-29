package packprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/versionpolicy"
)

const (
	MaxProtocolMessageBytes = 64 << 10 // 64 KiB
	MaxProtocolBatchEvents  = 16
	ProtocolSchemaV1        = "acornfox-pack-protocol-v1"
	ProtocolVersion1        = "1.0"

	KindDiagnosticObserve       = "pack.protocol.observe"
	CapabilityDiagnosticObserve = "diagnostic.observe"

	EventDigestDomain = "acornfox-event-digest-v1\x00"

	CanonicalTimeLayout = "2006-01-02T15:04:05.000000000Z"
)

func FormatCanonicalTime(t time.Time) string {
	return t.UTC().Format(CanonicalTimeLayout)
}

func ParseCanonicalTime(s string) (time.Time, error) {
	if len(s) != 30 || s[29] != 'Z' || s[10] != 'T' || s[19] != '.' {
		return time.Time{}, fmt.Errorf("invalid non-canonical timestamp %q: must match %s", s, CanonicalTimeLayout)
	}
	t, err := time.Parse(CanonicalTimeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse canonical timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

var (
	ErrInvalidProtocolSchema      = errors.New("invalid protocol schema")
	ErrInvalidProtocolVersion     = errors.New("invalid protocol version")
	ErrInvalidProtocolCapability  = errors.New("invalid protocol capability")
	ErrInvalidProtocolDigest      = errors.New("invalid protocol digest")
	ErrInvalidProtocolSequence    = errors.New("invalid protocol sequence")
	ErrProtocolMessageBound       = errors.New("protocol message exceeds bound")
	ErrInvalidProtocolIdentity    = errors.New("invalid protocol identity")
	ErrInvalidProtocolGenerations = errors.New("invalid protocol generations")
)

type DiagnosticInputContext struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Param  string `json:"param"`
}

type DiagnosticObservation struct {
	CheckedAt   string `json:"checked_at"`
	InputDigest string `json:"input_digest"`
	Status      string `json:"status"`
	Summary     string `json:"summary"`
}

type HealthResponse struct {
	Schema          string   `json:"schema"`
	ProtocolVersion string   `json:"protocol_version"`
	PackID          string   `json:"pack_id"`
	Version         string   `json:"version"`
	InstanceID      string   `json:"instance_id"`
	Status          string   `json:"status"`
	Capabilities    []string `json:"capabilities"`
}

type ObserveTaskRequest struct {
	Schema             string                 `json:"schema"`
	ProtocolVersion    string                 `json:"protocol_version"`
	TaskID             string                 `json:"task_id"`
	OperationID        string                 `json:"operation_id"`
	PackID             string                 `json:"pack_id"`
	InstanceID         string                 `json:"instance_id"`
	InstanceGeneration int64                  `json:"instance_generation"`
	CoreGeneration     int64                  `json:"core_generation"`
	LeaseGeneration    int64                  `json:"lease_generation"`
	Kind               string                 `json:"kind"`
	Capability         string                 `json:"capability"`
	InputDigest        string                 `json:"input_digest"`
	InputContext       DiagnosticInputContext `json:"input_context"`
	Deadline           string                 `json:"deadline"`
}

type ObserveTaskEvent struct {
	Schema             string                `json:"schema"`
	TaskID             string                `json:"task_id"`
	InstanceID         string                `json:"instance_id"`
	CoreGeneration     int64                 `json:"core_generation"`
	LeaseGeneration    int64                 `json:"lease_generation"`
	InstanceGeneration int64                 `json:"instance_generation"`
	Sequence           uint64                `json:"sequence"`
	InputDigest        string                `json:"input_digest"`
	EventDigest        string                `json:"event_digest"`
	Kind               string                `json:"kind"`
	Terminal           bool                  `json:"terminal"`
	TerminalStatus     string                `json:"terminal_status,omitempty"`
	Observation        DiagnosticObservation `json:"observation"`
	OccurredAt         string                `json:"occurred_at"`
}

type ObserveTaskAck struct {
	Schema      string `json:"schema"`
	ReceiptID   string `json:"receipt_id"`
	TaskID      string `json:"task_id"`
	InstanceID  string `json:"instance_id"`
	Sequence    uint64 `json:"sequence"`
	EventDigest string `json:"event_digest"`
	Status      string `json:"status"`
	CommittedAt string `json:"committed_at"`
}

type CancelTaskRequest struct {
	Schema      string `json:"schema"`
	TaskID      string `json:"task_id"`
	OperationID string `json:"operation_id"`
	InstanceID  string `json:"instance_id"`
	Reason      string `json:"reason"`
}

type CancelTaskResponse struct {
	Schema string `json:"schema"`
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

func DigestDiagnosticInput(in DiagnosticInputContext) (string, []byte, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b, nil
}

func DigestDiagnosticObservation(obs DiagnosticObservation) (string, []byte, error) {
	b, err := json.Marshal(obs)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b, nil
}

func ComputeEventDigest(
	taskID, instanceID string,
	coreGen, leaseGen, instGen int64,
	seq uint64,
	kind, inputDigest string,
	terminal bool,
	terminalStatus string,
	occurredAt string,
	observationDigest string,
) string {
	h := sha256.New()
	h.Write([]byte(EventDigestDomain))
	fmt.Fprintf(h, "task:%s\ninst:%s\ncore:%d\nlease:%d\ninstgen:%d\nseq:%d\nkind:%s\ninput:%s\nterminal:%t\ntermstatus:%s\noccurred:%s\nobs:%s\n",
		taskID, instanceID, coreGen, leaseGen, instGen, seq, kind, inputDigest, terminal, terminalStatus, occurredAt, observationDigest)
	return hex.EncodeToString(h.Sum(nil))
}

func ParseHealthResponse(raw []byte) (HealthResponse, error) {
	var resp HealthResponse
	if err := StrictJSON(raw, &resp, MaxProtocolMessageBytes); err != nil {
		return resp, err
	}
	if resp.Schema != ProtocolSchemaV1 {
		return resp, ErrInvalidProtocolSchema
	}
	if resp.ProtocolVersion != ProtocolVersion1 {
		return resp, ErrInvalidProtocolVersion
	}
	if !ValidPackID(resp.PackID) {
		return resp, ErrInvalidProtocolIdentity
	}
	if _, err := versionpolicy.ParseSemver(resp.Version); err != nil {
		return resp, err
	}
	if resp.InstanceID == "" || len(resp.InstanceID) > 128 {
		return resp, ErrInvalidProtocolIdentity
	}
	if resp.Status != "ok" && resp.Status != "serving" {
		return resp, errors.New("health status rejected")
	}
	if len(resp.Capabilities) == 0 || len(resp.Capabilities) > 32 {
		return resp, ErrInvalidProtocolCapability
	}
	seen := map[string]bool{}
	for _, c := range resp.Capabilities {
		if c == "" || len(c) > 64 || seen[c] {
			return resp, ErrInvalidProtocolCapability
		}
		seen[c] = true
	}
	return resp, nil
}

func ParseObserveTaskRequest(raw []byte) (ObserveTaskRequest, error) {
	var req ObserveTaskRequest
	if err := StrictJSON(raw, &req, MaxProtocolMessageBytes); err != nil {
		return req, err
	}
	if req.Schema != ProtocolSchemaV1 {
		return req, ErrInvalidProtocolSchema
	}
	if req.ProtocolVersion != ProtocolVersion1 {
		return req, ErrInvalidProtocolVersion
	}
	if !ValidPackID(req.PackID) {
		return req, ErrInvalidProtocolIdentity
	}
	if req.TaskID == "" || req.OperationID == "" || req.InstanceID == "" {
		return req, ErrInvalidProtocolIdentity
	}
	if req.InstanceGeneration <= 0 || req.CoreGeneration <= 0 || req.LeaseGeneration <= 0 {
		return req, ErrInvalidProtocolGenerations
	}
	if req.Kind != KindDiagnosticObserve {
		return req, errors.New("unsupported task kind")
	}
	if req.Capability != CapabilityDiagnosticObserve {
		return req, ErrInvalidProtocolCapability
	}
	if !validDigest(req.InputDigest) {
		return req, ErrInvalidProtocolDigest
	}
	expectedInputDigest, _, err := DigestDiagnosticInput(req.InputContext)
	if err != nil || req.InputDigest != expectedInputDigest {
		return req, ErrInvalidProtocolDigest
	}
	if _, err := ParseCanonicalTime(req.Deadline); err != nil {
		return req, errors.New("invalid deadline format")
	}
	return req, nil
}

func ParseObserveTaskEvent(raw []byte) (ObserveTaskEvent, error) {
	var ev ObserveTaskEvent
	if err := StrictJSON(raw, &ev, MaxProtocolMessageBytes); err != nil {
		return ev, err
	}
	if ev.Schema != ProtocolSchemaV1 {
		return ev, ErrInvalidProtocolSchema
	}
	if ev.TaskID == "" || ev.InstanceID == "" {
		return ev, ErrInvalidProtocolIdentity
	}
	if ev.CoreGeneration <= 0 || ev.LeaseGeneration <= 0 || ev.InstanceGeneration <= 0 {
		return ev, ErrInvalidProtocolGenerations
	}
	if ev.Sequence == 0 {
		return ev, ErrInvalidProtocolSequence
	}
	if !validDigest(ev.InputDigest) || !validDigest(ev.EventDigest) {
		return ev, ErrInvalidProtocolDigest
	}
	if ev.Kind != KindDiagnosticObserve {
		return ev, errors.New("unsupported event kind")
	}
	if ev.Terminal {
		if ev.TerminalStatus != "succeeded" && ev.TerminalStatus != "failed" {
			return ev, errors.New("invalid terminal status")
		}
	} else if ev.TerminalStatus != "" {
		return ev, errors.New("nonterminal event has terminal status")
	}
	if _, err := ParseCanonicalTime(ev.OccurredAt); err != nil {
		return ev, errors.New("invalid occurred_at format")
	}

	obsDigest, _, err := DigestDiagnosticObservation(ev.Observation)
	if err != nil {
		return ev, errors.New("invalid observation encoding")
	}
	if ev.Observation.InputDigest != ev.InputDigest {
		return ev, ErrInvalidProtocolDigest
	}

	expectedDigest := ComputeEventDigest(
		ev.TaskID, ev.InstanceID,
		ev.CoreGeneration, ev.LeaseGeneration, ev.InstanceGeneration,
		ev.Sequence, ev.Kind, ev.InputDigest,
		ev.Terminal, ev.TerminalStatus, ev.OccurredAt, obsDigest,
	)
	if ev.EventDigest != expectedDigest {
		return ev, ErrInvalidProtocolDigest
	}

	return ev, nil
}

func ParseObserveTaskAck(raw []byte) (ObserveTaskAck, error) {
	var ack ObserveTaskAck
	if err := StrictJSON(raw, &ack, MaxProtocolMessageBytes); err != nil {
		return ack, err
	}
	if ack.Schema != ProtocolSchemaV1 {
		return ack, ErrInvalidProtocolSchema
	}
	if ack.ReceiptID == "" || ack.TaskID == "" || ack.InstanceID == "" {
		return ack, ErrInvalidProtocolIdentity
	}
	if ack.Sequence == 0 {
		return ack, ErrInvalidProtocolSequence
	}
	if !validDigest(ack.EventDigest) {
		return ack, ErrInvalidProtocolDigest
	}
	if ack.Status != "persisted" && ack.Status != "accepted" {
		return ack, errors.New("invalid ack status")
	}
	if _, err := ParseCanonicalTime(ack.CommittedAt); err != nil {
		return ack, errors.New("invalid committed_at format")
	}
	return ack, nil
}

func ParseCancelTaskRequest(raw []byte) (CancelTaskRequest, error) {
	var req CancelTaskRequest
	if err := StrictJSON(raw, &req, MaxProtocolMessageBytes); err != nil {
		return req, err
	}
	if req.Schema != ProtocolSchemaV1 {
		return req, ErrInvalidProtocolSchema
	}
	if req.TaskID == "" || req.OperationID == "" || req.InstanceID == "" {
		return req, ErrInvalidProtocolIdentity
	}
	if strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 256 {
		return req, errors.New("invalid cancel reason")
	}
	return req, nil
}

func ParseCancelTaskResponse(raw []byte) (CancelTaskResponse, error) {
	var resp CancelTaskResponse
	if err := StrictJSON(raw, &resp, MaxProtocolMessageBytes); err != nil {
		return resp, err
	}
	if resp.Schema != ProtocolSchemaV1 {
		return resp, ErrInvalidProtocolSchema
	}
	if resp.TaskID == "" {
		return resp, ErrInvalidProtocolIdentity
	}
	if resp.Status != "accepted" && resp.Status != "cancelling" && resp.Status != "cancelled" {
		return resp, errors.New("invalid cancel status")
	}
	return resp, nil
}
