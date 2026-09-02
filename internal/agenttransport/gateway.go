package agenttransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/compatibility"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	maxGatewayBody     = 1 << 20
	maxPollWait        = 2 * time.Second
	maxQueueDepth      = 256
	heartbeatInterval  = 5 * time.Second
	heartbeatMissLimit = 3
)

type ConnectRequest struct {
	Hello      v1.Hello `json:"hello"`
	MinVersion string   `json:"min_version,omitempty"`
	MaxVersion string   `json:"max_version,omitempty"`
}

type ConnectResponse struct {
	SessionID            string   `json:"session_id"`
	HeartbeatSeconds     int      `json:"heartbeat_seconds"`
	CurrentCursor        uint64   `json:"current_cursor"`
	NegotiatedVersion    string   `json:"negotiated_version"`
	DisabledCapabilities []string `json:"disabled_capabilities,omitempty"`
	EnabledCapabilities  []string `json:"enabled_capabilities,omitempty"`
}

type PollRequest struct {
	SessionID string `json:"session_id"`
	After     uint64 `json:"after"`
	WaitMS    int    `json:"wait_ms"`
}

type QueuedEnvelope struct {
	Cursor   uint64      `json:"cursor"`
	Envelope v1.Envelope `json:"envelope"`
}

type PollResponse struct {
	Items []QueuedEnvelope `json:"items"`
}

type EventBatch struct {
	SessionID string        `json:"session_id"`
	Events    []v1.Envelope `json:"events"`
}

type EventBatchResponse struct {
	Accepted             int                      `json:"accepted"`
	CompatibilityReports []v1.CompatibilityReport `json:"compatibility_reports,omitempty"`
}

type EventSink interface {
	RecordAgentEnvelope(context.Context, v1.Envelope) error
}

type gatewaySession struct {
	id              string
	instanceID      string
	nodeID          string
	lastSeen        time.Time
	queue           []QueuedEnvelope
	cursor          uint64
	changed         chan struct{}
	received        map[string]string
	protocolVersion string
	certificateID   string
	capabilities    map[string]struct{}
}

type Gateway struct {
	mu                        sync.Mutex
	sessions                  map[string]*gatewaySession
	byNode                    map[string]string
	sink                      EventSink
	clock                     func() time.Time
	requireRegisteredIdentity bool
	identities                map[string]string
	supportedVersions         []compatibility.Version
}

func NewGateway(sink EventSink) *Gateway {
	return NewGatewayForVersions(sink, v1.SupportedAgentVersions)
}

func NewGatewayForVersions(sink EventSink, supported []compatibility.Version) *Gateway {
	return &Gateway{sessions: make(map[string]*gatewaySession), byNode: make(map[string]string), sink: sink, clock: time.Now, identities: make(map[string]string), supportedVersions: append([]compatibility.Version(nil), supported...)}
}

func NewStrictGateway(sink EventSink) *Gateway {
	gateway := NewGateway(sink)
	gateway.requireRegisteredIdentity = true
	return gateway
}

func (g *Gateway) RegisterIdentity(certificateID, instanceID, nodeID string) error {
	certificateID = strings.TrimSpace(certificateID)
	instanceID = strings.TrimSpace(instanceID)
	nodeID = strings.TrimSpace(nodeID)
	if certificateID == "" || instanceID == "" || nodeID == "" {
		return errors.New("certificate, instance, and node identity are required")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	wanted := nodeKey(instanceID, nodeID)
	if previous := g.identities[certificateID]; previous != "" && previous != wanted {
		return errors.New("certificate identity is already bound to another node")
	}
	g.identities[certificateID] = wanted
	return nil
}

func (g *Gateway) SetEventSink(sink EventSink) {
	g.mu.Lock()
	g.sink = sink
	g.mu.Unlock()
}

func (g *Gateway) NodeCapabilities(instanceID, nodeID string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	session := g.sessionByIdentityLocked(instanceID, nodeID)
	if session == nil {
		return nil
	}
	values := make([]string, 0, len(session.capabilities))
	for capability := range session.capabilities {
		values = append(values, capability)
	}
	sort.Strings(values)
	return values
}

func (g *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		writeGatewayError(writer, http.StatusUnauthorized, "mtls_required", "trusted client certificate is required")
		return
	}
	switch request.URL.Path {
	case "/v1/agent/connect":
		g.handleConnect(writer, request)
	case "/v1/agent/poll":
		g.handlePoll(writer, request)
	case "/v1/agent/events":
		g.handleEvents(writer, request)
	default:
		writeGatewayError(writer, http.StatusNotFound, "not_found", "agent gateway route not found")
	}
}

func (g *Gateway) Enqueue(instanceID, nodeID string, envelope v1.Envelope) (uint64, error) {
	if err := v1.ValidateEnvelopePayload(envelope); err != nil {
		return 0, err
	}
	if envelope.InstanceID != instanceID || envelope.NodeID != nodeID {
		return 0, errors.New("queued envelope identity mismatch")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	session := g.sessionByIdentityLocked(instanceID, nodeID)
	if session == nil {
		return 0, errors.New("agent session is not connected")
	}
	if envelope.Kind == v1.KindTaskRequest {
		var task v1.TaskRequest
		if err := json.Unmarshal(envelope.Payload, &task); err != nil {
			return 0, errors.New("queued task payload is invalid")
		}
		if required := v1.RequiredCapabilityForTaskRequest(task); required != "" {
			if session.protocolVersion != v1.ProtocolVersion {
				return 0, fmt.Errorf("%w: agent protocol cannot accept aggregate runtime tasks", v1.ErrCapabilityUnavailable)
			}
			if _, ok := session.capabilities[required]; !ok {
				return 0, fmt.Errorf("%w: agent session lacks required capability: %s", v1.ErrCapabilityUnavailable, required)
			}
		}
	}
	session.cursor++
	queued := QueuedEnvelope{Cursor: session.cursor, Envelope: envelope}
	session.queue = append(session.queue, queued)
	if len(session.queue) > maxQueueDepth {
		session.queue = append([]QueuedEnvelope(nil), session.queue[len(session.queue)-maxQueueDepth:]...)
	}
	close(session.changed)
	session.changed = make(chan struct{})
	return queued.Cursor, nil
}

func (g *Gateway) handleConnect(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeGatewayError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input ConnectRequest
	if err := decodeGatewayJSON(writer, request, &input); err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_connect", err.Error())
		return
	}
	if strings.TrimSpace(input.Hello.InstanceID) == "" || strings.TrimSpace(input.Hello.NodeID) == "" || strings.TrimSpace(input.Hello.AgentVersion) == "" {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_connect", "agent hello identity and version are required")
		return
	}
	negotiation, err := v1.NegotiateProtocol(input.MinVersion, input.MaxVersion, g.supportedVersions)
	if err != nil {
		writeGatewayError(writer, http.StatusUpgradeRequired, "protocol_incompatible", err.Error())
		return
	}
	certificate := request.TLS.PeerCertificates[0]
	certificateID := certificate.SerialNumber.String()
	if input.Hello.CertificateID != "" && subtle.ConstantTimeCompare([]byte(input.Hello.CertificateID), []byte(certificateID)) != 1 {
		writeGatewayError(writer, http.StatusForbidden, "certificate_identity_mismatch", "hello certificate identity does not match mTLS peer")
		return
	}
	g.mu.Lock()
	registeredIdentity := g.identities[certificateID]
	requireRegisteredIdentity := g.requireRegisteredIdentity
	g.mu.Unlock()
	if requireRegisteredIdentity && registeredIdentity != nodeKey(input.Hello.InstanceID, input.Hello.NodeID) {
		writeGatewayError(writer, http.StatusForbidden, "node_identity_mismatch", "mTLS certificate is not registered for this instance and node")
		return
	}
	now := g.clock().UTC()
	g.mu.Lock()
	key := nodeKey(input.Hello.InstanceID, input.Hello.NodeID)
	var session *gatewaySession
	if sessionID := g.byNode[key]; sessionID != "" {
		session = g.sessions[sessionID]
	}
	if session == nil {
		id, err := domain.NewID("agent_session")
		if err != nil {
			g.mu.Unlock()
			writeGatewayError(writer, http.StatusServiceUnavailable, "unavailable", "unable to allocate session")
			return
		}
		session = &gatewaySession{id: id.String(), instanceID: input.Hello.InstanceID, nodeID: input.Hello.NodeID, changed: make(chan struct{}), received: make(map[string]string)}
		g.sessions[session.id] = session
		g.byNode[key] = session.id
	}
	session.lastSeen = now
	session.protocolVersion = negotiation.Version.String()
	session.certificateID = certificateID
	enabled, disabled := negotiateSessionCapabilities(input.Hello.Capabilities, session.protocolVersion, negotiation.DisabledCapabilities)
	session.capabilities = make(map[string]struct{}, len(enabled))
	for _, capability := range enabled {
		session.capabilities[capability] = struct{}{}
	}
	response := ConnectResponse{SessionID: session.id, HeartbeatSeconds: int(heartbeatInterval / time.Second), CurrentCursor: session.cursor, NegotiatedVersion: session.protocolVersion, DisabledCapabilities: disabled, EnabledCapabilities: enabled}
	g.mu.Unlock()
	writeGatewayJSON(writer, http.StatusOK, response)
}

func negotiateSessionCapabilities(advertised []string, protocolVersion string, protocolDisabled []string) ([]string, []string) {
	allowed := map[string]struct{}{
		"docker.read.facts": {}, "runtime.deploy.digest": {}, "runtime.observe": {}, "runtime.logs": {}, "runtime.restart": {}, "runtime.destroy": {},
		v1.AgentCapabilityAcornFoxRuntime:    {},
		v1.AgentCapabilityRuntimeDeployGroup: {}, v1.AgentCapabilityRuntimeObserveGroup: {}, v1.AgentCapabilityRuntimeLogsGroup: {}, v1.AgentCapabilityRuntimeRollbackGroup: {}, v1.AgentCapabilityRuntimeDestroyGroup: {},
		v1.AgentCapabilityRuntimeRestartGroupService: {}, v1.AgentCapabilityRuntimeRestartGroup: {},
	}
	enabledSet := make(map[string]struct{})
	disabledSet := make(map[string]struct{}, len(protocolDisabled)+1)
	for _, capability := range protocolDisabled {
		disabledSet[capability] = struct{}{}
	}
	for _, capability := range advertised {
		capability = strings.TrimSpace(capability)
		if _, ok := allowed[capability]; !ok {
			continue
		}
		if v1.IsAggregateRuntimeCapability(capability) && protocolVersion != v1.ProtocolVersion {
			disabledSet[capability] = struct{}{}
			continue
		}
		enabledSet[capability] = struct{}{}
	}
	for _, capability := range []string{v1.AgentCapabilityRuntimeDeployGroup, v1.AgentCapabilityRuntimeObserveGroup, v1.AgentCapabilityRuntimeLogsGroup, v1.AgentCapabilityRuntimeRollbackGroup, v1.AgentCapabilityRuntimeDestroyGroup, v1.AgentCapabilityRuntimeRestartGroupService, v1.AgentCapabilityRuntimeRestartGroup} {
		if _, ok := enabledSet[capability]; !ok {
			disabledSet[capability] = struct{}{}
		}
	}
	if protocolVersion != v1.ProtocolVersion {
		delete(enabledSet, v1.AgentCapabilityAcornFoxRuntime)
		disabledSet[v1.AgentCapabilityAcornFoxRuntime] = struct{}{}
	} else if _, ok := enabledSet[v1.AgentCapabilityAcornFoxRuntime]; !ok {
		disabledSet[v1.AgentCapabilityAcornFoxRuntime] = struct{}{}
	}
	enabled := make([]string, 0, len(enabledSet))
	for capability := range enabledSet {
		enabled = append(enabled, capability)
	}
	disabled := make([]string, 0, len(disabledSet))
	for capability := range disabledSet {
		disabled = append(disabled, capability)
	}
	sort.Strings(enabled)
	sort.Strings(disabled)
	return enabled, disabled
}

func (g *Gateway) handlePoll(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeGatewayError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var input PollRequest
	if err := decodeGatewayJSON(writer, request, &input); err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_poll", err.Error())
		return
	}
	wait := time.Duration(input.WaitMS) * time.Millisecond
	if wait < 0 || wait > maxPollWait {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_poll", "poll wait is outside the allowed range")
		return
	}
	certificateID := peerCertificateID(request)
	items, changed, err := g.pollSnapshot(input.SessionID, input.After, certificateID)
	if err != nil {
		writeGatewayError(writer, http.StatusConflict, "poll_cursor_invalid", err.Error())
		return
	}
	if len(items) == 0 && wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-changed:
			timer.Stop()
		}
		items, _, err = g.pollSnapshot(input.SessionID, input.After, certificateID)
		if err != nil {
			writeGatewayError(writer, http.StatusConflict, "poll_cursor_invalid", err.Error())
			return
		}
	}
	writeGatewayJSON(writer, http.StatusOK, PollResponse{Items: items})
}

func (g *Gateway) pollSnapshot(sessionID string, after uint64, certificateID string) ([]QueuedEnvelope, <-chan struct{}, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	session := g.sessions[strings.TrimSpace(sessionID)]
	if session == nil {
		return nil, nil, errors.New("agent session not found")
	}
	if !sameCertificate(session.certificateID, certificateID) {
		return nil, nil, errors.New("mTLS certificate does not own agent session")
	}
	if len(session.queue) > 0 && after+1 < session.queue[0].Cursor {
		return nil, nil, errors.New("agent replay cursor has expired")
	}
	items := make([]QueuedEnvelope, 0)
	for _, item := range session.queue {
		if item.Cursor > after {
			downgraded, _, err := v1.DowngradeEnvelope(item.Envelope, session.protocolVersion)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, QueuedEnvelope{Cursor: item.Cursor, Envelope: downgraded})
		}
	}
	return items, session.changed, nil
}

func (g *Gateway) handleEvents(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeGatewayError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	certificateID := peerCertificateID(request)
	input, reports, err := g.decodeCompatibleEventBatch(writer, request, certificateID)
	if err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_events", err.Error())
		return
	}
	if len(input.Events) == 0 || len(input.Events) > 100 {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_events", "event batch size is outside the allowed range")
		return
	}
	for _, envelope := range input.Events {
		if err := g.acceptEvent(request.Context(), input.SessionID, certificateID, envelope); err != nil {
			log.Printf("Agent event rejected: kind=%s error=%s", envelope.Kind, foundation.RedactText(err.Error()))
			writeGatewayError(writer, http.StatusConflict, "event_rejected", err.Error())
			return
		}
	}
	writeGatewayJSON(writer, http.StatusAccepted, EventBatchResponse{Accepted: len(input.Events), CompatibilityReports: reports})
}

func (g *Gateway) decodeCompatibleEventBatch(writer http.ResponseWriter, request *http.Request, certificateID string) (EventBatch, []v1.CompatibilityReport, error) {
	data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxGatewayBody))
	if err != nil {
		return EventBatch{}, nil, err
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		return EventBatch{}, nil, err
	}
	for field := range outer {
		if field != "session_id" && field != "events" {
			return EventBatch{}, nil, errors.New("unknown event batch field: " + field)
		}
	}
	var sessionID string
	if err := json.Unmarshal(outer["session_id"], &sessionID); err != nil || strings.TrimSpace(sessionID) == "" {
		return EventBatch{}, nil, errors.New("event batch session_id is required")
	}
	var rawEvents []json.RawMessage
	if err := json.Unmarshal(outer["events"], &rawEvents); err != nil {
		return EventBatch{}, nil, err
	}
	g.mu.Lock()
	session := g.sessions[sessionID]
	version := ""
	if session != nil {
		version = session.protocolVersion
		if !sameCertificate(session.certificateID, certificateID) {
			version = ""
		}
	}
	g.mu.Unlock()
	if version == "" {
		return EventBatch{}, nil, errors.New("agent session not found")
	}
	input := EventBatch{SessionID: sessionID, Events: make([]v1.Envelope, 0, len(rawEvents))}
	reports := make([]v1.CompatibilityReport, 0)
	for _, raw := range rawEvents {
		envelope, report, err := v1.DecodeCompatibleEnvelope(raw, version)
		if err != nil {
			return EventBatch{}, reports, err
		}
		input.Events = append(input.Events, envelope)
		if len(report.UnknownFields) > 0 || len(report.MissingOptional) > 0 || len(report.DisabledCapabilities) > 0 {
			reports = append(reports, report)
		}
	}
	return input, reports, nil
}

func (g *Gateway) acceptEvent(ctx context.Context, sessionID, certificateID string, envelope v1.Envelope) error {
	if err := v1.ValidateEnvelopePayload(envelope); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	session := g.sessions[strings.TrimSpace(sessionID)]
	if session == nil {
		return errors.New("agent session not found")
	}
	if !sameCertificate(session.certificateID, certificateID) {
		return errors.New("mTLS certificate does not own agent session")
	}
	if envelope.InstanceID != session.instanceID || envelope.NodeID != session.nodeID {
		return errors.New("agent event identity mismatch")
	}
	normalizedVersion, err := v1.NormalizeProtocolVersion(envelope.Version)
	if err != nil || normalizedVersion != session.protocolVersion {
		return errors.New("agent event version does not match negotiated session")
	}
	envelope, _, err = v1.DowngradeEnvelope(envelope, session.protocolVersion)
	if err != nil {
		return err
	}
	digest, err := envelopeDigest(envelope)
	if err != nil {
		return err
	}
	if previous := session.received[envelope.MessageID]; previous != "" {
		if previous == digest {
			return nil
		}
		return errors.New("agent message id conflicts with prior payload")
	}
	if g.sink != nil {
		if err := g.sink.RecordAgentEnvelope(ctx, envelope); err != nil {
			return err
		}
	}
	session.received[envelope.MessageID] = digest
	session.lastSeen = g.clock().UTC()
	return nil
}

func (g *Gateway) sessionByIdentityLocked(instanceID, nodeID string) *gatewaySession {
	return g.sessions[g.byNode[nodeKey(instanceID, nodeID)]]
}

func nodeKey(instanceID, nodeID string) string { return instanceID + "\x00" + nodeID }

func peerCertificateID(request *http.Request) string {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return ""
	}
	return request.TLS.PeerCertificates[0].SerialNumber.String()
}

func sameCertificate(expected, actual string) bool {
	return expected != "" && actual != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func envelopeDigest(envelope v1.Envelope) (string, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func decodeGatewayJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maxGatewayBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

func writeGatewayJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeGatewayError(writer http.ResponseWriter, status int, code, message string) {
	writeGatewayJSON(writer, status, map[string]string{"code": code, "message": message})
}

var _ http.Handler = (*Gateway)(nil)

func (g *Gateway) SessionLastSeen(instanceID, nodeID string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	session := g.sessionByIdentityLocked(instanceID, nodeID)
	if session == nil {
		return time.Time{}, false
	}
	return session.lastSeen, true
}

func (g *Gateway) NodeStatus(instanceID, nodeID string, now time.Time) string {
	lastSeen, ok := g.SessionLastSeen(instanceID, nodeID)
	if !ok || now.UTC().Sub(lastSeen) > heartbeatInterval*heartbeatMissLimit {
		return "unknown"
	}
	return "online"
}

func (g *Gateway) CloseSession(instanceID, nodeID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := nodeKey(instanceID, nodeID)
	id := g.byNode[key]
	if id == "" {
		return fmt.Errorf("agent session not found")
	}
	delete(g.byNode, key)
	delete(g.sessions, id)
	return nil
}
