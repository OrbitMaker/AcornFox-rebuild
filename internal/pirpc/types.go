// Package pirpc implements the host-controlled subset of the Pi v0.85.1
// stdio RPC protocol used by AcornFox.
package pirpc

import (
	"errors"
	"time"
)

const (
	// DefaultMaxFrameBytes is large enough for normal Pi events while keeping
	// allocation bounded. Operators should set MaxFrameBytes explicitly after
	// measuring their installed Pi configuration.
	DefaultMaxFrameBytes = 1 << 20
	DefaultEventQueue    = 64
	DefaultMaxPending    = 128
	DefaultMaxUIRequests = 32
	DefaultMaxTextBytes  = 64 << 10
)

var (
	ErrClosed          = errors.New("pirpc: transport closed")
	ErrProtocol        = errors.New("pirpc: protocol violation")
	ErrFrameTooLarge   = errors.New("pirpc: frame exceeds configured limit")
	ErrTooManyRequests = errors.New("pirpc: too many pending requests")
	ErrSubscriberSlow  = errors.New("pirpc: event subscriber is too slow")
	ErrProcessExited   = errors.New("pirpc: process exited")
	ErrUIRequest       = errors.New("pirpc: invalid extension UI response")
)

// Options bounds memory and fan-out behavior. Zero values select conservative
// defaults; the effective values are available through Transport.Options.
type Options struct {
	MaxFrameBytes int
	EventQueue    int
	MaxPending    int
	MaxUIRequests int
	MaxTextBytes  int
}

func (o Options) normalized() Options {
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if o.EventQueue <= 0 {
		o.EventQueue = DefaultEventQueue
	}
	if o.MaxPending <= 0 {
		o.MaxPending = DefaultMaxPending
	}
	if o.MaxUIRequests <= 0 {
		o.MaxUIRequests = DefaultMaxUIRequests
	}
	if o.MaxTextBytes <= 0 {
		o.MaxTextBytes = DefaultMaxTextBytes
	}
	return o
}

// Acceptance confirms only that Pi accepted or queued a command. It does not
// mean the agent run or an AcornFox operation succeeded. Agent completion is
// delivered separately as EventAgentEnd/EventAgentSettled.
type Acceptance struct {
	RequestID string
	Command   string
}

// ClearedQueue is returned before Abort is issued.
type ClearedQueue struct {
	Steering []string
	FollowUp []string
}

// SessionState is the safe projection of get_state. It intentionally omits the
// session file path and the raw model object.
type SessionState struct {
	SessionID             string
	SessionName           string
	ThinkingLevel         string
	IsStreaming           bool
	IsCompacting          bool
	SteeringMode          string
	FollowUpMode          string
	AutoCompactionEnabled bool
	MessageCount          int
	PendingMessageCount   int
}

// Message is a bounded projection of get_messages. Images, attachments,
// thinking text, tool arguments, provider metadata and local paths are omitted.
type Message struct {
	Role       string
	Text       string
	ToolCallID string
	ToolName   string
	StopReason string
	IsError    bool
	Truncated  bool
}

type EventType string

const (
	EventAgentStart                  EventType = "agent_start"
	EventAgentEnd                    EventType = "agent_end"
	EventAgentSettled                EventType = "agent_settled"
	EventTurnStart                   EventType = "turn_start"
	EventTurnEnd                     EventType = "turn_end"
	EventMessageStart                EventType = "message_start"
	EventMessageUpdate               EventType = "message_update"
	EventMessageEnd                  EventType = "message_end"
	EventToolExecutionStart          EventType = "tool_execution_start"
	EventToolExecutionUpdate         EventType = "tool_execution_update"
	EventToolExecutionEnd            EventType = "tool_execution_end"
	EventQueueUpdate                 EventType = "queue_update"
	EventCompactionStart             EventType = "compaction_start"
	EventCompactionEnd               EventType = "compaction_end"
	EventAutoRetryStart              EventType = "auto_retry_start"
	EventAutoRetryEnd                EventType = "auto_retry_end"
	EventSummarizationRetryScheduled EventType = "summarization_retry_scheduled"
	EventSummarizationRetryAttempt   EventType = "summarization_retry_attempt_start"
	EventSummarizationRetryFinished  EventType = "summarization_retry_finished"
	EventEntryAppended               EventType = "entry_appended"
	EventSessionInfoChanged          EventType = "session_info_changed"
	EventThinkingLevelChanged        EventType = "thinking_level_changed"
	EventExtensionError              EventType = "extension_error"
	EventExtensionUIRequest          EventType = "extension_ui_request"
)

// DeltaType identifies the Pi assistantMessageEvent nested in message_update.
type DeltaType string

const (
	DeltaTextStart     DeltaType = "text_start"
	DeltaText          DeltaType = "text_delta"
	DeltaTextEnd       DeltaType = "text_end"
	DeltaThinkingStart DeltaType = "thinking_start"
	DeltaThinking      DeltaType = "thinking_delta"
	DeltaThinkingEnd   DeltaType = "thinking_end"
	DeltaToolCallStart DeltaType = "toolcall_start"
	DeltaToolCall      DeltaType = "toolcall_delta"
	DeltaToolCallEnd   DeltaType = "toolcall_end"
)

// Event is a normalized, bounded projection of a Pi event. Raw event payloads,
// tool arguments/results, messages and extension paths remain private to the
// transport and are never returned or included in errors.
type Event struct {
	Type         EventType
	DeltaType    DeltaType
	ContentIndex int
	Text         string
	Truncated    bool
	ToolCallID   string
	ToolName     string
	IsError      bool
	WillRetry    bool
	RetryAttempt int
	MaxAttempts  int
	RetryDelay   time.Duration
	Reason       string
	UI           *UIRequest
}

type UIMethod string

const (
	UISelect        UIMethod = "select"
	UIConfirm       UIMethod = "confirm"
	UIInput         UIMethod = "input"
	UIEditor        UIMethod = "editor"
	UINotify        UIMethod = "notify"
	UISetStatus     UIMethod = "setStatus"
	UISetWidget     UIMethod = "setWidget"
	UISetTitle      UIMethod = "setTitle"
	UISetEditorText UIMethod = "set_editor_text"
)

// UIRequest is a bounded projection of an extension UI request. Dialog methods
// require a correlated response; fire-and-forget methods do not.
type UIRequest struct {
	ID              string
	Method          UIMethod
	Title           string
	Message         string
	Options         []string
	Placeholder     string
	Prefill         string
	Timeout         time.Duration
	NotifyType      string
	StatusKey       string
	StatusText      string
	WidgetKey       string
	WidgetLines     []string
	WidgetPlacement string
	Text            string
	Truncated       bool
}

func (r UIRequest) requiresResponse() bool {
	switch r.Method {
	case UISelect, UIConfirm, UIInput, UIEditor:
		return true
	default:
		return false
	}
}

// Subscription has a bounded event queue. A slow subscriber is detached rather
// than blocking Pi stdout or other subscribers.
type Subscription struct {
	Events <-chan Event
	Done   <-chan error
	cancel func()
}

func (s *Subscription) Close() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}
