package pirpc

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

var knownEventTypes = map[string]EventType{
	string(EventAgentStart):                  EventAgentStart,
	string(EventAgentEnd):                    EventAgentEnd,
	string(EventAgentSettled):                EventAgentSettled,
	string(EventTurnStart):                   EventTurnStart,
	string(EventTurnEnd):                     EventTurnEnd,
	string(EventMessageStart):                EventMessageStart,
	string(EventMessageUpdate):               EventMessageUpdate,
	string(EventMessageEnd):                  EventMessageEnd,
	string(EventToolExecutionStart):          EventToolExecutionStart,
	string(EventToolExecutionUpdate):         EventToolExecutionUpdate,
	string(EventToolExecutionEnd):            EventToolExecutionEnd,
	string(EventQueueUpdate):                 EventQueueUpdate,
	string(EventCompactionStart):             EventCompactionStart,
	string(EventCompactionEnd):               EventCompactionEnd,
	string(EventAutoRetryStart):              EventAutoRetryStart,
	string(EventAutoRetryEnd):                EventAutoRetryEnd,
	string(EventSummarizationRetryScheduled): EventSummarizationRetryScheduled,
	string(EventSummarizationRetryAttempt):   EventSummarizationRetryAttempt,
	string(EventSummarizationRetryFinished):  EventSummarizationRetryFinished,
	string(EventEntryAppended):               EventEntryAppended,
	string(EventSessionInfoChanged):          EventSessionInfoChanged,
	string(EventThinkingLevelChanged):        EventThinkingLevelChanged,
	string(EventExtensionError):              EventExtensionError,
	string(EventExtensionUIRequest):          EventExtensionUIRequest,
}

func normalizeEvent(frame []byte, rawType string, maxText int) (Event, *UIRequest, error) {
	eventType, ok := knownEventTypes[rawType]
	if !ok {
		return Event{}, nil, fmt.Errorf("%w: unknown event type", ErrProtocol)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(frame, &object); err != nil {
		return Event{}, nil, fmt.Errorf("%w: malformed event", ErrProtocol)
	}
	event := Event{Type: eventType}
	var err error

	switch eventType {
	case EventAgentStart, EventAgentSettled, EventTurnStart, EventSummarizationRetryFinished:
		err = allowFields(object, "type")
	case EventAgentEnd:
		err = allowFields(object, "type", "messages", "willRetry")
		if err == nil {
			err = requireJSONArray(object, "messages")
		}
		if err == nil {
			event.WillRetry, err = requiredBool(object, "willRetry")
		}
	case EventTurnEnd:
		err = allowFields(object, "type", "message", "toolResults")
		if err == nil {
			err = requireJSONObject(object, "message")
		}
		if err == nil {
			err = requireJSONArray(object, "toolResults")
		}
	case EventMessageStart, EventMessageEnd:
		err = allowFields(object, "type", "message")
		if err == nil {
			err = requireJSONObject(object, "message")
		}
	case EventMessageUpdate:
		err = allowFields(object, "type", "usage", "assistantMessageEvent")
		if err == nil {
			err = requireJSONObject(object, "usage")
		}
		if err == nil {
			err = normalizeMessageDelta(object["assistantMessageEvent"], &event, maxText)
		}
	case EventToolExecutionStart:
		err = allowFields(object, "type", "toolCallId", "toolName", "args")
		if err == nil {
			event.ToolCallID, err = requiredString(object, "toolCallId")
		}
		if err == nil {
			event.ToolName, err = requiredString(object, "toolName")
		}
	case EventToolExecutionUpdate:
		err = allowFields(object, "type", "toolCallId", "toolName", "args", "partialResult")
		if err == nil {
			event.ToolCallID, err = requiredString(object, "toolCallId")
		}
		if err == nil {
			event.ToolName, err = requiredString(object, "toolName")
		}
	case EventToolExecutionEnd:
		err = allowFields(object, "type", "toolCallId", "toolName", "result", "isError")
		if err == nil {
			event.ToolCallID, err = requiredString(object, "toolCallId")
		}
		if err == nil {
			event.ToolName, err = requiredString(object, "toolName")
		}
		if err == nil {
			event.IsError, err = requiredBool(object, "isError")
		}
	case EventQueueUpdate:
		err = allowFields(object, "type", "steering", "followUp")
		if err == nil {
			err = requireJSONArray(object, "steering")
		}
		if err == nil {
			err = requireJSONArray(object, "followUp")
		}
	case EventCompactionStart:
		err = allowFields(object, "type", "reason")
		if err == nil {
			event.Reason, err = requiredString(object, "reason")
		}
	case EventCompactionEnd:
		err = allowFields(object, "type", "reason", "result", "aborted", "willRetry", "errorMessage")
		if err == nil {
			event.Reason, err = requiredString(object, "reason")
		}
		if err == nil {
			event.WillRetry, err = requiredBool(object, "willRetry")
		}
		if err == nil {
			event.Text, event.Truncated, err = optionalBoundedString(object, "errorMessage", maxText)
		}
	case EventAutoRetryStart, EventSummarizationRetryScheduled:
		err = allowFields(object, "type", "attempt", "maxAttempts", "delayMs", "errorMessage")
		if err == nil {
			event.RetryAttempt, err = requiredInt(object, "attempt")
		}
		if err == nil {
			event.MaxAttempts, err = requiredInt(object, "maxAttempts")
		}
		if err == nil {
			var delay int
			delay, err = requiredInt(object, "delayMs")
			event.RetryDelay = time.Duration(delay) * time.Millisecond
		}
		if err == nil {
			event.Text, event.Truncated, err = optionalBoundedString(object, "errorMessage", maxText)
		}
	case EventAutoRetryEnd:
		err = allowFields(object, "type", "success", "attempt", "finalError")
		if err == nil {
			event.RetryAttempt, err = requiredInt(object, "attempt")
		}
		if err == nil {
			var success bool
			success, err = requiredBool(object, "success")
			event.IsError = !success
		}
		if err == nil {
			event.Text, event.Truncated, err = optionalBoundedString(object, "finalError", maxText)
		}
	case EventSummarizationRetryAttempt:
		err = allowFields(object, "type", "source", "reason")
		if err == nil {
			event.Reason, err = requiredString(object, "source")
		}
	case EventEntryAppended:
		err = allowFields(object, "type", "entry")
		if err == nil {
			err = requireJSONObject(object, "entry")
		}
	case EventSessionInfoChanged:
		err = allowFields(object, "type", "name")
	case EventThinkingLevelChanged:
		err = allowFields(object, "type", "level")
		if err == nil {
			event.Reason, err = requiredString(object, "level")
		}
	case EventExtensionError:
		err = allowFields(object, "type", "extensionPath", "event", "error")
		if err == nil {
			_, err = requiredString(object, "extensionPath")
		}
		if err == nil {
			_, err = requiredString(object, "event")
		}
		if err == nil {
			event.Text, event.Truncated, err = requiredBoundedString(object, "error", maxText)
		}
		event.IsError = true
	case EventExtensionUIRequest:
		var request UIRequest
		request, err = normalizeUIRequest(object, maxText)
		if err == nil {
			event.UI = &request
			return event, &request, nil
		}
	}
	if err != nil {
		return Event{}, nil, fmt.Errorf("%w: malformed %s event", ErrProtocol, eventType)
	}
	return event, nil, nil
}

func normalizeMessageDelta(raw json.RawMessage, event *Event, maxText int) error {
	if len(raw) == 0 {
		return ErrProtocol
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	rawDeltaType, err := requiredString(object, "type")
	if err != nil {
		return err
	}
	event.DeltaType = DeltaType(rawDeltaType)
	switch event.DeltaType {
	case DeltaTextStart, DeltaThinkingStart:
		err = allowFields(object, "type", "contentIndex")
	case DeltaText:
		err = allowFields(object, "type", "contentIndex", "delta")
		if err == nil {
			event.Text, event.Truncated, err = requiredBoundedString(object, "delta", maxText)
		}
	case DeltaThinking, DeltaToolCall:
		err = allowFields(object, "type", "contentIndex", "delta")
		if err == nil {
			// Validate the field but keep thinking and partial tool arguments out
			// of the public event projection.
			_, _, err = requiredBoundedString(object, "delta", maxText)
		}
	case DeltaTextEnd:
		err = allowFields(object, "type", "contentIndex", "content")
		if err == nil {
			event.Text, event.Truncated, err = requiredBoundedString(object, "content", maxText)
		}
	case DeltaThinkingEnd:
		err = allowFields(object, "type", "contentIndex", "content", "signature")
		if err == nil {
			_, _, err = requiredBoundedString(object, "content", maxText)
		}
		// Validated thinking content is intentionally not projected.
	case DeltaToolCallStart:
		err = allowFields(object, "type", "contentIndex", "id", "toolName")
		if err == nil {
			event.ToolCallID, err = requiredString(object, "id")
		}
		if err == nil {
			event.ToolName, err = requiredString(object, "toolName")
		}
	case DeltaToolCallEnd:
		err = allowFields(object, "type", "contentIndex", "toolCall")
		if err == nil {
			var toolCall struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if decodeErr := json.Unmarshal(object["toolCall"], &toolCall); decodeErr != nil || toolCall.ID == "" || toolCall.Name == "" {
				return ErrProtocol
			}
			event.ToolCallID = toolCall.ID
			event.ToolName = toolCall.Name
		}
	default:
		return ErrProtocol
	}
	if err != nil {
		return err
	}
	event.ContentIndex, err = requiredInt(object, "contentIndex")
	return err
}

func normalizeUIRequest(object map[string]json.RawMessage, maxText int) (UIRequest, error) {
	request := UIRequest{}
	var err error
	request.ID, err = requiredString(object, "id")
	if err != nil {
		return UIRequest{}, err
	}
	method, err := requiredString(object, "method")
	if err != nil {
		return UIRequest{}, err
	}
	request.Method = UIMethod(method)
	allowed := []string{"type", "id", "method"}
	switch request.Method {
	case UISelect:
		allowed = append(allowed, "title", "options", "timeout")
	case UIConfirm:
		allowed = append(allowed, "title", "message", "timeout")
	case UIInput:
		allowed = append(allowed, "title", "placeholder", "timeout")
	case UIEditor:
		allowed = append(allowed, "title", "prefill")
	case UINotify:
		allowed = append(allowed, "message", "notifyType")
	case UISetStatus:
		allowed = append(allowed, "statusKey", "statusText")
	case UISetWidget:
		allowed = append(allowed, "widgetKey", "widgetLines", "widgetPlacement")
	case UISetTitle:
		allowed = append(allowed, "title")
	case UISetEditorText:
		allowed = append(allowed, "text")
	default:
		return UIRequest{}, ErrProtocol
	}
	if err := allowFields(object, allowed...); err != nil {
		return UIRequest{}, err
	}

	if request.Method == UISelect || request.Method == UIConfirm || request.Method == UIInput || request.Method == UIEditor || request.Method == UISetTitle {
		request.Title, request.Truncated, err = requiredBoundedString(object, "title", maxText)
	} else {
		request.Title, request.Truncated, err = optionalBoundedString(object, "title", maxText)
	}
	if err != nil {
		return UIRequest{}, err
	}
	for rawKey, destination := range map[string]*string{
		"message": &request.Message, "placeholder": &request.Placeholder, "prefill": &request.Prefill,
		"notifyType": &request.NotifyType, "statusKey": &request.StatusKey, "statusText": &request.StatusText,
		"widgetKey": &request.WidgetKey, "widgetPlacement": &request.WidgetPlacement, "text": &request.Text,
	} {
		var truncated bool
		*destination, truncated, err = optionalBoundedString(object, rawKey, maxText)
		request.Truncated = request.Truncated || truncated
		if err != nil {
			return UIRequest{}, err
		}
	}
	for requiredKey, destination := range map[string]*string{
		"message": &request.Message, "statusKey": &request.StatusKey,
		"widgetKey": &request.WidgetKey, "text": &request.Text,
	} {
		required := ((request.Method == UIConfirm || request.Method == UINotify) && requiredKey == "message") ||
			(request.Method == UISetStatus && requiredKey == "statusKey") ||
			(request.Method == UISetWidget && requiredKey == "widgetKey") ||
			(request.Method == UISetEditorText && requiredKey == "text")
		if !required {
			continue
		}
		var truncated bool
		*destination, truncated, err = requiredBoundedString(object, requiredKey, maxText)
		request.Truncated = request.Truncated || truncated
		if err != nil {
			return UIRequest{}, err
		}
	}
	if raw, ok := object["options"]; ok {
		if err := json.Unmarshal(raw, &request.Options); err != nil {
			return UIRequest{}, err
		}
		for index := range request.Options {
			request.Options[index], _ = truncateUTF8(request.Options[index], maxText)
		}
	} else if request.Method == UISelect {
		return UIRequest{}, ErrProtocol
	}
	if raw, ok := object["widgetLines"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &request.WidgetLines); err != nil {
			return UIRequest{}, err
		}
		for index := range request.WidgetLines {
			request.WidgetLines[index], _ = truncateUTF8(request.WidgetLines[index], maxText)
		}
	}
	if raw, ok := object["timeout"]; ok {
		var timeoutMS int
		if err := json.Unmarshal(raw, &timeoutMS); err != nil || timeoutMS < 0 {
			return UIRequest{}, ErrProtocol
		}
		request.Timeout = time.Duration(timeoutMS) * time.Millisecond
	}
	return request, nil
}

func allowFields(object map[string]json.RawMessage, fields ...string) error {
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return ErrProtocol
		}
	}
	return nil
}

func requiredString(object map[string]json.RawMessage, key string) (string, error) {
	raw, ok := object[key]
	if !ok {
		return "", ErrProtocol
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", ErrProtocol
	}
	return value, nil
}

func optionalBoundedString(object map[string]json.RawMessage, key string, maxBytes int) (string, bool, error) {
	raw, ok := object[key]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, err
	}
	value, truncated := truncateUTF8(value, maxBytes)
	return value, truncated, nil
}

func requiredBoundedString(object map[string]json.RawMessage, key string, maxBytes int) (string, bool, error) {
	raw, ok := object[key]
	if !ok || string(raw) == "null" {
		return "", false, ErrProtocol
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, err
	}
	value, truncated := truncateUTF8(value, maxBytes)
	return value, truncated, nil
}

func requiredBool(object map[string]json.RawMessage, key string) (bool, error) {
	raw, ok := object[key]
	if !ok {
		return false, ErrProtocol
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, ErrProtocol
	}
	return value, nil
}

func requiredInt(object map[string]json.RawMessage, key string) (int, error) {
	raw, ok := object[key]
	if !ok {
		return 0, ErrProtocol
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 {
		return 0, ErrProtocol
	}
	return value, nil
}

func requireJSONObject(object map[string]json.RawMessage, key string) error {
	raw, ok := object[key]
	if !ok {
		return ErrProtocol
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return ErrProtocol
	}
	return nil
}

func requireJSONArray(object map[string]json.RawMessage, key string) error {
	raw, ok := object[key]
	if !ok {
		return ErrProtocol
	}
	var value []json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return ErrProtocol
	}
	return nil
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value, true
}
