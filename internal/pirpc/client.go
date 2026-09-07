package pirpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Client exposes only the Pi commands approved for the first AcornFox
// integration. It has no generic Call method and does not expose bash, session
// switching, export, model switching or filesystem-path commands.
type Client struct{ transport *Transport }

func NewClient(transport *Transport) *Client { return &Client{transport: transport} }

func (c *Client) Subscribe() *Subscription { return c.transport.Subscribe() }

func (c *Client) Prompt(ctx context.Context, message string) (Acceptance, error) {
	return c.accept(ctx, "prompt", map[string]any{"message": message})
}

func (c *Client) Steer(ctx context.Context, message string) (Acceptance, error) {
	return c.accept(ctx, "steer", map[string]any{"message": message})
}

func (c *Client) FollowUp(ctx context.Context, message string) (Acceptance, error) {
	return c.accept(ctx, "follow_up", map[string]any{"message": message})
}

func (c *Client) accept(ctx context.Context, command string, fields map[string]any) (Acceptance, error) {
	response, err := c.transport.request(ctx, command, fields)
	if err != nil {
		return Acceptance{}, err
	}
	return Acceptance{RequestID: response.ID, Command: response.Command}, nil
}

// Abort clears queued steering/follow-up messages before asking Pi to abort.
// Cleared text is returned so the host can restore it to the editor.
func (c *Client) Abort(ctx context.Context) (ClearedQueue, Acceptance, error) {
	response, err := c.transport.request(ctx, "clear_queue", nil)
	if err != nil {
		return ClearedQueue{}, Acceptance{}, err
	}
	var data struct {
		Steering []string `json:"steering"`
		FollowUp []string `json:"followUp"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return ClearedQueue{}, Acceptance{}, fmt.Errorf("%w: malformed clear_queue response", ErrProtocol)
	}
	abort, err := c.accept(ctx, "abort", nil)
	return ClearedQueue{Steering: data.Steering, FollowUp: data.FollowUp}, abort, err
}

func (c *Client) GetState(ctx context.Context) (SessionState, error) {
	response, err := c.transport.request(ctx, "get_state", nil)
	if err != nil {
		return SessionState{}, err
	}
	var data struct {
		ThinkingLevel         string `json:"thinkingLevel"`
		IsStreaming           bool   `json:"isStreaming"`
		IsCompacting          bool   `json:"isCompacting"`
		SteeringMode          string `json:"steeringMode"`
		FollowUpMode          string `json:"followUpMode"`
		SessionID             string `json:"sessionId"`
		SessionName           string `json:"sessionName"`
		AutoCompactionEnabled bool   `json:"autoCompactionEnabled"`
		MessageCount          int    `json:"messageCount"`
		PendingMessageCount   int    `json:"pendingMessageCount"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil || data.SessionID == "" {
		return SessionState{}, fmt.Errorf("%w: malformed get_state response", ErrProtocol)
	}
	return SessionState{
		SessionID: data.SessionID, SessionName: data.SessionName, ThinkingLevel: data.ThinkingLevel,
		IsStreaming: data.IsStreaming, IsCompacting: data.IsCompacting, SteeringMode: data.SteeringMode,
		FollowUpMode: data.FollowUpMode, AutoCompactionEnabled: data.AutoCompactionEnabled,
		MessageCount: data.MessageCount, PendingMessageCount: data.PendingMessageCount,
	}, nil
}

func (c *Client) GetMessages(ctx context.Context) ([]Message, error) {
	response, err := c.transport.request(ctx, "get_messages", nil)
	if err != nil {
		return nil, err
	}
	var data struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return nil, fmt.Errorf("%w: malformed get_messages response", ErrProtocol)
	}
	messages := make([]Message, 0, len(data.Messages))
	for _, raw := range data.Messages {
		message, err := normalizeMessage(raw, c.transport.opts.MaxTextBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed message projection", ErrProtocol)
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func normalizeMessage(raw json.RawMessage, maxText int) (Message, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return Message{}, err
	}
	role, err := requiredString(object, "role")
	if err != nil {
		return Message{}, err
	}
	message := Message{Role: role}
	message.ToolCallID, _, err = optionalBoundedString(object, "toolCallId", maxText)
	if err != nil {
		return Message{}, err
	}
	message.ToolName, _, err = optionalBoundedString(object, "toolName", maxText)
	if err != nil {
		return Message{}, err
	}
	message.StopReason, _, err = optionalBoundedString(object, "stopReason", maxText)
	if err != nil {
		return Message{}, err
	}
	if rawError, ok := object["isError"]; ok {
		if err := json.Unmarshal(rawError, &message.IsError); err != nil {
			return Message{}, err
		}
	}

	switch role {
	case "user", "assistant", "toolResult":
		message.Text, message.Truncated, err = projectMessageContent(object["content"], maxText)
	case "bashExecution":
		// The host allowlist cannot create this role. Refuse rather than expose
		// command output or fullOutputPath from an externally altered session.
		return Message{}, ErrProtocol
	default:
		return Message{}, ErrProtocol
	}
	return message, err
}

func projectMessageContent(raw json.RawMessage, maxText int) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, ErrProtocol
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		plain, truncated := truncateUTF8(plain, maxText)
		return plain, truncated, nil
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", false, err
	}
	var builder strings.Builder
	truncated := false
	for _, block := range blocks {
		blockType, err := requiredString(block, "type")
		if err != nil {
			return "", false, err
		}
		if blockType != "text" {
			// These known v0.85.1 content types are deliberately omitted.
			switch blockType {
			case "thinking", "image", "toolCall":
				continue
			default:
				return "", false, ErrProtocol
			}
		}
		text, _, err := optionalBoundedString(block, "text", maxText)
		if err != nil {
			return "", false, err
		}
		remaining := maxText - builder.Len()
		if remaining <= 0 {
			truncated = true
			break
		}
		text, wasTruncated := truncateUTF8(text, remaining)
		builder.WriteString(text)
		truncated = truncated || wasTruncated
	}
	return builder.String(), truncated, nil
}

func (c *Client) RespondUIValue(ctx context.Context, id, value string) error {
	return c.respondUI(ctx, id, map[string]any{"value": value}, UISelect, UIInput, UIEditor)
}

func (c *Client) RespondUIConfirm(ctx context.Context, id string, confirmed bool) error {
	return c.respondUI(ctx, id, map[string]any{"confirmed": confirmed}, UIConfirm)
}

func (c *Client) CancelUI(ctx context.Context, id string) error {
	return c.respondUI(ctx, id, map[string]any{"cancelled": true}, UISelect, UIConfirm, UIInput, UIEditor)
}

func (c *Client) respondUI(ctx context.Context, id string, fields map[string]any, allowed ...UIMethod) error {
	if id == "" {
		return ErrUIRequest
	}
	c.transport.mu.Lock()
	method, exists := c.transport.uiPending[id]
	if exists {
		valid := false
		for _, candidate := range allowed {
			valid = valid || method == candidate
		}
		if !valid {
			exists = false
		}
	}
	c.transport.mu.Unlock()
	if !exists {
		return ErrUIRequest
	}
	object := map[string]any{"type": "extension_ui_response", "id": id}
	for key, value := range fields {
		object[key] = value
	}
	if err := c.transport.sendOneWay(ctx, object); err != nil {
		return err
	}
	c.transport.mu.Lock()
	delete(c.transport.uiPending, id)
	c.transport.mu.Unlock()
	return nil
}
