package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type responseShape int

const (
	shapeSession responseShape = iota
	shapeApps
	shapeCreateApp
	shapeApplication
	shapeSourceList
	shapeSource
	shapeDeploymentList
	shapeCommand
	shapeStatus
	shapeLogs
	shapePublicAccess
)

func (c *cli) callCommand(method, path string, body any, csrf bool, key string, timeout time.Duration, shape responseShape) error {
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	return c.callWithState(state, method, path, body, csrf, key, timeout, shape)
}
func (c *cli) callWithState(state sessionState, method, path string, body any, csrf bool, key string, timeout time.Duration, shape responseShape) error {
	value, err := c.performCall(state, method, path, body, csrf, key, timeout, shape)
	if err != nil {
		return err
	}
	return c.emit(value)
}
func (c *cli) performCall(state sessionState, method, path string, body any, csrf bool, key string, timeout time.Duration, shape responseShape) (any, error) {
	c.secrets = append(c.secrets, state.Session, state.CSRF)
	response, err := c.request(context.Background(), state, method, path, body, csrf, key, timeout)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		if err := removeState(c.env); err != nil {
			response.Body.Close()
			return nil, localStateError()
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeError(response)
	}
	if response.StatusCode == http.StatusNoContent {
		defer response.Body.Close()
		if data, readErr := io.ReadAll(response.Body); readErr != nil || len(bytes.TrimSpace(data)) != 0 {
			return nil, invalidResponse("204 response must be empty")
		}
		return map[string]bool{"ok": true}, nil
	}
	defer response.Body.Close()
	value, err := decodeResponse(response.Body, shape)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (c *cli) request(ctx context.Context, state sessionState, method, path string, body any, csrf bool, key string, timeout time.Duration) (*http.Response, error) {
	var data io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		data = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, state.Origin+apiBase+path, data)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if state.Session != "" {
		request.AddCookie(&http.Cookie{Name: "__Host-acornfox_session", Value: state.Session})
	}
	if path == "/auth/login" {
		request.Header.Set("Origin", state.Origin)
	}
	if csrf {
		request.Header.Set("Origin", state.Origin)
		request.AddCookie(&http.Cookie{Name: "__Host-acornfox_csrf", Value: state.CSRF})
		request.Header.Set("X-AcornFox-CSRF", state.CSRF)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	client := *c.client
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, apiError{network: true, Code: "network_error", Message: "request unavailable"}
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		return nil, apiError{status: response.StatusCode, Code: "redirect_rejected", Message: "redirect response rejected", contract: true}
	}
	return response, nil
}

func generatedKey() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
func idempotencyKey(values map[string]string) (string, error) {
	if key, present := values["--idempotency-key"]; present {
		if strings.TrimSpace(key) == "" {
			return "", errors.New("idempotency key must not be empty")
		}
		return key, nil
	}
	return generatedKey()
}
func pathID(value string) string { return url.PathEscape(value) }
func optionalQuery(values map[string]string) string {
	query := url.Values{}
	if value := values["--limit"]; value != "" {
		query.Set("limit", value)
	}
	if value := values["--cursor"]; value != "" {
		query.Set("cursor", value)
	}
	if len(query) == 0 {
		return ""
	}
	return "?" + query.Encode()
}

func invalidResponse(message string) error {
	return apiError{status: http.StatusInternalServerError, Code: "invalid_response", Message: message, contract: true}
}
func localStateError() error {
	return apiError{status: http.StatusInternalServerError, Code: "local_state_error", Message: "session state cleanup failed", contract: true}
}
func decodeError(response *http.Response) error {
	defer response.Body.Close()
	var value struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Code == "" || value.Message == "" {
		return apiError{status: response.StatusCode, Code: "invalid_error_response", Message: "server error response is invalid", contract: true}
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return apiError{status: response.StatusCode, Code: "invalid_error_response", Message: "server error response is invalid", contract: true}
	}
	return apiError{status: response.StatusCode, Code: value.Code, Message: value.Message}
}

func cookie(response *http.Response, name string) string {
	for _, value := range response.Cookies() {
		if value.Name == name {
			return value.Value
		}
	}
	return ""
}
func responseExpiry(value map[string]json.RawMessage, requireAuthenticated bool) (time.Time, error) {
	var absolute, idle string
	var authenticated bool
	if json.Unmarshal(value["absolute_expires_at"], &absolute) != nil || json.Unmarshal(value["idle_expires_at"], &idle) != nil || json.Unmarshal(value["authenticated"], &authenticated) != nil {
		return time.Time{}, errors.New("missing expiry")
	}
	if requireAuthenticated && !authenticated {
		return time.Time{}, errors.New("not authenticated")
	}
	abs, err := time.Parse(time.RFC3339, absolute)
	if err != nil {
		return time.Time{}, err
	}
	idleAt, err := time.Parse(time.RFC3339, idle)
	if err != nil {
		return time.Time{}, err
	}
	if !abs.After(time.Now().UTC()) || !idleAt.After(time.Now().UTC()) {
		return time.Time{}, errors.New("expiry is not future")
	}
	if idleAt.Before(abs) {
		return idleAt, nil
	}
	return abs, nil
}
