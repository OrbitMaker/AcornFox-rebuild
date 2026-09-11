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
	"strconv"
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
	shapeHostMetrics
	shapeSourceMetadata
	shapeDeploymentPlan
	shapeDeliverySource
	shapeOperationResult
	shapeSourceUpdate
	shapeFixCandidate
	shapeFixCandidateList
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
	expectedStatus, known := expectedSuccessStatus(method, path, shape)
	if !known || (response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices && response.StatusCode != expectedStatus) {
		response.Body.Close()
		return nil, apiError{status: response.StatusCode, Code: "invalid_response", Message: "server response used an unexpected success status", contract: true}
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

func expectedSuccessStatus(method, rawPath string, shape responseShape) (int, bool) {
	if strings.Contains(rawPath, "#") || strings.HasSuffix(rawPath, "?") {
		return 0, false
	}
	parsed, err := url.ParseRequestURI(rawPath)
	if err != nil || parsed.Path == "" || strings.HasSuffix(parsed.EscapedPath(), "/") {
		return 0, false
	}
	segments := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	for _, segment := range segments {
		decoded, decodeErr := url.PathUnescape(segment)
		if segment == "" || decodeErr != nil || decoded == "" || strings.Contains(decoded, "/") {
			return 0, false
		}
	}
	noQuery := parsed.RawQuery == ""
	hasApp := len(segments) >= 2 && segments[0] == "apps" && segments[1] != ""
	switch method {
	case http.MethodPost:
		switch {
		case len(segments) == 2 && segments[0] == "auth" && segments[1] == "login" && noQuery && shape == shapeSession:
			return http.StatusOK, true
		case len(segments) == 2 && segments[0] == "auth" && (segments[1] == "logout" || segments[1] == "password") && noQuery && shape == shapeSession:
			return http.StatusNoContent, true
		case len(segments) == 1 && segments[0] == "apps" && noQuery && shape == shapeCreateApp:
			return http.StatusCreated, true
		case hasApp && len(segments) == 3 && segments[2] == "sources" && noQuery && shape == shapeSourceUpdate:
			return http.StatusCreated, true
		case hasApp && len(segments) == 3 && segments[2] == "fix-candidates" && noQuery && shape == shapeFixCandidate:
			return http.StatusAccepted, true
		case hasApp && len(segments) == 5 && segments[2] == "fix-candidates" && segments[4] == "source-match" && noQuery && shape == shapeFixCandidate:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "fix-candidates" && segments[4] == "publish" && noQuery && shape == shapeCommand:
			return http.StatusAccepted, true
		case hasApp && len(segments) == 3 && segments[2] == "deliveries" && noQuery && shape == shapeCommand:
			return http.StatusAccepted, true
		case hasApp && len(segments) == 5 && segments[2] == "deliveries" && (segments[4] == "restart" || segments[4] == "redeploy" || segments[4] == "probes") && noQuery && shape == shapeCommand:
			return http.StatusAccepted, true
		}
	case http.MethodPut:
		if hasApp && len(segments) == 5 && segments[2] == "deliveries" && segments[4] == "public-access" && noQuery && shape == shapePublicAccess {
			return http.StatusOK, true
		}
	case http.MethodGet:
		switch {
		case len(segments) == 2 && segments[0] == "host" && segments[1] == "metrics" && noQuery && shape == shapeHostMetrics:
			return http.StatusOK, true
		case len(segments) == 2 && segments[0] == "auth" && segments[1] == "session" && noQuery && shape == shapeSession:
			return http.StatusOK, true
		case len(segments) == 1 && segments[0] == "apps" && noQuery && shape == shapeApps:
			return http.StatusOK, true
		case hasApp && len(segments) == 2 && noQuery && shape == shapeApplication:
			return http.StatusOK, true
		case hasApp && len(segments) == 4 && segments[2] == "operations" && noQuery && shape == shapeOperationResult:
			return http.StatusOK, true
		case hasApp && len(segments) == 3 && segments[2] == "sources" && validListQuery(parsed.RawQuery) && shape == shapeSourceList:
			return http.StatusOK, true
		case hasApp && len(segments) == 4 && segments[2] == "sources" && noQuery && shape == shapeSource:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "sources" && segments[4] == "metadata" && noQuery && shape == shapeSourceMetadata:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "sources" && segments[4] == "deployment-plan" && noQuery && shape == shapeDeploymentPlan:
			return http.StatusOK, true
		case hasApp && len(segments) == 4 && segments[2] == "fix-candidates" && noQuery && shape == shapeFixCandidate:
			return http.StatusOK, true
		case hasApp && len(segments) == 3 && segments[2] == "fix-candidates" && noQuery && shape == shapeFixCandidateList:
			return http.StatusOK, true
		case hasApp && len(segments) == 3 && segments[2] == "deliveries" && validListQuery(parsed.RawQuery) && shape == shapeDeploymentList:
			return http.StatusOK, true
		case hasApp && len(segments) == 4 && segments[2] == "deliveries" && noQuery && shape == shapeStatus:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "deliveries" && segments[4] == "source" && noQuery && shape == shapeDeliverySource:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "deliveries" && segments[4] == "logs" && validLogsQuery(parsed.RawQuery) && shape == shapeLogs:
			return http.StatusOK, true
		case hasApp && len(segments) == 5 && segments[2] == "deliveries" && segments[4] == "public-access" && noQuery && shape == shapePublicAccess:
			return http.StatusOK, true
		}
	}
	return 0, false
}

func validListQuery(raw string) bool { return validQuery(raw, false) }
func validLogsQuery(raw string) bool { return raw != "" && validQuery(raw, true) }
func validQuery(raw string, logs bool) bool {
	if raw == "" {
		return !logs
	}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			return false
		}
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return false
	}
	allowed := map[string]bool{"limit": true, "cursor": true}
	if logs {
		allowed["source"] = true
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return false
		}
	}
	if logs {
		source, ok := values["source"]
		if !ok || len(source) != 1 || (source[0] != "build" && source[0] != "runtime") {
			return false
		}
	}
	if limit, ok := values["limit"]; ok {
		value, err := strconv.Atoi(limit[0])
		if err != nil || value < 1 || value > 100 {
			return false
		}
	}
	if cursor, ok := values["cursor"]; ok && cursor[0] == "" {
		return false
	}
	return true
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
func responseExpiry(value apiSession, requireAuthenticated bool) (time.Time, error) {
	if value.Authenticated == nil {
		return time.Time{}, errors.New("missing expiry")
	}
	if requireAuthenticated && !*value.Authenticated {
		return time.Time{}, errors.New("not authenticated")
	}
	abs := value.AbsoluteExpiresAt
	idleAt := value.IdleExpiresAt
	if !abs.After(time.Now().UTC()) || !idleAt.After(time.Now().UTC()) {
		return time.Time{}, errors.New("expiry is not future")
	}
	if idleAt.Before(abs) {
		return idleAt, nil
	}
	return abs, nil
}
