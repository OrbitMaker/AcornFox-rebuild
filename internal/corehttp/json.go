package corehttp

import (
	"encoding/json"
	"net/http"
)

// WriteJSON encodes value as JSON to writer with the given HTTP status code.
func WriteJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// WriteJSONError encodes a standard JSON error response with code and message.
func WriteJSONError(writer http.ResponseWriter, status int, code, message string) {
	WriteJSON(writer, status, map[string]string{"code": code, "message": message})
}

// WriteCapabilityUnavailable writes a structured 503 response indicating a required
// capability is not implemented or installed in this thin core.
func WriteCapabilityUnavailable(writer http.ResponseWriter, capability, message string) {
	WriteJSON(writer, http.StatusServiceUnavailable, map[string]string{
		"code":       "capability_unavailable",
		"message":    message,
		"capability": capability,
	})
}
