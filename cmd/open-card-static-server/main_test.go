package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogHandlerDoesNotExposeRequestPathOrHeaders(t *testing.T) {
	var output bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}()
	handler := accessLogHandler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://fixture.test/token=do-not-log", nil)
	request.Header.Set("Authorization", "Bearer do-not-log")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("wrapped response status=%d", response.Code)
	}
	line := output.String()
	if !strings.Contains(line, "level=info event=http_request method=GET status=202") || strings.Contains(line, "do-not-log") || strings.Contains(strings.ToLower(line), "authorization") {
		t.Fatalf("access log is not bounded and secret-free: %q", line)
	}
	if safeHTTPMethod("BAD\nMETHOD") != "OTHER" {
		t.Fatal("untrusted method was not normalized")
	}
}
