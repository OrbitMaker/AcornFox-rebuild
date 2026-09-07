package main

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/open-card/open-card/internal/assistanttools"
)

func TestAssistantToolHTTPUsesConcreteHostPathAndSafeProbe(t *testing.T) {
	g := assistanttools.Grant{Actor: "admin_1", RunID: "run_1", Scope: assistanttools.Scope{Admin: true}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/acornfox/host/metrics" {
			t.Fatal(r.URL.Path)
		}
		w.Write([]byte(`{"availability":"available"}`))
	})
	if got := assistantToolHTTP(context.Background(), g, assistanttools.Call{CallID: "c", Tool: "acornfox_host_metrics", Arguments: []byte(`{}`)}, h, "/api/v1/acornfox/host/metrics", http.MethodGet); !got.OK {
		t.Fatal(got)
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("probe method")
		}
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != "{\"protocol\":\"http\",\"path\":\"/\"}" {
			t.Fatal(string(raw))
		}
		w.Write([]byte(`{}`))
	})
	if got := assistantToolHTTP(context.Background(), g, assistanttools.Call{CallID: "probe", Tool: "acornfox_probe", Arguments: []byte(`{}`)}, probe, "/api/v1/acornfox/apps/app_1/deliveries/dep_1/probes", http.MethodPost); !got.OK {
		t.Fatal(got)
	}
}

type assistantFalseHandler struct{}

func (assistantFalseHandler) ServeHTTP(http.ResponseWriter, *http.Request)   {}
func (assistantFalseHandler) Handle(http.ResponseWriter, *http.Request) bool { return false }
func TestAssistantToolHTTPRejectsUnhandledRoute(t *testing.T) {
	g := assistanttools.Grant{Actor: "admin_1", RunID: "r", Scope: assistanttools.Scope{Admin: true}}
	if got := assistantToolHTTP(context.Background(), g, assistanttools.Call{CallID: "x", Arguments: []byte(`{}`)}, assistantFalseHandler{}, "/no", http.MethodGet); got.Code != "not_found" {
		t.Fatal(got)
	}
}
