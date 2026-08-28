package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

type tlsAllowHTTPStore struct{ state domain.TLSAllowState }

func (s tlsAllowHTTPStore) TLSAllowState(context.Context, string) (domain.TLSAllowState, error) {
	return s.state, nil
}

func tlsAllowRequest(remote, target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.RemoteAddr = remote
	return request
}

func TestTLSAllowHTTPHandlerAllowsOnlyLoopbackFirstIssuanceState(t *testing.T) {
	handler := &TLSAllowHTTPHandler{Controller: &controllers.TLSAllowController{Store: tlsAllowHTTPStore{state: domain.TLSAllowState{DNSVerified: true, RouteDesired: true, RuntimeReady: true}}}}
	allowed := httptest.NewRecorder()
	if !handler.Handle(allowed, tlsAllowRequest("127.0.0.1:49152", "/internal/tls/allow?domain=app.example.test")) || allowed.Code != http.StatusNoContent {
		t.Fatalf("loopback first issuance response=%d body=%q", allowed.Code, allowed.Body.String())
	}
	for _, request := range []*http.Request{
		tlsAllowRequest("192.0.2.1:49152", "/internal/tls/allow?domain=app.example.test"),
		tlsAllowRequest("127.0.0.1:49152", "/internal/tls/allow?domain=not-a-domain"),
		tlsAllowRequest("127.0.0.1:49152", "/internal/tls/allow?domain=app.example.test&domain=other.example.test"),
	} {
		recorder := httptest.NewRecorder()
		handler.Handle(recorder, request)
		if recorder.Code != http.StatusForbidden || recorder.Body.Len() != 0 {
			t.Fatalf("TLS allow denial leaked state: status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	}
}

func TestServerRoutesTLSAllowBeforePublicAPI(t *testing.T) {
	server := NewServer()
	server.SetTLSAllow(&TLSAllowHTTPHandler{Controller: &controllers.TLSAllowController{Store: tlsAllowHTTPStore{state: domain.TLSAllowState{DNSVerified: true, RouteDesired: true, RuntimeReady: true}}}})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, tlsAllowRequest("127.0.0.1:49152", "/internal/tls/allow?domain=app.example.test"))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("server TLS allow status=%d", recorder.Code)
	}
}
