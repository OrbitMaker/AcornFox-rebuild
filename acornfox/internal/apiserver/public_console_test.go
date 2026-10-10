package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/publicconsole"
)

type fakePublicConsole struct {
	enabled  bool
	domain   string
	verified string
	disabled bool
}

func (f *fakePublicConsole) Status(context.Context) (publicconsole.Status, error) {
	if !f.enabled {
		return publicconsole.Status{}, nil
	}
	return publicconsole.Status{Enabled: true, Domain: f.domain, URL: "https://" + f.domain}, nil
}

func (f *fakePublicConsole) StartVerify(_ context.Context, d string) (publicconsole.VerifyInfo, error) {
	if d == "bad" {
		return publicconsole.VerifyInfo{}, &publicconsole.Error{Status: 400, Code: "invalid_domain", Message: "域名不合法"}
	}
	f.verified = d
	return publicconsole.VerifyInfo{Domain: d, VerifyID: "v1", Path: "/.well-known/acornfox-verify/v1", Token: "t"}, nil
}

func (f *fakePublicConsole) Enable(_ context.Context, d, id string, _ bool) (publicconsole.EnableResult, error) {
	if id != "v1" {
		return publicconsole.EnableResult{}, &publicconsole.Error{Status: 409, Code: "verify_required", Message: "请先验证"}
	}
	f.enabled, f.domain = true, d
	return publicconsole.EnableResult{Domain: d, URL: "https://" + d, Password: "pw"}, nil
}

func (f *fakePublicConsole) Disable(context.Context) (bool, error) {
	was := f.enabled
	f.enabled, f.disabled = false, true
	return was, nil
}

func doJSON(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	return do(t, h, method, target, b, map[string]string{"Content-Type": "application/json"})
}

func TestPublicConsoleEndpoints(t *testing.T) {
	pc := &fakePublicConsole{}
	cfg, store, _ := newTestConfig(t)
	cfg.PublicConsole = pc
	h := New(cfg)

	rr := doJSON(t, h, http.MethodPost, "/v1/public-console/verify", `{"domain":"panel.example.com"}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"verify_id":"v1"`) || pc.verified != "panel.example.com" {
		t.Fatalf("verify = %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/public-console/verify", `{"domain":"bad"}`)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid_domain") {
		t.Fatalf("bad verify = %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/public-console/enable", `{"domain":"panel.example.com","verify_id":"x"}`)
	if rr.Code != 409 {
		t.Fatalf("enable unverified = %d", rr.Code)
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/public-console/enable", `{"domain":"panel.example.com","verify_id":"v1"}`)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"password":"pw"`) {
		t.Fatalf("enable = %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/public-console", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Fatalf("status = %d %s", rr.Code, rr.Body.String())
	}

	// An app cannot take the public console's domain.
	if _, _, err := store.EnsureApp(context.Background(), "web"); err != nil {
		t.Fatalf("EnsureApp: %v", err)
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/apps/web/domains", `{"name":"panel.example.com"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("app domain = console domain: %d %s", rr.Code, rr.Body.String())
	}

	rr = doJSON(t, h, http.MethodDelete, "/v1/public-console", "")
	if rr.Code != 200 || !pc.disabled || !strings.Contains(rr.Body.String(), `"was_enabled":true`) {
		t.Fatalf("disable = %d %s", rr.Code, rr.Body.String())
	}
}

func TestPublicConsoleNotConfigured(t *testing.T) {
	cfg, _, _ := newTestConfig(t)
	h := New(cfg)
	if rr := doJSON(t, h, http.MethodGet, "/v1/public-console", ""); rr.Code != 404 {
		t.Fatalf("status without manager = %d", rr.Code)
	}
	// The console entry never exposes management.
	cfg.PublicConsole = &fakePublicConsole{}
	req := httptest.NewRequest(http.MethodDelete, "/v1/public-console", nil)
	req.Host = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	NewConsole(cfg).ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("console entry allowed public-console management")
	}
}
