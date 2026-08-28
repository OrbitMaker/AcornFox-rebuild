package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
)

type g3HTTPStore struct {
	apps     map[domain.ID]string
	platform *controllers.G3PlatformDomainFact
	domains  map[domain.ID]controllers.G3ApplicationDomainFact
}

func (s *g3HTTPStore) ApplicationName(_ context.Context, id domain.ID) (string, bool, error) {
	value, ok := s.apps[id]
	return value, ok, nil
}
func (s *g3HTTPStore) PlatformDomain(context.Context) (controllers.G3PlatformDomainFact, bool, error) {
	if s.platform == nil {
		return controllers.G3PlatformDomainFact{}, false, nil
	}
	return *s.platform, true, nil
}
func (s *g3HTTPStore) ReplayG3Idempotency(context.Context, controllers.G3Idempotency) ([]byte, bool, error) {
	return nil, false, nil
}
func (s *g3HTTPStore) PutPlatformDomain(_ context.Context, value controllers.G3PlatformDomainFact, _ controllers.G3Idempotency) (controllers.G3PlatformDomainFact, bool, error) {
	if s.platform != nil && s.platform.BaseDomain != value.BaseDomain {
		return controllers.G3PlatformDomainFact{}, false, controllers.ErrG3AccessConflict
	}
	s.platform = &value
	return value, false, nil
}
func (s *g3HTTPStore) ListApplicationDomains(_ context.Context, applicationID domain.ID) ([]controllers.G3ApplicationDomainFact, error) {
	items := make([]controllers.G3ApplicationDomainFact, 0)
	for _, item := range s.domains {
		if item.ApplicationID == applicationID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (s *g3HTTPStore) ApplicationDomain(_ context.Context, applicationID, id domain.ID) (controllers.G3ApplicationDomainFact, bool, error) {
	item, ok := s.domains[id]
	return item, ok && item.ApplicationID == applicationID, nil
}
func (s *g3HTTPStore) BindCustomDomain(_ context.Context, value controllers.G3ApplicationDomainFact, _ controllers.G3Idempotency) (controllers.G3ApplicationDomainFact, bool, error) {
	for _, item := range s.domains {
		if item.Hostname == value.Hostname {
			if item.ApplicationID != value.ApplicationID {
				return controllers.G3ApplicationDomainFact{}, false, controllers.ErrG3AccessConflict
			}
			return item, false, nil
		}
	}
	s.domains[value.ID] = value
	return value, true, nil
}
func (s *g3HTTPStore) SetApplicationDomainVerification(_ context.Context, applicationID, id domain.ID, status controllers.G3VerificationStatus, at *time.Time, _ controllers.G3Idempotency) (controllers.G3ApplicationDomainFact, bool, error) {
	item, ok := s.domains[id]
	if !ok || item.ApplicationID != applicationID {
		return controllers.G3ApplicationDomainFact{}, false, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	item.VerificationStatus, item.VerifiedAt = status, at
	s.domains[id] = item
	return item, false, nil
}
func (s *g3HTTPStore) UnbindCustomDomain(_ context.Context, applicationID, id domain.ID, _ string, _ controllers.G3Idempotency) (bool, error) {
	item, ok := s.domains[id]
	if !ok || item.ApplicationID != applicationID {
		return false, domain.NewError(domain.ErrNotFound, "application domain not found")
	}
	if item.Serving {
		return false, controllers.ErrG3AccessConflict
	}
	delete(s.domains, id)
	return false, nil
}
func (s *g3HTTPStore) ApplicationAccessFacts(context.Context, domain.ID) (controllers.G3ApplicationAccessFacts, error) {
	return controllers.G3ApplicationAccessFacts{Runtime: controllers.G3RuntimeFact{RuntimeReady: true}}, nil
}

type g3HTTPDNS struct{}

func (g3HTTPDNS) VerifyPlatformAddress(_ context.Context, hostname, expected string) (contracts.PublicDNSVerification, error) {
	return contracts.PublicDNSVerification{Hostname: hostname, Expected: expected, Status: contracts.PublicDNSVerified}, nil
}
func (g3HTTPDNS) VerifyCustomerIngress(_ context.Context, hostname, zone string) (contracts.PublicDNSVerification, error) {
	return contracts.PublicDNSVerification{Hostname: hostname, Expected: "ingress." + zone, Status: contracts.PublicDNSVerified}, nil
}

func newG3HTTPServer(t *testing.T) (*Server, *http.Cookie, *http.Cookie) {
	t.Helper()
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	store := &g3HTTPStore{apps: map[domain.ID]string{"app_1": "Demo"}, domains: map[domain.ID]controllers.G3ApplicationDomainFact{}}
	controller := &controllers.G3AccessController{Store: store, Config: controllers.G3AccessConfig{PublicDNSVerifier: g3HTTPDNS{}, ExpectedPublicIP: "203.0.113.77", IngressLabel: "ingress", AppsLabel: "apps", WildcardProbeLabel: "wildcard-probe"}, Clock: func() time.Time { return now }}
	server.SetG3Access(&G3AccessHTTPHandler{Controller: controller})
	return server, session, csrf
}

func TestG3AccessHTTPFacadeUsesSessionCSRFAndFrozenResponses(t *testing.T) {
	server, session, csrf := newG3HTTPServer(t)

	anonymous := httptest.NewRecorder()
	server.Handler().ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/settings/platform-domain", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous settings status=%d", anonymous.Code)
	}

	put := controlPlaneRequest(http.MethodPut, "/api/v1/settings/platform-domain", strings.NewReader(`{"base_domain":"example.test"}`), session)
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("Idempotency-Key", "g3-platform")
	addControlPlaneWriteProof(put, csrf)
	putResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(putResponse, put)
	if putResponse.Code != http.StatusAccepted || !strings.Contains(putResponse.Body.String(), `"certificate_pending"`) {
		t.Fatalf("platform response=%d %s", putResponse.Code, putResponse.Body.String())
	}

	bind := controlPlaneRequest(http.MethodPost, "/api/v1/applications/app_1/domains", strings.NewReader(`{"hostname":"www.customer.test"}`), session)
	bind.Header.Set("Content-Type", "application/json")
	bind.Header.Set("Idempotency-Key", "g3-bind")
	addControlPlaneWriteProof(bind, csrf)
	bound := httptest.NewRecorder()
	server.Handler().ServeHTTP(bound, bind)
	if bound.Code != http.StatusAccepted || !strings.Contains(bound.Body.String(), `"cname_target":"ingress.example.test"`) {
		t.Fatalf("bind response=%d %s", bound.Code, bound.Body.String())
	}
	var decoded struct {
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(bound.Body.Bytes(), &decoded); err != nil || decoded.Domain.ID == "" {
		t.Fatalf("decode bound domain=%+v err=%v", decoded, err)
	}
	chunked := controlPlaneRequest(http.MethodPost, "/api/v1/applications/app_1/domains/"+decoded.Domain.ID+"/verify", strings.NewReader(`unexpected`), session)
	chunked.ContentLength = -1
	chunked.Header.Set("Idempotency-Key", "g3-verify-chunked")
	addControlPlaneWriteProof(chunked, csrf)
	chunkedRejected := httptest.NewRecorder()
	server.Handler().ServeHTTP(chunkedRejected, chunked)
	if chunkedRejected.Code != http.StatusUnprocessableEntity {
		t.Fatalf("chunked verification body=%d %s", chunkedRejected.Code, chunkedRejected.Body.String())
	}

	verify := controlPlaneRequest(http.MethodPost, "/api/v1/applications/app_1/domains/"+decoded.Domain.ID+"/verify", nil, session)
	verify.Header.Set("Idempotency-Key", "g3-verify")
	addControlPlaneWriteProof(verify, csrf)
	verified := httptest.NewRecorder()
	server.Handler().ServeHTTP(verified, verify)
	if verified.Code != http.StatusAccepted || !strings.Contains(verified.Body.String(), `"certificate_pending"`) {
		t.Fatalf("verify response=%d %s", verified.Code, verified.Body.String())
	}

	access := httptest.NewRecorder()
	server.Handler().ServeHTTP(access, controlPlaneRequest(http.MethodGet, "/api/v1/applications/app_1/access", nil, session))
	if access.Code != http.StatusOK || !strings.Contains(access.Body.String(), `"runtimeReady":true`) || strings.Contains(access.Body.String(), `"status":"ready"`) {
		t.Fatalf("access response=%d %s", access.Code, access.Body.String())
	}

	remove := controlPlaneRequest(http.MethodDelete, "/api/v1/applications/app_1/domains/"+decoded.Domain.ID, nil, session)
	remove.Header.Set("Idempotency-Key", "g3-unbind")
	addControlPlaneWriteProof(remove, csrf)
	removed := httptest.NewRecorder()
	server.Handler().ServeHTTP(removed, remove)
	if removed.Code != http.StatusNoContent {
		t.Fatalf("unbind response=%d %s", removed.Code, removed.Body.String())
	}
}

func TestG3AccessHTTPUnconfiguredWriteFailsClosed(t *testing.T) {
	server := NewServer()
	now := time.Unix(1_700_000_000, 0).UTC()
	_, session, csrf := attachTestAdministratorTokens(t, server, &now)
	server.SetG3Access(&G3AccessHTTPHandler{Controller: &controllers.G3AccessController{Store: &g3HTTPStore{apps: map[domain.ID]string{}, domains: map[domain.ID]controllers.G3ApplicationDomainFact{}}}})
	read := httptest.NewRecorder()
	server.Handler().ServeHTTP(read, controlPlaneRequest(http.MethodGet, "/api/v1/settings/platform-domain", nil, session))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"unconfigured"`) {
		t.Fatalf("unconfigured read=%d %s", read.Code, read.Body.String())
	}
	write := controlPlaneRequest(http.MethodPut, "/api/v1/settings/platform-domain", strings.NewReader(`{"base_domain":"example.test"}`), session)
	write.Header.Set("Content-Type", "application/json")
	write.Header.Set("Idempotency-Key", "g3-unconfigured")
	addControlPlaneWriteProof(write, csrf)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, write)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "resolver") {
		t.Fatalf("unconfigured write=%d %s", response.Code, response.Body.String())
	}
}
