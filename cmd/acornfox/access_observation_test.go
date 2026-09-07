package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxobserver"
)

type fixedAccessObserver struct {
	mu      sync.Mutex
	calls   int
	targets []string
	report  acornfoxobserver.Report
}

func (o *fixedAccessObserver) Observe(_ context.Context, reportID, target string) acornfoxobserver.Report {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	o.targets = append(o.targets, target)
	result := o.report
	result.ReportID = reportID
	return result
}

type observationRoundTripper struct {
	base         http.RoundTripper
	mu           sync.Mutex
	postFailures int
	reportIDs    []string
}

type deadlineResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *deadlineResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *observationRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	failAfterResponse := false
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access-observation") {
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var report acornfoxobserver.Report
		_ = json.Unmarshal(raw, &report)
		t.mu.Lock()
		t.reportIDs = append(t.reportIDs, report.ReportID)
		if t.postFailures > 0 {
			t.postFailures--
			failAfterResponse = true
		}
		t.mu.Unlock()
	}
	response, err := t.base.RoundTrip(r)
	if failAfterResponse && err == nil {
		response.Body.Close()
		return nil, errors.New("lost post acknowledgement")
	}
	return response, err
}

func TestPublicAccessCheckObservesOnceAndSafelyRetriesSameReport(t *testing.T) {
	observed := time.Date(2026, 9, 8, 2, 0, 0, 0, time.UTC)
	sampleBytes := 3
	truncated := false
	status := 503
	observer := &fixedAccessObserver{report: acornfoxobserver.Report{ObservedAt: observed, DNS: acornfoxobserver.DNSFact{State: acornfoxobserver.DNSObserved, Addresses: []string{"93.184.216.34"}}, TLS: acornfoxobserver.TLSFact{State: acornfoxobserver.LayerObserved, CertificateSHA256: "sha256:" + strings.Repeat("a", 64)}, HTTPS: acornfoxobserver.HTTPSFact{State: acornfoxobserver.LayerObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:" + strings.Repeat("b", 64), ResponseSampleBytes: &sampleBytes, ResponseTruncated: &truncated}}}
	var server *httptest.Server
	postCount := 0
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/public-access"):
			_, _ = io.WriteString(w, `{"desired_public":true,"url":"https://app.example.test/","endpoint":{"deployment_id":"dep_1"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`)
		case strings.HasSuffix(r.URL.Path, "/access-observation"):
			postCount++
			if r.Header.Get("Origin") != server.URL || r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Idempotency-Key") != "" {
				t.Errorf("proof headers=%v", r.Header)
			}
			var report acornfoxobserver.Report
			if json.NewDecoder(r.Body).Decode(&report) != nil {
				t.Fatal("invalid report")
			}
			received := observed.Add(time.Second)
			if postCount == 1 {
				w.WriteHeader(http.StatusCreated)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_ = json.NewEncoder(w).Encode(apiAccessObservation{Observer: "administrator_client", ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: "app.example.test", ReportID: report.ReportID, ObservedAt: report.ObservedAt, ReceivedAt: received, ExpiresAt: received.Add(5 * time.Minute), DNS: report.DNS, TLS: report.TLS, HTTPS: report.HTTPS})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := &observationRoundTripper{base: server.Client().Transport, postFailures: 1}
	client := *server.Client()
	client.Transport = transport
	stateRoot := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &cli{out: &output, err: io.Discard, env: env, client: &client, json: true}
	if err := c.publicAccessCheckWithObserver([]string{"app_1", "dep_1"}, observer); err != nil {
		t.Fatal(err)
	}
	observer.mu.Lock()
	calls := observer.calls
	target := observer.targets[0]
	observer.mu.Unlock()
	transport.mu.Lock()
	ids := append([]string(nil), transport.reportIDs...)
	transport.mu.Unlock()
	if calls != 1 || target != "https://app.example.test/" || len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] || postCount != 2 {
		t.Fatalf("calls=%d target=%q ids=%v post=%d", calls, target, ids, postCount)
	}
	if !strings.Contains(output.String(), `"observer":"administrator_client"`) || !strings.Contains(output.String(), `"response_sample_sha256"`) {
		t.Fatalf("output=%s", output.String())
	}
}

func TestPublicAccessCheckRefusesDisabledOrNonRootURLBeforeObservation(t *testing.T) {
	tests := []struct{ name, body string }{{"disabled", `{"desired_public":false,"url":"https://app.example.test/","endpoint":{"deployment_id":"dep_1"},"components":{"internal_endpoint":"accepted","local_route":"disabled","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PUBLIC_DISABLED"}`}, {"non root", `{"desired_public":true,"url":"https://app.example.test/private","endpoint":{"deployment_id":"dep_1"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					t.Fatal("unexpected report")
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			if err := saveState(env, sessionState{Origin: server.URL, Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			observer := &fixedAccessObserver{}
			c := &cli{out: io.Discard, err: io.Discard, env: env, client: server.Client()}
			err := c.publicAccessCheckWithObserver([]string{"app_1", "dep_1"}, observer)
			if err == nil {
				t.Fatal("unsafe check accepted")
			}
			if observer.calls != 0 {
				t.Fatalf("observer calls=%d", observer.calls)
			}
		})
	}
}

func TestPublicAccessObservationIsStrictReadOnly(t *testing.T) {
	received := time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC)
	observation := apiAccessObservation{Observer: "administrator_client", ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: "app.example.test", ReportID: "access_report_0123456789abcdef0123456789abcdef", ObservedAt: received.Add(-time.Second), ReceivedAt: received, ExpiresAt: received.Add(5 * time.Minute), DNS: acornfoxobserver.DNSFact{State: acornfoxobserver.DNSFailed, FailureCode: acornfoxobserver.DNSNoAnswer}, TLS: acornfoxobserver.TLSFact{State: acornfoxobserver.LayerNotAttempted}, HTTPS: acornfoxobserver.HTTPSFact{State: acornfoxobserver.LayerNotAttempted}}
	for _, test := range []struct {
		name string
		view apiAccessObservationWrapper
	}{{"not observed", apiAccessObservationWrapper{Availability: "not_observed"}}, {"available", apiAccessObservationWrapper{Availability: "available", Observation: &observation}}} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/access-observation") {
					t.Fatalf("request=%s %s", r.Method, r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(test.view)
			}))
			defer server.Close()
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			if err := saveState(env, sessionState{Origin: server.URL, Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			c := &cli{out: &output, err: io.Discard, env: env, client: server.Client(), json: true}
			if err := c.publicAccessObservation([]string{"app_1", "dep_1"}); err != nil {
				t.Fatal(err)
			}
			if requests != 1 || !strings.Contains(output.String(), `"availability":"`+test.view.Availability+`"`) {
				t.Fatalf("requests=%d output=%s", requests, output.String())
			}
		})
	}
	invalid := apiAccessObservationWrapper{Availability: "not_observed", Observation: &observation}
	if validateAccessObservationWrapper(invalid, "app_1", "dep_1") {
		t.Fatal("not_observed accepted observation")
	}
}

func TestAccessObservationDecoderRejectsBareSHA256Hex(t *testing.T) {
	status, size, truncated := 200, 0, false
	dns := acornfoxobserver.DNSFact{State: acornfoxobserver.DNSObserved, Addresses: []string{"1.1.1.1"}}
	tlsFact := acornfoxobserver.TLSFact{State: acornfoxobserver.LayerObserved, CertificateSHA256: strings.Repeat("a", 64)}
	https := acornfoxobserver.HTTPSFact{State: acornfoxobserver.LayerObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:" + strings.Repeat("b", 64), ResponseSampleBytes: &size, ResponseTruncated: &truncated}
	if validAccessLayers(dns, tlsFact, https) {
		t.Fatal("bare certificate SHA-256 was accepted")
	}
	tlsFact.CertificateSHA256 = "sha256:" + strings.Repeat("a", 64)
	https.ResponseSampleSHA256 = strings.Repeat("b", 64)
	if validAccessLayers(dns, tlsFact, https) {
		t.Fatal("bare response sample SHA-256 was accepted")
	}
}

func TestPublicAccessCheckPostsTimeoutReportWithFreshReportBudget(t *testing.T) {
	observed := time.Date(2026, 9, 8, 5, 0, 0, 123456789, time.UTC)
	resolver := &deadlineResolver{}
	observer, err := acornfoxobserver.New(acornfoxobserver.Config{Resolver: resolver, Clock: func() time.Time { return observed }})
	if err != nil {
		t.Fatal(err)
	}
	postCount := 0
	var posted acornfoxobserver.Report
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/public-access"):
			_, _ = io.WriteString(w, `{"desired_public":true,"url":"https://app.example.test/","endpoint":{"deployment_id":"dep_1"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`)
		case strings.HasSuffix(r.URL.Path, "/access-observation"):
			postCount++
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			received := observed.UTC().Truncate(time.Microsecond).Add(time.Second)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(apiAccessObservation{Observer: "administrator_client", ApplicationID: "app_1", DeploymentID: "dep_1", Hostname: "app.example.test", ReportID: posted.ReportID, ObservedAt: posted.ObservedAt, ReceivedAt: received, ExpiresAt: received.Add(5 * time.Minute), DNS: posted.DNS, TLS: posted.TLS, HTTPS: posted.HTTPS})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err = saveState(env, sessionState{Origin: server.URL, Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c := &cli{out: io.Discard, err: io.Discard, env: env, client: server.Client()}
	started := time.Now()
	if err = c.publicAccessCheckWithBudgets([]string{"app_1", "dep_1"}, observer, 25*time.Millisecond, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	calls := resolver.calls
	resolver.mu.Unlock()
	if calls != 1 || postCount != 1 || posted.DNS.State != acornfoxobserver.DNSFailed || posted.DNS.FailureCode != acornfoxobserver.DNSTimeout || posted.TLS.State != acornfoxobserver.LayerNotAttempted || posted.HTTPS.State != acornfoxobserver.LayerNotAttempted || time.Since(started) > time.Second {
		t.Fatalf("calls=%d posts=%d report=%+v elapsed=%s", calls, postCount, posted, time.Since(started))
	}
}
