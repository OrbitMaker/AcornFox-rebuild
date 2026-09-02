package aliyundns

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 9, 2, 3, 4, 5, 0, time.UTC)

func fixtureAdapter(endpoint string) Adapter {
	return Adapter{
		Endpoint:    endpoint,
		Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", AccessKeySecret: "secret-for-test-only", SecurityToken: "token-for-test-only"},
		Clock:       func() time.Time { return fixedTime },
		Nonce:       func() string { return "00000000-0000-4000-8000-000000000001" },
	}
}

func TestSignedRequestCanonicalFixedVector(t *testing.T) {
	adapter := fixtureAdapter("https://alidns.aliyuncs.com/")
	request, err := adapter.signedRequest(context.Background(), mustURL(t, adapter.Endpoint), ActionAddDomainRecord, canonicalForm(map[string]string{
		"DomainName": "example.com", "RR": "*.apps", "Type": "A", "Value": "8.8.8.8", "TTL": "600", "Line": "default",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := request.Method, http.MethodPost; got != want {
		t.Fatalf("method=%q want=%q", got, want)
	}
	if got, want := request.Header.Get("X-Acs-Action"), ActionAddDomainRecord; got != want {
		t.Fatalf("action=%q want=%q", got, want)
	}
	if got, want := request.Header.Get("X-Acs-Version"), APIVersion; got != want {
		t.Fatalf("version=%q want=%q", got, want)
	}
	if got, want := request.Header.Get("X-Acs-Date"), "2026-09-02T03:04:05Z"; got != want {
		t.Fatalf("date=%q want=%q", got, want)
	}
	if got, want := request.Header.Get("X-Acs-Signature-Nonce"), "00000000-0000-4000-8000-000000000001"; got != want {
		t.Fatalf("nonce=%q want=%q", got, want)
	}
	body, _ := io.ReadAll(request.Body)
	if got, want := string(body), "DomainName=example.com&Line=default&RR=%2A.apps&TTL=600&Type=A&Value=8.8.8.8"; got != want {
		t.Fatalf("canonical form=%q want=%q", got, want)
	}
	// This fixed value protects the full ACS3 canonical request: method, path,
	// empty query, signed headers, body digest, date, nonce and credential.
	const wantAuthorization = "ACS3-HMAC-SHA256 Credential=AKIDEXAMPLE,SignedHeaders=content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=5217593601d02812cafce13f68477ca9f7f784272d9f807f727be5a648503ecf"
	if got := independentlyComputedAuthorization(); got != wantAuthorization {
		t.Fatalf("independent authorization=%q\nwant=%q", got, wantAuthorization)
	}
	if got := request.Header.Get("Authorization"); got != wantAuthorization {
		t.Fatalf("authorization=%q\nwant=%q", got, wantAuthorization)
	}
}

func TestEndpointRequiresHTTPS(t *testing.T) {
	adapter := fixtureAdapter("http://127.0.0.1:1/")
	if _, err := adapter.ListRecords(context.Background(), "example.com"); !errors.Is(err, ErrContract) {
		t.Fatalf("list error=%v", err)
	}
	if _, err := adapter.DeleteRecord(context.Background(), "opaque-id"); !errors.Is(err, ErrContract) {
		t.Fatalf("delete error=%v", err)
	}
}

func TestListRecordsPaginatesAndSignsExactRequest(t *testing.T) {
	var mu sync.Mutex
	var requests []*http.Request
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.Clone(request.Context()))
		mu.Unlock()
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		page := request.PostForm.Get("PageNumber")
		if request.PostForm.Get("DomainName") != "example.com" || request.PostForm.Get("PageSize") != "500" || request.Header.Get("X-Acs-Action") != ActionDescribeDomainRecords {
			t.Fatalf("unsafe list request form=%v headers=%v", request.PostForm, request.Header)
		}
		if page == "1" {
			_, _ = io.WriteString(writer, `{"TotalCount":2,"PageNumber":1,"PageSize":500,"RequestId":"req-1","DomainRecords":{"Record":[{"RecordId":"record-a","DomainName":"example.com","RR":"*.apps","Type":"A","Value":"8.8.8.8","TTL":600,"Line":"default"}]}}`)
			return
		}
		if page == "2" {
			_, _ = io.WriteString(writer, `{"TotalCount":2,"PageNumber":2,"PageSize":500,"RequestId":"req-2","DomainRecords":{"Record":[{"RecordId":"opaque/record:2","DomainName":"example.com","RR":"console","Type":"A","Value":"1.1.1.1","TTL":600,"Line":"default"}]}}`)
			return
		}
		t.Fatalf("unexpected page %q", page)
	}))
	defer server.Close()
	adapter := serverAdapter(server)
	records, err := adapter.ListRecords(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ID != "record-a" || records[0].RR != "*.apps" || records[1].ID != "opaque/record:2" {
		t.Fatalf("records=%+v", records)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("requests=%d", len(requests))
	}
	for _, request := range requests {
		if got := request.Header.Get("Authorization"); !strings.HasPrefix(got, signatureAlgorithm+" Credential=AKIDEXAMPLE,SignedHeaders=content-type;host;") || strings.Contains(got, "secret-for-test-only") || strings.Contains(got, "token-for-test-only") {
			t.Fatalf("unsafe authorization=%q", got)
		}
		if request.Header.Get("X-Acs-Content-Sha256") == "" || request.Header.Get("X-Acs-Security-Token") != "token-for-test-only" || request.Header.Get("X-Acs-Version") != APIVersion {
			t.Fatalf("missing signed headers=%v", request.Header)
		}
	}
}

func TestWriteActionsAreExactAndDoNotRetry(t *testing.T) {
	actions := []struct {
		name   string
		action string
		call   func(Adapter) (WriteReceipt, error)
		wantID string
	}{
		{"create", ActionAddDomainRecord, func(a Adapter) (WriteReceipt, error) {
			return a.CreateRecord(context.Background(), CreateRecord{DomainName: "example.com", RR: "*.apps", Type: "A", Value: "8.8.8.8", TTL: 600})
		}, "new-opaque-id"},
		{"update", ActionUpdateDomainRecord, func(a Adapter) (WriteReceipt, error) {
			return a.UpdateRecord(context.Background(), UpdateRecord{ID: "old-opaque-id", RR: "*.apps", Type: "A", Value: "8.8.4.4", TTL: 300})
		}, "old-opaque-id"},
		{"delete", ActionDeleteDomainRecord, func(a Adapter) (WriteReceipt, error) { return a.DeleteRecord(context.Background(), "old-opaque-id") }, "old-opaque-id"},
	}
	for _, test := range actions {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.Header.Get("X-Acs-Action") != test.action || request.Method != http.MethodPost {
					t.Fatalf("action=%q method=%q", request.Header.Get("X-Acs-Action"), request.Method)
				}
				if err := request.ParseForm(); err != nil {
					t.Fatal(err)
				}
				switch test.action {
				case ActionAddDomainRecord:
					if got := request.PostForm.Get("RR"); got != "*.apps" {
						t.Fatalf("RR=%q", got)
					}
					_, _ = io.WriteString(writer, `{"RecordId":"new-opaque-id","RequestId":"req-create"}`)
				default:
					if request.PostForm.Get("RecordId") != "old-opaque-id" {
						t.Fatalf("form=%v", request.PostForm)
					}
					_, _ = io.WriteString(writer, `{"RequestId":"req-write"}`)
				}
			}))
			defer server.Close()
			receipt, err := test.call(serverAdapter(server))
			if err != nil || receipt.RecordID != test.wantID || receipt.RequestID == "" || calls != 1 {
				t.Fatalf("receipt=%+v err=%v calls=%d", receipt, err, calls)
			}
		})
	}
}

func TestProviderErrorsPreserveFactsWithoutCredentialCanaries(t *testing.T) {
	const accessKey = "AKID-CANARY"
	const secret = "SECRET-CANARY"
	const token = "TOKEN-CANARY"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, `{"Code":"Forbidden.RAM-AKID-CANARY","Message":"policy denied SECRET-CANARY TOKEN-CANARY","RequestId":"req-denied-AKID-CANARY","HostId":"host-denied-TOKEN-CANARY"}`)
	}))
	defer server.Close()
	adapter := serverAdapter(server)
	adapter.Credentials = Credentials{AccessKeyID: accessKey, AccessKeySecret: secret, SecurityToken: token}
	_, err := adapter.ListRecords(context.Background(), "example.com")
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.HTTPStatus != http.StatusForbidden || providerErr.Code != "Forbidden.RAM-[REDACTED]" || providerErr.Message != "policy denied [REDACTED] [REDACTED]" || providerErr.RequestID != "req-denied-[REDACTED]" || providerErr.HostID != "host-denied-[REDACTED]" {
		t.Fatalf("provider error=%#v err=%v", providerErr, err)
	}
	for _, canary := range []string{accessKey, secret, token} {
		if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(fmt.Sprintf("%#v", providerErr), canary) {
			t.Fatalf("credential leaked through error %q", canary)
		}
	}
}

func TestIndeterminateWriteRequiresReconcileWithoutRetry(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(writer, `upstream temporarily unavailable`)
	}))
	defer server.Close()
	_, err := serverAdapter(server).DeleteRecord(context.Background(), "opaque-id")
	var indeterminate *IndeterminateWriteError
	if !errors.As(err, &indeterminate) || !indeterminate.RequiresReconcile() || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestRedirectOversizeAndTimeoutFailClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		adapter func(Adapter) Adapter
	}{
		{"redirect", func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/other", http.StatusFound)
		}, func(a Adapter) Adapter { return a }},
		{"oversize", func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, strings.Repeat("x", maxResponseBytes+1))
		}, func(a Adapter) Adapter { return a }},
		{"timeout", func(writer http.ResponseWriter, request *http.Request) {
			select {
			case <-request.Context().Done():
			case <-time.After(20 * time.Millisecond):
			}
		}, func(a Adapter) Adapter { a.Client = &http.Client{Transport: timeoutRoundTripper{}}; return a }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			adapter := test.adapter(serverAdapter(server))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			_, err := adapter.ListRecords(ctx, "example.com")
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("read err=%v", err)
			}
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			_, err = adapter.DeleteRecord(ctx, "opaque-id")
			var indeterminate *IndeterminateWriteError
			if !errors.As(err, &indeterminate) {
				t.Fatalf("write err=%v", err)
			}
		})
	}
}

func TestPaginationBoundAndIncompletePagesFailClosed(t *testing.T) {
	t.Run("twenty pages are bounded", func(t *testing.T) {
		calls := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			calls++
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			page := request.PostForm.Get("PageNumber")
			_, _ = io.WriteString(writer, fmt.Sprintf(`{"TotalCount":10001,"PageNumber":%s,"PageSize":500,"RequestId":"req-%s","DomainRecords":{"Record":[{"RecordId":"record-%s","DomainName":"example.com","RR":"www","Type":"A","Value":"8.8.8.8","TTL":60,"Line":"default"}]}}`, page, page, page))
		}))
		defer server.Close()
		_, err := serverAdapter(server).ListRecords(context.Background(), "example.com")
		if !errors.Is(err, ErrContract) || calls != maxPages {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("empty page before total is rejected", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"TotalCount":1,"PageNumber":1,"PageSize":500,"RequestId":"req","DomainRecords":{"Record":[]}}`)
		}))
		defer server.Close()
		if _, err := serverAdapter(server).ListRecords(context.Background(), "example.com"); !errors.Is(err, ErrTransport) {
			t.Fatalf("err=%v", err)
		}
	})
}

type timeoutRoundTripper struct{}

func (timeoutRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	return nil, request.Context().Err()
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func serverAdapter(server *httptest.Server) Adapter {
	adapter := fixtureAdapter(server.URL)
	adapter.Client = server.Client()
	return adapter
}

// independentlyComputedAuthorization uses only literal test data and standard
// crypto primitives.  It does not call adapter signing helpers, so it catches
// mistakes in canonical headers, body digest, and StringToSign construction.
func independentlyComputedAuthorization() string {
	body := "DomainName=example.com&Line=default&RR=%2A.apps&TTL=600&Type=A&Value=8.8.8.8"
	bodySum := sha256.Sum256([]byte(body))
	bodyHash := hex.EncodeToString(bodySum[:])
	names := "content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version"
	headers := "content-type:application/x-www-form-urlencoded\n" +
		"host:alidns.aliyuncs.com\n" +
		"x-acs-action:AddDomainRecord\n" +
		"x-acs-content-sha256:" + bodyHash + "\n" +
		"x-acs-date:2026-09-02T03:04:05Z\n" +
		"x-acs-security-token:token-for-test-only\n" +
		"x-acs-signature-nonce:00000000-0000-4000-8000-000000000001\n" +
		"x-acs-version:2015-01-09\n"
	canonicalRequest := "POST\n/\n\n" + headers + "\n" + names + "\n" + bodyHash
	canonicalSum := sha256.Sum256([]byte(canonicalRequest))
	mac := hmac.New(sha256.New, []byte("secret-for-test-only"))
	_, _ = mac.Write([]byte("ACS3-HMAC-SHA256\n" + hex.EncodeToString(canonicalSum[:])))
	return "ACS3-HMAC-SHA256 Credential=AKIDEXAMPLE,SignedHeaders=" + names + ",Signature=" + hex.EncodeToString(mac.Sum(nil))
}
