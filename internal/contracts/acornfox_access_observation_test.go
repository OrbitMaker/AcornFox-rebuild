package contracts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAcornFoxAccessObservationReportValidatesLayersAndSamples(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	status := 500
	sampleBytes := 64 << 10
	truncated := true
	valid := AcornFoxAccessObservationReport{
		ReportID: "report_1", ObservedAt: now,
		DNS:   AcornFoxAccessDNSReport{State: AcornFoxAccessObserved, Addresses: []string{"1.1.1.1", "2001:db8::1"}},
		TLS:   AcornFoxAccessTLSReport{State: AcornFoxAccessObserved, CertificateSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		HTTPS: AcornFoxAccessHTTPSReport{State: AcornFoxAccessObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ResponseSampleBytes: &sampleBytes, ResponseTruncated: &truncated},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	bad := valid
	bad.DNS = AcornFoxAccessDNSReport{State: AcornFoxAccessFailed, FailureCode: "dns_timeout"}
	if err := bad.Validate(); err == nil {
		t.Fatal("DNS failure with downstream facts was accepted")
	}
	bad = valid
	bad.TLS = AcornFoxAccessTLSReport{State: AcornFoxAccessFailed, FailureCode: "tls_timeout"}
	if err := bad.Validate(); err == nil {
		t.Fatal("TLS failure with HTTPS fact was accepted")
	}
	bad = valid
	tooLarge := 65537
	bad.HTTPS.ResponseSampleBytes = &tooLarge
	if err := bad.Validate(); err == nil {
		t.Fatal("oversized HTTPS sample was accepted")
	}
	bad = valid
	bad.HTTPS.State = AcornFoxAccessFailed
	bad.HTTPS.HTTPStatus = nil
	bad.HTTPS.ResponseSampleSHA256 = ""
	leakedBytes := 1
	bad.HTTPS.ResponseSampleBytes = &leakedBytes
	bad.HTTPS.FailureCode = "https_timeout"
	if err := bad.Validate(); err == nil {
		t.Fatal("failed HTTPS retained sample bytes")
	}
}

func TestAcornFoxAccessObservedJSONKeepsZeroAndFalseSampleFields(t *testing.T) {
	status, sampleBytes, truncated := 200, 0, false
	value := AcornFoxAccessHTTPSReport{State: AcornFoxAccessObserved, HTTPStatus: &status, ResponseSampleSHA256: "sha256:" + strings.Repeat("a", 64), ResponseSampleBytes: &sampleBytes, ResponseTruncated: &truncated}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"response_sample_bytes":0`) || !strings.Contains(string(raw), `"response_truncated":false`) {
		t.Fatalf("observed empty response fields were omitted: %s", raw)
	}
	var roundTrip AcornFoxAccessHTTPSReport
	if err := json.Unmarshal(raw, &roundTrip); err != nil || roundTrip.ResponseSampleBytes == nil || *roundTrip.ResponseSampleBytes != 0 || roundTrip.ResponseTruncated == nil || *roundTrip.ResponseTruncated {
		t.Fatalf("round trip=%+v err=%v", roundTrip, err)
	}
}

func TestAcornFoxAccessObservationReportCanonicalizesOrderingAndRejectsNonCanonicalIP(t *testing.T) {
	value := AcornFoxAccessObservationReport{
		ReportID: "report", ObservedAt: time.Date(2026, 9, 7, 12, 0, 0, 123456789, time.FixedZone("offset", 3600)),
		DNS: AcornFoxAccessDNSReport{State: AcornFoxAccessObserved, Addresses: []string{"2001:db8::1", "1.1.1.1"}},
		TLS: AcornFoxAccessTLSReport{State: AcornFoxAccessNotAttempted}, HTTPS: AcornFoxAccessHTTPSReport{State: AcornFoxAccessNotAttempted},
	}
	canonical, err := value.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonical.DNS.Addresses, []string{"1.1.1.1", "2001:db8::1"}) || canonical.ObservedAt.Location() != time.UTC || canonical.ObservedAt.Nanosecond() != 123456000 {
		t.Fatalf("canonical report=%+v", canonical)
	}
	value.DNS.Addresses = []string{"2001:0db8::1"}
	if _, err := value.Canonical(); err == nil {
		t.Fatal("noncanonical IP was accepted")
	}
}
