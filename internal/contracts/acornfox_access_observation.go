package contracts

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type AcornFoxAccessObservationState string

const (
	AcornFoxAccessObserved     AcornFoxAccessObservationState = "observed"
	AcornFoxAccessFailed       AcornFoxAccessObservationState = "failed"
	AcornFoxAccessNotAttempted AcornFoxAccessObservationState = "not_attempted"
)

const AcornFoxAccessObservationLifetime = 5 * time.Minute

type AcornFoxAccessDNSReport struct {
	State       AcornFoxAccessObservationState `json:"state"`
	Addresses   []string                       `json:"addresses,omitempty"`
	FailureCode string                         `json:"failure_code,omitempty"`
}

type AcornFoxAccessTLSReport struct {
	State             AcornFoxAccessObservationState `json:"state"`
	CertificateSHA256 string                         `json:"certificate_sha256,omitempty"`
	FailureCode       string                         `json:"failure_code,omitempty"`
}

type AcornFoxAccessHTTPSReport struct {
	State                AcornFoxAccessObservationState `json:"state"`
	HTTPStatus           *int                           `json:"http_status,omitempty"`
	ResponseSampleSHA256 string                         `json:"response_sample_sha256,omitempty"`
	ResponseSampleBytes  *int                           `json:"response_sample_bytes,omitempty"`
	ResponseTruncated    *bool                          `json:"response_truncated,omitempty"`
	FailureCode          string                         `json:"failure_code,omitempty"`
}

type AcornFoxAccessObservationReport struct {
	ReportID   string                    `json:"report_id"`
	ObservedAt time.Time                 `json:"observed_at"`
	DNS        AcornFoxAccessDNSReport   `json:"dns"`
	TLS        AcornFoxAccessTLSReport   `json:"tls"`
	HTTPS      AcornFoxAccessHTTPSReport `json:"https"`
}

// AcornFoxAccessObservation records what an authenticated administrator
// explicitly reported from their client. Observer identifies that source of
// evidence; it is not an independently established geographic claim.
type AcornFoxAccessObservation struct {
	Observer      string `json:"observer"`
	ApplicationID string `json:"application_id"`
	DeploymentID  string `json:"deployment_id"`
	Hostname      string `json:"hostname"`
	AcornFoxAccessObservationReport
	ReceivedAt time.Time `json:"received_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type AcornFoxAccessObservationAvailability string

const (
	AcornFoxAccessObservationAvailable   AcornFoxAccessObservationAvailability = "available"
	AcornFoxAccessObservationExpired     AcornFoxAccessObservationAvailability = "expired"
	AcornFoxAccessObservationNotObserved AcornFoxAccessObservationAvailability = "not_observed"
)

type AcornFoxAccessObservationView struct {
	Availability AcornFoxAccessObservationAvailability `json:"availability"`
	Observation  *AcornFoxAccessObservation            `json:"observation,omitempty"`
}

func (o AcornFoxAccessObservation) Validate() error {
	if o.Observer != "administrator_client" || domain.RequireID(domain.ID(o.ApplicationID), "application id") != nil || domain.RequireID(domain.ID(o.DeploymentID), "deployment id") != nil || !validAcornFoxPublicHostname(o.Hostname) || o.ReceivedAt.IsZero() || o.ExpiresAt.Sub(o.ReceivedAt) != AcornFoxAccessObservationLifetime {
		return fmt.Errorf("access observation is invalid")
	}
	return o.AcornFoxAccessObservationReport.Validate()
}

// Canonical returns the stable representation used by idempotency. IP text is
// required to already be canonical, while address ordering and timestamp
// precision are normalized because neither changes the observed fact.
func (r AcornFoxAccessObservationReport) Canonical() (AcornFoxAccessObservationReport, error) {
	r.ObservedAt = r.ObservedAt.UTC().Truncate(time.Microsecond)
	for _, value := range r.DNS.Addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value {
			return AcornFoxAccessObservationReport{}, fmt.Errorf("dns observation address is not canonical")
		}
	}
	r.DNS.Addresses = append([]string(nil), r.DNS.Addresses...)
	sort.Strings(r.DNS.Addresses)
	if err := r.Validate(); err != nil {
		return AcornFoxAccessObservationReport{}, err
	}
	return r, nil
}

func (r AcornFoxAccessObservationReport) Validate() error {
	if !accessReportID(r.ReportID) || r.ObservedAt.IsZero() {
		return fmt.Errorf("access observation report identity is invalid")
	}
	if err := r.DNS.validate(); err != nil {
		return err
	}
	if err := r.TLS.validate(); err != nil {
		return err
	}
	if err := r.HTTPS.validate(); err != nil {
		return err
	}
	if r.DNS.State == AcornFoxAccessFailed && (r.TLS.State != AcornFoxAccessNotAttempted || r.HTTPS.State != AcornFoxAccessNotAttempted) {
		return fmt.Errorf("access observation layers are invalid")
	}
	if r.TLS.State == AcornFoxAccessFailed && r.HTTPS.State != AcornFoxAccessNotAttempted {
		return fmt.Errorf("access observation layers are invalid")
	}
	if r.TLS.State == AcornFoxAccessNotAttempted && r.HTTPS.State != AcornFoxAccessNotAttempted {
		return fmt.Errorf("access observation layers are invalid")
	}
	return nil
}

func (r AcornFoxAccessDNSReport) validate() error {
	switch r.State {
	case AcornFoxAccessObserved:
		if r.FailureCode != "" || len(r.Addresses) == 0 || len(r.Addresses) > 8 {
			break
		}
		last := ""
		for _, value := range r.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || address.String() != value || value <= last {
				return fmt.Errorf("dns observation invalid")
			}
			last = value
		}
		return nil
	case AcornFoxAccessFailed:
		if len(r.Addresses) == 0 && oneOf(r.FailureCode, "dns_no_answer", "dns_timeout", "dns_lookup_failed") {
			return nil
		}
	}
	return fmt.Errorf("dns observation invalid")
}

func (r AcornFoxAccessTLSReport) validate() error {
	switch r.State {
	case AcornFoxAccessNotAttempted:
		if r.CertificateSHA256 == "" && r.FailureCode == "" {
			return nil
		}
	case AcornFoxAccessObserved:
		if validSHA(r.CertificateSHA256) && r.FailureCode == "" {
			return nil
		}
	case AcornFoxAccessFailed:
		if r.CertificateSHA256 == "" && oneOf(r.FailureCode, "tls_connect_failed", "tls_name_mismatch", "tls_certificate_invalid", "tls_timeout") {
			return nil
		}
	}
	return fmt.Errorf("tls observation invalid")
}

func (r AcornFoxAccessHTTPSReport) validate() error {
	switch r.State {
	case AcornFoxAccessNotAttempted:
		if r.HTTPStatus == nil && r.ResponseSampleSHA256 == "" && r.ResponseSampleBytes == nil && r.ResponseTruncated == nil && r.FailureCode == "" {
			return nil
		}
	case AcornFoxAccessObserved:
		// Every observed response, including 5xx, is a successful transport
		// observation. The digest covers only the reported sample, whose length
		// is strictly bounded to 64 KiB.
		if r.HTTPStatus != nil && *r.HTTPStatus >= 100 && *r.HTTPStatus <= 599 && validSHA(r.ResponseSampleSHA256) && r.ResponseSampleBytes != nil && *r.ResponseSampleBytes >= 0 && *r.ResponseSampleBytes <= 64<<10 && r.ResponseTruncated != nil && r.FailureCode == "" {
			return nil
		}
	case AcornFoxAccessFailed:
		if r.HTTPStatus == nil && r.ResponseSampleSHA256 == "" && r.ResponseSampleBytes == nil && r.ResponseTruncated == nil && oneOf(r.FailureCode, "https_timeout", "https_transport_failed") {
			return nil
		}
	}
	return fmt.Errorf("https observation invalid")
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func validSHA(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[7:] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func accessReportID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
