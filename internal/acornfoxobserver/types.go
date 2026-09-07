package acornfoxobserver

import "time"

const (
	DNSObserved           = "observed"
	DNSFailed             = "failed"
	LayerObserved         = "observed"
	LayerFailed           = "failed"
	LayerNotAttempted     = "not_attempted"
	DNSNoAnswer           = "dns_no_answer"
	DNSTimeout            = "dns_timeout"
	DNSLookupFailed       = "dns_lookup_failed"
	TLSConnectFailed      = "tls_connect_failed"
	TLSNameMismatch       = "tls_name_mismatch"
	TLSCertificateInvalid = "tls_certificate_invalid"
	TLSTimeout            = "tls_timeout"
	HTTPSTimeout          = "https_timeout"
	HTTPSTransportFailed  = "https_transport_failed"
	ResponseSampleLimit   = 64 << 10
	ObservationTimeout    = 30 * time.Second
)

type DNSFact struct {
	State       string   `json:"state"`
	Addresses   []string `json:"addresses,omitempty"`
	FailureCode string   `json:"failure_code,omitempty"`
}
type TLSFact struct {
	State             string `json:"state"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	FailureCode       string `json:"failure_code,omitempty"`
}
type HTTPSFact struct {
	State                string `json:"state"`
	HTTPStatus           *int   `json:"http_status,omitempty"`
	ResponseSampleSHA256 string `json:"response_sample_sha256,omitempty"`
	ResponseSampleBytes  *int   `json:"response_sample_bytes,omitempty"`
	ResponseTruncated    *bool  `json:"response_truncated,omitempty"`
	FailureCode          string `json:"failure_code,omitempty"`
}
type Report struct {
	ReportID   string    `json:"report_id"`
	ObservedAt time.Time `json:"observed_at"`
	DNS        DNSFact   `json:"dns"`
	TLS        TLSFact   `json:"tls"`
	HTTPS      HTTPSFact `json:"https"`
}
