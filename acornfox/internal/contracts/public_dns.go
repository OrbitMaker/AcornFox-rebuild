package contracts

import "context"

// PublicDNSRecord is a normalized A, AAAA, or CNAME observation. TTL is
// intentionally absent: callers must not infer TTL when a resolver did not
// provide it.
type PublicDNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PublicDNSResolver is an injected recursive-resolver boundary. Implementers
// may only read DNS; there is no mutation operation in this contract.
type PublicDNSResolver interface {
	Lookup(context.Context, string, string) ([]PublicDNSRecord, error)
}

type PublicDNSStatus string

const (
	PublicDNSVerified      PublicDNSStatus = "verified"
	PublicDNSPending       PublicDNSStatus = "pending"
	PublicDNSNotFound      PublicDNSStatus = "not_found"
	PublicDNSMismatch      PublicDNSStatus = "mismatch"
	PublicDNSTimeout       PublicDNSStatus = "timeout"
	PublicDNSResolverError PublicDNSStatus = "resolver_error"
	PublicDNSConflict      PublicDNSStatus = "conflict"
	PublicDNSUnknown       PublicDNSStatus = "unknown"
)

type PublicDNSObservation struct {
	Resolver string            `json:"resolver"`
	Status   PublicDNSStatus   `json:"status"`
	Records  []PublicDNSRecord `json:"records,omitempty"`
}

type PublicDNSVerification struct {
	Status       PublicDNSStatus        `json:"status"`
	Hostname     string                 `json:"hostname"`
	Expected     string                 `json:"expected"`
	Observations []PublicDNSObservation `json:"observations"`
}

// PublicDNSVerifier is the controller-facing read-only verification boundary.
// VerifyPlatformAddress checks an explicitly configured fixed public IP; it
// never resolves a local default resolver. VerifyCustomerIngress follows a
// bounded CNAME chain toward ingress.<zone>.
type PublicDNSVerifier interface {
	VerifyPlatformAddress(context.Context, string, string) (PublicDNSVerification, error)
	VerifyCustomerIngress(context.Context, string, string) (PublicDNSVerification, error)
}
