package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxProbeProtocol is deliberately limited to the two protocol checks the
// standalone runtime can make against its own loopback publication.
type AcornFoxProbeProtocol string

const (
	AcornFoxProbeProtocolHTTP AcornFoxProbeProtocol = "http"
	AcornFoxProbeProtocolTCP  AcornFoxProbeProtocol = "tcp"
)

// AcornFoxProbeOutcome describes a transport observation. It is not an
// application-health, public-reachability, DNS, TLS, or business-status claim.
type AcornFoxProbeOutcome string

const (
	AcornFoxProbeOutcomeResponded         AcornFoxProbeOutcome = "responded"
	AcornFoxProbeOutcomeTimeout           AcornFoxProbeOutcome = "timeout"
	AcornFoxProbeOutcomeRefused           AcornFoxProbeOutcome = "refused"
	AcornFoxProbeOutcomeMalformedResponse AcornFoxProbeOutcome = "malformed_response"
	AcornFoxProbeOutcomeCancelled         AcornFoxProbeOutcome = "cancelled"
	AcornFoxProbeOutcomeNotApplicable     AcornFoxProbeOutcome = "not_applicable"
	AcornFoxProbeTargetClassLoopback                           = "loopback"
	acornFoxProbeMaxLatencyMS             int64                = 60_000
)

const (
	AcornFoxProbeErrorTimeout           = "timeout"
	AcornFoxProbeErrorConnectionRefused = "connection_refused"
	AcornFoxProbeErrorMalformedResponse = "malformed_response"
	AcornFoxProbeErrorCancelled         = "cancelled"
)

// AcornFoxProbeRequest contains no network target. The runtime observer is
// the only authority that can derive a loopback address for this reference.
type AcornFoxProbeRequest struct {
	Reference      AcornFoxRuntimeReference `json:"runtime_reference"`
	Protocol       AcornFoxProbeProtocol    `json:"protocol"`
	HTTPPath       string                   `json:"http_path,omitempty"`
	IdempotencyKey string                   `json:"idempotency_key"`
}

// NewAcornFoxProbeRequest returns an immutable, normalized request. TCP has
// no path; an empty HTTP path is the normalized root path.
func NewAcornFoxProbeRequest(reference AcornFoxRuntimeReference, protocol AcornFoxProbeProtocol, httpPath, idempotencyKey string) (AcornFoxProbeRequest, error) {
	request := AcornFoxProbeRequest{Reference: reference, Protocol: protocol, IdempotencyKey: idempotencyKey}
	switch protocol {
	case AcornFoxProbeProtocolHTTP:
		normalized, err := NormalizeAcornFoxProbeHTTPPath(httpPath)
		if err != nil {
			return AcornFoxProbeRequest{}, err
		}
		request.HTTPPath = normalized
	case AcornFoxProbeProtocolTCP:
		if httpPath != "" {
			return AcornFoxProbeRequest{}, fmt.Errorf("tcp probe path is invalid")
		}
	default:
		return AcornFoxProbeRequest{}, fmt.Errorf("probe protocol is invalid")
	}
	if err := request.Validate(); err != nil {
		return AcornFoxProbeRequest{}, err
	}
	return request, nil
}

func (request AcornFoxProbeRequest) Validate() error {
	if err := request.Reference.Fact.Validate(); err != nil {
		return fmt.Errorf("probe runtime reference is invalid")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return fmt.Errorf("probe idempotency key is required")
	}
	switch request.Protocol {
	case AcornFoxProbeProtocolHTTP:
		normalized, err := NormalizeAcornFoxProbeHTTPPath(request.HTTPPath)
		if err != nil || request.HTTPPath != normalized {
			return fmt.Errorf("http probe path is invalid")
		}
	case AcornFoxProbeProtocolTCP:
		if request.HTTPPath != "" {
			return fmt.Errorf("tcp probe path is invalid")
		}
	default:
		return fmt.Errorf("probe protocol is invalid")
	}
	return nil
}

// NormalizeAcornFoxProbeHTTPPath accepts only an origin-form path. It rejects
// URLs, query strings, fragments, whitespace, and encoded path ambiguities.
func NormalizeAcornFoxProbeHTTPPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if strings.TrimSpace(raw) != raw || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "?#%") {
		return "", fmt.Errorf("http probe path is invalid")
	}
	for _, character := range raw {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", fmt.Errorf("http probe path is invalid")
		}
	}
	normalized := path.Clean(raw)
	if normalized == "." || !strings.HasPrefix(normalized, "/") {
		return "", fmt.Errorf("http probe path is invalid")
	}
	return normalized, nil
}

// AcornFoxProbeResult is a bounded fact, suitable for persistence later. It
// intentionally omits an address, response body, raw error, URL, and every
// broader claim about application or public service health.
type AcornFoxProbeResult struct {
	ApplicationID domain.ID             `json:"application_id"`
	EnvironmentID domain.ID             `json:"environment_id"`
	ReleaseID     domain.ID             `json:"release_id"`
	DeploymentID  domain.ID             `json:"deployment_id"`
	ServiceName   string                `json:"service_name"`
	Protocol      AcornFoxProbeProtocol `json:"protocol"`
	TargetClass   string                `json:"target_class"`
	Outcome       AcornFoxProbeOutcome  `json:"outcome"`
	HTTPStatus    *int                  `json:"http_status,omitempty"`
	LatencyMS     int64                 `json:"latency_ms"`
	ErrorCode     string                `json:"error_code,omitempty"`
	ObservedAt    time.Time             `json:"observed_at"`
	FactDigest    string                `json:"fact_digest"`
}

func (result AcornFoxProbeResult) Validate() error {
	if result.ApplicationID.Empty() || result.EnvironmentID.Empty() || result.ReleaseID.Empty() || result.DeploymentID.Empty() || !acornFoxRuntimeServiceName.MatchString(result.ServiceName) || result.TargetClass != AcornFoxProbeTargetClassLoopback || !validAcornFoxProbeOutcomeForProtocol(result.Protocol, result.Outcome) || result.LatencyMS < 0 || result.LatencyMS > acornFoxProbeMaxLatencyMS || result.ObservedAt.IsZero() || !validAcornFoxProbeDigest(result.FactDigest) {
		return fmt.Errorf("probe result is invalid")
	}
	if result.Protocol == AcornFoxProbeProtocolHTTP && result.Outcome == AcornFoxProbeOutcomeResponded {
		if result.HTTPStatus == nil || *result.HTTPStatus < 100 || *result.HTTPStatus > 599 || result.ErrorCode != "" {
			return fmt.Errorf("probe result is invalid")
		}
	} else if result.HTTPStatus != nil {
		return fmt.Errorf("probe result is invalid")
	}
	if result.Protocol == AcornFoxProbeProtocolTCP && result.Outcome == AcornFoxProbeOutcomeResponded && result.ErrorCode != "" {
		return fmt.Errorf("probe result is invalid")
	}
	if result.Outcome == AcornFoxProbeOutcomeNotApplicable {
		if result.LatencyMS != 0 || result.ErrorCode != "" || result.HTTPStatus != nil {
			return fmt.Errorf("probe result is invalid")
		}
		return nil
	}
	if result.Outcome != AcornFoxProbeOutcomeResponded && result.ErrorCode != acornFoxProbeErrorCode(result.Outcome) {
		return fmt.Errorf("probe result is invalid")
	}
	return nil
}

func validAcornFoxProbeOutcome(outcome AcornFoxProbeOutcome) bool {
	switch outcome {
	case AcornFoxProbeOutcomeResponded, AcornFoxProbeOutcomeTimeout, AcornFoxProbeOutcomeRefused, AcornFoxProbeOutcomeMalformedResponse, AcornFoxProbeOutcomeCancelled, AcornFoxProbeOutcomeNotApplicable:
		return true
	default:
		return false
	}
}

func validAcornFoxProbeOutcomeForProtocol(protocol AcornFoxProbeProtocol, outcome AcornFoxProbeOutcome) bool {
	if !validAcornFoxProbeOutcome(outcome) {
		return false
	}
	switch protocol {
	case AcornFoxProbeProtocolHTTP:
		return true
	case AcornFoxProbeProtocolTCP:
		return outcome != AcornFoxProbeOutcomeMalformedResponse
	default:
		return false
	}
}

func acornFoxProbeErrorCode(outcome AcornFoxProbeOutcome) string {
	switch outcome {
	case AcornFoxProbeOutcomeTimeout:
		return AcornFoxProbeErrorTimeout
	case AcornFoxProbeOutcomeRefused:
		return AcornFoxProbeErrorConnectionRefused
	case AcornFoxProbeOutcomeMalformedResponse:
		return AcornFoxProbeErrorMalformedResponse
	case AcornFoxProbeOutcomeCancelled:
		return AcornFoxProbeErrorCancelled
	default:
		return ""
	}
}

// AcornFoxProbeFactDigest is stable for the immutable request/reference,
// current runtime observation, and bounded result facts. Clocks and elapsed
// duration are intentionally not inputs.
func AcornFoxProbeFactDigest(request AcornFoxProbeRequest, observation AcornFoxRuntimeObservation, outcome AcornFoxProbeOutcome, httpStatus *int) (string, error) {
	if err := request.Validate(); err != nil || !validAcornFoxProbeOutcomeForProtocol(request.Protocol, outcome) {
		return "", fmt.Errorf("probe digest inputs are invalid")
	}
	if httpStatus != nil && (request.Protocol != AcornFoxProbeProtocolHTTP || outcome != AcornFoxProbeOutcomeResponded || *httpStatus < 100 || *httpStatus > 599) {
		return "", fmt.Errorf("probe digest inputs are invalid")
	}
	deploymentID, err := AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil || observation.DeploymentID != deploymentID || observation.ServiceName != request.Reference.Fact.ServiceName {
		return "", fmt.Errorf("probe digest inputs are invalid")
	}
	status := ""
	if httpStatus != nil {
		status = fmt.Sprint(*httpStatus)
	}
	sum := sha256.New()
	for _, value := range []string{
		request.Reference.Fact.ApplicationID.String(), request.Reference.Fact.EnvironmentID.String(), request.Reference.Fact.ReleaseID.String(), request.Reference.Fact.ServiceName,
		request.Reference.Fact.Image.Repository, request.Reference.Fact.Image.Digest, fmt.Sprint(request.Reference.Fact.Resources), fmt.Sprint(request.Reference.Fact.ContainerPort),
		string(request.Protocol), request.HTTPPath, request.IdempotencyKey, observation.DeploymentID.String(), observation.ServiceName, observation.InternalAddress,
		string(outcome), status, acornFoxProbeErrorCode(outcome),
	} {
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil)), nil
}

func validAcornFoxProbeDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
