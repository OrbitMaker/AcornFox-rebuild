package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxobserver"
)

type accessObserver interface {
	Observe(context.Context, string, string) acornfoxobserver.Report
}
type apiAccessObservation struct {
	Observer      string                     `json:"observer"`
	ApplicationID string                     `json:"application_id"`
	DeploymentID  string                     `json:"deployment_id"`
	Hostname      string                     `json:"hostname"`
	ReportID      string                     `json:"report_id"`
	ObservedAt    time.Time                  `json:"observed_at"`
	ReceivedAt    time.Time                  `json:"received_at"`
	ExpiresAt     time.Time                  `json:"expires_at"`
	DNS           acornfoxobserver.DNSFact   `json:"dns"`
	TLS           acornfoxobserver.TLSFact   `json:"tls"`
	HTTPS         acornfoxobserver.HTTPSFact `json:"https"`
}
type apiAccessObservationWrapper struct {
	Availability string                `json:"availability"`
	Observation  *apiAccessObservation `json:"observation,omitempty"`
}

const (
	accessObservationProbeBudget  = 30 * time.Second
	accessObservationReportBudget = 10 * time.Second
)

func (c *cli) publicAccessCheck(args []string) error {
	observer, err := acornfoxobserver.New(acornfoxobserver.Config{})
	if err != nil {
		return errors.New("external observer unavailable")
	}
	return c.publicAccessCheckWithObserver(args, observer)
}

// publicAccessObservation reads only the server's stored administrator-client
// fact. It never resolves DNS, opens the public URL, or submits a report.
func (c *cli) publicAccessObservation(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox public-access observation APP_ID DEPLOYMENT_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	c.secrets = append(c.secrets, state.Session, state.CSRF)
	ctx, cancel := context.WithTimeout(context.Background(), acornfoxobserver.ObservationTimeout)
	defer cancel()
	path := "/apps/" + pathID(app) + "/deliveries/" + pathID(deployment) + "/access-observation"
	value, err := c.accessControlCall(ctx, state, http.MethodGet, path, nil, false, http.StatusOK)
	if err != nil {
		return err
	}
	view, ok := value.(apiAccessObservationWrapper)
	if !ok || !validateAccessObservationWrapper(view, app, deployment) {
		return invalidResponse("server response does not match the access observation contract")
	}
	return c.emit(view)
}
func (c *cli) publicAccessCheckWithObserver(args []string, observer accessObserver) error {
	return c.publicAccessCheckWithBudgets(args, observer, accessObservationProbeBudget, accessObservationReportBudget)
}

// publicAccessCheckWithBudgets keeps observation and reporting in separate
// bounded phases. A probe that consumes its full budget can still submit the
// resulting timeout fact; the normal end-to-end ceiling is 40 seconds.
func (c *cli) publicAccessCheckWithBudgets(args []string, observer accessObserver, probeBudget, reportBudget time.Duration) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox public-access check APP_ID DEPLOYMENT_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	c.secrets = append(c.secrets, state.Session, state.CSRF)
	if probeBudget <= 0 || probeBudget > accessObservationProbeBudget || reportBudget <= 0 || reportBudget > accessObservationReportBudget {
		return errors.New("external observation budget is invalid")
	}
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), probeBudget)
	publicPath := "/apps/" + pathID(app) + "/deliveries/" + pathID(deployment) + "/public-access"
	value, err := c.accessControlCall(probeCtx, state, http.MethodGet, publicPath, nil, false, http.StatusOK)
	if err != nil {
		cancelProbe()
		return err
	}
	publicAccess, ok := value.(apiPublicAccess)
	if !ok || publicAccess.DesiredPublic == nil || !*publicAccess.DesiredPublic || publicAccess.Endpoint.DeploymentID != deployment {
		cancelProbe()
		return apiError{status: http.StatusConflict, Code: "public_access_not_enabled", Message: "public access is not enabled for this deployment"}
	}
	if err = acornfoxobserver.ValidateTarget(publicAccess.URL); err != nil {
		cancelProbe()
		return invalidResponse("public access URL is not an exact HTTPS root")
	}
	reportKey, err := generatedKey()
	if err != nil {
		cancelProbe()
		return apiError{network: true, Code: "observer_unavailable", Message: "external observer unavailable"}
	}
	report := observer.Observe(probeCtx, "access_report_"+reportKey, publicAccess.URL)
	cancelProbe()
	observationPath := "/apps/" + pathID(app) + "/deliveries/" + pathID(deployment) + "/access-observation"
	reportCtx, cancelReport := context.WithTimeout(context.Background(), reportBudget)
	defer cancelReport()
	var response any
	for attempt := 0; attempt < 2; attempt++ {
		response, err = c.accessControlCall(reportCtx, state, http.MethodPost, observationPath, report, true, http.StatusCreated, http.StatusOK)
		if err == nil {
			break
		}
		var apiErr apiError
		if !errors.As(err, &apiErr) || !apiErr.network {
			break
		}
	}
	if err != nil {
		return err
	}
	observation, ok := response.(apiAccessObservation)
	parsed, _ := url.Parse(publicAccess.URL)
	if !ok || !validateAccessObservation(observation, app, deployment, strings.ToLower(parsed.Hostname()), report) {
		return invalidResponse("server response does not match the access observation contract")
	}
	return c.emit(observation)
}

func (c *cli) accessControlCall(ctx context.Context, state sessionState, method, path string, body any, csrf bool, success ...int) (any, error) {
	response, err := c.request(ctx, state, method, path, body, csrf, "", acornfoxobserver.ObservationTimeout)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, status := range success {
		if response.StatusCode == status {
			allowed = true
		}
	}
	if !allowed {
		if response.StatusCode == http.StatusUnauthorized {
			if removeErr := removeState(c.env); removeErr != nil {
				response.Body.Close()
				return nil, localStateError()
			}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, decodeError(response)
		}
		response.Body.Close()
		return nil, invalidResponse("server response used an unexpected success status")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxResponseBytes {
		return nil, invalidResponse("server response is invalid")
	}
	if method == http.MethodGet && strings.HasSuffix(path, "/public-access") {
		return decodeResponse(bytes.NewReader(data), shapePublicAccess)
	}
	if method == http.MethodGet && strings.HasSuffix(path, "/access-observation") {
		var view apiAccessObservationWrapper
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&view) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return nil, invalidResponse("server response does not match the access observation contract")
		}
		return view, nil
	}
	var observation apiAccessObservation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observation) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, invalidResponse("server response does not match the access observation contract")
	}
	return observation, nil
}

func validateAccessObservation(value apiAccessObservation, app, deployment, hostname string, report acornfoxobserver.Report) bool {
	if !validateStoredAccessObservation(value, app, deployment) || value.Hostname != hostname || value.ReportID != report.ReportID || !value.ObservedAt.Equal(report.ObservedAt) || !reflect.DeepEqual(value.DNS, report.DNS) || !reflect.DeepEqual(value.TLS, report.TLS) || !reflect.DeepEqual(value.HTTPS, report.HTTPS) {
		return false
	}
	return true
}
func validateAccessObservationWrapper(view apiAccessObservationWrapper, app, deployment string) bool {
	switch view.Availability {
	case "not_observed":
		return view.Observation == nil
	case "available", "expired":
		return view.Observation != nil && validateStoredAccessObservation(*view.Observation, app, deployment)
	default:
		return false
	}
}
func validateStoredAccessObservation(value apiAccessObservation, app, deployment string) bool {
	if value.Observer != "administrator_client" || value.ApplicationID != app || value.DeploymentID != deployment || !validObservationHostname(value.Hostname) || !validReportID(value.ReportID) || value.ObservedAt.IsZero() || value.ReceivedAt.IsZero() || value.ExpiresAt.IsZero() || !value.ExpiresAt.Equal(value.ReceivedAt.Add(5*time.Minute)) {
		return false
	}
	return validAccessLayers(value.DNS, value.TLS, value.HTTPS)
}
func validObservationHostname(host string) bool {
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "/: \\%\r\n\t") {
		return false
	}
	parsed, err := url.Parse("https://" + host + "/")
	return err == nil && parsed.Hostname() == host && parsed.Port() == ""
}
func validReportID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
func validAccessLayers(dns acornfoxobserver.DNSFact, tlsFact acornfoxobserver.TLSFact, https acornfoxobserver.HTTPSFact) bool {
	dnsOK := dns.State == acornfoxobserver.DNSObserved && len(dns.Addresses) > 0 && dns.FailureCode == "" || dns.State == acornfoxobserver.DNSFailed && len(dns.Addresses) == 0 && oneOf(dns.FailureCode, acornfoxobserver.DNSNoAnswer, acornfoxobserver.DNSTimeout, acornfoxobserver.DNSLookupFailed)
	if !dnsOK {
		return false
	}
	tlsOK := tlsFact.State == acornfoxobserver.LayerObserved && lowerSHA256(tlsFact.CertificateSHA256) && tlsFact.FailureCode == "" || tlsFact.State == acornfoxobserver.LayerFailed && tlsFact.CertificateSHA256 == "" && oneOf(tlsFact.FailureCode, acornfoxobserver.TLSConnectFailed, acornfoxobserver.TLSNameMismatch, acornfoxobserver.TLSCertificateInvalid, acornfoxobserver.TLSTimeout) || tlsFact.State == acornfoxobserver.LayerNotAttempted && tlsFact.CertificateSHA256 == "" && tlsFact.FailureCode == ""
	if !tlsOK {
		return false
	}
	httpsOK := https.State == acornfoxobserver.LayerObserved && https.HTTPStatus != nil && https.ResponseSampleBytes != nil && *https.ResponseSampleBytes >= 0 && *https.ResponseSampleBytes <= acornfoxobserver.ResponseSampleLimit && lowerSHA256(https.ResponseSampleSHA256) && https.ResponseTruncated != nil && https.FailureCode == "" || https.State == acornfoxobserver.LayerFailed && https.HTTPStatus == nil && https.ResponseSampleBytes == nil && https.ResponseSampleSHA256 == "" && https.ResponseTruncated == nil && oneOf(https.FailureCode, acornfoxobserver.HTTPSTimeout, acornfoxobserver.HTTPSTransportFailed) || https.State == acornfoxobserver.LayerNotAttempted && https.HTTPStatus == nil && https.ResponseSampleBytes == nil && https.ResponseSampleSHA256 == "" && https.ResponseTruncated == nil && https.FailureCode == ""
	if !httpsOK {
		return false
	}
	if dns.State == acornfoxobserver.DNSFailed {
		return tlsFact.State == acornfoxobserver.LayerNotAttempted && https.State == acornfoxobserver.LayerNotAttempted
	}
	if tlsFact.State == acornfoxobserver.LayerFailed {
		return https.State == acornfoxobserver.LayerNotAttempted
	}
	return true
}
func lowerSHA256(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}
func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
