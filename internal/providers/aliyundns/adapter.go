// Package aliyundns is a small, dependency-free Alibaba Cloud DNS RPC adapter.
//
// It owns only Alibaba's wire contract.  It deliberately does not know about
// Open Card's DNS-change ledger, ownership rules, or public API.  Callers map
// its opaque provider IDs into their own durable model.
package aliyundns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEndpoint = "https://alidns.aliyuncs.com/"
	APIVersion      = "2015-01-09"

	ActionDescribeDomainRecords = "DescribeDomainRecords"
	ActionAddDomainRecord       = "AddDomainRecord"
	ActionUpdateDomainRecord    = "UpdateDomainRecord"
	ActionDeleteDomainRecord    = "DeleteDomainRecord"

	signatureAlgorithm = "ACS3-HMAC-SHA256"
	maxPageSize        = 500
	maxPages           = 20
	maxResponseBytes   = 1 << 20
	requestTimeout     = 10 * time.Second
)

var (
	// ErrContract means that caller input or adapter configuration is unsafe.
	ErrContract = errors.New("aliyun dns contract validation failed")
	// ErrTransport deliberately does not include endpoints, credentials, or raw
	// provider response bodies.
	ErrTransport = errors.New("aliyun dns operation could not be verified")
)

// Credentials are explicit because credential discovery belongs to a separate,
// reviewed integration layer.  Never log this value.
type Credentials struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

// Record is Alibaba's provider-local representation.  ID is deliberately a
// string: Alibaba record IDs are opaque and must never be narrowed to int64.
type Record struct {
	ID         string
	DomainName string
	RR         string
	Type       string
	Value      string
	TTL        int
	Line       string
}

// CreateRecord carries the fields accepted by AddDomainRecord.
type CreateRecord struct {
	DomainName string
	RR         string
	Type       string
	Value      string
	TTL        int
	Line       string
}

// UpdateRecord carries the fields accepted by UpdateDomainRecord.
type UpdateRecord struct {
	ID    string
	RR    string
	Type  string
	Value string
	TTL   int
	Line  string
}

// WriteReceipt carries only provider identifiers needed for caller-side
// reconciliation.  Update/Delete normally return only RequestID.
type WriteReceipt struct {
	RecordID  string
	RequestID string
}

// DNS is the narrow provider port consumed by the integration layer.
type DNS interface {
	ListRecords(context.Context, string) ([]Record, error)
	CreateRecord(context.Context, CreateRecord) (WriteReceipt, error)
	UpdateRecord(context.Context, UpdateRecord) (WriteReceipt, error)
	DeleteRecord(context.Context, string) (WriteReceipt, error)
}

// Adapter talks to one injected endpoint.  Endpoint injection is solely for
// fake-server tests; production callers use DefaultEndpoint.
type Adapter struct {
	Endpoint    string
	Credentials Credentials
	// Client is optional.  A shallow copy is made per call so this adapter can
	// enforce no redirects even when a caller supplies a custom transport.
	Client *http.Client
	Clock  func() time.Time
	Nonce  func() string
}

var _ DNS = Adapter{}

// ProviderError is an exact, determinate provider rejection.  Its error text
// intentionally excludes Message: callers can inspect the preserved field
// without accidentally emitting arbitrary provider text into logs.
type ProviderError struct {
	HTTPStatus int
	Code       string
	Message    string
	RequestID  string
	HostID     string
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "aliyun dns provider error"
	}
	if e.Code != "" {
		return fmt.Sprintf("aliyun dns provider rejected request (status=%d code=%s request_id=%s)", e.HTTPStatus, e.Code, e.RequestID)
	}
	return fmt.Sprintf("aliyun dns provider rejected request (status=%d request_id=%s)", e.HTTPStatus, e.RequestID)
}

// IndeterminateWriteError means the write may have reached Alibaba Cloud.  The
// caller must reconcile by listing records; this adapter never retries writes.
type IndeterminateWriteError struct{ Action string }

func (e *IndeterminateWriteError) Error() string {
	if e == nil || e.Action == "" {
		return "aliyun dns write outcome is indeterminate; reconcile before retrying"
	}
	return "aliyun dns " + e.Action + " outcome is indeterminate; reconcile before retrying"
}

func (*IndeterminateWriteError) RequiresReconcile() bool { return true }

// ListRecords reads the complete named zone using bounded pagination.
func (a Adapter) ListRecords(ctx context.Context, domainName string) ([]Record, error) {
	domainName = normalizeDomain(domainName)
	if !validDomain(domainName) {
		return nil, ErrContract
	}
	items := make([]Record, 0)
	for page := 1; page <= maxPages; page++ {
		body := map[string]string{
			"DomainName": domainName,
			"PageNumber": strconv.Itoa(page),
			"PageSize":   strconv.Itoa(maxPageSize),
		}
		response, err := a.call(ctx, ActionDescribeDomainRecords, body, false)
		if err != nil {
			return nil, err
		}
		var decoded struct {
			TotalCount    int    `json:"TotalCount"`
			PageNumber    int    `json:"PageNumber"`
			PageSize      int    `json:"PageSize"`
			RequestID     string `json:"RequestId"`
			DomainRecords struct {
				Record []struct {
					ID         string `json:"RecordId"`
					DomainName string `json:"DomainName"`
					RR         string `json:"RR"`
					Type       string `json:"Type"`
					Value      string `json:"Value"`
					TTL        int    `json:"TTL"`
					Line       string `json:"Line"`
				} `json:"Record"`
			} `json:"DomainRecords"`
		}
		if err := json.Unmarshal(response, &decoded); err != nil || decoded.TotalCount < 0 || decoded.PageNumber != page || decoded.PageSize < 0 || decoded.PageSize > maxPageSize || strings.TrimSpace(decoded.RequestID) == "" {
			return nil, ErrTransport
		}
		if decoded.TotalCount < len(items)+len(decoded.DomainRecords.Record) {
			return nil, ErrTransport
		}
		for _, item := range decoded.DomainRecords.Record {
			record := Record{ID: strings.TrimSpace(item.ID), DomainName: normalizeDomain(item.DomainName), RR: normalizeRR(item.RR), Type: normalizeType(item.Type), Value: strings.TrimSpace(item.Value), TTL: item.TTL, Line: normalizeLine(item.Line)}
			if record.DomainName == "" {
				record.DomainName = domainName
			}
			if record.DomainName != domainName || !record.valid() {
				return nil, ErrTransport
			}
			items = append(items, record)
		}
		if len(items) == decoded.TotalCount {
			return items, nil
		}
		if len(decoded.DomainRecords.Record) == 0 {
			return nil, ErrTransport
		}
	}
	return nil, ErrContract
}

func (a Adapter) CreateRecord(ctx context.Context, record CreateRecord) (WriteReceipt, error) {
	if !record.valid() {
		return WriteReceipt{}, ErrContract
	}
	response, err := a.call(ctx, ActionAddDomainRecord, createParams(record), true)
	if err != nil {
		return WriteReceipt{}, err
	}
	var decoded struct {
		RecordID  string `json:"RecordId"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(response, &decoded); err != nil || !validOpaqueID(decoded.RecordID) || strings.TrimSpace(decoded.RequestID) == "" {
		return WriteReceipt{}, &IndeterminateWriteError{Action: ActionAddDomainRecord}
	}
	return WriteReceipt{RecordID: strings.TrimSpace(decoded.RecordID), RequestID: strings.TrimSpace(decoded.RequestID)}, nil
}

func (a Adapter) UpdateRecord(ctx context.Context, record UpdateRecord) (WriteReceipt, error) {
	if !record.valid() {
		return WriteReceipt{}, ErrContract
	}
	params := map[string]string{
		"RecordId": strings.TrimSpace(record.ID), "RR": normalizeRR(record.RR), "Type": normalizeType(record.Type),
		"Value": strings.TrimSpace(record.Value), "TTL": strconv.Itoa(record.TTL), "Line": normalizeLine(record.Line),
	}
	return a.write(ctx, ActionUpdateDomainRecord, params, strings.TrimSpace(record.ID))
}

func (a Adapter) DeleteRecord(ctx context.Context, recordID string) (WriteReceipt, error) {
	if !validOpaqueID(recordID) {
		return WriteReceipt{}, ErrContract
	}
	return a.write(ctx, ActionDeleteDomainRecord, map[string]string{"RecordId": strings.TrimSpace(recordID)}, strings.TrimSpace(recordID))
}

func (a Adapter) write(ctx context.Context, action string, params map[string]string, recordID string) (WriteReceipt, error) {
	response, err := a.call(ctx, action, params, true)
	if err != nil {
		return WriteReceipt{}, err
	}
	var decoded struct {
		RecordID  string `json:"RecordId"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(response, &decoded); err != nil || strings.TrimSpace(decoded.RequestID) == "" {
		return WriteReceipt{}, &IndeterminateWriteError{Action: action}
	}
	if decoded.RecordID != "" && !validOpaqueID(decoded.RecordID) {
		return WriteReceipt{}, &IndeterminateWriteError{Action: action}
	}
	if decoded.RecordID != "" {
		recordID = strings.TrimSpace(decoded.RecordID)
	}
	return WriteReceipt{RecordID: recordID, RequestID: strings.TrimSpace(decoded.RequestID)}, nil
}

func (a Adapter) call(parent context.Context, action string, params map[string]string, write bool) ([]byte, error) {
	endpoint, err := a.endpoint()
	if err != nil || !validAction(action) || !validCredentials(a.Credentials) {
		return nil, ErrContract
	}
	ctx, cancel := context.WithTimeout(parent, requestTimeout)
	defer cancel()
	body := canonicalForm(params)
	req, err := a.signedRequest(ctx, endpoint, action, body)
	if err != nil {
		return nil, ErrContract
	}
	client := http.Client{}
	if a.Client != nil {
		client = *a.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		if write {
			return nil, &IndeterminateWriteError{Action: action}
		}
		return nil, ErrTransport
	}
	if response == nil || response.Body == nil {
		if write {
			return nil, &IndeterminateWriteError{Action: action}
		}
		return nil, ErrTransport
	}
	defer response.Body.Close()
	payload, readErr := boundedRead(response.Body)
	if readErr != nil || response.StatusCode >= 300 && response.StatusCode < 400 {
		if write {
			return nil, &IndeterminateWriteError{Action: action}
		}
		return nil, ErrTransport
	}
	// A 5xx response proves neither that Alibaba applied the write nor that it
	// did not.  Preserve the no-blind-retry rule even when it has a JSON body.
	if write && response.StatusCode >= 500 {
		return nil, &IndeterminateWriteError{Action: action}
	}
	if providerErr := decodeProviderError(response.StatusCode, response.Header, payload, a.Credentials); providerErr != nil {
		return nil, providerErr
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if write {
			return nil, &IndeterminateWriteError{Action: action}
		}
		return nil, ErrTransport
	}
	return payload, nil
}

func (a Adapter) endpoint() (*url.URL, error) {
	value := strings.TrimSpace(a.Endpoint)
	if value == "" {
		value = DefaultEndpoint
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrContract
	}
	return parsed, nil
}

func (a Adapter) signedRequest(ctx context.Context, endpoint *url.URL, action, body string) (*http.Request, error) {
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock().UTC()
	}
	nonce := ""
	if a.Nonce != nil {
		nonce = strings.TrimSpace(a.Nonce())
	}
	if nonce == "" || len(nonce) > 256 || strings.ContainsAny(nonce, "\r\n") {
		return nil, ErrContract
	}
	date := now.Format("2006-01-02T15:04:05Z")
	bodyHash := sha256Hex([]byte(body))
	headers := map[string]string{
		"content-type":          "application/x-www-form-urlencoded",
		"host":                  endpoint.Host,
		"x-acs-action":          action,
		"x-acs-content-sha256":  bodyHash,
		"x-acs-date":            date,
		"x-acs-signature-nonce": nonce,
		"x-acs-version":         APIVersion,
	}
	if token := strings.TrimSpace(a.Credentials.SecurityToken); token != "" {
		headers["x-acs-security-token"] = token
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(normalizeHeaderValue(headers[name]))
		canonicalHeaders.WriteByte('\n')
	}
	path := endpoint.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{http.MethodPost, path, "", canonicalHeaders.String(), strings.Join(names, ";"), bodyHash}, "\n")
	stringToSign := signatureAlgorithm + "\n" + sha256Hex([]byte(canonicalRequest))
	signature := hmacSHA256Hex(a.Credentials.AccessKeySecret, stringToSign)
	authorization := signatureAlgorithm + " Credential=" + strings.TrimSpace(a.Credentials.AccessKeyID) + ",SignedHeaders=" + strings.Join(names, ";") + ",Signature=" + signature
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)
	for name, value := range headers {
		if name == "host" {
			req.Host = value
			continue
		}
		req.Header.Set(name, value)
	}
	return req, nil
}

func decodeProviderError(status int, headers http.Header, payload []byte, credentials Credentials) error {
	var decoded struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
		HostID    string `json:"HostId"`
	}
	_ = json.Unmarshal(payload, &decoded)
	if decoded.RequestID == "" {
		decoded.RequestID = headers.Get("x-acs-request-id")
	}
	if status >= 200 && status <= 299 && decoded.Code == "" {
		return nil
	}
	if decoded.Code != "" || status < 200 || status > 299 {
		return &ProviderError{
			HTTPStatus: status,
			Code:       providerText(decoded.Code, 256, credentials),
			Message:    providerText(decoded.Message, 4096, credentials),
			RequestID:  providerText(decoded.RequestID, 512, credentials),
			HostID:     providerText(decoded.HostID, 512, credentials),
		}
	}
	return nil
}

func canonicalForm(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, percentEncode(key)+"="+percentEncode(params[key]))
	}
	return strings.Join(parts, "&")
}

func percentEncode(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func boundedRead(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes {
		return nil, ErrTransport
	}
	return payload, nil
}

func createParams(record CreateRecord) map[string]string {
	return map[string]string{"DomainName": normalizeDomain(record.DomainName), "RR": normalizeRR(record.RR), "Type": normalizeType(record.Type), "Value": strings.TrimSpace(record.Value), "TTL": strconv.Itoa(record.TTL), "Line": normalizeLine(record.Line)}
}

func (r Record) valid() bool {
	return validOpaqueID(r.ID) && validDomain(r.DomainName) && validRR(r.RR) && validType(r.Type) && validValue(r.Value) && validTTL(r.TTL) && validLine(r.Line)
}

func (r CreateRecord) valid() bool {
	return validDomain(normalizeDomain(r.DomainName)) && validRR(normalizeRR(r.RR)) && validType(normalizeType(r.Type)) && validValue(r.Value) && validTTL(r.TTL) && validLine(normalizeLine(r.Line))
}

func (r UpdateRecord) valid() bool {
	return validOpaqueID(r.ID) && validRR(normalizeRR(r.RR)) && validType(normalizeType(r.Type)) && validValue(r.Value) && validTTL(r.TTL) && validLine(normalizeLine(r.Line))
}

func validCredentials(value Credentials) bool {
	return validOpaqueID(value.AccessKeyID) && validOpaqueID(value.AccessKeySecret) && (value.SecurityToken == "" || validOpaqueID(value.SecurityToken))
}

func validAction(value string) bool {
	return value == ActionDescribeDomainRecords || value == ActionAddDomainRecord || value == ActionUpdateDomainRecord || value == ActionDeleteDomainRecord
}

func validDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " /\\@:*\t\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

func validRR(value string) bool {
	return value != "" && len(value) <= 253 && !strings.ContainsAny(value, " \t\r\n")
}

func validType(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if char < 'A' || char > 'Z' {
			return false
		}
	}
	return true
}

func validValue(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 1024 && !strings.ContainsAny(value, "\r\n")
}
func validTTL(value int) bool { return value >= 1 && value <= 604800 }
func validLine(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n")
}
func validOpaqueID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\r\n")
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}
func normalizeRR(value string) string   { return strings.TrimSpace(value) }
func normalizeType(value string) string { return strings.ToUpper(strings.TrimSpace(value)) }
func normalizeLine(value string) string {
	if strings.TrimSpace(value) == "" {
		return "default"
	}
	return strings.TrimSpace(value)
}
func normalizeHeaderValue(value string) string { return strings.Join(strings.Fields(value), " ") }
func sha256Hex(value []byte) string            { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func hmacSHA256Hex(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

// providerText keeps the usable provider diagnostic while removing the only
// secret values this adapter knows.  It is applied to every provider-controlled
// field that may later be surfaced through an error or receipt.
func providerText(value string, max int, credentials Credentials) string {
	value = boundedText(value, max)
	for _, secret := range []string{strings.TrimSpace(credentials.AccessKeyID), strings.TrimSpace(credentials.AccessKeySecret), strings.TrimSpace(credentials.SecurityToken)} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}
