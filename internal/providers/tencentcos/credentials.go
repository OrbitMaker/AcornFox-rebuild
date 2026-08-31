package tencentcos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const (
	metadataHost       = "metadata.tencentyun.com"
	metadataPort       = "80"
	metadataPathPrefix = "/latest/meta-data/cam/security-credentials/"
	metadataBodyLimit  = 16 << 10
	credentialMaxSize  = 4 << 10
	credentialRefresh  = 5 * time.Minute
)

var (
	// ErrCredentialsUnavailable deliberately carries no role, endpoint, response,
	// or credential detail. It is the only non-cancellation error from this
	// metadata boundary.
	ErrCredentialsUnavailable = errors.New("tencent cos credentials unavailable")
	ErrCredentialUnavailable  = ErrCredentialsUnavailable
)

// HTTPDoer is the narrow HTTP dependency used by task-only construction. The
// requested endpoint remains fixed even when a test injects its own doer.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// CredentialMaterial holds one caller-owned copy of temporary credentials.
// Its unexported pointer state keeps copied values synchronized and redacted.
type CredentialMaterial struct {
	state *credentialMaterialState
}

// Credentials is a concise synonym for CredentialMaterial for future COS SDK
// wiring. It intentionally has the same opaque representation.
type Credentials = CredentialMaterial

type credentialMaterialState struct {
	mu         sync.Mutex
	id         []byte
	key        []byte
	token      []byte
	expiration time.Time
	destroyed  bool
}

// WithCredentials lends independent, transient copies to callback. The copies
// are zeroed after callback returns, including when it returns an error.
func (m CredentialMaterial) WithCredentials(callback func(id, key, token []byte) error) error {
	if m.state == nil || callback == nil {
		return ErrCredentialsUnavailable
	}
	m.state.mu.Lock()
	if m.state.destroyed {
		m.state.mu.Unlock()
		return ErrCredentialsUnavailable
	}
	id := append([]byte(nil), m.state.id...)
	key := append([]byte(nil), m.state.key...)
	token := append([]byte(nil), m.state.token...)
	m.state.mu.Unlock()
	defer zeroCredentials(id)
	defer zeroCredentials(key)
	defer zeroCredentials(token)
	return callback(id, key, token)
}

// Expiration returns the precise temporary-credential expiry without exposing
// credential material.
func (m CredentialMaterial) Expiration() (time.Time, error) {
	if m.state == nil {
		return time.Time{}, ErrCredentialsUnavailable
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	if m.state.destroyed {
		return time.Time{}, ErrCredentialsUnavailable
	}
	return m.state.expiration, nil
}

// Destroy is idempotent and only destroys this caller-owned material copy.
func (m CredentialMaterial) Destroy() {
	if m.state == nil {
		return
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	zeroCredentials(m.state.id)
	zeroCredentials(m.state.key)
	zeroCredentials(m.state.token)
	m.state.id = nil
	m.state.key = nil
	m.state.token = nil
	m.state.destroyed = true
}

func (CredentialMaterial) String() string   { return "tencent-cos-credential-material(redacted)" }
func (CredentialMaterial) GoString() string { return "tencentcos.CredentialMaterial(redacted)" }
func (CredentialMaterial) MarshalJSON() ([]byte, error) {
	return json.Marshal("tencent_cos_credential_material_redacted")
}

// CredentialProvider obtains only the role named by the installed backup
// profile. It is not a COS signer and makes no COS request.
type CredentialProvider struct {
	state *credentialProviderState
}

// The mutable provider state is intentionally one pointer behind the public
// value. Copies of CredentialProvider share one cache, flight, close state, and
// synchronization boundary without making their internals printable.
type credentialProviderState struct {
	mu      sync.Mutex
	profile install.BackupRoleProfileV1
	doer    HTTPDoer
	now     func() time.Time
	cache   cachedCredentials
	flight  *credentialFlight
	closed  bool
}

type credentialFlight struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	err    error
}

// Provider and CVMRoleCredentialProvider name the same narrowly-scoped
// temporary credential provider.
type Provider = CredentialProvider
type CVMRoleCredentialProvider = CredentialProvider

type cachedCredentials struct {
	id         []byte
	key        []byte
	token      []byte
	expiration time.Time
}

// NewProductionCredentialProvider reads only the fixed root-owned profile and
// uses the fixed Tencent CVM metadata endpoint. It accepts no caller-supplied
// paths, endpoint, environment, or transport.
func NewProductionCredentialProvider() (*CredentialProvider, error) {
	reader, err := install.ProductionBackupConfigReader()
	if err != nil {
		return nil, ErrCredentialsUnavailable
	}
	profile, err := reader.ReadRoleProfile()
	if err != nil {
		return nil, ErrCredentialsUnavailable
	}
	return newCredentialProvider(profile, newMetadataHTTPClient(defaultMetadataResolver, defaultMetadataDial), time.Now)
}

// NewProductionCVMRoleCredentialProvider is the explicit production-name
// entrypoint for callers that avoid the generic temporary-credential name.
func NewProductionCVMRoleCredentialProvider() (*CredentialProvider, error) {
	return NewProductionCredentialProvider()
}

// NewTaskCredentialProvider constructs the same fixed-endpoint provider with
// explicit test dependencies. It never accepts an endpoint override.
func NewTaskCredentialProvider(profile install.BackupRoleProfileV1, doer HTTPDoer, now func() time.Time) (*CredentialProvider, error) {
	return newCredentialProvider(profile, doer, now)
}

// NewTaskCVMRoleCredentialProvider is the explicit task-name entrypoint.
func NewTaskCVMRoleCredentialProvider(profile install.BackupRoleProfileV1, doer HTTPDoer, now func() time.Time) (*CredentialProvider, error) {
	return NewTaskCredentialProvider(profile, doer, now)
}

func newCredentialProvider(profile install.BackupRoleProfileV1, doer HTTPDoer, now func() time.Time) (*CredentialProvider, error) {
	if profile.Validate() != nil || doer == nil || now == nil {
		return nil, ErrCredentialsUnavailable
	}
	return &CredentialProvider{state: &credentialProviderState{profile: profile, doer: doer, now: now}}, nil
}

// Credentials returns a new caller-owned material copy. Concurrent cache
// misses coalesce into one provider-owned metadata request. Every caller,
// including the caller that starts the request, only waits on that request;
// canceling a caller never cancels a live waiter's shared acquisition.
func (p CredentialProvider) Credentials(ctx context.Context) (CredentialMaterial, error) {
	if p.state == nil || ctx == nil {
		return CredentialMaterial{}, ErrCredentialsUnavailable
	}
	if err := ctx.Err(); err != nil {
		return CredentialMaterial{}, err
	}
	state := p.state
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return CredentialMaterial{}, ErrCredentialsUnavailable
	}
	if state.cache.validAt(state.now()) {
		material := state.cache.material()
		state.mu.Unlock()
		return material, nil
	}
	flight := state.flight
	if flight == nil {
		flightContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		flight = &credentialFlight{ctx: flightContext, cancel: cancel, done: make(chan struct{})}
		state.flight = flight
		go p.runFlight(flight)
	}
	state.mu.Unlock()

	select {
	case <-ctx.Done():
		return CredentialMaterial{}, ctx.Err()
	case <-flight.done:
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || flight.err != nil {
		return CredentialMaterial{}, ErrCredentialsUnavailable
	}
	if !state.cache.validAt(state.now()) {
		return CredentialMaterial{}, ErrCredentialsUnavailable
	}
	return state.cache.material(), nil
}

// Get and Retrieve are aliases for the single credential acquisition path.
func (p CredentialProvider) Get(ctx context.Context) (CredentialMaterial, error) {
	return p.Credentials(ctx)
}

func (p CredentialProvider) Retrieve(ctx context.Context) (CredentialMaterial, error) {
	return p.Credentials(ctx)
}

// Close erases cached credentials and permanently disables the provider.
func (p CredentialProvider) Close() error {
	if p.state == nil {
		return nil
	}
	state := p.state
	state.mu.Lock()
	state.cache.destroy()
	state.closed = true
	flight := state.flight
	state.mu.Unlock()
	if flight != nil {
		flight.cancel()
		p.completeFlight(flight, cachedCredentials{}, ErrCredentialsUnavailable)
	}
	return nil
}

func (CredentialProvider) String() string   { return "tencent-cos-credential-provider(redacted)" }
func (CredentialProvider) GoString() string { return "tencentcos.CredentialProvider(redacted)" }
func (CredentialProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal("tencent_cos_credential_provider_redacted")
}

func (p CredentialProvider) runFlight(flight *credentialFlight) {
	fetched, err := p.fetch(flight.ctx)
	p.completeFlight(flight, fetched, err)
}

func (p CredentialProvider) completeFlight(flight *credentialFlight, fetched cachedCredentials, err error) {
	if p.state == nil || flight == nil {
		fetched.destroy()
		return
	}
	completed := false
	flight.once.Do(func() {
		completed = true
		state := p.state
		state.mu.Lock()
		defer state.mu.Unlock()
		if err != nil || state.closed {
			fetched.destroy()
			flight.err = ErrCredentialsUnavailable
		} else {
			state.cache.destroy()
			state.cache = fetched
			fetched = cachedCredentials{}
			flight.err = nil
		}
		if state.flight == flight {
			state.flight = nil
		}
		flight.cancel()
		close(flight.done)
	})
	if !completed {
		fetched.destroy()
	}
}

func (p CredentialProvider) fetch(ctx context.Context) (cachedCredentials, error) {
	if p.state == nil {
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	state := p.state
	requestURL := "http://" + metadataHost + metadataPathPrefix + url.PathEscape(state.profile.RoleName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil || req.URL.Scheme != "http" || req.URL.Host != metadataHost || req.URL.Port() != "" || req.URL.Path != metadataPathPrefix+url.PathEscape(state.profile.RoleName) || req.URL.RawQuery != "" || req.URL.Fragment != "" {
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	response, err := state.doer.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return cachedCredentials{}, ctx.Err()
		}
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	if response == nil || response.Body == nil {
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, metadataBodyLimit+1))
	if err != nil || len(raw) > metadataBodyLimit {
		zeroCredentials(raw)
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	defer zeroCredentials(raw)
	parsed, err := parseMetadataCredentials(raw, state.now())
	if err != nil {
		return cachedCredentials{}, ErrCredentialsUnavailable
	}
	return parsed, nil
}

func (c cachedCredentials) validAt(now time.Time) bool {
	return len(c.id) != 0 && len(c.key) != 0 && len(c.token) != 0 && c.expiration.After(now.Add(credentialRefresh))
}

func (c cachedCredentials) material() CredentialMaterial {
	return CredentialMaterial{state: &credentialMaterialState{
		id:         append([]byte(nil), c.id...),
		key:        append([]byte(nil), c.key...),
		token:      append([]byte(nil), c.token...),
		expiration: c.expiration,
	}}
}

func (c *cachedCredentials) destroy() {
	if c == nil {
		return
	}
	zeroCredentials(c.id)
	zeroCredentials(c.key)
	zeroCredentials(c.token)
	c.id = nil
	c.key = nil
	c.token = nil
	c.expiration = time.Time{}
}

func parseMetadataCredentials(raw []byte, now time.Time) (cachedCredentials, error) {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return cachedCredentials{}, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	fields = make(map[string]json.RawMessage, 6)
	defer func() {
		for _, value := range fields {
			zeroCredentials(value)
		}
	}()
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return cachedCredentials{}, err
		}
		name, ok := key.(string)
		if !ok {
			return cachedCredentials{}, errors.New("invalid metadata response")
		}
		switch name {
		case "TmpSecretId", "TmpSecretKey", "ExpiredTime", "Expiration", "Token", "Code":
		default:
			return cachedCredentials{}, errors.New("invalid metadata response")
		}
		if _, duplicate := fields[name]; duplicate {
			return cachedCredentials{}, errors.New("invalid metadata response")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return cachedCredentials{}, errors.New("invalid metadata response")
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return cachedCredentials{}, err
	}
	if decoder.More() {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	if err := requireMetadataEOF(decoder); err != nil {
		return cachedCredentials{}, err
	}
	if len(fields) != 6 {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}

	id, err := strictJSONString(fields["TmpSecretId"])
	if err != nil || !validCredentialText(id) {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	key, err := strictJSONString(fields["TmpSecretKey"])
	if err != nil || !validCredentialText(key) {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	token, err := strictJSONString(fields["Token"])
	if err != nil || !validCredentialText(token) {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	code, err := strictJSONString(fields["Code"])
	if err != nil || code != "Success" {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	expiredTime, err := strictJSONInt64(fields["ExpiredTime"])
	if err != nil || expiredTime <= 0 {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	expirationText, err := strictJSONString(fields["Expiration"])
	if err != nil {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	expiration, err := time.Parse(time.RFC3339, expirationText)
	if err != nil || !expiration.Equal(time.Unix(expiredTime, 0)) || !expiration.After(now.Add(credentialRefresh)) {
		return cachedCredentials{}, errors.New("invalid metadata response")
	}
	return cachedCredentials{id: []byte(id), key: []byte(key), token: []byte(token), expiration: expiration}, nil
}

func requireMetadataEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing metadata response")
		}
		return err
	}
	return nil
}

func strictJSONString(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", errors.New("invalid metadata response")
	}
	return value, nil
}

func strictJSONInt64(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || bytes.ContainsAny(raw, ".eE") {
		return 0, errors.New("invalid metadata response")
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, errors.New("invalid metadata response")
	}
	return value, nil
}

func validCredentialText(value string) bool {
	if len(value) == 0 || len(value) > credentialMaxSize {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func zeroCredentials(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type metadataResolver func(context.Context, string) ([]net.IPAddr, error)
type metadataDial func(context.Context, string, string) (net.Conn, error)

func defaultMetadataResolver(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func defaultMetadataDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
}

// newMetadataHTTPClient is intentionally injectable only inside this package
// so tests can prove link-local pinning without making an external request.
func newMetadataHTTPClient(resolve metadataResolver, dial metadataDial) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || host != metadataHost || port != metadataPort || resolve == nil || dial == nil {
				return nil, ErrCredentialsUnavailable
			}
			addresses, err := resolve(ctx, metadataHost)
			if err != nil || len(addresses) == 0 {
				return nil, ErrCredentialsUnavailable
			}
			for _, candidate := range addresses {
				if !validMetadataAddress(candidate.IP) {
					return nil, ErrCredentialsUnavailable
				}
			}
			return dial(ctx, network, net.JoinHostPort(addresses[0].IP.String(), metadataPort))
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validMetadataAddress(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && ip.To4().Equal(ip) && ip.IsLinkLocalUnicast()
}
