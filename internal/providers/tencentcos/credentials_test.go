package tencentcos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

type credentialDoer struct {
	do func(*http.Request) (*http.Response, error)
}

func (d credentialDoer) Do(request *http.Request) (*http.Response, error) {
	return d.do(request)
}

func testRoleProfile() install.BackupRoleProfileV1 {
	return install.BackupRoleProfileV1{SchemaVersion: 1, RoleName: "OpenCardBackupRole_1"}
}

func metadataSuccess(now time.Time) []byte {
	expires := now.Add(10 * time.Minute).UTC().Truncate(time.Second)
	return []byte(fmt.Sprintf(`{"TmpSecretId":"id-test","TmpSecretKey":"key-test","ExpiredTime":%d,"Expiration":"%s","Token":"token-test","Code":"Success"}`, expires.Unix(), expires.Format(time.RFC3339)))
}

func response(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
}

func TestCredentialProviderUsesOnlyFixedMetadataRequest(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Host != metadataHost || request.URL.Port() != "" || request.URL.Path != metadataPathPrefix+"OpenCardBackupRole_1" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
			t.Fatalf("unsafe metadata request: %#v", request.URL)
		}
		if request.Host != metadataHost {
			t.Fatalf("request host = %q", request.Host)
		}
		return response(http.StatusOK, metadataSuccess(now)), nil
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	material, err := provider.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if expiry, err := material.Expiration(); err != nil || !expiry.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("expiration = %v, %v", expiry, err)
	}
}

func TestMetadataResponseStrictness(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	valid := metadataSuccess(now)
	for name, raw := range map[string][]byte{
		"unknown":         []byte(`{"TmpSecretId":"id","TmpSecretKey":"key","ExpiredTime":178815? ,"Expiration":"x","Token":"token","Code":"Success","Extra":"no"}`),
		"duplicate":       []byte(`{"TmpSecretId":"id","TmpSecretId":"again","TmpSecretKey":"key","ExpiredTime":178815? ,"Expiration":"x","Token":"token","Code":"Success"}`),
		"missing":         []byte(`{"TmpSecretId":"id","TmpSecretKey":"key","ExpiredTime":1,"Expiration":"1970-01-01T00:00:01Z","Token":"token"}`),
		"null":            []byte(`{"TmpSecretId":null,"TmpSecretKey":"key","ExpiredTime":1,"Expiration":"1970-01-01T00:00:01Z","Token":"token","Code":"Success"}`),
		"trailing":        append(append([]byte(nil), valid...), []byte(` {}`)...),
		"not success":     bytes.Replace(valid, []byte(`"Success"`), []byte(`"Failure"`), 1),
		"fractional unix": bytes.Replace(valid, []byte(fmt.Sprintf(`%d`, now.Add(10*time.Minute).Unix())), []byte(`1780000000.0`), 1),
		"mismatch":        bytes.Replace(valid, []byte(now.Add(10*time.Minute).UTC().Truncate(time.Second).Format(time.RFC3339)), []byte(`2026-08-31T05:00:01Z`), 1),
		"too soon":        []byte(`{"TmpSecretId":"id","TmpSecretKey":"key","ExpiredTime":1788120240,"Expiration":"2026-08-31T04:04:00Z","Token":"token","Code":"Success"}`),
		"control secret":  bytes.Replace(valid, []byte(`"token-test"`), []byte(`"token\n"`), 1),
		"empty secret":    bytes.Replace(valid, []byte(`"id-test"`), []byte(`""`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMetadataCredentials(raw, now); err == nil {
				t.Fatalf("accepted invalid response %q", raw)
			}
		})
	}
	if _, err := parseMetadataCredentials(valid, now); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
}

func TestCredentialProviderCachesRefreshesAndCoalesces(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	calls := 0
	started := make(chan struct{})
	release := make(chan struct{})
	provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(*http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			close(started)
			<-release
		}
		return response(http.StatusOK, metadataSuccess(now)), nil
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const callers = 12
	results := make(chan error, callers)
	for range callers {
		go func() {
			material, err := provider.Get(context.Background())
			if err == nil {
				err = material.WithCredentials(func(id, key, token []byte) error {
					if string(id) != "id-test" || string(key) != "key-test" || string(token) != "token-test" {
						return errors.New("incorrect credentials")
					}
					return nil
				})
			}
			results <- err
		}()
	}
	<-started
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if calls != 1 {
		t.Fatalf("metadata calls = %d, want 1", calls)
	}
	mu.Unlock()
	first, err := provider.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()
	if err := second.WithCredentials(func(id, key, token []byte) error {
		if string(id) != "id-test" || string(key) != "key-test" || string(token) != "token-test" {
			return errors.New("material copies are not independent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("metadata calls after refresh = %d, want 2", calls)
	}
}

func TestCredentialProviderFailureBoundariesAndClose(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	for name, do := range map[string]func(*http.Request) (*http.Response, error){
		"status": func(*http.Request) (*http.Response, error) {
			return response(http.StatusForbidden, []byte("forbidden")), nil
		},
		"oversize": func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, bytes.Repeat([]byte("x"), metadataBodyLimit+1)), nil
		},
		"timeout": func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded },
	} {
		t.Run(name, func(t *testing.T) {
			provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: do}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Credentials(context.Background()); !errors.Is(err, ErrCredentialsUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Credentials(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	provider, err = NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, metadataSuccess(now)), nil
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	provider.state.mu.Lock()
	cacheEmpty := len(provider.state.cache.id) == 0 && len(provider.state.cache.key) == 0 && len(provider.state.cache.token) == 0
	provider.state.mu.Unlock()
	if !cacheEmpty {
		t.Fatal("close did not erase provider cache")
	}
	if _, err := provider.Credentials(context.Background()); !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("closed provider error = %v", err)
	}
}

func TestCredentialMaterialRedactionAndTransientZeroing(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	parsed, err := parseMetadataCredentials(metadataSuccess(now), now)
	if err != nil {
		t.Fatal(err)
	}
	material := parsed.material()
	var id, key, token []byte
	if err := material.WithCredentials(func(gotID, gotKey, gotToken []byte) error {
		id, key, token = gotID, gotKey, gotToken
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, transient := range [][]byte{id, key, token} {
		for _, value := range transient {
			if value != 0 {
				t.Fatal("transient credentials were not erased")
			}
		}
	}
	value := material
	for _, candidate := range []any{material, &material, value, &value} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(verb, candidate)
			if strings.Contains(printed, "id-test") || strings.Contains(printed, "key-test") || strings.Contains(printed, "token-test") || strings.Contains(printed, "credentialMaterialState") {
				t.Fatalf("format %q leaked material: %q", verb, printed)
			}
		}
		raw, err := json.Marshal(candidate)
		if err != nil || string(raw) != `"tencent_cos_credential_material_redacted"` {
			t.Fatalf("json = %s, %v", raw, err)
		}
	}
	material.Destroy()
	material.Destroy()
	if _, err := material.Expiration(); !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("destroyed expiration = %v", err)
	}
}

func TestCredentialProviderRedactionAndLeaderCancellationSingleFlight(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		close(started)
		select {
		case <-release:
			return response(http.StatusOK, metadataSuccess(now)), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	value := *provider
	for _, candidate := range []any{provider, value, &value} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(verb, candidate)
			for _, forbidden := range []string{"OpenCardBackupRole_1", "credentialProviderState", "cachedCredentials", "profile", "state"} {
				if strings.Contains(printed, forbidden) {
					t.Fatalf("format %q leaked provider internals: %q", verb, printed)
				}
			}
		}
		raw, err := json.Marshal(candidate)
		if err != nil || string(raw) != `"tencent_cos_credential_provider_redacted"` {
			t.Fatalf("provider json = %s, %v", raw, err)
		}
	}

	leaderContext, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderResult := make(chan error, 1)
	go func() {
		_, err := provider.Credentials(leaderContext)
		leaderResult <- err
	}()
	<-started
	liveResult := make(chan error, 1)
	go func() {
		material, err := provider.Credentials(context.Background())
		if err == nil {
			err = material.WithCredentials(func(id, key, token []byte) error {
				if string(id) != "id-test" || string(key) != "key-test" || string(token) != "token-test" {
					return errors.New("live waiter received wrong credentials")
				}
				return nil
			})
		}
		liveResult <- err
	}()
	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader cancellation = %v", err)
	}
	close(release)
	if err := <-liveResult; err != nil {
		t.Fatalf("live waiter = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("metadata calls = %d, want one shared flight", calls)
	}
}

func TestCredentialProviderCloseCancelsAndCompletesInFlight(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	canceled := make(chan struct{})
	provider, err := NewTaskCredentialProvider(testRoleProfile(), credentialDoer{do: func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		close(canceled)
		return nil, request.Context().Err()
	}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := provider.Credentials(context.Background())
		result <- err
	}()
	<-started
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("closed in-flight result = %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel the provider-owned flight")
	}
}

func TestMetadataHTTPClientPinsLinkLocalAddressAndRejectsRedirect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	var mu sync.Mutex
	dialed := make([]string, 0, 2)
	client := newMetadataHTTPClient(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.100.10")}}, nil
	}, func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			request, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err != nil {
				return
			}
			if request.Host != metadataHost || request.URL.Path != metadataPathPrefix+"OpenCardBackupRole_1" {
				return
			}
			_, _ = io.WriteString(serverConn, "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}()
		return clientConn, nil
	})
	request, err := http.NewRequest(http.MethodGet, "http://"+metadataHost+metadataPathPrefix+"OpenCardBackupRole_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d", result.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 1 || dialed[0] != "169.254.100.10:80" {
		t.Fatalf("dial targets = %v", dialed)
	}

	blocked := newMetadataHTTPClient(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.100.10")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unsafe resolver target was dialed")
		return nil, nil
	})
	_, err = blocked.Do(request)
	if !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("unsafe resolver error = %v", err)
	}
}
