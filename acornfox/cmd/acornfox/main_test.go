package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestSessionStateUsesOwnerOnlyAtomicFileAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	want := sessionState{Origin: "https://console.example.test", Session: "session-secret", CSRF: "csrf-secret", ExpiresAt: time.Now().Add(time.Hour)}
	if err := saveState(env, want); err != nil {
		t.Fatal(err)
	}
	path, err := statePath(env)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode=%v err=%v", info.Mode(), err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file mode=%v err=%v", info.Mode(), err)
	}
	got, err := loadState(env)
	if err != nil || got.Session != want.Session || got.CSRF != want.CSRF {
		t.Fatalf("state=%+v err=%v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Fatal(err)
	}
	if err := saveState(env, want); err == nil {
		t.Fatal("session symlink was accepted")
	}
}

func TestSessionStateRejectsModesTrailingJSONAndExpiry(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
	if err := saveState(env, state); err != nil {
		t.Fatal(err)
	}
	path, _ := statePath(env)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(env); err == nil {
		t.Fatal("insecure mode accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"origin":"https://console.example.test","session":"session","csrf":"csrf","expires_at":"2030-01-01T00:00:00Z"} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(env); err == nil {
		t.Fatal("trailing state JSON accepted")
	}
	if err := saveState(env, sessionState{Origin: state.Origin, Session: state.Session, CSRF: state.CSRF, ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(env); err == nil {
		t.Fatal("expired state accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired state was not removed")
	}
}

func TestSessionPathRejectsParentRootAndAcornFoxSymlinks(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	for _, tc := range []struct {
		name, root string
		setup      func()
	}{
		{"root", filepath.Join(base, "root-link"), func() {
			if err := os.Symlink(target, filepath.Join(base, "root-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"parent", filepath.Join(base, "parent-link", "state"), func() {
			if err := os.Symlink(target, filepath.Join(base, "parent-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"acornfox", filepath.Join(base, "state"), func() {
			if err := os.MkdirAll(filepath.Join(base, "state"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(base, "state", "acornfox")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return tc.root
				}
				return ""
			}
			if err := saveState(env, sessionState{Origin: "https://console.example.test", Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
				t.Fatal("symlink path accepted")
			}
			if _, err := loadState(env); err == nil {
				t.Fatal("symlink path loaded")
			}
			if err := removeState(env); err == nil {
				t.Fatal("symlink path removed")
			}
		})
	}
}

func TestLoginUsesTLSOriginWithoutSessionCSRFOrIdempotency(t *testing.T) {
	var saw bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.Method == http.MethodPost && r.URL.Path == apiBase+"/auth/login" && r.Header.Get("Origin") == server.URL && r.Header.Get("Idempotency-Key") == "" && r.Header.Get("X-AcornFox-CSRF") == "" && len(r.Cookies()) == 0
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["password"] != "correct" {
			t.Errorf("password body=%v", body)
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_session", Value: "session"})
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_csrf", Value: "csrf"})
		_, _ = io.WriteString(w, `{"authenticated":true,"idle_expires_at":"2030-01-01T00:00:00Z","absolute_expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	stateRoot := t.TempDir()
	env := func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	c := &cli{in: strings.NewReader("correct\n"), out: io.Discard, err: io.Discard, env: env, client: server.Client()}
	if err := c.login([]string{"--server", server.URL, "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	if !saw {
		t.Fatal("login request proof was incomplete")
	}
	state, err := loadState(env)
	if err != nil || state.Session != "session" || state.CSRF != "csrf" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestLoginRejectsFalseOrExpiredSessionResponsesAndServerSwitch(t *testing.T) {
	for _, response := range []string{
		`{"authenticated":false,"idle_expires_at":"2030-01-01T00:00:00Z","absolute_expires_at":"2030-01-01T00:00:00Z"}`,
		`{"authenticated":true,"idle_expires_at":"2000-01-01T00:00:00Z","absolute_expires_at":"2030-01-01T00:00:00Z"}`,
	} {
		t.Run(response[:24], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_session", Value: "s"})
				http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_csrf", Value: "c"})
				_, _ = io.WriteString(w, response)
			}))
			defer server.Close()
			c := &cli{in: strings.NewReader("password\n"), out: io.Discard, err: io.Discard, env: func(string) string { return t.TempDir() }, client: server.Client()}
			if err := c.login([]string{"--server", server.URL, "--password-stdin"}); err == nil {
				t.Fatal("invalid login response accepted")
			}
		})
	}
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: "https://saved.example.test", Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c := &cli{in: strings.NewReader("password\n"), out: io.Discard, err: io.Discard, env: env, client: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not call") })}}
	if err := c.login([]string{"--server", "https://other.example.test", "--password-stdin"}); err == nil || calls != 0 {
		t.Fatalf("server switch err=%v calls=%d", err, calls)
	}
}

func TestLoginSameServerReplacesExistingState(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_session", Value: "new"})
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_csrf", Value: "newcsrf"})
		_, _ = io.WriteString(w, `{"authenticated":true,"idle_expires_at":"2030-01-01T00:00:00Z","absolute_expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	if err := saveState(env, sessionState{Origin: server.URL, Session: "old", CSRF: "oldcsrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c := &cli{in: strings.NewReader("password\n"), out: io.Discard, err: io.Discard, env: env, client: server.Client()}
	if err := c.login([]string{"--server", server.URL, "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(env)
	if err != nil || state.Session != "new" || state.CSRF != "newcsrf" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestJSON204AndErrorExitAreDeterministic(t *testing.T) {
	var out, errOut bytes.Buffer
	env := func(string) string { return t.TempDir() }
	code := run([]string{"--json", "apps", "unknown"}, strings.NewReader(""), &out, &errOut, env)
	if code != 2 || !strings.Contains(out.String(), `"class":"usage"`) || errOut.Len() != 0 {
		t.Fatalf("code/out/err=%d/%q/%q", code, out.String(), errOut.String())
	}
}

func TestRequestProofMatrix(t *testing.T) {
	state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf"}
	cases := []struct {
		name, method, path                        string
		csrf                                      bool
		key                                       string
		wantCookie, wantOrigin, wantCSRF, wantKey bool
	}{
		{"read apps", "GET", "/apps", false, "", true, false, false, false},
		{"read sources", "GET", "/apps/app/sources?limit=1", false, "", true, false, false, false},
		{"read delivery", "GET", "/apps/app/deliveries/dep", false, "", true, false, false, false},
		{"read logs", "GET", "/apps/app/deliveries/dep/logs?source=runtime", false, "", true, false, false, false},
		{"create app", "POST", "/apps", true, "key-app", true, true, true, true},
		{"deploy", "POST", "/apps/app/deliveries", true, "key-deploy", true, true, true, true},
		{"probe", "POST", "/apps/app/deliveries/dep/probes", true, "key-probe", true, true, true, true},
		{"restart", "POST", "/apps/app/deliveries/dep/restart", true, "key-restart", true, true, true, true},
		{"redeploy", "POST", "/apps/app/deliveries/dep/redeploy", true, "key-redeploy", true, true, true, true},
		{"public", "PUT", "/apps/app/deliveries/dep/public-access", true, "key-public", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *http.Request
			transport := roundTripper(func(r *http.Request) (*http.Response, error) {
				got = r
				return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			c := &cli{client: &http.Client{Transport: transport}}
			response, err := c.request(context.Background(), state, tc.method, tc.path, map[string]bool{"x": true}, tc.csrf, tc.key, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			pieces := strings.SplitN(tc.path, "?", 2)
			wantQuery := ""
			if len(pieces) == 2 {
				wantQuery = pieces[1]
			}
			if got.Method != tc.method || got.URL.Path != apiBase+pieces[0] || got.URL.RawQuery != wantQuery {
				t.Fatalf("request=%s %s?%s", got.Method, got.URL.Path, got.URL.RawQuery)
			}
			if (len(got.Cookies()) > 0) != tc.wantCookie || (got.Header.Get("Origin") != "") != tc.wantOrigin || (got.Header.Get("X-AcornFox-CSRF") != "") != tc.wantCSRF || (got.Header.Get("Idempotency-Key") != "") != tc.wantKey {
				t.Fatalf("headers=%v cookies=%v", got.Header, got.Cookies())
			}
		})
	}
}

func TestExpectedSuccessStatusCoversEveryCLICommandRouteClass(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		shape        responseShape
		want         int
	}{
		{http.MethodPost, "/auth/login", shapeSession, http.StatusOK}, {http.MethodGet, "/auth/session", shapeSession, http.StatusOK}, {http.MethodPost, "/auth/logout", shapeSession, http.StatusNoContent}, {http.MethodPost, "/auth/password", shapeSession, http.StatusNoContent},
		{http.MethodGet, "/host/metrics", shapeHostMetrics, http.StatusOK},
		{http.MethodGet, "/apps", shapeApps, http.StatusOK}, {http.MethodPost, "/apps", shapeCreateApp, http.StatusCreated}, {http.MethodGet, "/apps/app", shapeApplication, http.StatusOK}, {http.MethodGet, "/apps/app/operations/operation", shapeOperationResult, http.StatusOK},
		{http.MethodGet, "/apps/app/sources", shapeSourceList, http.StatusOK}, {http.MethodPost, "/apps/app/sources", shapeSourceUpdate, http.StatusCreated}, {http.MethodGet, "/apps/app/sources/source", shapeSource, http.StatusOK}, {http.MethodGet, "/apps/app/sources/source/metadata", shapeSourceMetadata, http.StatusOK}, {http.MethodGet, "/apps/app/deliveries", shapeDeploymentList, http.StatusOK},
		{http.MethodPost, "/apps/app/deliveries", shapeCommand, http.StatusAccepted}, {http.MethodGet, "/apps/app/deliveries/deployment", shapeStatus, http.StatusOK}, {http.MethodGet, "/apps/app/deliveries/deployment/source", shapeDeliverySource, http.StatusOK}, {http.MethodGet, "/apps/app/deliveries/deployment/logs?source=runtime", shapeLogs, http.StatusOK},
		{http.MethodPost, "/apps/app/deliveries/deployment/probes", shapeCommand, http.StatusAccepted},
		{http.MethodPost, "/apps/app/deliveries/deployment/restart", shapeCommand, http.StatusAccepted}, {http.MethodPost, "/apps/app/deliveries/deployment/redeploy", shapeCommand, http.StatusAccepted}, {http.MethodGet, "/apps/app/deliveries/deployment/public-access", shapePublicAccess, http.StatusOK}, {http.MethodPut, "/apps/app/deliveries/deployment/public-access", shapePublicAccess, http.StatusOK},
	} {
		got, known := expectedSuccessStatus(tc.method, tc.path, tc.shape)
		if !known || got != tc.want {
			t.Fatalf("%s %s shape=%d: got=%d known=%t want=%d", tc.method, tc.path, tc.shape, got, known, tc.want)
		}
	}
	if _, known := expectedSuccessStatus(http.MethodDelete, "/apps/app", shapeApplication); known {
		t.Fatal("unsupported command route must fail closed")
	}
	for _, tc := range []struct {
		method, path string
		shape        responseShape
	}{
		{http.MethodGet, "/unknown", shapeApps}, {http.MethodGet, "/apps/app/", shapeApplication}, {http.MethodGet, "/apps?limit=1", shapeApps}, {http.MethodGet, "/host/metrics?x=1", shapeHostMetrics}, {http.MethodGet, "/apps/app/operations/operation?x=1", shapeOperationResult}, {http.MethodPost, "/apps/app/sources?x=1", shapeSourceUpdate}, {http.MethodGet, "/apps/app/sources/source?cursor=opaque", shapeSource}, {http.MethodGet, "/apps/app/sources/source/metadata?cursor=opaque", shapeSourceMetadata}, {http.MethodGet, "/apps/app/deliveries/deployment/source?cursor=opaque", shapeDeliverySource},
		{http.MethodPost, "/apps/app/deliveries/deployment/probes?x=1", shapeCommand}, {http.MethodGet, "/apps/app/deliveries/deployment/probes", shapeCommand}, {http.MethodPost, "/apps/app/deliveries/deployment/probes/extra", shapeCommand}, {http.MethodPost, "/apps/app/deliveries/deployment/restart/extra", shapeCommand}, {http.MethodPost, "/anything", shapeCommand}, {http.MethodPut, "/apps/app/deliveries/deployment/public-access?x=1", shapePublicAccess},
	} {
		if _, known := expectedSuccessStatus(tc.method, tc.path, tc.shape); known {
			t.Fatalf("unexpected known route: %s %s", tc.method, tc.path)
		}
	}
	for _, tc := range []struct {
		path  string
		shape responseShape
	}{{"/apps/app/sources?limit=1", shapeSourceList}, {"/apps/app/deliveries?cursor=opaque", shapeDeploymentList}, {"/apps/app/deliveries/deployment/logs?source=runtime", shapeLogs}} {
		if _, known := expectedSuccessStatus(http.MethodGet, tc.path, tc.shape); !known {
			t.Fatalf("canonical query route rejected: %s", tc.path)
		}
	}
	for _, path := range []string{
		"/apps/app%2Fother/sources", "/apps/app/sources?limit=0", "/apps/app/sources?limit=101", "/apps/app/sources?limit=bad", "/apps/app/sources?limit=1&limit=2", "/apps/app/sources?limit=1&", "/apps/app/sources?cursor=", "/apps/app/sources?unknown=1", "/apps/app/sources?cursor=%ZZ",
		"/apps/app/deliveries?limit=1&cursor=opaque&extra=1", "/apps/app/deliveries?cursor=one&cursor=two",
		"/apps/app/deliveries/deployment/logs", "/apps/app/deliveries/deployment/logs?source=other", "/apps/app/deliveries/deployment/logs?source=build&source=runtime", "/apps/app/deliveries/deployment/logs?source=runtime&limit=", "/apps/app/deliveries/deployment/logs?source=runtime&cursor=", "/apps/app/deliveries/deployment/logs?source=runtime&unknown=1",
		"/apps/app/sources?", "/apps/app/deliveries/deployment/logs?source=runtime#fragment",
	} {
		shape := shapeSourceList
		if strings.Contains(path, "deliveries?") {
			shape = shapeDeploymentList
		}
		if strings.Contains(path, "/logs") {
			shape = shapeLogs
		}
		if _, known := expectedSuccessStatus(http.MethodGet, path, shape); known {
			t.Fatalf("invalid query accepted: %s", path)
		}
	}
	for _, tc := range []struct {
		path  string
		shape responseShape
	}{
		{"/apps/app/sources?limit=100&cursor=opaque%2Fcursor", shapeSourceList}, {"/apps/app/deliveries?cursor=opaque%20value", shapeDeploymentList}, {"/apps/app/deliveries/deployment/logs?source=build&limit=1&cursor=opaque%2Fcursor", shapeLogs},
	} {
		if _, known := expectedSuccessStatus(http.MethodGet, tc.path, tc.shape); !known {
			t.Fatalf("valid opaque query rejected: %s", tc.path)
		}
	}
}

func TestUnexpectedSuccessStatusesAreContractFailuresWithoutStateMutation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		method, path string
		shape        responseShape
		status       int
	}{
		{"session 201", http.MethodGet, "/auth/session", shapeSession, http.StatusCreated}, {"deploy 200", http.MethodPost, "/apps/app/deliveries", shapeCommand, http.StatusOK}, {"probe 200", http.MethodPost, "/apps/app/deliveries/deployment/probes", shapeCommand, http.StatusOK}, {"logout 200", http.MethodPost, "/auth/logout", shapeSession, http.StatusOK}, {"password 200", http.MethodPost, "/auth/password", shapeSession, http.StatusOK}, {"read 204", http.MethodGet, "/apps", shapeApps, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
			if err := saveState(env, state); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			c := &cli{out: &out, err: io.Discard, env: env, client: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}, json: true}
			err := c.callWithState(state, tc.method, tc.path, nil, tc.method != http.MethodGet, "key", time.Second, tc.shape)
			var responseErr apiError
			if !errors.As(err, &responseErr) || responseErr.class() != "contract" || responseErr.Code != "invalid_response" || out.Len() != 0 {
				t.Fatalf("err=%v out=%q", err, out.String())
			}
			if _, err := loadState(env); err != nil {
				t.Fatalf("mismatched success mutated state: %v", err)
			}
		})
	}
}

func TestMismatchedLogoutAndPasswordDoNotEmitOrRemoveState(t *testing.T) {
	for _, password := range []bool{false, true} {
		t.Run(map[bool]string{false: "logout", true: "password"}[password], func(t *testing.T) {
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
			if err := saveState(env, state); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			c := &cli{in: strings.NewReader("old\nnew\nnew\n"), out: &out, err: io.Discard, env: env, json: true, client: &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}}
			var err error
			if password {
				err = c.password([]string{"--password-stdin"})
			} else {
				err = c.logout(nil)
			}
			var responseErr apiError
			if !errors.As(err, &responseErr) || responseErr.class() != "contract" || out.Len() != 0 {
				t.Fatalf("err=%v out=%q", err, out.String())
			}
			if _, err := loadState(env); err != nil {
				t.Fatalf("state removed: %v", err)
			}
		})
	}
}

func TestAPIErrorClassMatrix(t *testing.T) {
	for _, tc := range []struct {
		status  int
		network bool
		want    string
	}{
		{400, false, "usage"}, {401, false, "authentication"}, {404, false, "usage"}, {409, false, "conflict"}, {422, false, "usage"}, {429, false, "authentication"}, {503, false, "unavailable"}, {500, false, "contract"}, {0, true, "unavailable"},
	} {
		if got := (apiError{status: tc.status, network: tc.network}).class(); got != tc.want {
			t.Fatalf("status=%d network=%v got=%s", tc.status, tc.network, got)
		}
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPasswordStdinRequiresExactLines(t *testing.T) {
	if _, err := readLinesN(strings.NewReader("one\ntwo\n"), 1); err == nil {
		t.Fatal("trailing password input was accepted")
	}
	if values, err := readLinesN(strings.NewReader("one\ntwo\nthree\n"), 3); err != nil || len(values) != 3 {
		t.Fatalf("values=%v err=%v", values, err)
	}
	if _, err := readLinesN(strings.NewReader("one"), 1); err == nil {
		t.Fatal("unterminated password input was accepted")
	}
}

func TestStrictCommandParsingRejectsInvalidInputs(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "--json", "session"},
		{"login", "--server", "https://example.test", "--server", "https://other.test", "--password-stdin"},
		{"apps", "create", "--name", "x", "--repository", "https://example.test/repo.git", "--ref", "main", "--unknown", "x"},
		{"apps", "create", "--name", "x", "--repository", "https://example.test/repo.git", "--ref", "main", "--ref", "next"},
		{"apps", "get"},
		{"sources", "get", "app"},
		{"deploy", "app", "--source", "source", "--port", "65536"},
		{"deploy", "app", "--source", "source", "--port", "not-a-port"},
		{"logs", "app", "deployment", "--source", "runtime", "--limit", "101"},
		{"logs", "app", "deployment", "--source", "runtime", "--limit", "zero"},
		{"sources", "list", "app", "--cursor", ""},
		{"restart", "app", "deployment", "--idempotency-key", ""},
		{"apps", "create", "--name", "x", "--repository", "http://example.test/repo.git", "--ref", "main"},
		{"apps", "create", "--name", "x", "--repository", "https://example.test/repo.git", "--ref", "line\nbreak"},
		{"session", "--server", "https://other.test"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, strings.NewReader("password\n"), &out, &errOut, func(string) string { return t.TempDir() }); code != 2 {
			t.Fatalf("args=%v exit=%d output=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestMalformedAndUnavailableResponsesAreContractFailures(t *testing.T) {
	state := sessionState{Origin: "https://console.example.test", Session: "session", CSRF: "csrf"}
	for _, body := range []string{"", "[]", `{"unexpected":true}`} {
		transport := roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		c := &cli{client: &http.Client{Transport: transport}, out: io.Discard, err: io.Discard, env: func(string) string { return t.TempDir() }}
		err := c.callWithState(state, http.MethodGet, "/apps", nil, false, "", time.Second, shapeApps)
		var responseErr apiError
		if !errors.As(err, &responseErr) || responseErr.class() != "contract" {
			t.Fatalf("body=%q err=%v", body, err)
		}
	}
	transport := roundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("down") })
	c := &cli{client: &http.Client{Transport: transport}}
	if _, err := c.request(context.Background(), state, http.MethodGet, "/apps", nil, false, "", time.Second); err == nil || !errors.Is(err, err) {
		t.Fatal("network error was not returned")
	}
	badError := roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"only-code"}`))}, nil
	})
	c.client = &http.Client{Transport: badError}
	err := c.callWithState(state, http.MethodGet, "/apps", nil, false, "", time.Second, shapeApps)
	var responseErr apiError
	if !errors.As(err, &responseErr) || responseErr.class() != "contract" || responseErr.status != http.StatusBadRequest {
		t.Fatalf("malformed error was misclassified: %#v", err)
	}
}

func TestTypedResponsesRejectUnknownNullAndOversizedPayloads(t *testing.T) {
	for _, body := range []string{
		`{"items":[],"extra":true}`,
		`{"items":[{"id":"app","name":"demo","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z","extra":true}]}`,
		`{"desired_public":null,"url":"https://app.example.test","endpoint":{"deployment_id":"dep"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`,
	} {
		if _, err := decodeResponse(strings.NewReader(body), shapeApps); err == nil && strings.Contains(body, "items") {
			t.Fatalf("invalid app response accepted: %s", body)
		}
	}
	if _, err := decodeResponse(strings.NewReader(`{"desired_public":null,"url":"https://app.example.test","endpoint":{"deployment_id":"dep"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`), shapePublicAccess); err == nil {
		t.Fatal("null required bool accepted")
	}
	if _, err := decodeResponse(strings.NewReader(`{"items":`+strings.Repeat(" ", maxResponseBytes)+`[]}`), shapeApps); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestProbeOptionalFieldsPreserveOpenAPIOmissionAndNullNormalization(t *testing.T) {
	base := `{"deployment":{"id":"deployment","application_id":"app","environment_id":"environment","release_id":"release","stage":"starting","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"},"desired":null,"runtime":null,"response":{"protocol":"http","outcome":"responded","observed_at":"2030-01-01T00:00:00Z","fact_digest":"sha256:fact"}}`
	value, err := decodeResponse(strings.NewReader(base), shapeStatus)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"http_status", "latency_ms", "error_code"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("minimal response invented %s: %s", forbidden, encoded)
		}
	}
	nullable := strings.Replace(base, `"fact_digest":"sha256:fact"`, `"fact_digest":"sha256:fact","http_status":null`, 1)
	value, err = decodeResponse(strings.NewReader(nullable), shapeStatus)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"http_status", "latency_ms", "error_code"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("null response invented %s: %s", forbidden, encoded)
		}
	}
	for _, invalid := range []string{
		strings.Replace(base, `"fact_digest":"sha256:fact"`, `"fact_digest":"sha256:fact","http_status":99`, 1),
		strings.Replace(base, `"fact_digest":"sha256:fact"`, `"fact_digest":"sha256:fact","latency_ms":-1`, 1),
	} {
		if _, err := decodeResponse(strings.NewReader(invalid), shapeStatus); err == nil {
			t.Fatalf("invalid probe accepted: %s", invalid)
		}
	}
}

func TestOptionalNonNullableFieldsRejectExplicitNull(t *testing.T) {
	source := `{"id":"source","application_id":"app","kind":"git_https","locator_sha256":"sha256:locator","content_digest":"sha256:content","created_at":"2030-01-01T00:00:00Z","immutable":true}`
	for _, invalid := range []string{
		strings.Replace(source, `"immutable":true`, `"immutable":true,"ref":null`, 1),
		strings.Replace(source, `"immutable":true`, `"immutable":true,"commit":null`, 1),
		`{"items":[` + strings.Replace(source, `"immutable":true`, `"immutable":true,"ref":null`, 1) + `],"next_cursor":null}`,
	} {
		shape := shapeSource
		if strings.Contains(invalid, `"items"`) {
			shape = shapeSourceList
		}
		if _, err := decodeResponse(strings.NewReader(invalid), shape); err == nil {
			t.Fatalf("source null accepted: %s", invalid)
		}
	}
	deployment := `{"id":"deployment","application_id":"app","environment_id":"environment","release_id":"release","stage":"starting","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"}`
	release := `{"application_id":"app","environment_id":"environment","release_id":"release","service_name":"web","image":{"repository":"repo","digest":"sha256:image"},"resources":{"cpu_millis":1,"memory_bytes":1,"pids":1,"disk_reservation_bytes":1},"accepted_at":"2030-01-01T00:00:00Z","immutable":true}`
	runtime := `{"deployment_id":"deployment","service_name":"web","runtime_state":"running","restart_count":0,"requested_resources":{"cpu_millis":1,"memory_bytes":1,"pids":1,"disk_reservation_bytes":1},"applied_limits":{"cpu_millis":1,"memory_bytes":1,"pids":1},"disk":{"reservation_bytes":1,"accounting_reconciled":true,"per_container_enforced":true},"observed_at":"2030-01-01T00:00:00Z"}`
	probe := `{"protocol":"http","outcome":"responded","observed_at":"2030-01-01T00:00:00Z","fact_digest":"sha256:fact"}`
	for _, status := range []string{
		`{"deployment":` + deployment + `,"desired":` + strings.Replace(release, `"immutable":true`, `"immutable":true,"container_port":null`, 1) + `,"runtime":null,"response":null}`,
		`{"deployment":` + deployment + `,"desired":null,"runtime":` + strings.Replace(runtime, `"observed_at"`, `"container_id":null,"observed_at"`, 1) + `,"response":null}`,
		`{"deployment":` + deployment + `,"desired":null,"runtime":` + strings.Replace(runtime, `"observed_at"`, `"internal_address":null,"observed_at"`, 1) + `,"response":null}`,
		`{"deployment":` + deployment + `,"desired":null,"runtime":null,"response":` + strings.Replace(probe, `"fact_digest":"sha256:fact"`, `"fact_digest":"sha256:fact","latency_ms":null`, 1) + `}`,
		`{"deployment":` + deployment + `,"desired":null,"runtime":null,"response":` + strings.Replace(probe, `"fact_digest":"sha256:fact"`, `"fact_digest":"sha256:fact","error_code":null`, 1) + `}`,
	} {
		if _, err := decodeResponse(strings.NewReader(status), shapeStatus); err == nil {
			t.Fatalf("status null accepted: %s", status)
		}
	}
}

func TestRedirectIsRejectedBeforeAnyFollow(t *testing.T) {
	for _, target := range []string{"https://other.example.test/next", "http://127.0.0.1/next"} {
		calls := 0
		transport := roundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})
		c := &cli{client: &http.Client{Transport: transport}}
		_, err := c.request(context.Background(), sessionState{Origin: "https://console.example.test"}, http.MethodGet, "/apps", nil, false, "", time.Second)
		var responseErr apiError
		if !errors.As(err, &responseErr) || responseErr.class() != "contract" || calls != 1 {
			t.Fatalf("target=%s err=%v calls=%d", target, err, calls)
		}
	}
}

func TestCleanupFailureSuppressesSuccessOutput(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, _ := statePath(env)
		_ = os.Remove(path)
		_ = os.Symlink(filepath.Join(root, "target"), path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := saveState(env, sessionState{Origin: server.URL, Session: "s", CSRF: "c", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	err := c.logout(nil)
	var responseErr apiError
	if !errors.As(err, &responseErr) || responseErr.class() != "contract" || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}

func TestLoginOutputNeverContainsCredentialsOrCookies(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_session", Value: "session-secret"})
		http.SetCookie(w, &http.Cookie{Name: "__Host-acornfox_csrf", Value: "csrf-secret"})
		_, _ = io.WriteString(w, `{"authenticated":true,"idle_expires_at":"2030-01-01T00:00:00Z","absolute_expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	c := &cli{in: strings.NewReader("password-secret\n"), out: &output, err: io.Discard, env: func(string) string { return t.TempDir() }, client: server.Client(), json: true}
	if err := c.login([]string{"--server", server.URL, "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password-secret", "session-secret", "csrf-secret"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("output leaked %q: %s", secret, output.String())
		}
	}
}

func cookieRequest(request *http.Request, name string) string {
	for _, value := range request.Cookies() {
		if value.Name == name {
			return value.Value
		}
	}
	return ""
}

func TestRequestUsesPerOperationBudgetWithoutExpandingOrdinaryCalls(t *testing.T) {
	const ordinaryBudget = 5 * time.Millisecond
	const longBudget = time.Second
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(20 * time.Millisecond):
			return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
	})
	original := &http.Client{Timeout: ordinaryBudget, Transport: transport}
	c := &cli{client: original}
	state := sessionState{Origin: "https://console.example.test"}
	response, err := c.request(context.Background(), state, http.MethodPost, "/apps/app/deliveries", nil, false, "", longBudget)
	if err != nil {
		t.Fatal("long operation inherited the ordinary client's short timeout", err)
	}
	response.Body.Close()
	if response, err = c.request(context.Background(), state, http.MethodGet, "/apps", nil, false, "", ordinaryBudget); err == nil {
		response.Body.Close()
		t.Fatal("ordinary API call inherited the long-operation budget")
	}
	if original.Timeout != ordinaryBudget {
		t.Fatal("per-operation client copy mutated the shared client's timeout")
	}
}

func TestNativeImageCommandsUseRealAPIAndExplicitConfirmation(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	plan := appcontracts.ImagePlan{
		ID: "plan_native", AdminID: "admin_native", AppName: "demo", Status: appcontracts.ImagePlanStatusNeedsInput,
		CanonicalInput:     appcontracts.CanonicalExecutionInput{AppName: "demo", Repository: "registry-1.docker.io/library/nginx", ResolvedRef: "latest"},
		ResolvedImage:      appcontracts.ResolvedImage{Repository: "registry-1.docker.io/library/nginx", Digest: digest, OS: "linux", Architecture: "amd64"},
		ResolverProvenance: appcontracts.ResolverProvenance{Provider: "registryhttp", Digest: digest, ResolvedAt: now},
		MissingInputs:      []string{"container_port"}, CreatedAt: now, UpdatedAt: now,
	}
	var err error
	plan.PlanDigest, err = appcontracts.ComputePlanDigest(plan.CanonicalInput, digest)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := appcontracts.ConfirmImagePlanResult{ApplicationID: "app_native", EnvironmentID: "env_native", OperationID: "op_native", TaskID: "task_native", PlanID: plan.ID, PlanDigest: plan.PlanDigest, Status: "pending", CreatedAt: now}
	op := appcontracts.ImageOperationDetailWithResult{ImageOperationDetail: appcontracts.ImageOperationDetail{OperationID: "op_native", ApplicationID: "app_native", EnvironmentID: "env_native", OperationType: "deploy_image", State: "unknown", PlanID: plan.ID, PlanDigest: plan.PlanDigest, TaskID: "task_native", Reason: "needs_action: budget exhausted", ActionRequired: true, CreatedAt: now, UpdatedAt: now}}
	requests := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if session, err := r.Cookie("__Host-acornfox_session"); err != nil || session.Value != "session" {
			t.Error("missing session")
		}
		if r.Method == http.MethodPost {
			csrf, err := r.Cookie("__Host-acornfox_csrf")
			if err != nil || csrf.Value != "csrf" || r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Origin") != server.URL {
				t.Error("POST omitted mandatory CSRF proof")
			}
		}
		switch r.Method + " " + r.URL.Path {
		case "POST " + apiBase + "/image-plans":
			var input appcontracts.ImagePlanInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.Image != "nginx:latest" || input.AppName != "demo" || input.Port != 0 || input.Environment["MODE"] != "demo" || input.Environment["LANG"] != "C" {
				t.Errorf("incorrect image input: %+v", input)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(plan)
		case "GET " + apiBase + "/image-plans/plan_native":
			_ = json.NewEncoder(w).Encode(plan)
		case "POST " + apiBase + "/image-plans/plan_native/confirm":
			var input appcontracts.ConfirmImagePlanInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.PlanID != domain.ID("plan_native") || input.PlanDigest != plan.PlanDigest || input.IdempotencyKey != "confirm-key" || r.Header.Get("Idempotency-Key") != "confirm-key" {
				t.Error("confirmation changed explicit input")
			}
			_ = json.NewEncoder(w).Encode(confirmed)
		case "GET " + apiBase + "/operations/op_native":
			_ = json.NewEncoder(w).Encode(op)
		default:
			t.Errorf("unexpected Native request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{in: strings.NewReader(""), out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	for _, args := range [][]string{
		{"image", "plan", "--image", "nginx:latest", "--name", "demo", "--env", "MODE=demo", "--env", "LANG=C"},
		{"image", "plan", "get", "plan_native"},
		{"image", "confirm", "plan_native", "--digest", plan.PlanDigest, "--idempotency-key", "confirm-key"},
		{"image", "operation", "op_native"},
	} {
		out.Reset()
		if err := c.command(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if out.Len() == 0 {
			t.Fatal("real API result omitted")
		}
		if args[1] == "confirm" && !strings.Contains(out.String(), `"status":"pending"`) {
			t.Fatal("confirmation was presented as deployed")
		}
		if args[1] == "operation" && (!strings.Contains(out.String(), `"action_required":true`) || !strings.Contains(out.String(), "needs_action")) {
			t.Fatal("durable diagnostic omitted")
		}
	}
	if requests != 4 {
		t.Fatalf("unexpected automatic request count: %d", requests)
	}
	if err := c.command([]string{"image", "confirm", "plan_native", "--digest", plan.PlanDigest}); err == nil {
		t.Fatal("confirmation silently generated an idempotency key")
	}
	if requests != 4 {
		t.Fatal("missing explicit key reached server")
	}
	// Internally valid responses for another identity must never be emitted.
	for _, kind := range []string{"plan", "operation", "confirm-plan", "confirm-digest"} {
		args := []string{"image", "plan", "get", "plan_native"}
		plan.ID, op.OperationID, confirmed.PlanID, confirmed.PlanDigest = "plan_native", "op_native", "plan_native", plan.PlanDigest
		switch kind {
		case "plan":
			plan.ID = "plan_other"
		case "operation":
			op.OperationID = "op_other"
			args = []string{"image", "operation", "op_native"}
		case "confirm-plan", "confirm-digest":
			args = []string{"image", "confirm", "plan_native", "--digest", plan.PlanDigest, "--idempotency-key", "confirm-key"}
			if kind == "confirm-plan" {
				confirmed.PlanID = "plan_other"
			} else {
				confirmed.PlanDigest = digest
			}
		}
		out.Reset()
		err := c.command(args)
		var apiErr apiError
		if !errors.As(err, &apiErr) || !apiErr.contract || out.Len() != 0 {
			t.Fatalf("%s mismatch accepted: output=%q err=%v", kind, out.String(), err)
		}
		if strings.HasPrefix(kind, "confirm") && !strings.Contains(apiErr.Message, "same --idempotency-key") {
			t.Fatal("uncertain confirmation lost same-key guidance")
		}
	}
	if requests != 8 {
		t.Fatalf("identity mismatch triggered unexpected retries: %d", requests)
	}

}

func TestNativeImageConfirmationFailureKeepsKeyAndRejectsWrongSuccessStatus(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusCreated, 0} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != apiBase+"/image-plans/plan_native/confirm" || r.Header.Get("Idempotency-Key") != "same-key" {
					t.Error("confirmation retry identity changed")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"code":"unavailable","message":"retry later"}`)
			}))
			defer server.Close()
			if status == 0 {
				server.Close()
			}
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			c := &cli{out: io.Discard, err: io.Discard, env: env, client: server.Client()}
			err := c.command([]string{"image", "confirm", "plan_native", "--digest", "sha256:" + strings.Repeat("a", 64), "--idempotency-key", "same-key"})
			var apiErr apiError
			if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "same --idempotency-key") || (status != 0 && calls != 1) || (status == 0 && calls != 0) {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
			if status == 0 && !apiErr.network {
				t.Fatal("network error mapping changed")
			}
			if status == http.StatusCreated && !apiErr.contract {
				t.Fatal("incorrect confirmation status accepted")
			}
			if status == http.StatusServiceUnavailable && apiErr.class() != "unavailable" {
				t.Fatal("structured error mapping changed")
			}
		})
	}
}

func TestSourceBuildCLIKeepsFourExplicitPhasesAndOriginalIdentity(t *testing.T) {
	now := time.Now().UTC()
	sourceDigest := "sha256:" + strings.Repeat("a", 64)
	manifestDigest := "sha256:" + strings.Repeat("b", 64)
	prepared := appcontracts.SourceBuildPublicIntent{IntentID: "spi_original", Stage: appcontracts.SourceBuildPrepare, State: "pending", ApplicationID: "app_original", OperationID: "op_prepare"}
	preparedRead := prepared
	preparedRead.State, preparedRead.SourceRevisionID, preparedRead.SourceDigest, preparedRead.DefinitionStatus = "prepared", "src_original", sourceDigest, "ready"
	built := appcontracts.SourceBuildPublicIntent{IntentID: "sbi_original", Stage: appcontracts.SourceBuildBuild, State: "pending", ApplicationID: prepared.ApplicationID, OperationID: "op_build", PrepareIntentID: prepared.IntentID, SourceRevisionID: preparedRead.SourceRevisionID, SourceDigest: sourceDigest, PlanID: "bplan_original", BuildID: "build_original"}
	builtRead := built
	builtRead.State, builtRead.ArtifactID = "succeeded", "art_original"
	builtRead.Image = &domain.ImageDigest{Repository: "ghcr.io/acme/source", Digest: manifestDigest}
	canonical := appcontracts.CanonicalExecutionInput{AppName: "original-app", Repository: builtRead.Image.Repository, ResolvedRef: manifestDigest, Port: 8080, Resources: appcontracts.RuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 128 << 20, DiskReservationBytes: 1 << 30, PIDs: 64}}
	planDigest, err := appcontracts.ComputePlanDigest(canonical, manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	runPlan := appcontracts.ImagePlan{ID: "ipl_original", AdminID: "admin_original", AppName: canonical.AppName, Status: appcontracts.ImagePlanStatusPlanned, PlanDigest: planDigest, CanonicalInput: canonical, ResolvedImage: appcontracts.ResolvedImage{Repository: canonical.Repository, Digest: manifestDigest, Architecture: "amd64", OS: "linux"}, ResolverProvenance: appcontracts.ResolverProvenance{Provider: "source-build", EvidenceRef: builtRead.ArtifactID.String(), Digest: manifestDigest, ResolvedAt: now}, CreatedAt: now, UpdatedAt: now}
	confirmed := appcontracts.ConfirmImagePlanResult{ApplicationID: prepared.ApplicationID, EnvironmentID: "env_original", OperationID: "op_run", TaskID: "task_run", PlanID: runPlan.ID, PlanDigest: planDigest, Status: "pending", CreatedAt: now}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method == http.MethodPost {
			if r.Header.Get("Origin") != "https://"+r.Host || r.Header.Get("X-AcornFox-CSRF") != "csrf" {
				t.Error("source mutation omitted original CSRF/origin")
			}
			if cookie, err := r.Cookie("__Host-acornfox_csrf"); err != nil || cookie.Value != "csrf" {
				t.Error("source mutation omitted CSRF cookie")
			}
			if cookie, err := r.Cookie("__Host-acornfox_session"); err != nil || cookie.Value != "session" {
				t.Error("source mutation omitted authenticated session cookie")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST " + apiBase + "/source-build/prepare":
			var body appcontracts.CreateSourcePrepareIntentInput
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.IdempotencyKey != "key-prepare" || r.Header.Get("Idempotency-Key") != body.IdempotencyKey || body.Repository != "https://github.com/acme/source" || body.Commit != strings.Repeat("c", 40) || body.TimeoutSeconds != 120 {
				t.Error("prepare changed original public Git input/key")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(prepared)
		case "GET " + apiBase + "/source-build/intents/spi_original":
			_ = json.NewEncoder(w).Encode(preparedRead)
		case "POST " + apiBase + "/source-build/approve":
			var body appcontracts.SourceBuildPublicApprovalInput
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.IdempotencyKey != "key-build" || r.Header.Get("Idempotency-Key") != body.IdempotencyKey || body.PrepareIntentID != prepared.IntentID || body.SourceRevisionID != preparedRead.SourceRevisionID || body.SourceDigest != sourceDigest || body.ContextPath != "." || body.DockerfilePath != "Dockerfile" || body.Resources.CPUMillis != 500 || body.Resources.MemoryBytes != 512<<20 || body.Resources.PIDs != 0 || body.Resources.DiskBytes != 1<<30 || body.Resources.TimeoutSeconds != 120 || body.Resources.ConcurrencySlot != 1 {
				t.Error("build approval changed Core-supported fixed contract")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(built)
		case "GET " + apiBase + "/source-build/intents/sbi_original":
			_ = json.NewEncoder(w).Encode(builtRead)
		case "POST " + apiBase + "/source-build/run-plans":
			var body appcontracts.SourceRunPlanInput
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.BuildIntentID != built.IntentID || body.ArtifactID != builtRead.ArtifactID || body.Port != 8080 || body.IdempotencyKey != "key-run-plan" || r.Header.Get("Idempotency-Key") != body.IdempotencyKey {
				t.Error("run plan invented a different app/artifact/key")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(runPlan)
		case "GET " + apiBase + "/source-build/run-plans/ipl_original":
			_ = json.NewEncoder(w).Encode(runPlan)
		case "POST " + apiBase + "/source-build/run-plans/ipl_original/confirm":
			var body appcontracts.ConfirmImagePlanInput
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.PlanID != runPlan.ID || body.PlanDigest != runPlan.PlanDigest || body.IdempotencyKey != "key-run-confirm" || r.Header.Get("Idempotency-Key") != body.IdempotencyKey {
				t.Error("run confirmation changed reviewed plan/key")
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(confirmed)
		default:
			t.Errorf("unexpected source command route: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	for _, args := range [][]string{
		{"source-build", "prepare", "--name", "original-app", "--repository", "https://github.com/acme/source", "--commit", strings.Repeat("c", 40), "--idempotency-key", "key-prepare"},
		{"source-build", "get", "spi_original"},
		{"source-build", "build-confirm", "spi_original", "--source-revision", "src_original", "--source-digest", sourceDigest, "--service", "web", "--repository", "ghcr.io/acme/source", "--disk-bytes", "1073741824", "--timeout-seconds", "120", "--idempotency-key", "key-build"},
		{"source-build", "get", "sbi_original"},
		{"source-build", "run-plan", "sbi_original", "--artifact", "art_original", "--port", "8080", "--idempotency-key", "key-run-plan"},
		{"source-build", "run-plan", "get", "ipl_original"},
		{"source-build", "run-confirm", "ipl_original", "--digest", planDigest, "--idempotency-key", "key-run-confirm"},
	} {
		out.Reset()
		if err := c.command(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if out.Len() == 0 {
			t.Fatal("source command emitted no typed API result")
		}
	}
	if requests != 7 {
		t.Fatalf("source phases auto-dispatched or dropped: %d", requests)
	}
	if err := c.command([]string{"source-build", "run-confirm", "ipl_original", "--digest", planDigest}); err == nil || requests != 7 {
		t.Fatal("missing explicit confirmation key reached API")
	}
	if err := c.command([]string{"source-build", "prepare", "--name", "original-app", "--repository", "https://LOCALHOST.../acme/source", "--commit", strings.Repeat("c", 40), "--idempotency-key", "alias-key"}); err == nil || requests != 7 {
		t.Fatal("canonical private-host alias reached the API")
	}
	prepared.PrepareIntentID = "sbi_forged"
	out.Reset()
	err = c.command([]string{"source-build", "prepare", "--name", "original-app", "--repository", "https://github.com/acme/source", "--commit", strings.Repeat("c", 40), "--idempotency-key", "key-prepare"})
	var contractErr apiError
	if !errors.As(err, &contractErr) || !contractErr.contract || out.Len() != 0 || requests != 8 {
		t.Fatal("prepare response carrying build-only authority was accepted")
	}
}

func TestSourceBuildRunConfirmUnknownKeepsExactKey(t *testing.T) {
	wantDigest := "sha256:" + strings.Repeat("a", 64)
	calls, status := 0, http.StatusServiceUnavailable
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != apiBase+"/source-build/run-plans/ipl_original/confirm" || r.Header.Get("Idempotency-Key") != "original-key" {
			t.Error("unknown retry changed exact route, method or key")
		}
		var body appcontracts.ConfirmImagePlanInput
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.PlanID != "ipl_original" || body.PlanDigest != wantDigest || body.IdempotencyKey != "original-key" {
			t.Error("unknown retry changed original confirm body")
		}
		w.WriteHeader(status)
		if status == http.StatusServiceUnavailable {
			_, _ = io.WriteString(w, `{"code":"unavailable","message":"retry later"}`)
			return
		}
		if status == http.StatusConflict {
			_, _ = io.WriteString(w, `{"code":"conflict","message":"original key is in progress"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(appcontracts.ConfirmImagePlanResult{ApplicationID: "app_original", EnvironmentID: "env_original", OperationID: "op_original", TaskID: "task_original", PlanID: "ipl_original", PlanDigest: "sha256:" + strings.Repeat("b", 64), Status: "pending", CreatedAt: time.Now().UTC()})
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	args := []string{"source-build", "run-confirm", "ipl_original", "--digest", wantDigest, "--idempotency-key", "original-key"}
	for _, nextStatus := range []int{http.StatusConflict, http.StatusAccepted, http.StatusAccepted} {
		out.Reset()
		err := c.command(args)
		var apiErr apiError
		if !errors.As(err, &apiErr) || out.Len() != 0 {
			t.Fatalf("uncertain source confirm mishandled: %+v output=%q", err, out.String())
		}
		if status == http.StatusConflict {
			if !strings.Contains(apiErr.Message, "exact same body and --idempotency-key") || strings.Contains(apiErr.Message, "outcome is unknown") {
				t.Fatal("409 overstated completion or lost original-body guidance")
			}
		} else if !strings.Contains(apiErr.Message, "same --idempotency-key") || apiErr.contract != (status == http.StatusAccepted) {
			t.Fatal("unknown/contract response lost same-key guidance")
		}
		status = nextStatus
	}
	if calls != 3 {
		t.Fatalf("source CLI retried automatically: %d", calls)
	}
}

func TestNativeImageAppsUsesBoundedPublicListAndStrictLimit(t *testing.T) {
	active := &appcontracts.ManagedImageCommandSummary{OperationID: "op_stop", Action: appcontracts.ImageLifecycleStop, State: "unknown"}
	item := appcontracts.ManagedImageApplicationSummary{ApplicationID: "app_saved", Name: "saved", EnvironmentID: "env_saved", PlanID: "plan_saved", PlanDigest: "sha256:" + strings.Repeat("a", 64), DeployOperationID: "op_deploy", DeployState: "succeeded", DeploymentID: "dep_saved", DeploymentState: "running", UpdatedAt: time.Now().UTC(), ActiveCommand: active, LastCommand: active}
	failed := appcontracts.ManagedImageApplicationSummary{ApplicationID: "app_failed", Name: "failed", EnvironmentID: "env_failed", PlanID: "plan_failed", PlanDigest: item.PlanDigest, DeployOperationID: "op_failed", DeployState: "failed", UpdatedAt: item.UpdatedAt}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != apiBase+"/image-apps" || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-AcornFox-CSRF") != "" {
			t.Errorf("wrong list transport: %s %s", r.Method, r.URL.Path)
		}
		if cookie, err := r.Cookie("__Host-acornfox_session"); err != nil || cookie.Value != "session" {
			t.Error("list omitted normal authentication")
		}
		if r.URL.RawQuery != "" && r.URL.RawQuery != "limit=1" && r.URL.RawQuery != "limit=2" {
			t.Error("noncanonical query reached server")
		}
		if requests == 4 {
			_, _ = io.WriteString(w, `{"items":[],"truncated":false,"private_plan":{"environment":"secret"}}`)
			return
		}
		list := appcontracts.ManagedImageApplicationList{Items: []appcontracts.ManagedImageApplicationSummary{item, failed}}
		if r.URL.RawQuery == "limit=1" {
			list.Items = list.Items[:1]
			list.Truncated = true
		}
		_ = json.NewEncoder(w).Encode(list)
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	if err := c.command([]string{"image", "apps"}); err != nil {
		t.Fatal(err)
	}
	var list appcontracts.ManagedImageApplicationList
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Items) != 2 || list.Items[0].ActiveCommand.OperationID != "op_stop" || list.Items[1].DeployState != "failed" {
		t.Fatalf("public saved results lost: %v", err)
	}
	out.Reset()
	if err := c.command([]string{"image", "apps", "--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Items) != 1 || !list.Truncated {
		t.Fatal("bounded/truncated response lost")
	}
	out.Reset()
	c.json = false
	if err := c.command([]string{"image", "apps", "--limit", "2"}); err != nil || !strings.Contains(out.String(), "saved") {
		t.Fatal("normal human output omitted saved application")
	}
	for _, raw := range []string{"0", "101", "01", "+1", "invalid"} {
		if err := c.command([]string{"image", "apps", "--limit", raw}); err == nil {
			t.Fatalf("bad limit accepted: %q", raw)
		}
	}
	if requests != 3 {
		t.Fatal("invalid limit sent a request")
	}
	out.Reset()
	var apiErr apiError
	if err := c.command([]string{"image", "apps"}); !errors.As(err, &apiErr) || !apiErr.contract || out.Len() != 0 {
		t.Fatal("private extra response field accepted")
	}
	if _, ok := expectedSuccessStatus(http.MethodGet, "/apps", shapeManagedImageApps); ok {
		t.Fatal("Native image list accepted legacy apps path")
	}
}

func TestNativeImageObservationAndLogsUseReadOnlyBoundedAPI(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	observation := appcontracts.ImageObservationResult{State: appcontracts.ImageLifecycleResult{Running: true, VerifiedIdentity: true, ContainerID: "container_actual", ImageID: digest, ManifestDigest: digest, HostPort: 45165, ContainerPort: 9898, EndpointReady: false, ObservedAt: now.Add(100 * time.Millisecond)}}
	requests := 0
	since := now.Add(-time.Minute).Format(time.RFC3339Nano)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-AcornFox-CSRF") != "" {
			t.Error("observation did not use normal authenticated read transport")
		}
		if cookie, err := r.Cookie("__Host-acornfox_session"); err != nil || cookie.Value != "session" {
			t.Error("observation omitted session")
		}
		if requests == 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"observation_unavailable","message":"observation unavailable"}`)
			return
		}
		value := observation
		switch r.URL.Path {
		case apiBase + "/image-deployments/dep_actual/observation":
			if r.URL.RawQuery != "" {
				t.Error("status sent logs query")
			}
		case apiBase + "/image-deployments/dep_actual/logs":
			if r.URL.Query().Get("tail") != "2" || r.URL.Query().Get("since") != since {
				t.Error("bounded logs arguments changed")
			}
			value.Records = []appcontracts.ImageObservationLog{{Stream: "stdout", Data: "safe log line"}}
			value.SourceLimited = true
		default:
			t.Errorf("wrong observation path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(value)
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out, notes bytes.Buffer
	c := &cli{out: &out, err: &notes, env: env, client: server.Client(), json: false}
	if err := c.command([]string{"image", "status", "dep_actual"}); err != nil || !strings.Contains(notes.String(), "not probed") {
		t.Fatalf("status/not-probed semantics lost: %v", err)
	}
	out.Reset()
	c.json = true
	if err := c.command([]string{"image", "logs", "dep_actual", "--tail", "2", "--since", since}); err != nil {
		t.Fatal(err)
	}
	var actual appcontracts.ImageObservationResult
	if err := json.Unmarshal(out.Bytes(), &actual); err != nil || actual.State.EndpointReady || !actual.SourceLimited || len(actual.Records) != 1 || actual.Records[0].Data != "safe log line" {
		t.Fatal("real limited logs/state result lost")
	}
	for _, args := range [][]string{{"image", "logs", "dep_actual", "--tail", "65"}, {"image", "logs", "dep_actual", "--tail", "01"}, {"image", "logs", "dep_actual", "--since", "invalid"}, {"image", "logs", "dep_actual", "--since", now.Add(-time.Hour).Format(time.RFC3339)}, {"image", "logs", "dep_actual", "--tail", "1", "--tail", "2"}, {"image", "status", "dep_actual", "--since", since}} {
		if err := c.command(args); err == nil {
			t.Fatalf("invalid observation argument accepted: %v", args)
		}
	}
	if requests != 2 {
		t.Fatal("invalid observation bounds sent an extra request")
	}
	var apiErr apiError
	if err := c.command([]string{"image", "status", "dep_actual"}); !errors.As(err, &apiErr) || apiErr.Code != "observation_unavailable" || apiErr.class() != "unavailable" {
		t.Fatal("real structured observation failure lost")
	}
	bad := observation
	bad.Records = []appcontracts.ImageObservationLog{{Stream: "stdout", Data: strings.Repeat("x", appcontracts.ImageObservationLogBytes+1)}}
	encoded, _ := json.Marshal(bad)
	if _, err := decodeResponse(bytes.NewReader(encoded), shapeImageLogObservation); err == nil {
		t.Fatal("oversized logs decoded")
	}
}

func TestNativeImageMetricsAndRecentReadOnlyTransport(t *testing.T) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	cpu, oldCPU := uint64(5), uint64(100)
	state := appcontracts.ImageLifecycleResult{Running: true, VerifiedIdentity: true, ContainerID: "metric_cid", ImageID: digest, ManifestDigest: digest, HostPort: 45165, ContainerPort: 9898, EndpointReady: false, ObservedAt: now}
	current := appcontracts.ImageMetricsResult{State: state, Available: true, SampledAt: now, ProcessStartedAt: now.Add(-5 * time.Second), CPUUsageMillis: &cpu}
	start := now.Add(-20 * time.Second)
	segment := now.Add(-4 * time.Second)
	firstProcess := now.Add(-time.Minute)
	secondProcess := now.Add(-5 * time.Second)
	recent := appcontracts.ImageMetricsRecentResult{DeploymentID: "dep_metric", ContainerID: state.ContainerID, HistoryEpoch: now.Add(-time.Minute), HistoryStart: &start, SegmentStart: &segment, CurrentSegmentID: 2, Scheduled: true, StaleAfterSeconds: 250, Stale: false, RecordingStatus: "recording", Samples: []appcontracts.ImageMetricsHistoryPoint{{SegmentID: 1, ContainerID: state.ContainerID, ProcessStartedAt: &firstProcess, ObservedAt: start, Available: true, CPUUsageMillis: &oldCPU}, {SegmentID: 2, ContainerID: state.ContainerID, ProcessStartedAt: &secondProcess, ObservedAt: segment, Available: true, CPUUsageMillis: &cpu}}}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-AcornFox-CSRF") != "" {
			t.Fatal("metrics call changed normal read transport")
		}
		if cookie, err := r.Cookie("__Host-acornfox_session"); err != nil || cookie.Value != "session" {
			t.Error("metrics call omitted session")
		}
		switch requests {
		case 1:
			if r.URL.Path != apiBase+"/image-deployments/dep_metric/metrics" || r.URL.RawQuery != "" {
				t.Error("current metrics path/query invalid")
			}
			_ = json.NewEncoder(w).Encode(current)
		case 2:
			if r.URL.Path != apiBase+"/image-deployments/dep_metric/metrics/recent" || r.URL.RawQuery != "limit=2" {
				t.Error("recent metrics path/query invalid")
			}
			_ = json.NewEncoder(w).Encode(recent)
		case 3:
			if r.URL.Path != apiBase+"/image-deployments/dep_metric/metrics/recent" || r.URL.RawQuery != "limit=1" {
				t.Error("request-bound recent fixture route changed")
			}
			_ = json.NewEncoder(w).Encode(recent) // Deliberately exceeds requested one point.
		case 4:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"metrics_unavailable","message":"metrics unavailable"}`)
		default:
			t.Error("invalid metrics argument sent a request")
		}
	}))
	defer server.Close()
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cli{out: &out, err: io.Discard, env: env, client: server.Client(), json: true}
	if err := c.command([]string{"image", "metrics", "dep_metric"}); err != nil {
		t.Fatal(err)
	}
	var gotCurrent appcontracts.ImageMetricsResult
	if err := json.Unmarshal(out.Bytes(), &gotCurrent); err != nil || gotCurrent.CPUUsageMillis == nil || *gotCurrent.CPUUsageMillis != cpu || gotCurrent.MemoryUsageBytes != nil {
		t.Fatal("current metric nil/observed values were changed")
	}
	out.Reset()
	if err := c.command([]string{"image", "metrics-recent", "dep_metric", "--limit", "2"}); err != nil {
		t.Fatal(err)
	}
	var gotRecent appcontracts.ImageMetricsRecentResult
	if err := json.Unmarshal(out.Bytes(), &gotRecent); err != nil || len(gotRecent.Samples) != 2 || gotRecent.StaleAfterSeconds != 250 || gotRecent.Samples[1].SegmentID != 2 || gotRecent.Samples[1].CPUPercent != nil || gotRecent.Samples[1].CPUUsageMillis == nil || *gotRecent.Samples[1].CPUUsageMillis != cpu {
		t.Fatal("recent segment/rate/actual freshness budget changed")
	}
	for _, args := range [][]string{{"image", "metrics-recent", "dep_metric", "--limit", "0"}, {"image", "metrics-recent", "dep_metric", "--limit", "361"}, {"image", "metrics-recent", "dep_metric", "--limit", "02"}, {"image", "metrics-recent", "dep_metric", "--limit", "2", "--limit", "3"}, {"image", "metrics", "dep_metric", "--limit", "2"}} {
		if err := c.command(args); err == nil {
			t.Fatalf("invalid metrics argument accepted: %v", args)
		}
	}
	if requests != 2 {
		t.Fatal("bad metrics bounds reached server")
	}
	var apiErr apiError
	out.Reset()
	if err := c.command([]string{"image", "metrics-recent", "dep_metric", "--limit", "1"}); !errors.As(err, &apiErr) || !apiErr.contract || out.Len() != 0 {
		t.Fatal("server exceeded requested sample count")
	}
	if err := c.command([]string{"image", "metrics", "dep_metric"}); !errors.As(err, &apiErr) || apiErr.Code != "metrics_unavailable" || apiErr.class() != "unavailable" {
		t.Fatal("real structured metrics error lost")
	}
	outside := appcontracts.ImageMetricsRecentResult{DeploymentID: "dep_metric", ContainerID: state.ContainerID, HistoryEpoch: now, Scheduled: false, SelectionLimited: true, StaleAfterSeconds: 30, Stale: true, RecordingStatus: "not_selected", Reason: "outside_sampling_selection", Samples: []appcontracts.ImageMetricsHistoryPoint{}}
	encoded, _ := json.Marshal(outside)
	if _, err := decodeResponse(bytes.NewReader(encoded), shapeImageMetricsRecent); err != nil {
		t.Fatal("outside32 sampling was treated as zero/invalid", err)
	}
	unavailable := recent
	unavailable.RecordingStatus = "stale"
	unavailable.Stale = true
	unavailable.Reason = "not_running"
	unavailable.Samples = append([]appcontracts.ImageMetricsHistoryPoint(nil), recent.Samples...)
	unavailable.Samples[1] = appcontracts.ImageMetricsHistoryPoint{SegmentID: 2, ContainerID: state.ContainerID, ObservedAt: segment, Available: false, UnavailableReason: "not_running"}
	encoded, _ = json.Marshal(unavailable)
	if _, err := decodeResponse(bytes.NewReader(encoded), shapeImageMetricsRecent); err != nil {
		t.Fatal("unavailable sample was forged as zero", err)
	}
	bad := recent
	bad.DeploymentID = "dep_other"
	encoded, _ = json.Marshal(bad)
	if _, err := decodeResponse(bytes.NewReader(encoded), shapeImageMetricsRecent); err != nil {
		t.Fatal("typed recent fixture invalid", err)
	}
	if _, err := decodeResponse(bytes.NewReader(bytes.Repeat([]byte(" "), appcontracts.ImageMetricsJSONBytes+1)), shapeImageMetrics); err == nil {
		t.Fatal("4KiB current response bound lost")
	}
	if _, err := decodeResponse(bytes.NewReader(bytes.Repeat([]byte(" "), appcontracts.ImageMetricsHistoryJSONBytes+1)), shapeImageMetricsRecent); err == nil {
		t.Fatal("256KiB recent response bound lost")
	}
}
