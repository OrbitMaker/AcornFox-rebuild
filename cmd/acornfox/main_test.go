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

func TestCallResponseContractAndSessionRemoval(t *testing.T) {
	stateRoot := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return stateRoot
		}
		return ""
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiBase + "/apps":
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, `{"items":[]}`)
				return
			}
			if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("Origin") != server.URL || r.Header.Get("X-AcornFox-CSRF") != "csrf" {
				t.Errorf("write proof headers=%v", r.Header)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"application":{"id":"app","name":"demo","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"},"source_revision_id":"source","operation_id":"operation"}`)
		case apiBase + "/auth/logout":
			if r.Header.Get("Idempotency-Key") != "" || r.Header.Get("Origin") != server.URL || r.Header.Get("X-AcornFox-CSRF") != "csrf" {
				t.Errorf("logout proof headers=%v", r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"code":"not_found","message":"not found"}`)
		}
	}))
	defer server.Close()
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := &cli{in: strings.NewReader(""), out: &output, err: io.Discard, env: env, client: server.Client(), json: true}
	if err := c.apps([]string{"create", "--name", "demo", "--repository", "https://github.com/example/repo.git", "--ref", "main"}); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "{\"application\":{\"id\":\"app\",\"name\":\"demo\",\"created_at\":\"2030-01-01T00:00:00Z\",\"updated_at\":\"2030-01-01T00:00:00Z\"},\"source_revision_id\":\"source\",\"operation_id\":\"operation\"}\n"; got != want {
		t.Fatalf("json=%q", got)
	}
	output.Reset()
	if err := c.logout(nil); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "{\"ok\":true}\n" {
		t.Fatalf("204 json=%q", got)
	}
	if _, err := loadState(env); err == nil {
		t.Fatal("logout did not remove session")
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

func TestUnauthorizedAndPasswordSuccessRemoveState(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			root := t.TempDir()
			env := func(key string) string {
				if key == "XDG_STATE_HOME" {
					return root
				}
				return ""
			}
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == http.StatusUnauthorized {
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `{"code":"invalid_session","message":"invalid"}`)
					return
				}
				if r.URL.Path != apiBase+"/auth/password" || r.Header.Get("Idempotency-Key") != "" {
					t.Errorf("password request=%s headers=%v", r.URL.Path, r.Header)
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			c := &cli{in: strings.NewReader("old\nnew\nnew\n"), out: io.Discard, err: io.Discard, env: env, client: server.Client()}
			var err error
			if status == http.StatusUnauthorized {
				err = c.apps([]string{"list"})
			} else {
				err = c.password([]string{"--password-stdin"})
			}
			if status == http.StatusUnauthorized && err == nil {
				t.Fatal("401 accepted")
			}
			if status == http.StatusNoContent && err != nil {
				t.Fatal(err)
			}
			if _, loadErr := loadState(env); loadErr == nil {
				t.Fatal("state persisted after session-ending response")
			}
		})
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

func TestAllCommandFamiliesUseTheirDeclaredRouteAndProof(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isWrite := r.Method == http.MethodPost || r.Method == http.MethodPut
		if session := cookieRequest(r, "__Host-acornfox_session"); session != "session" {
			t.Errorf("%s missing session cookie", r.URL.Path)
		}
		if isWrite {
			if r.Header.Get("Origin") != server.URL || r.Header.Get("X-AcornFox-CSRF") != "csrf" || r.Header.Get("Idempotency-Key") == "" {
				t.Errorf("%s write proof headers=%v", r.URL.Path, r.Header)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("%s invalid JSON body: %v", r.URL.Path, err)
			}
			if r.URL.Path == apiBase+"/apps" && body["name"] != "demo" {
				t.Errorf("app body=%v", body)
			}
			if r.URL.Path == apiBase+"/apps/app/deliveries" && (body["source_revision_id"] != "source" || body["container_port"] != float64(8080)) {
				t.Errorf("deploy body=%v", body)
			}
			if r.URL.Path == apiBase+"/apps/app/deliveries/deployment/probes" && (len(body) != 2 || body["protocol"] != "http" || body["path"] != "/") {
				t.Errorf("probe body=%v", body)
			}
			if r.URL.Path == apiBase+"/apps/app/deliveries/deployment/public-access" {
				if _, ok := body["enabled"].(bool); !ok {
					t.Errorf("public body=%v", body)
				}
			}
		} else if r.Header.Get("Origin") != "" || r.Header.Get("X-AcornFox-CSRF") != "" || r.Header.Get("Idempotency-Key") != "" || cookieRequest(r, "__Host-acornfox_csrf") != "" {
			t.Errorf("%s read had write proof headers=%v", r.URL.Path, r.Header)
		}
		var response string
		status := http.StatusOK
		switch r.URL.Path {
		case apiBase + "/host/metrics":
			response = `{"schema_version":1,"availability":"warming_up","observed_at":"2030-01-01T00:00:00Z","stale_after_seconds":15,"cpu":{"logical_cores":4},"memory":{"total_bytes":4096,"available_bytes":1024,"used_bytes":3072},"disk":{"mountpoint":"/","total_bytes":8192,"free_bytes":4096,"used_bytes":4096}}`
		case apiBase + "/apps":
			if r.Method == http.MethodGet {
				response = `{"items":[]}`
			} else {
				status = http.StatusCreated
				response = `{"application":{"id":"app","name":"demo","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"},"source_revision_id":"source","operation_id":"operation"}`
			}
		case apiBase + "/apps/app":
			response = `{"id":"app","name":"demo","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"}`
		case apiBase + "/apps/app/operations/operation":
			response = `{"operation_id":"operation","operation_type":"observe","status":"verified","task_id":"task","deployment_id":"deployment","accepted_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:01Z","evidence":{"kind":"response_observation","verdict":"unhealthy","observed_at":"2030-01-01T00:00:01Z","http_status":500}}`
		case apiBase + "/apps/app/sources":
			if r.Method == http.MethodGet {
				response = `{"items":[],"next_cursor":null}`
			} else {
				status = http.StatusCreated
				response = `{"source_revision_id":"source-new","status":"imported"}`
			}
		case apiBase + "/apps/app/sources/source":
			response = `{"id":"source","application_id":"app","kind":"git_https","locator_sha256":"digest","content_digest":"content","created_at":"2030-01-01T00:00:00Z","immutable":true}`
		case apiBase + "/apps/app/sources/source/metadata":
			response = `{"source_revision_id":"source","availability":"unavailable"}`
		case apiBase + "/apps/app/sources/source/deployment-plan":
			response = `{"application_id":"app","source_revision_id":"source","repository_url":"https://github.com/example/repo.git","ref":"main","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dockerfile":{"status":"ready","path":"Dockerfile","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","stage_count":1,"final_stage":{"name":"final","index":0,"from":"scratch"}},"ports":[{"port":8080,"protocol":"tcp","source":"dockerfile_expose"}],"port_selection":{"status":"selected","reason":"dockerfile_expose","selected_port":8080,"candidates":[8080]},"healthcheck":{"present":false},"environment":[],"gaps":["healthcheck_missing"],"warnings":[],"required_actions":[],"ready_to_deploy":true}`
		case apiBase + "/apps/app/deliveries":
			if r.Method == http.MethodGet {
				response = `{"items":[],"next_cursor":null}`
			} else {
				status = http.StatusAccepted
				response = `{"deployment_id":"deployment","operation_id":"operation","task_id":"task","status":"accepted"}`
			}
		case apiBase + "/apps/app/deliveries/deployment":
			response = `{"deployment":{"id":"deployment","application_id":"app","environment_id":"environment","release_id":"release","stage":"starting","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"},"desired":null,"runtime":null,"response":null}`
		case apiBase + "/apps/app/deliveries/deployment/source":
			response = `{"deployment_id":"deployment","availability":"unavailable"}`
		case apiBase + "/apps/app/deliveries/deployment/logs":
			if r.URL.Query().Get("source") != "runtime" || r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("cursor") != "opaque" {
				t.Errorf("logs query=%q", r.URL.RawQuery)
			}
			response = `{"source":"runtime","availability":"available","items":[],"next_cursor":null,"retention_limited":false}`
		case apiBase + "/apps/app/deliveries/deployment/probes":
			status = http.StatusAccepted
			response = `{"deployment_id":"deployment","operation_id":"operation","task_id":"task","status":"accepted"}`
		case apiBase + "/apps/app/deliveries/deployment/restart", apiBase + "/apps/app/deliveries/deployment/redeploy":
			status = http.StatusAccepted
			response = `{"deployment_id":"deployment","operation_id":"operation","task_id":"task","status":"accepted"}`
		case apiBase + "/apps/app/deliveries/deployment/public-access":
			response = `{"desired_public":true,"url":"https://app.example.test","endpoint":{"deployment_id":"deployment"},"components":{"internal_endpoint":"accepted","local_route":"configured","dns":"not_validated","tls":"not_validated","external":"not_validated"},"status":"PENDING_EXTERNAL_VALIDATION"}`
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			response = `{"code":"not_found","message":"not found"}`
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c := &cli{in: strings.NewReader(""), out: io.Discard, err: io.Discard, env: env, client: server.Client(), json: true}
	commands := [][]string{
		{"host", "metrics"}, {"apps", "list"}, {"apps", "get", "app"}, {"operation", "app", "operation"}, {"apps", "create", "--name", "demo", "--repository", "https://github.com/example/repo.git", "--ref", "main"},
		{"up", "https://github.com/example/repo.git", "--name", "demo", "--ref", "main", "--port", "8080"},
		{"sources", "list", "app", "--limit", "2", "--cursor", "opaque"}, {"sources", "update", "app", "source", "main"}, {"sources", "get", "app", "source"}, {"sources", "metadata", "app", "source"}, {"deployments", "list", "app", "--limit", "2", "--cursor", "opaque"},
		{"deploy", "app", "--source", "source", "--port", "8080"}, {"status", "app", "deployment"}, {"delivery-source", "app", "deployment"}, {"logs", "app", "deployment", "--source", "runtime", "--limit", "2", "--cursor", "opaque"},
		{"probe", "app", "deployment"}, {"restart", "app", "deployment"}, {"redeploy", "app", "deployment"}, {"public-access", "get", "app", "deployment"}, {"public-access", "enable", "app", "deployment"}, {"public-access", "disable", "app", "deployment"},
	}
	for _, args := range commands {
		if err := c.command(args); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
}

func TestUpRequiresPortWhenDeploymentPlanIsAmbiguous(t *testing.T) {
	root := t.TempDir()
	env := func(key string) string {
		if key == "XDG_STATE_HOME" {
			return root
		}
		return ""
	}
	deployed := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == apiBase+"/apps" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"application":{"id":"app","name":"demo","created_at":"2030-01-01T00:00:00Z","updated_at":"2030-01-01T00:00:00Z"},"source_revision_id":"source","operation_id":"operation"}`)
		case r.URL.Path == apiBase+"/apps/app/sources/source/deployment-plan":
			_, _ = io.WriteString(w, `{"application_id":"app","source_revision_id":"source","repository_url":"https://github.com/example/repo.git","ref":"main","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dockerfile":{"status":"ready","path":"Dockerfile","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","stage_count":1},"ports":[{"port":3000,"protocol":"tcp","source":"dockerfile_expose"},{"port":8080,"protocol":"tcp","source":"dockerfile_expose"}],"port_selection":{"status":"required","reason":"multiple_dockerfile_ports","candidates":[3000,8080]},"healthcheck":{"present":false},"environment":[],"gaps":[],"warnings":[],"required_actions":[],"ready_to_deploy":false}`)
		case r.URL.Path == apiBase+"/apps/app/deliveries":
			deployed = true
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"deployment_id":"deployment","operation_id":"operation","task_id":"task","status":"accepted"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"code":"not_found","message":"not found"}`)
		}
	}))
	defer server.Close()
	if err := saveState(env, sessionState{Origin: server.URL, Session: "session", CSRF: "csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c := &cli{in: strings.NewReader(""), out: io.Discard, err: io.Discard, env: env, client: server.Client(), json: true}
	err := c.command([]string{"up", "https://github.com/example/repo.git", "--name", "demo"})
	if err == nil || !strings.Contains(err.Error(), "3000") || !strings.Contains(err.Error(), "8080") {
		t.Fatalf("ambiguous plan error=%v", err)
	}
	if deployed {
		t.Fatal("up deployed without an explicit port")
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
