package acornfoxroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
)

type testSource struct {
	states  []RouteState
	err     error
	lockErr error
	calls   int
}

func (s *testSource) WithRoutes(_ context.Context, apply func([]RouteState, func() error) error) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	return apply(append([]RouteState(nil), s.states...), func() error { return s.lockErr })
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeCaddy struct {
	body     []byte
	tag      string
	methods  []string
	reject   bool
	reserved []byte
}

func (f *fakeCaddy) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != AdminURL+"/id/"+SubtreeID {
		panic("escaped scoped admin endpoint: " + r.URL.String())
	}
	f.methods = append(f.methods, r.Method)
	status := 200
	body := f.body
	if r.Method == http.MethodPatch {
		if r.Header.Get("If-Match") != f.tag || f.reject {
			status = 412
			body = []byte("private-canary")
		} else {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			f.body = data
			body = nil
		}
	} else if r.Method != http.MethodGet {
		panic("unsafe HTTP method")
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{"Etag": []string{f.tag}}}, nil
}
func fixture(t *testing.T) (*Provider, *testSource, *fakeCaddy, contracts.AcornFoxPublicRouteIntent) {
	t.Helper()
	host, _ := contracts.AcornFoxPublicHostname("console.example.com", "app_one", "dep_one")
	i := contracts.AcornFoxPublicRouteIntent{ApplicationID: "app_one", DeploymentID: "dep_one", Hostname: host, ServiceName: "web", Port: 39130}
	source := &testSource{states: []RouteState{{Intent: i, Enabled: true}}}
	p, err := New(Config{AuthorizedRoot: "console.example.com", Source: source})
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := json.Marshal(emptySubtree())
	server := &fakeCaddy{body: initial, tag: `"/config/apps/http/servers/public_https/routes/3/handle/0 e456"`, reserved: []byte("console and health remain unchanged")}
	p.client = &http.Client{Transport: server}
	return p, source, server, i
}
func TestScopedProjectionEnableReplayDisableAndRestart(t *testing.T) {
	p, s, c, i := fixture(t)
	if err := p.EnsureAcornFoxPublicRoute(context.Background(), i, "enable"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(c.body, []byte(i.Hostname)) || !bytes.Contains(c.body, []byte("127.0.0.1:39130")) {
		t.Fatal("missing route")
	}
	reserved := append([]byte(nil), c.reserved...)
	c.methods = nil
	// A new provider reads DB state again; it has no remembered route cache.
	other, err := New(Config{AuthorizedRoot: p.root, Source: s})
	if err != nil {
		t.Fatal(err)
	}
	other.client = p.client
	if err := other.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.methods, []string{http.MethodGet}) {
		t.Fatalf("unchanged route reloaded: %v", c.methods)
	}
	// Edge restart resets the subtree, and completed enabled DB state rebuilds it.
	c.body, _ = json.Marshal(emptySubtree())
	c.methods = nil
	if err := other.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.methods, []string{http.MethodGet, http.MethodPatch}) {
		t.Fatal(c.methods)
	}
	s.states[0].Enabled = false
	if err := p.RemoveAcornFoxPublicRoute(context.Background(), i, "disable"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c.body, []byte(i.Hostname)) || !bytes.Equal(reserved, c.reserved) {
		t.Fatal("disabled route or reserved subtree changed")
	}
}
func TestProjectionRefusesForeignOrChangedCaddySubtrees(t *testing.T) {
	for _, mode := range []string{"foreign-target", "unknown-route", "missing-etag", "etag-conflict", "unknown-field", "duplicate-field", "db-writer-conflict", "lost-db-lock"} {
		t.Run(mode, func(t *testing.T) {
			p, s, c, i := fixture(t)
			if mode == "db-writer-conflict" {
				s.err = application.ErrAcornFoxPublicAccessConflict
			} else {
				if err := p.EnsureAcornFoxPublicRoute(context.Background(), i, "one"); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "lost-db-lock":
					s.lockErr = errors.New("lost lock")
					s.states[0].Enabled = false
				case "foreign-target":
					c.body = bytes.Replace(c.body, []byte("127.0.0.1:39130"), []byte("127.0.0.1:2020"), 1)
				case "unknown-route":
					c.body = bytes.Replace(c.body, []byte(i.Hostname), []byte("foreign.example.com"), 1)
				case "missing-etag":
					c.tag = ""
				case "etag-conflict":
					c.reject = true
					s.states[0].Enabled = false
				case "unknown-field":
					c.body = append([]byte(`{"foreign":true,`), c.body[1:]...)
				case "duplicate-field":
					c.body = bytes.Replace(c.body, []byte(`"handler":"subroute"`), []byte(`"handler":"other","handler":"subroute"`), 1)
				}
			}
			c.methods = nil
			err := p.Reconcile(context.Background())
			if err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatalf("unsafe success/error %v", err)
			}
			if mode != "etag-conflict" {
				for _, method := range c.methods {
					if method != http.MethodGet {
						t.Fatal("foreign projection overwritten")
					}
				}
			}
		})
	}
}
func TestValidateIntentRejectsHostnameAndLocalAdminTargets(t *testing.T) {
	p, s, c, i := fixture(t)
	for _, port := range []int{0, 80, 443, 2019, 2020, 5432, 8080, 8092, 18481, 18482, 65536} {
		bad := i
		bad.Port = port
		if ValidateIntent(p.root, bad) == nil {
			t.Fatal("unsafe port", port)
		}
	}
	for _, host := range []string{"console.example.com", "delivery-fake.apps.console.example.com", "foreign.example.com", i.Hostname + ".evil.example", strings.ToUpper(i.Hostname)} {
		bad := i
		bad.Hostname = host
		if ValidateIntent(p.root, bad) == nil {
			t.Fatal("unsafe hostname")
		}
	}
	bad := i
	bad.DeploymentID = "dep_other"
	if err := p.EnsureAcornFoxPublicRoute(context.Background(), bad, "key"); !errors.Is(err, application.ErrAcornFoxPublicAccessOwnershipConflict) || len(c.methods) != 0 {
		t.Fatal(err)
	}
	s.states[0].Enabled = false
	if err := p.EnsureAcornFoxPublicRoute(context.Background(), i, "key"); err == nil {
		t.Fatal("enabled unpersisted request")
	}
}
func TestCaddyClientHasNoAmbientProxyOrRedirect(t *testing.T) {
	p, err := New(Config{AuthorizedRoot: "console.example.com", Source: &testSource{}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.client.Transport.(*http.Transport).Proxy != nil || p.client.CheckRedirect(nil, nil) == nil {
		t.Fatal("unsafe admin transport")
	}
}
