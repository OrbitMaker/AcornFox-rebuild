package cli

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/client"
)

// scriptedDNS answers every server the same way, one answer per check round.
type scriptedDNS struct {
	rounds [][]string // nil entry = NXDOMAIN
	calls  int
	perRun int
}

func (s *scriptedDNS) LookupIPs(_ context.Context, _, host string) ([]string, error) {
	i := s.calls / s.perRun
	s.calls++
	if i >= len(s.rounds) {
		i = len(s.rounds) - 1
	}
	if s.rounds[i] == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return s.rounds[i], nil
}

type scriptedHTTP struct {
	challenge func() (int, string, error)
	https     func() (int, string, error)
	tokenPath string
}

func (s *scriptedHTTP) Get(_ context.Context, u string) (int, []byte, error) {
	var st int
	var body string
	var err error
	if strings.HasPrefix(u, "https://") {
		st, body, err = s.https()
	} else {
		st, body, err = s.challenge()
	}
	return st, []byte(body), err
}

func refused() error {
	return &url.Error{Op: "Get", URL: "http://x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
}

// installNet swaps the CLI's network for scripted fakes and a virtual clock.
func installNet(t *testing.T, dns *scriptedDNS, web *scriptedHTTP) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	orig := newPublicConsoleNet
	newPublicConsoleNet = func() *publicConsoleNet {
		return &publicConsoleNet{
			resolver: dns,
			getter:   web,
			dns:      []string{"223.5.5.5", "1.1.1.1"},
			interval: 15 * time.Second,
			certWait: time.Minute,
			sleep: func(_ context.Context, d time.Duration) error {
				now = now.Add(d)
				return nil
			},
			now: func() time.Time { return now },
		}
	}
	t.Cleanup(func() { newPublicConsoleNet = orig })
	return &now
}

func verifyOK(_ context.Context, domain string) (client.PublicConsoleVerify, error) {
	v := client.PublicConsoleVerify{Domain: domain, VerifyID: "v1", Path: "/.well-known/acornfox-verify/v1", Token: "tok"}
	v.IPs.V4 = []string{"203.0.113.10"}
	return v, nil
}

func TestPublicConsoleEnableHappyPath(t *testing.T) {
	h := newHarness(t)
	h.addTarget("prod", "http://127.0.0.1:1")
	var gotVerifyID string
	h.api.pcVerifyFn = verifyOK
	h.api.pcEnableFn = func(_ context.Context, d, id string, reset bool) (client.PublicConsoleEnabled, error) {
		gotVerifyID = id
		return client.PublicConsoleEnabled{Domain: d, URL: "https://" + d, Password: "aaaaaa-bbbbbb-cccccc-dddddd"}, nil
	}
	// DNS not there for two rounds, then correct; HTTPS needs one retry.
	dns := &scriptedDNS{rounds: [][]string{nil, nil, {"203.0.113.10"}}, perRun: 2}
	httpsCalls := 0
	web := &scriptedHTTP{
		challenge: func() (int, string, error) { return 200, "tok", nil },
		https: func() (int, string, error) {
			httpsCalls++
			if httpsCalls == 1 {
				return 0, "", &url.Error{Op: "Get", URL: "https://x", Err: errTLS{}}
			}
			return 200, "login", nil
		},
	}
	installNet(t, dns, web)

	code, out, errOut := h.run("--json", "public-console", "enable", "Panel.Example.com")
	if code != exitOK {
		t.Fatalf("exit = %d\n%s\n%s", code, out, errOut)
	}
	m := decodeJSON(t, out)
	if m["url"] != "https://panel.example.com" || gotVerifyID != "v1" {
		t.Fatalf("out = %v", m)
	}
	if strings.Contains(out, "aaaaaa-bbbbbb") {
		t.Fatal("password leaked into JSON output")
	}
	if m["https"].(map[string]any)["code"] != "ok" {
		t.Fatalf("https = %v", m["https"])
	}
	pf, _ := m["password_file"].(string)
	b, err := os.ReadFile(pf)
	if err != nil || !strings.Contains(string(b), "aaaaaa-bbbbbb-cccccc-dddddd") {
		t.Fatalf("password file %q: %v %s", pf, err, b)
	}
	if fi, _ := os.Stat(pf); fi.Mode().Perm() != 0o600 {
		t.Fatalf("password file mode = %v", fi.Mode())
	}
}

type errTLS struct{}

func (errTLS) Error() string { return "remote error: tls: internal error" }

func TestPublicConsoleEnableHumanShowsGuidance(t *testing.T) {
	h := newHarness(t)
	h.addTarget("prod", "http://127.0.0.1:1")
	h.api.pcVerifyFn = verifyOK
	enabled := false
	h.api.pcEnableFn = func(context.Context, string, string, bool) (client.PublicConsoleEnabled, error) {
		enabled = true
		return client.PublicConsoleEnabled{}, nil
	}
	installNet(t, &scriptedDNS{rounds: [][]string{nil}, perRun: 2}, &scriptedHTTP{})

	code, out, errOut := h.run("public-console", "enable", "panel.example.com", "--wait", "1m")
	if code != exitOpFailed || enabled {
		t.Fatalf("exit = %d enabled=%v", code, enabled)
	}
	if !strings.Contains(out, "A 记录：主机记录 panel，记录值 203.0.113.10") || !strings.Contains(out, "自动重查") {
		t.Fatalf("guidance missing:\n%s", out)
	}
	if strings.Count(out, "未通过") != 1 {
		t.Fatalf("same diagnosis repeated:\n%s", out)
	}
	if !strings.Contains(errOut, "等待超时") {
		t.Fatalf("stderr = %s", errOut)
	}
}

func TestPublicConsoleEnableDiagnoses(t *testing.T) {
	cases := []struct {
		name string
		dns  [][]string
		web  *scriptedHTTP
		code string
	}{
		{"unresolved", [][]string{nil}, &scriptedHTTP{}, "dns_unresolved"},
		{"points elsewhere", [][]string{{"198.51.100.7"}}, &scriptedHTTP{}, "dns_mismatch"},
		{"port 80 closed", [][]string{{"203.0.113.10"}}, &scriptedHTTP{challenge: func() (int, string, error) { return 0, "", refused() }}, "port_closed"},
		{"unfiled domain", [][]string{{"203.0.113.10"}}, &scriptedHTTP{challenge: func() (int, string, error) {
			return 403, "<title>Non-compliance ICP Filing</title>未备案", nil
		}}, "icp_blocked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.addTarget("prod", "http://127.0.0.1:1")
			h.api.pcVerifyFn = verifyOK
			h.api.pcEnableFn = func(context.Context, string, string, bool) (client.PublicConsoleEnabled, error) {
				t.Fatal("enable must not be called")
				return client.PublicConsoleEnabled{}, nil
			}
			installNet(t, &scriptedDNS{rounds: c.dns, perRun: 2}, c.web)
			code, out, _ := h.run("--json", "public-console", "enable", "panel.example.com", "--wait", "0")
			if code != exitOpFailed {
				t.Fatalf("exit = %d\n%s", code, out)
			}
			d := decodeJSON(t, out)["diagnosis"].(map[string]any)
			if d["code"] != c.code || d["hint"] == "" {
				t.Fatalf("diagnosis = %v", d)
			}
		})
	}
}

func TestPublicConsoleStatusDisableAndLocal(t *testing.T) {
	h := newHarness(t)
	var dialed client.Target
	h.connect = func(_ context.Context, tgt client.Target) (client.API, error) {
		dialed = tgt
		return h.api, nil
	}
	installNet(t, &scriptedDNS{rounds: [][]string{nil}, perRun: 1}, &scriptedHTTP{https: func() (int, string, error) { return 200, "", nil }})

	// --local needs no targets.json and dials the server's own socket.
	code, out, _ := h.run("public-console", "status", "--local")
	if code != exitOK || dialed.URL != "unix:///run/acornfox/api.sock" || !strings.Contains(out, "未开启") {
		t.Fatalf("status local = %d %q %s", code, dialed.URL, out)
	}

	h.api.pcStatusFn = func(context.Context) (client.PublicConsoleStatus, error) {
		return client.PublicConsoleStatus{Enabled: true, Domain: "panel.example.com", URL: "https://panel.example.com"}, nil
	}
	code, out, _ = h.run("--json", "public-console", "status", "--local")
	m := decodeJSON(t, out)
	if code != exitOK || m["enabled"] != true || m["https"].(map[string]any)["code"] != "ok" {
		t.Fatalf("status = %d %v", code, m)
	}

	h.api.pcDisableFn = func(context.Context) (bool, error) { return true, nil }
	code, out, _ = h.run("public-console", "disable", "--local")
	if code != exitOK || !strings.Contains(out, "已关闭公网控制台") {
		t.Fatalf("disable = %d %s", code, out)
	}

	if code, _, _ := h.run("public-console", "enable", "https://panel.example.com", "--local"); code != exitUsage {
		t.Fatalf("bad domain exit = %d", code)
	}
	if code, _, _ := h.run("public-console", "enable", "panel.example.com", "--wait", "2h", "--local"); code != exitUsage {
		t.Fatalf("long wait exit = %d", code)
	}
}
