package publicconsole

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

// fakeResolver answers per DNS server.
type fakeResolver map[string]struct {
	ips []string
	err error
}

func (f fakeResolver) LookupIPs(_ context.Context, server, _ string) ([]string, error) {
	a := f[server]
	return a.ips, a.err
}

var notFound = &net.DNSError{Err: "no such host", Name: "panel.example.com", IsNotFound: true}
var dnsTimeout = &net.DNSError{Err: "i/o timeout", Name: "panel.example.com", IsTimeout: true}

var mine = PublicIPs{V4: []string{"203.0.113.10"}}

func TestCheckDNS(t *testing.T) {
	cases := []struct {
		name string
		r    fakeResolver
		want string
		hint string
	}{
		{"ok on both servers", fakeResolver{
			"a": {ips: []string{"203.0.113.10"}}, "b": {ips: []string{"203.0.113.10"}},
		}, CodeOK, ""},
		{"ok when one server is slow", fakeResolver{
			"a": {err: dnsTimeout}, "b": {ips: []string{"203.0.113.10"}},
		}, CodeOK, ""},
		{"unresolved", fakeResolver{
			"a": {err: notFound}, "b": {err: notFound},
		}, CodeDNSUnresolved, "A 记录：主机记录 panel，记录值 203.0.113.10"},
		{"points elsewhere", fakeResolver{
			"a": {ips: []string{"198.51.100.7"}}, "b": {ips: []string{"198.51.100.7"}},
		}, CodeDNSMismatch, "CDN"},
		{"stray AAAA record", fakeResolver{
			"a": {ips: []string{"203.0.113.10", "2001:db8::1"}}, "b": {ips: []string{"203.0.113.10"}},
		}, CodeDNSMismatch, "删除指向其他地址的记录"},
		{"all servers time out", fakeResolver{
			"a": {err: dnsTimeout}, "b": {err: dnsTimeout},
		}, CodeDNSError, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckDNS(context.Background(), c.r, []string{"a", "b"}, "panel.example.com", mine)
			if got.Code != c.want {
				t.Fatalf("code = %s (%s), want %s", got.Code, got.Message, c.want)
			}
			if c.hint != "" && !strings.Contains(got.Hint, c.hint) {
				t.Fatalf("hint %q lacks %q", got.Hint, c.hint)
			}
		})
	}
}

// fakeGetter returns a canned answer per URL.
type fakeGetter map[string]struct {
	status int
	body   string
	err    error
}

func (f fakeGetter) Get(_ context.Context, u string) (int, []byte, error) {
	a, ok := f[u]
	if !ok {
		return 0, nil, fmt.Errorf("unexpected url %s", u)
	}
	return a.status, []byte(a.body), a.err
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func opErr(err error) error {
	return &url.Error{Op: "Get", URL: "http://panel.example.com/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: err}}
}

const icpPage = `<html><head><title>Non-compliance ICP Filing</title></head><body>该网站暂时无法进行访问，可能由于未按照《非经营性互联网信息服务备案管理办法》进行备案</body></html>`

func TestProbeHTTP(t *testing.T) {
	const u = "http://panel.example.com/.well-known/acornfox-verify/abc"
	cases := []struct {
		name string
		ans  fakeGetter
		want string
	}{
		{"token served", fakeGetter{u: {status: 200, body: "tok\n"}}, CodeOK},
		{"port 80 refused", fakeGetter{u: {err: opErr(syscall.ECONNREFUSED)}}, CodePortClosed},
		{"port 80 dropped by security group", fakeGetter{u: {err: opErr(timeoutErr{})}}, CodePortUnreachable},
		{"unfiled domain intercepted", fakeGetter{u: {status: 403, body: icpPage}}, CodeICPBlocked},
		{"CDN answers instead", fakeGetter{u: {status: 200, body: "<html>cdn</html>"}}, CodeWrongTarget},
		{"other server 404", fakeGetter{u: {status: 404, body: "not found"}}, CodeWrongTarget},
		{"connection reset", fakeGetter{u: {err: opErr(syscall.ECONNRESET)}}, CodeConnReset},
		{"local DNS not updated", fakeGetter{u: {err: &url.Error{Op: "Get", URL: u, Err: notFound}}}, CodeDNSUnresolved},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ProbeHTTP(context.Background(), c.ans, "panel.example.com", "/.well-known/acornfox-verify/abc", "tok")
			if got.Code != c.want {
				t.Fatalf("code = %s (%s), want %s", got.Code, got.Message, c.want)
			}
		})
	}
	if d := ProbeHTTP(context.Background(), fakeGetter{u: {err: opErr(syscall.ECONNREFUSED)}}, "panel.example.com", "/.well-known/acornfox-verify/abc", "tok"); !strings.Contains(d.Hint, "安全组") {
		t.Fatalf("port hint = %q", d.Hint)
	}
	if d := ProbeHTTP(context.Background(), fakeGetter{u: {status: 403, body: icpPage}}, "panel.example.com", "/.well-known/acornfox-verify/abc", "tok"); !strings.Contains(d.Hint, "该域名未备案，国内服务器无法使用") {
		t.Fatalf("icp hint = %q", d.Hint)
	}
}

func TestProbeHTTPS(t *testing.T) {
	const u = "https://panel.example.com/login"
	cases := []struct {
		name string
		ans  fakeGetter
		want string
	}{
		{"ready", fakeGetter{u: {status: 200, body: "<html>登录</html>"}}, CodeOK},
		{"certificate not issued yet", fakeGetter{u: {err: &url.Error{Op: "Get", URL: u, Err: x509.UnknownAuthorityError{}}}}, CodeCertPending},
		{"tls alert", fakeGetter{u: {err: &url.Error{Op: "Get", URL: u, Err: errors.New("remote error: tls: internal error")}}}, CodeCertPending},
		{"443 closed", fakeGetter{u: {err: opErr(syscall.ECONNREFUSED)}}, CodePortClosed},
		{"443 timeout", fakeGetter{u: {err: opErr(timeoutErr{})}}, CodePortUnreachable},
		{"icp page over https", fakeGetter{u: {status: 403, body: icpPage}}, CodeICPBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ProbeHTTPS(context.Background(), c.ans, "panel.example.com")
			if got.Code != c.want {
				t.Fatalf("code = %s (%s), want %s", got.Code, got.Message, c.want)
			}
		})
	}
}

func TestDetectPublicIPs(t *testing.T) {
	fetch := func(answers map[string]string) Fetcher {
		return func(_ context.Context, u string) (string, error) {
			if v, ok := answers[u]; ok {
				return v, nil
			}
			return "", errors.New("unreachable")
		}
	}
	// Aliyun EIP from metadata; no IPv6.
	got := DetectPublicIPs(context.Background(), fetch(map[string]string{MetadataIPv4URLs[0]: "203.0.113.10"}))
	if len(got.V4) != 1 || got.V4[0] != "203.0.113.10" || got.Source != "metadata" || len(got.V6) != 0 {
		t.Fatalf("aliyun = %+v", got)
	}
	// Volcengine (last metadata URL) after others fail or return junk.
	got = DetectPublicIPs(context.Background(), fetch(map[string]string{
		MetadataIPv4URLs[1]: "<html>404</html>",
		MetadataIPv4URLs[3]: "198.51.100.20",
	}))
	if len(got.V4) != 1 || got.V4[0] != "198.51.100.20" {
		t.Fatalf("volcengine = %+v", got)
	}
	// Private metadata answer ignored; public service and IPv6 used.
	got = DetectPublicIPs(context.Background(), fetch(map[string]string{
		MetadataIPv4URLs[2]: "10.0.0.5",
		PublicIPv4URLs[0]:   "203.0.113.11",
		PublicIPv6URLs[0]:   "2001:db8:1::5",
	}))
	if got.Source != "public" || got.V4[0] != "203.0.113.11" || len(got.V6) != 1 {
		t.Fatalf("public = %+v", got)
	}
	// CGNAT is not public.
	got = DetectPublicIPs(context.Background(), fetch(map[string]string{PublicIPv4URLs[0]: "100.64.1.2"}))
	if len(got.All()) != 0 {
		t.Fatalf("cgnat accepted: %+v", got)
	}
}

func TestHostRecordAndNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"panel.example.com":    "panel",
		"example.com":          "@",
		"a.b.example.com":      "a.b",
		"panel.example.com.cn": "panel",
		"example.com.cn":       "@",
	} {
		if got := HostRecord(in); got != want {
			t.Errorf("HostRecord(%s) = %s, want %s", in, got, want)
		}
	}
	if d, ok := NormalizeDomain(" Panel.Example.COM. "); !ok || d != "panel.example.com" {
		t.Errorf("normalize = %q %v", d, ok)
	}
	for _, bad := range []string{"", "localhost", "https://panel.example.com", "panel.example.com:443", "1.2.3.4", "pa nel.example.com"} {
		if _, ok := NormalizeDomain(bad); ok {
			t.Errorf("NormalizeDomain(%q) accepted", bad)
		}
	}
}
