package publicconsole

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// Getter performs one GET and returns the status and (truncated) body.
type Getter interface {
	Get(ctx context.Context, url string) (status int, body []byte, err error)
}

// ProbeHTTP fetches the ownership challenge over plain HTTP on port 80 and
// tells whether the domain really reaches this server.
func ProbeHTTP(ctx context.Context, g Getter, domain, path, token string) Diagnosis {
	status, body, err := g.Get(ctx, "http://"+domain+path)
	if err != nil {
		return classifyNetErr(err, domain, 80)
	}
	if status == http.StatusOK && strings.TrimSpace(string(body)) == token {
		return Diagnosis{Code: CodeOK, Message: fmt.Sprintf("已确认 %s 通到本服务器（80 端口）", domain)}
	}
	if IsICPBlockPage(body) {
		return Diagnosis{Code: CodeICPBlocked, Message: fmt.Sprintf("访问 %s 被云厂商拦截：域名未备案", domain), Hint: icpHint}
	}
	return Diagnosis{
		Code:    CodeWrongTarget,
		Message: fmt.Sprintf("能连上 %s 的 80 端口，但返回的不是本服务器的验证内容（HTTP %d）", domain, status),
		Hint:    "域名可能经过了 CDN 或代理，或者指向了另一台服务器。请关闭 CDN/代理，确认解析记录指向本服务器后重试。",
	}
}

// ProbeHTTPS checks that https://domain answers with a valid certificate.
func ProbeHTTPS(ctx context.Context, g Getter, domain string) Diagnosis {
	_, body, err := g.Get(ctx, "https://"+domain+"/login")
	if err != nil {
		return classifyNetErr(err, domain, 443)
	}
	if IsICPBlockPage(body) {
		return Diagnosis{Code: CodeICPBlocked, Message: fmt.Sprintf("访问 %s 被云厂商拦截：域名未备案", domain), Hint: icpHint}
	}
	return Diagnosis{Code: CodeOK, Message: fmt.Sprintf("https://%s 已可访问，证书有效", domain)}
}

// icpMarkers are fragments of the pages Chinese cloud providers return for
// domains without an ICP filing (阿里云 "Non-compliance ICP Filing"、腾讯云 /
// 火山引擎 “未备案”提示页).
var icpMarkers = []string{"备案", "icp filing", "non-compliance", "beian.miit.gov.cn", "beian.aliyun.com"}

// IsICPBlockPage reports whether body looks like an unfiled-domain page.
func IsICPBlockPage(body []byte) bool {
	s := strings.ToLower(string(body))
	for _, m := range icpMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func classifyNetErr(err error, domain string, port int) Diagnosis {
	var de *net.DNSError
	switch {
	case errors.As(err, &de):
		return Diagnosis{Code: CodeDNSUnresolved, Message: fmt.Sprintf("本机解析不到 %s", domain), Hint: "解析记录可能还没生效，请稍等几分钟再试。"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return Diagnosis{Code: CodePortClosed, Message: fmt.Sprintf("%s 的 %d 端口拒绝连接", domain, port), Hint: portHint(port)}
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return Diagnosis{
			Code:    CodeConnReset,
			Message: fmt.Sprintf("连接 %s 的 %d 端口时被对方断开", domain, port),
			Hint:    "国内服务器的域名未备案时，云厂商会直接断开连接；" + icpHint + "域名已备案的话，多半是安全组没有放行 80 和 443（电脑上开着代理软件时，端口不通也会显示为连接被断开），放行后重试。",
		}
	case isTimeout(err):
		return Diagnosis{Code: CodePortUnreachable, Message: fmt.Sprintf("连接 %s 的 %d 端口超时", domain, port), Hint: portHint(port)}
	case isTLSError(err):
		return Diagnosis{
			Code:    CodeCertPending,
			Message: fmt.Sprintf("%s 的 443 端口已通，但证书还没有就绪", domain),
			Hint:    "Caddy 正在自动申请证书，通常一两分钟。",
		}
	}
	return Diagnosis{Code: CodeHTTPError, Message: fmt.Sprintf("访问 %s 失败：%v", domain, err)}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isTLSError(err error) bool {
	var (
		cv  *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		he  x509.HostnameError
		ci  x509.CertificateInvalidError
		rec tls.RecordHeaderError
		al  tls.AlertError
	)
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) ||
		errors.As(err, &rec) || errors.As(err, &al) || strings.Contains(err.Error(), "tls:")
}

// CertFailedDiagnosis is reported when HTTPS is still not ready after waiting.
func CertFailedDiagnosis(domain string) Diagnosis {
	return Diagnosis{
		Code:    CodeCertFailed,
		Message: fmt.Sprintf("等待后 %s 的 HTTPS 证书仍未签发", domain),
		Hint:    "常见原因：80 端口没有放行（证书机构要通过 80 端口验证）；域名的 CAA 记录不允许 Let's Encrypt/ZeroSSL；同一域名短时间内申请次数过多。可在服务器上用 journalctl -u caddy 查看原因，稍后用 acornfox public-console status 再看。",
	}
}

// HTTPGetter is the production Getter: direct connection (no proxy), no
// redirects, system roots for HTTPS, body capped at 64 KB.
func HTTPGetter(timeout time.Duration) Getter {
	return &httpGetter{client: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type httpGetter struct{ client *http.Client }

func (h *httpGetter) Get(ctx context.Context, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "acornfox-public-console-check")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, err
}
