package publicconsole

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Fetcher returns the trimmed body of a successful GET of url.
type Fetcher func(ctx context.Context, url string) (string, error)

// MetadataIPv4URLs are cloud metadata endpoints that return this instance's
// public IPv4, tried in order. They only answer from inside the instance.
var MetadataIPv4URLs = []string{
	"http://100.100.100.200/latest/meta-data/eipv4",                // 阿里云（弹性公网 IP）
	"http://100.100.100.200/latest/meta-data/public-ipv4",          // 阿里云（固定公网 IP）
	"http://metadata.tencentyun.com/latest/meta-data/public-ipv4",  // 腾讯云
	"http://100.96.0.96/latest/eip_address",                        // 火山引擎
}

// PublicIPv4URLs and PublicIPv6URLs are public "what is my IP" services used
// when no metadata endpoint answers. The first of each is reachable in China.
var (
	PublicIPv4URLs = []string{"https://4.ipw.cn", "https://ipv4.icanhazip.com"}
	PublicIPv6URLs = []string{"https://6.ipw.cn", "https://ipv6.icanhazip.com"}
)

// PublicIPs is what DetectPublicIPs found.
type PublicIPs struct {
	V4     []string `json:"ipv4,omitempty"`
	V6     []string `json:"ipv6,omitempty"`
	Source string   `json:"source,omitempty"` // "metadata" or "public"
}

// All returns every address, IPv4 first.
func (p PublicIPs) All() []string { return append(append([]string(nil), p.V4...), p.V6...) }

// DetectPublicIPs finds this server's public addresses: cloud metadata first,
// then public services. A failing source is skipped, never fatal.
func DetectPublicIPs(ctx context.Context, fetch Fetcher) PublicIPs {
	var out PublicIPs
	for _, u := range MetadataIPv4URLs {
		if ip, ok := firstPublic(ctx, fetch, u, true); ok {
			out.V4, out.Source = []string{ip}, "metadata"
			break
		}
	}
	if len(out.V4) == 0 {
		for _, u := range PublicIPv4URLs {
			if ip, ok := firstPublic(ctx, fetch, u, true); ok {
				out.V4, out.Source = []string{ip}, "public"
				break
			}
		}
	}
	for _, u := range PublicIPv6URLs {
		if ip, ok := firstPublic(ctx, fetch, u, false); ok {
			out.V6 = []string{ip}
			if out.Source == "" {
				out.Source = "public"
			}
			break
		}
	}
	return out
}

func firstPublic(ctx context.Context, fetch Fetcher, url string, wantV4 bool) (string, bool) {
	body, err := fetch(ctx, url)
	if err != nil {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(body))
	if err != nil || addr.Is4() != wantV4 || !isPublic(addr) {
		return "", false
	}
	return addr.String(), true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// HTTPFetcher is the production Fetcher: a short timeout, no proxy, only 200
// answers, at most 256 bytes.
func HTTPFetcher(timeout time.Duration) Fetcher {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
	return func(ctx context.Context, url string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", &net.AddrError{Err: resp.Status, Addr: url}
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		return strings.TrimSpace(string(b)), err
	}
}
