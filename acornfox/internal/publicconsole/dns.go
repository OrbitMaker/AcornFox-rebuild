package publicconsole

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Public DNS servers queried directly, so a stale local cache or a split-horizon
// resolver on the user's machine does not decide the verdict.
var (
	DNSServersCN     = []string{"223.5.5.5", "119.29.29.29"}
	DNSServersGlobal = []string{"1.1.1.1", "8.8.8.8"}
)

// Resolver looks up the A and AAAA records of host on one DNS server.
type Resolver interface {
	LookupIPs(ctx context.Context, server, host string) ([]string, error)
}

// DNSResult is the verdict of CheckDNS.
type DNSResult struct {
	Diagnosis
	Found []string `json:"found,omitempty"`
}

// CheckDNS asks every server for domain's records and compares them with
// want (this server's public addresses). Every record must point here: a
// stray record (for example an old AAAA) sends some visitors elsewhere.
func CheckDNS(ctx context.Context, r Resolver, servers []string, domain string, want PublicIPs) DNSResult {
	found := map[string]bool{}
	notFound, failed := 0, 0
	for _, srv := range servers {
		ips, err := r.LookupIPs(ctx, srv, domain)
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				notFound++
			} else {
				failed++
			}
			continue
		}
		if len(ips) == 0 {
			notFound++
		}
		for _, ip := range ips {
			if a, perr := netip.ParseAddr(ip); perr == nil {
				found[a.Unmap().String()] = true
			}
		}
	}
	list := make([]string, 0, len(found))
	for ip := range found {
		list = append(list, ip)
	}
	sort.Strings(list)
	hint := recordHint(domain, want.V4, want.V6)

	if len(list) == 0 {
		if notFound == 0 && failed > 0 {
			return DNSResult{Diagnosis: Diagnosis{
				Code:    CodeDNSError,
				Message: "查询域名解析失败：公共 DNS 服务器都没有响应",
				Hint:    "请检查本机网络后重试。",
			}}
		}
		return DNSResult{Diagnosis: Diagnosis{
			Code:    CodeDNSUnresolved,
			Message: fmt.Sprintf("域名 %s 还没有解析到任何地址", domain),
			Hint:    hint + "添加后通常几分钟内生效。",
		}}
	}

	mine := map[string]bool{}
	for _, ip := range want.All() {
		mine[ip] = true
	}
	var stray []string
	for _, ip := range list {
		if !mine[ip] {
			stray = append(stray, ip)
		}
	}
	if len(stray) > 0 {
		msg := fmt.Sprintf("域名 %s 解析到了 %s，不是本服务器（%s）", domain, strings.Join(stray, "、"), strings.Join(want.All(), "、"))
		if len(stray) < len(list) {
			msg = fmt.Sprintf("域名 %s 有一部分解析记录（%s）不是本服务器（%s）", domain, strings.Join(stray, "、"), strings.Join(want.All(), "、"))
		}
		return DNSResult{Found: list, Diagnosis: Diagnosis{
			Code:    CodeDNSMismatch,
			Message: msg,
			Hint:    hint + "并删除指向其他地址的记录。如果开启了 CDN 或代理（解析里的“代理”“加速”开关），请先关闭。修改后通常几分钟内生效。",
		}}
	}
	return DNSResult{Found: list, Diagnosis: Diagnosis{Code: CodeOK, Message: fmt.Sprintf("域名 %s 已解析到本服务器", domain)}}
}

// NetResolver is the production Resolver: plain UDP DNS straight to server.
type NetResolver struct{ Timeout time.Duration }

// LookupIPs implements Resolver.
func (n NetResolver) LookupIPs(ctx context.Context, server, host string) ([]string, error) {
	timeout := n.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out, nil
}
