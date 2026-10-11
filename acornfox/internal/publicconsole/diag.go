// Package publicconsole lets users open the web console to the internet on a
// domain of their own (ADR-0016): verify that the domain reaches this server,
// route it through Caddy with automatic HTTPS, and guard it with a generated
// password, login rate limiting and the native console sessions.
//
// Network access (public IP discovery, DNS, HTTP probes) goes through small
// injected interfaces so every verdict is unit-testable.
package publicconsole

import (
	"fmt"
	"strings"

	"github.com/acornfox/acornfox/internal/domainname"
)

// Diagnosis is a plain-language verdict for one step of enabling the public
// console. Code is stable for tools (the Skill); Message and Hint are for
// people.
type Diagnosis struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// OK reports whether the step passed.
func (d Diagnosis) OK() bool { return d.Code == CodeOK }

// Diagnosis codes.
const (
	CodeOK              = "ok"
	CodeDNSUnresolved   = "dns_unresolved"   // no A/AAAA record yet
	CodeDNSMismatch     = "dns_mismatch"     // records point somewhere else
	CodeDNSError        = "dns_error"        // no DNS server answered
	CodePortClosed      = "port_closed"      // connection refused
	CodePortUnreachable = "port_unreachable" // timed out: usually a security group
	CodeConnReset       = "connection_reset" // reset mid-handshake
	CodeICPBlocked      = "icp_blocked"      // cloud provider's unfiled-domain page
	CodeWrongTarget     = "wrong_target"     // reachable, but not this server's answer
	CodeCertPending     = "cert_pending"     // HTTPS reachable, certificate not ready
	CodeCertFailed      = "cert_failed"      // still no certificate after waiting
	CodeHTTPError       = "http_error"       // anything else
)

// VerifyPathPrefix is where the HTTP ownership challenge is served.
const VerifyPathPrefix = "/.well-known/acornfox-verify/"

// twoLevelSuffixes are common public suffixes with two labels, so the host
// record of "panel.example.com.cn" is "panel", not "panel.example".
var twoLevelSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "ac.cn": true,
	"com.hk": true, "com.tw": true, "co.uk": true, "org.uk": true, "co.jp": true, "com.au": true,
}

// HostRecord returns what users type in the "主机记录" field of their DNS
// provider for domain: "panel" for panel.example.com, "@" for example.com.
func HostRecord(domain string) string {
	labels := strings.Split(domain, ".")
	root := 2
	if len(labels) >= 3 && twoLevelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		root = 3
	}
	if len(labels) <= root {
		return "@"
	}
	return strings.Join(labels[:len(labels)-root], ".")
}

// NormalizeDomain lowercases domain, drops a trailing dot and validates it as
// a hostname (no IP literals, no scheme, no port).
func NormalizeDomain(domain string) (string, bool) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !strings.Contains(d, ".") || !domainname.Valid(d) {
		return "", false
	}
	return d, true
}

// recordHint tells the user exactly which records to add.
func recordHint(domain string, v4, v6 []string) string {
	var parts []string
	host := HostRecord(domain)
	for _, ip := range v4 {
		parts = append(parts, fmt.Sprintf("A 记录：主机记录 %s，记录值 %s", host, ip))
	}
	for _, ip := range v6 {
		parts = append(parts, fmt.Sprintf("AAAA 记录：主机记录 %s，记录值 %s", host, ip))
	}
	if len(parts) == 0 {
		return ""
	}
	return "请在域名服务商的解析设置里添加 " + strings.Join(parts, "；") + "。"
}

func portHint(port int) string {
	return fmt.Sprintf("请在云厂商控制台的安全组（防火墙）里放行入方向 TCP %d；开通公网控制台需要同时放行 80 和 443。", port)
}

const icpHint = "该域名未备案，国内服务器无法使用。请先完成 ICP 备案，或换一个已备案的域名；海外服务器不需要备案。"
