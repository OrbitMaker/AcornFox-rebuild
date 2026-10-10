package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/client"
	"github.com/acornfox/acornfox/internal/publicconsole"
)

// localSocket is the trusted API socket used by `--local` (on the server).
const localSocket = "/run/acornfox/api.sock"

// maxVerifyWait keeps the whole wait inside one server-side verification
// (publicconsole.VerifyTTL is 30 minutes).
const maxVerifyWait = 25 * time.Minute

// publicConsoleNet is the network the CLI uses to check a domain from the
// user's side of the internet. Tests replace newPublicConsoleNet.
type publicConsoleNet struct {
	resolver publicconsole.Resolver
	getter   publicconsole.Getter
	dns      []string
	interval time.Duration
	certWait time.Duration
	sleep    func(ctx context.Context, d time.Duration) error
	now      func() time.Time
}

var newPublicConsoleNet = func() *publicConsoleNet {
	return &publicConsoleNet{
		resolver: publicconsole.NetResolver{},
		getter:   publicconsole.HTTPGetter(10 * time.Second),
		dns:      append(append([]string(nil), publicconsole.DNSServersCN...), publicconsole.DNSServersGlobal...),
		interval: 15 * time.Second,
		certWait: 3 * time.Minute,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		now: time.Now,
	}
}

// cmdPublicConsole implements `public-console enable DOMAIN | disable | status`.
func (a *app) cmdPublicConsole(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("public-console 需要子命令：enable 域名 / disable / status")
	}
	sub := args[0]
	fs := flag.NewFlagSet("public-console "+sub, flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	local := fs.Bool("local", false, "在服务器本机经 "+localSocket+" 执行")
	wait := fs.Duration("wait", 10*time.Minute, "等待域名解析与端口放行的最长时间（0 = 只检查一次）")
	reset := fs.Bool("reset-password", false, "重新生成登录密码（旧密码与登录会话立即失效）")
	rest, err := parseFlags(fs, args[1:])
	if err != nil {
		return exitUsage
	}

	var target client.Target
	if *local {
		target = client.Target{Name: "local", URL: "unix://" + localSocket}
	} else {
		t, _, terr := a.resolveTarget()
		if terr != nil {
			return a.out.usageError("%s", terr.Error())
		}
		target = t
	}

	switch sub {
	case "enable":
		if len(rest) != 1 {
			return a.out.usageError("用法：public-console enable 域名 [--wait 10m] [--reset-password] [--local]")
		}
		domain, ok := publicconsole.NormalizeDomain(rest[0])
		if !ok {
			return a.out.usageError("域名 %q 不合法：请填写完整域名，例如 panel.example.com（不要带 http:// 或端口）", rest[0])
		}
		if *wait < 0 || *wait > maxVerifyWait {
			return a.out.usageError("--wait 取值范围是 0 到 %s", maxVerifyWait)
		}
		api, derr := a.dial(ctx, target)
		if derr != nil {
			return a.out.fail(derr)
		}
		defer api.Close()
		return a.publicConsoleEnable(ctx, api, target.Name, domain, *wait, *reset)
	case "disable", "status":
		if len(rest) != 0 {
			return a.out.usageError("public-console %s 不接受参数", sub)
		}
		api, derr := a.dial(ctx, target)
		if derr != nil {
			return a.out.fail(derr)
		}
		defer api.Close()
		if sub == "disable" {
			return a.publicConsoleDisable(ctx, api)
		}
		return a.publicConsoleStatus(ctx, api)
	default:
		return a.out.usageError("未知的 public-console 子命令：%s（可用：enable / disable / status）", sub)
	}
}

func diagJSON(d publicconsole.Diagnosis) map[string]any {
	m := map[string]any{"code": d.Code, "message": d.Message}
	if d.Hint != "" {
		m["hint"] = d.Hint
	}
	return m
}

func (a *app) publicConsoleEnable(ctx context.Context, api client.API, targetName, domain string, wait time.Duration, reset bool) int {
	net := newPublicConsoleNet()

	info, err := api.PublicConsoleVerify(ctx, domain)
	if err != nil {
		return a.out.fail(err)
	}
	ips := publicconsole.PublicIPs{V4: info.IPs.V4, V6: info.IPs.V6}
	if !a.out.json {
		a.out.human("本服务器公网地址：%s", strings.Join(ips.All(), "、"))
		a.out.human("正在验证域名 %s 是否指向本服务器……", domain)
	}

	// 1. Wait until DNS points here and the HTTP challenge comes back.
	deadline := net.now().Add(wait)
	last := ""
	for {
		d := a.publicConsoleCheck(ctx, net, domain, ips, info)
		if d.OK() {
			break
		}
		if d.Code != last && !a.out.json {
			a.out.human("未通过：%s", d.Message)
			if d.Hint != "" {
				a.out.human("  怎么办：%s", d.Hint)
			}
		}
		if !net.now().Before(deadline) {
			return a.publicConsoleFailed(d, ips, wait)
		}
		if d.Code != last && !a.out.json {
			a.out.human("  每 %d 秒自动重查一次，最多等到 %s（按 Ctrl+C 可中断，之后重新运行同一条命令即可继续）。",
				int(net.interval.Seconds()), deadline.Format("15:04"))
		}
		last = d.Code
		if err := net.sleep(ctx, net.interval); err != nil {
			return a.publicConsoleFailed(d, ips, wait)
		}
	}
	if !a.out.json {
		a.out.human("域名验证通过：%s 已指向本服务器，80 端口可达。", domain)
	}

	// 2. Turn it on.
	res, err := api.PublicConsoleEnable(ctx, info.Domain, info.VerifyID, reset)
	if err != nil {
		return a.out.fail(err)
	}
	passwordFile := ""
	if res.Password != "" {
		passwordFile, err = a.writePasswordFile(targetName, res.Domain, res.URL, res.Password)
		if err != nil {
			a.out.humanErr("警告：密码文件写入失败：%v", err)
		}
	}

	// 3. Wait for HTTPS.
	https := publicconsole.ProbeHTTPS(ctx, net.getter, res.Domain)
	certDeadline := net.now().Add(net.certWait)
	if wait == 0 {
		certDeadline = net.now()
	}
	for !https.OK() && net.now().Before(certDeadline) && https.Code == publicconsole.CodeCertPending {
		if err := net.sleep(ctx, 10*time.Second); err != nil {
			break
		}
		https = publicconsole.ProbeHTTPS(ctx, net.getter, res.Domain)
	}
	if https.Code == publicconsole.CodeCertPending && wait > 0 {
		https = publicconsole.CertFailedDiagnosis(res.Domain)
	}

	if a.out.json {
		fields := map[string]any{
			"domain":          res.Domain,
			"url":             res.URL,
			"already_enabled": res.AlreadyEnabled,
			"https":           diagJSON(https),
		}
		if passwordFile != "" {
			fields["password_file"] = passwordFile
		}
		a.out.emitJSON(fields)
		return exitOK
	}
	if res.AlreadyEnabled {
		a.out.human("公网控制台已经是开启状态：%s（密码不变；要换密码加 --reset-password）", res.URL)
	} else {
		a.out.human("公网控制台已开通：%s", res.URL)
		a.out.human("登录密码（只显示这一次）：%s", res.Password)
		if passwordFile != "" {
			a.out.human("密码也保存在 %s（只有你能读）。存进密码管理器后请删除这个文件。", passwordFile)
		}
	}
	if https.OK() {
		a.out.human("HTTPS 证书已就绪，可以直接打开。")
	} else {
		a.out.human("HTTPS 还没就绪：%s", https.Message)
		if https.Hint != "" {
			a.out.human("  怎么办：%s", https.Hint)
		}
	}
	a.out.human("拿到这个密码就能管理整台服务器，请妥善保管。不用时关闭：acornfox public-console disable")
	return exitOK
}

// publicConsoleCheck runs one round: DNS first, then the HTTP challenge.
func (a *app) publicConsoleCheck(ctx context.Context, net *publicConsoleNet, domain string, ips publicconsole.PublicIPs, info client.PublicConsoleVerify) publicconsole.Diagnosis {
	dns := publicconsole.CheckDNS(ctx, net.resolver, net.dns, domain, ips)
	if !dns.OK() {
		return dns.Diagnosis
	}
	return publicconsole.ProbeHTTP(ctx, net.getter, domain, info.Path, info.Token)
}

func (a *app) publicConsoleFailed(d publicconsole.Diagnosis, ips publicconsole.PublicIPs, wait time.Duration) int {
	if a.out.json {
		a.out.encodeRedacted(a.out.stdout, map[string]any{
			"ok": false,
			"diagnosis": map[string]any{
				"stage": "public_console", "code": d.Code, "message": d.Message, "hint": d.Hint,
			},
			"server_ips": ips.All(),
		})
		return exitOpFailed
	}
	if wait > 0 {
		a.out.humanErr("等待超时，公网控制台没有开通。按上面的提示处理后，重新运行同一条命令即可。")
	} else {
		a.out.humanErr("检查未通过，公网控制台没有开通。按上面的提示处理后重新运行。")
	}
	return exitOpFailed
}

// writePasswordFile stores the one-time password next to targets.json, 0600.
func (a *app) writePasswordFile(targetName, domain, url, password string) (string, error) {
	dir, _, err := configPaths(a.configDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := "public-console-" + domain + ".txt"
	if targetName != "" {
		name = "public-console-" + targetName + "-" + domain + ".txt"
	}
	path := filepath.Join(dir, name)
	body := fmt.Sprintf("AcornFox 公网控制台\n地址：%s\n密码：%s\n\n拿到这个密码就能管理整台服务器。存进密码管理器后请删除本文件。\n", url, password)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600) // an existing file keeps its old mode otherwise
	return path, nil
}

func (a *app) publicConsoleDisable(ctx context.Context, api client.API) int {
	was, err := api.PublicConsoleDisable(ctx)
	if err != nil {
		return a.out.fail(err)
	}
	if a.out.json {
		a.out.emitJSON(map[string]any{"disabled": true, "was_enabled": was})
		return exitOK
	}
	if was {
		a.out.human("已关闭公网控制台：域名路由已移除，通过公网登录的会话全部失效。")
	} else {
		a.out.human("公网控制台本来就没有开启。")
	}
	return exitOK
}

func (a *app) publicConsoleStatus(ctx context.Context, api client.API) int {
	st, err := api.PublicConsoleStatus(ctx)
	if err != nil {
		return a.out.fail(err)
	}
	if !st.Enabled {
		if a.out.json {
			a.out.emitJSON(map[string]any{"enabled": false, "verifying": st.Verifying})
			return exitOK
		}
		a.out.human("公网控制台未开启（默认只能经 SSH 用 acornfox open 打开）。")
		a.out.human("需要从公网访问时：acornfox public-console enable 域名")
		return exitOK
	}
	https := publicconsole.ProbeHTTPS(ctx, newPublicConsoleNet().getter, st.Domain)
	if a.out.json {
		fields := map[string]any{"enabled": true, "domain": st.Domain, "url": st.URL, "https": diagJSON(https)}
		if st.EnabledAt != nil {
			fields["enabled_at"] = st.EnabledAt
		}
		a.out.emitJSON(fields)
		return exitOK
	}
	a.out.human("公网控制台已开启：%s", st.URL)
	if https.OK() {
		a.out.human("HTTPS：正常")
	} else {
		a.out.human("HTTPS：%s", https.Message)
		if https.Hint != "" {
			a.out.human("  怎么办：%s", https.Hint)
		}
	}
	return exitOK
}
