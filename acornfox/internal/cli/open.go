package cli

import (
	"context"
	"flag"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/acornfox/acornfox/internal/client"
)

// cmdOpen implements `open [--no-browser] [--port N]`: it fetches a single-use
// console token over the normal (proxy) connection, closes it, opens an SSH
// tunnel to the server's console listener (or uses the target URL directly in
// url mode), launches the browser at the login URL and blocks until Ctrl+C
// (context cancel) or the tunnel dies. See N3 contract section 5 / 1.1.
func (a *app) cmdOpen(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	var (
		noBrowser = fs.Bool("no-browser", false, "不自动打开浏览器，只打印链接")
		port      = fs.Int("port", 0, "本地转发端口（0 为自动挑选）")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		return a.out.usageError("open 不接受位置参数")
	}

	t, _, err := a.resolveTarget()
	if err != nil {
		return a.out.usageError("%s", err.Error())
	}

	// 1. Fetch the token over the normal connection, then close it.
	api, derr := a.dial(ctx, t)
	if derr != nil {
		return a.out.fail(derr)
	}
	token, terr := api.ConsoleToken(ctx)
	_ = api.Close()
	if terr != nil {
		return a.out.fail(terr)
	}

	// 2. Establish the console base URL: url mode connects to the target's own
	// host:port; ssh mode forwards a local port to the console listener.
	var (
		baseURL string
		tunnel  *client.Tunnel
	)
	if t.URL != "" {
		baseURL = strings.TrimRight(t.URL, "/")
	} else {
		localPort := *port
		if localPort == 0 {
			p, perr := a.pickFreePort()
			if perr != nil {
				return a.out.fail(&client.Error{Diag: client.Diagnosis{
					Stage: "connect", Code: "connect_failed", Message: "无法分配本地端口：" + perr.Error(),
				}})
			}
			localPort = p
		}
		tun, tunErr := a.openTunnelFn()(ctx, t, localPort)
		if tunErr != nil {
			return a.out.fail(tunErr)
		}
		tunnel = tun
		baseURL = tun.LocalURL
	}
	if tunnel != nil {
		defer tunnel.Close()
	}

	// 3. Build the login URL (the only place the token appears) and browser URL.
	loginURL := baseURL + "/console/login?t=" + url.QueryEscape(token)
	// The token must never be redacted-away in output; it only appears inside
	// loginURL which we never print unless the browser cannot be opened.

	// 4. Open the browser (unless suppressed); fall back to printing the link.
	browserOpened := false
	if !*noBrowser {
		if oerr := a.openURLFn()(loginURL); oerr == nil {
			browserOpened = true
		}
	}

	// 5. Report. Human output never prints the token when the browser opened.
	if a.out.json {
		a.out.emitJSON(map[string]any{"url": baseURL})
	} else if browserOpened {
		a.out.human("已在浏览器打开控制台：%s", baseURL)
		a.out.human("按 Ctrl+C 关闭。")
	} else {
		if *noBrowser {
			a.out.human("未打开浏览器。请在浏览器打开下面的登录链接（一次性，60 秒内有效）：")
		} else {
			a.out.human("无法自动打开浏览器。请手动打开下面的登录链接（一次性，60 秒内有效）：")
		}
		a.out.human("%s", loginURL)
		a.out.human("按 Ctrl+C 关闭。")
	}

	// 6. Block until Ctrl+C (ctx cancel) or the tunnel dies.
	if tunnel == nil {
		// url mode: no tunnel to watch; wait for ctx.
		<-ctx.Done()
		return exitOK
	}
	select {
	case <-ctx.Done():
		return exitOK
	case <-tunnel.Done():
		if e := tunnel.Err(); e != nil {
			if ce, ok := e.(*client.Error); ok && ce.Diag.Stage == "connect" {
				if !a.out.json {
					a.out.printDiagnosis(ce.Diag)
				} else {
					a.out.emitDiagnosisJSON(ce.Diag)
				}
				return exitConnect
			}
		}
		return exitOK
	}
}

// openTunnelFn returns the injected tunnel function or the real one.
func (a *app) openTunnelFn() func(ctx context.Context, t client.Target, localPort int) (*client.Tunnel, error) {
	if a.openTunnel != nil {
		return a.openTunnel
	}
	return client.OpenTunnel
}

// openURLFn returns the injected browser opener or the OS-specific default.
func (a *app) openURLFn() func(url string) error {
	if a.openURL != nil {
		return a.openURL
	}
	return openBrowser
}

// pickFreePort returns a free local TCP port using the injected picker or the
// OS.
func (a *app) pickFreePort() (int, error) {
	if a.freePort != nil {
		return a.freePort()
	}
	return freeLocalPort()
}

// freeLocalPort asks the OS for an ephemeral port and returns it. There is an
// inherent race between closing the listener and ssh binding the forward, but
// it is negligible for an interactive command.
func freeLocalPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// openBrowser launches the OS default handler for url. Commands per N3 contract
// section 5.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux and others
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
