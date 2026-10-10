//go:build !windows

// This file implements the "acornfox server" and "acornfox runner" subcommands
// (N1): it wires state, runner, caddyroute, reconcile and apiserver together.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moby/moby/client"

	"github.com/acornfox/acornfox/internal/apiserver"
	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/peer"
	"github.com/acornfox/acornfox/internal/publicconsole"
	"github.com/acornfox/acornfox/internal/reconcile"
	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// consoleFS holds the embedded console static assets. It is populated by
// console_wiring.go (init) when the github.com/acornfox/acornfox/internal/console
// package is present; otherwise it stays nil and the console listener serves a
// small placeholder page. The wiring lives in a separate file so the server can
// build before that package exists.
var consoleFS fs.FS

// runServer implements `acornfox server` (N1/N2/N3). It opens the state store,
// builds a runner client, a Caddy router, the reconciler and the API, then
// serves the trusted API on every -listen (unix sockets only) and the console
// handler on -console-listen (loopback TCP) until SIGTERM/SIGINT.
//
// N3: -listen no longer accepts TCP addresses; the unauthenticated trusted API
// is served only on unix sockets. The browser console is served separately on
// -console-listen behind cookie sessions and CSRF.
func runServer(args []string, stdout, stderr io.Writer) int {
	fs_ := flag.NewFlagSet("server", flag.ContinueOnError)
	fs_.SetOutput(stderr)
	var listens listenList
	fs_.Var(&listens, "listen", "trusted API unix socket (repeatable): unix:/path.sock")
	var (
		dataDir       = fs_.String("data-dir", "/var/lib/acornfox", "state directory (holds acornfox.db and uploads/)")
		listenGroup   = fs_.String("listen-group", "", "group owner for unix socket listeners (mode 0660)")
		consoleListen = fs_.String("console-listen", "127.0.0.1:18800", "browser console listener (loopback TCP only; empty disables it)")
		runnerSocket  = fs_.String("runner-socket", "/run/acornfox/runner.sock", "runner peer socket path")
		runnerUID     = fs_.Int("runner-uid", os.Getuid(), "uid the runner process runs as")
		caddyAdmin    = fs_.String("caddy-admin", "/run/acornfox/caddy-admin.sock", "Caddy admin API unix socket")
		publicHost    = fs_.String("public-host", "", "host used in app URLs (e.g. the LAN IP)")
		publicPortMin = fs_.Int("public-port-min", 18810, "应用公开端口范围下限")
		publicPortMax = fs_.Int("public-port-max", 18899, "应用公开端口范围上限")
		httpPort      = fs_.Int("http-port", 80, "HTTP port of the shared af-domains server (ACME HTTP-01 and redirect)")
		httpsPort     = fs_.Int("https-port", 443, "HTTPS port of the shared af-domains server")
		httpsIssuer   = fs_.String("https-issuer", "", "certificate issuer: \"\"/acme = public ACME, internal = Caddy local CA (dev)")
		httpsCAFile   = fs_.String("https-ca-file", "", "path to the CA root used to verify domain certificates (internal issuer)")
		acmeEmail     = fs_.String("acme-email", "", "optional ACME account email")
		publicListen  = fs_.String("public-console-listen", "127.0.0.1:18801", "public console gateway behind Caddy (loopback TCP only; empty disables it)")
	)
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	if len(listens) == 0 {
		// Default trusted entry is the unix socket per the N3 contract.
		listens = listenList{"unix:/run/acornfox/api.sock"}
	}

	// -listen accepts unix sockets only. TCP would re-expose the
	// unauthenticated API, so it is rejected with guidance to -console-listen.
	for _, addr := range listens {
		if err := validateTrustedListen(addr); err != nil {
			fmt.Fprintln(stderr, "invalid -listen:", err)
			return 2
		}
	}
	if err := validateConsoleListen(*consoleListen); err != nil {
		fmt.Fprintln(stderr, "invalid -console-listen:", err)
		return 2
	}
	if err := validateConsoleListen(*publicListen); err != nil {
		fmt.Fprintln(stderr, "invalid -public-console-listen:", err)
		return 2
	}

	gid := -1
	if *listenGroup != "" {
		g, err := lookupGroupID(*listenGroup)
		if err != nil {
			fmt.Fprintln(stderr, "invalid -listen-group:", err)
			return 2
		}
		gid = g
	}

	uploadDir := filepath.Join(*dataDir, "uploads")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "create upload dir:", err)
		return 1
	}

	st, err := state.Open(state.Config{
		Path:          filepath.Join(*dataDir, "acornfox.db"),
		PublicPortMin: *publicPortMin,
		PublicPortMax: *publicPortMax,
	})
	if err != nil {
		fmt.Fprintln(stderr, "open state:", err)
		return 1
	}
	defer st.Close()

	httpsCfg := caddyroute.HTTPSConfig{
		HTTPPort:  *httpPort,
		HTTPSPort: *httpsPort,
		Issuer:    *httpsIssuer,
		Email:     *acmeEmail,
	}

	runnerClient := runner.NewClient(*runnerSocket, uint32(*runnerUID))
	router := caddyroute.New(*caddyAdmin, httpsCfg)

	// ADR-0016: the public console's domain route rides along every route
	// sync; its configuration lives in the data directory.
	pcStore := publicconsole.NewFileStore(filepath.Join(*dataDir, "public-console.json"))
	if *publicListen != "" {
		router = publicconsole.WrapRouter(router, pcStore, *publicListen)
	}

	rec := reconcile.New(reconcile.Config{
		Store:       st,
		Runner:      runnerClient,
		Router:      router,
		UploadDir:   uploadDir,
		PublicHost:  *publicHost,
		HTTPS:       httpsCfg,
		HTTPSCAFile: *httpsCAFile,
	})

	apiCfg := apiserver.Config{
		Store:      st,
		Kicker:     rec,
		Runner:     runnerClient,
		UploadDir:  uploadDir,
		PublicHost: *publicHost,
		DataDir:    *dataDir,
	}
	var pcManager *publicconsole.Manager
	if *publicListen != "" {
		pcManager = publicconsole.NewManager(publicconsole.ManagerConfig{
			Store:    pcStore,
			Verifier: caddyroute.NewVerifier(*caddyAdmin, httpsCfg),
			Sessions: st,
			Routes:   rec,
			Domains: func(ctx context.Context) ([]string, error) {
				ds, err := st.ListDomains(ctx, "")
				names := make([]string, 0, len(ds))
				for _, d := range ds {
					names = append(names, d.Name)
				}
				return names, err
			},
		})
		apiCfg.PublicConsole = pcManager
	}
	trustedHandler := apiserver.New(apiCfg)

	// The console handler shares the same dependencies plus the embedded assets.
	consoleCfg := apiCfg
	consoleCfg.ConsoleFS = consoleFS
	consoleHandler := apiserver.NewConsole(consoleCfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if pcManager != nil {
		pcManager.Cleanup(ctx)
		// Caddy keeps no config across restarts (persist_config off); while the
		// public console is on, put its route back even when no app has a round.
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if cfg, err := pcStore.Load(); err == nil && cfg != nil {
						rec.RefreshRoutes(ctx)
					}
				}
			}
		}()
	}

	// Run the reconciler.
	recDone := make(chan struct{})
	go func() {
		defer close(recDone)
		if err := rec.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "reconciler stopped:", err)
		}
	}()

	// Open every trusted listener before serving.
	var listeners []net.Listener
	cleanup := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	for _, addr := range listens {
		ln, err := listenAPI(addr, gid)
		if err != nil {
			fmt.Fprintln(stderr, "listen:", err)
			cleanup()
			stop()
			<-recDone
			return 1
		}
		listeners = append(listeners, ln)
	}

	trustedSrv := &http.Server{Handler: trustedHandler}
	serveErr := make(chan error, len(listeners)+1)
	for _, ln := range listeners {
		go func(l net.Listener) { serveErr <- trustedSrv.Serve(l) }(ln)
	}
	for _, addr := range listens {
		fmt.Fprintln(stdout, "acornfox server (trusted) listening on", addr)
	}

	// Open the console listener (loopback TCP) when enabled.
	var consoleSrv *http.Server
	if *consoleListen != "" {
		cln, err := net.Listen("tcp", *consoleListen)
		if err != nil {
			fmt.Fprintln(stderr, "console listen:", err)
			cleanup()
			stop()
			<-recDone
			return 1
		}
		listeners = append(listeners, cln)
		consoleSrv = &http.Server{Handler: consoleHandler}
		go func() { serveErr <- consoleSrv.Serve(cln) }()
		fmt.Fprintln(stdout, "acornfox server (console) listening on", *consoleListen)
	}

	// The public console gateway (loopback; Caddy terminates TLS in front).
	var publicSrv *http.Server
	if pcManager != nil {
		pln, err := net.Listen("tcp", *publicListen)
		if err != nil {
			fmt.Fprintln(stderr, "public console listen:", err)
			cleanup()
			stop()
			<-recDone
			return 1
		}
		listeners = append(listeners, pln)
		publicSrv = &http.Server{
			Handler:           publicconsole.NewGateway(publicconsole.GatewayConfig{Store: pcStore, Sessions: st, Console: consoleHandler}),
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
		go func() { serveErr <- publicSrv.Serve(pln) }()
		fmt.Fprintln(stdout, "acornfox server (public console gateway) listening on", *publicListen)
	}

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "serve:", err)
		}
	}

	// Graceful shutdown.
	shCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = trustedSrv.Shutdown(shCtx)
	if consoleSrv != nil {
		_ = consoleSrv.Shutdown(shCtx)
	}
	if publicSrv != nil {
		_ = publicSrv.Shutdown(shCtx)
	}
	stop()
	<-recDone
	return 0
}

// validateTrustedListen rejects anything that is not an absolute unix socket
// path (optionally "unix:"-prefixed). TCP addresses are refused because the
// trusted API is unauthenticated; the browser console uses -console-listen.
func validateTrustedListen(addr string) error {
	if _, ok := stripUnix(addr); ok {
		if err := apiserver.ValidateListen(addr); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("-listen 只接受 unix socket（例如 unix:/run/acornfox/api.sock）；浏览器控制台请使用 -console-listen")
}

// validateConsoleListen accepts an empty value (console disabled) or a loopback
// TCP address (127.0.0.1, ::1, localhost). Non-loopback is rejected so the
// console is never bound to a public interface.
func validateConsoleListen(addr string) error {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-console-listen 需要 host:port 形式的回环地址")
	}
	if port == "" {
		return fmt.Errorf("-console-listen 缺少端口")
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-console-listen 只允许回环地址（127.0.0.1、::1、localhost）")
}

// listenList is a repeatable string flag preserving order.
type listenList []string

func (l *listenList) String() string { return strings.Join(*l, ",") }
func (l *listenList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// lookupGroupID resolves a group name (or numeric gid) to a gid.
func lookupGroupID(name string) (int, error) {
	if g, err := user.LookupGroup(name); err == nil {
		return strconv.Atoi(g.Gid)
	}
	// Allow a numeric group id directly.
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	return 0, fmt.Errorf("unknown group %q", name)
}

// listenAPI opens the API listener for a validated address: an absolute path
// (optionally "unix:"-prefixed) yields a unix socket, otherwise a TCP listener.
// For unix sockets it removes any stale socket first, then sets mode 0660 and,
// when gid >= 0, chowns the socket group so only that group may connect.
func listenAPI(addr string, gid int) (net.Listener, error) {
	if p, ok := stripUnix(addr); ok {
		if _, err := os.Stat(p); err == nil {
			_ = os.Remove(p)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		ln, err := net.Listen("unix", p)
		if err != nil {
			return nil, err
		}
		if gid >= 0 {
			if err := os.Chown(p, -1, gid); err != nil {
				_ = ln.Close()
				return nil, fmt.Errorf("chown socket group: %w", err)
			}
		}
		if err := os.Chmod(p, 0o660); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("chmod socket: %w", err)
		}
		return ln, nil
	}
	return net.Listen("tcp", addr)
}

func stripUnix(addr string) (string, bool) {
	if len(addr) > 5 && addr[:5] == "unix:" {
		return addr[5:], true
	}
	if len(addr) > 0 && addr[0] == '/' {
		return addr, true
	}
	return "", false
}

// runRunner implements `acornfox runner` (N1): connect to Docker via client
// environment and serve the runner API on the peer socket, accepting only the
// server uid.
func runRunner(args ...string) int {
	fs := flag.NewFlagSet("runner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		socket    = fs.String("socket", "/run/acornfox/runner.sock", "peer socket to serve on")
		serverUID = fs.Int("server-uid", os.Getuid(), "uid of the acornfox server allowed to connect")
		socketGID = fs.Int("socket-gid", 0, "group owner of the socket (0 = leave default)")
		uploadDir = fs.String("upload-dir", "/var/lib/acornfox/uploads", "directory holding server uploads; builds may only read files under it")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect docker:", err)
		return 1
	}
	defer cli.Close()

	api := runner.NewDocker(cli)
	// The runner does not stage uploads itself; the server writes them under
	// data-dir/uploads which the runner reads by absolute path.
	if !filepath.IsAbs(*uploadDir) {
		fmt.Fprintln(os.Stderr, "-upload-dir must be absolute")
		return 2
	}
	handler := runner.NewServer(api, filepath.Clean(*uploadDir))

	ln, err := peer.Listen(*socket, uint32(*socketGID), uint32(*serverUID))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen peer socket:", err)
		return 1
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := &http.Server{Handler: handler}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	fmt.Fprintln(os.Stdout, "acornfox runner serving on", *socket)

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "serve:", err)
		}
	}
	shCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = srv.Shutdown(shCtx)
	return 0
}
