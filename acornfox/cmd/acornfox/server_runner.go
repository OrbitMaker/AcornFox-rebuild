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
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/moby/moby/client"

	"github.com/acornfox/acornfox/internal/apiserver"
	"github.com/acornfox/acornfox/internal/caddyroute"
	"github.com/acornfox/acornfox/internal/peer"
	"github.com/acornfox/acornfox/internal/reconcile"
	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// runServer implements `acornfox server` (N1/N2). It opens the state store,
// builds a runner client, a Caddy router, the reconciler and the API, then
// serves the API on every -listen address until SIGTERM/SIGINT. -listen may be
// repeated (TCP loopback and/or unix sockets); -listen-group sets the group
// owner of unix sockets (mode 0660) so only members can connect.
func runServer(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var listens listenList
	fs.Var(&listens, "listen", "API listen address (repeatable): 127.0.0.1:PORT or unix:/path.sock")
	var (
		dataDir      = fs.String("data-dir", "/var/lib/acornfox", "state directory (holds acornfox.db and uploads/)")
		listenGroup  = fs.String("listen-group", "", "group owner for unix socket listeners (mode 0660)")
		runnerSocket = fs.String("runner-socket", "/run/acornfox/runner.sock", "runner peer socket path")
		runnerUID    = fs.Int("runner-uid", os.Getuid(), "uid the runner process runs as")
		caddyAdmin   = fs.String("caddy-admin", "/run/acornfox/caddy-admin.sock", "Caddy admin API unix socket")
		publicHost   = fs.String("public-host", "", "host used in app URLs (e.g. the LAN IP)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(listens) == 0 {
		// Default preserves the N1 behaviour when -listen is omitted.
		listens = listenList{"127.0.0.1:18800"}
	}

	for _, addr := range listens {
		if err := apiserver.ValidateListen(addr); err != nil {
			fmt.Fprintln(stderr, "invalid -listen:", err)
			return 2
		}
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

	st, err := state.Open(state.Config{Path: filepath.Join(*dataDir, "acornfox.db")})
	if err != nil {
		fmt.Fprintln(stderr, "open state:", err)
		return 1
	}
	defer st.Close()

	runnerClient := runner.NewClient(*runnerSocket, uint32(*runnerUID))
	router := caddyroute.New(*caddyAdmin)

	rec := reconcile.New(reconcile.Config{
		Store:      st,
		Runner:     runnerClient,
		Router:     router,
		UploadDir:  uploadDir,
		PublicHost: *publicHost,
	})

	handler := apiserver.New(apiserver.Config{
		Store:      st,
		Kicker:     rec,
		Runner:     runnerClient,
		UploadDir:  uploadDir,
		PublicHost: *publicHost,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Run the reconciler.
	recDone := make(chan struct{})
	go func() {
		defer close(recDone)
		if err := rec.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "reconciler stopped:", err)
		}
	}()

	// Open every listener before serving.
	var listeners []net.Listener
	for _, addr := range listens {
		ln, err := listenAPI(addr, gid)
		if err != nil {
			fmt.Fprintln(stderr, "listen:", err)
			for _, l := range listeners {
				_ = l.Close()
			}
			stop()
			<-recDone
			return 1
		}
		listeners = append(listeners, ln)
	}

	srv := &http.Server{Handler: handler}
	serveErr := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(l net.Listener) { serveErr <- srv.Serve(l) }(ln)
	}
	for _, addr := range listens {
		fmt.Fprintln(stdout, "acornfox server listening on", addr)
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
	_ = srv.Shutdown(shCtx)
	stop()
	<-recDone
	return 0
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
