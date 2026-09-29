// Command acornfox-executor runs every host side effect of AcornFox: container
// runtime, source build and gateway projection. It is the only AcornFox process
// with Docker, BuildKit and Caddy admin access, and it serves only acornfox-core.
//
// The container runtime is required; source build and gateway start when their
// host dependencies are present and are retried otherwise, so a missing BuildKit
// or Caddy never stops already deployed applications from being managed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	"github.com/acornfox/acornfox/internal/buildnetwork"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/imageexecution"
	"github.com/acornfox/acornfox/internal/layout"
	"github.com/acornfox/acornfox/internal/providers/acornfoxroute"
	"github.com/acornfox/acornfox/internal/providers/buildkit"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
	sourceprovider "github.com/acornfox/acornfox/internal/providers/source"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
)

// Public DNS resolvers used for Git host resolution when none are configured
// (AliDNS and DNSPod, reachable from mainland China).
const defaultGitResolvers = "223.5.5.5:53,119.29.29.29:53"

type config struct {
	dockerSocket    string
	registryBaseURL string
	taskPrefix      string
	gitResolvers    []string
	caddyAccount    string
	retryInterval   time.Duration
}

func parseFlags(args []string) (config, error) {
	var c config
	var resolvers string
	fs := flag.NewFlagSet("acornfox-executor", flag.ContinueOnError)
	fs.StringVar(&c.dockerSocket, "docker-socket", "/var/run/docker.sock", "Docker Engine Unix socket")
	fs.StringVar(&c.registryBaseURL, "registry-url", "", "Optional registry base URL override")
	fs.StringVar(&c.taskPrefix, "task-prefix", "acornfox-", "Name prefix of Docker objects owned by AcornFox")
	fs.StringVar(&resolvers, "git-resolvers", defaultGitResolvers, "Public DNS resolvers (IP:port, comma separated) used for Git hosts")
	fs.StringVar(&c.caddyAccount, "caddy-account", "caddy", "Account that owns the Caddy admin socket")
	fs.DurationVar(&c.retryInterval, "retry-interval", 10*time.Second, "Retry interval for optional subsystems")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !filepath.IsAbs(c.dockerSocket) || filepath.Clean(c.dockerSocket) != c.dockerSocket {
		return c, errors.New("docker socket path must be absolute and clean")
	}
	for _, r := range strings.Split(resolvers, ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.gitResolvers = append(c.gitResolvers, r)
		}
	}
	if len(c.gitResolvers) == 0 {
		return c, errors.New("at least one Git resolver is required")
	}
	if c.retryInterval <= 0 {
		return c, errors.New("retry interval must be positive")
	}
	return c, nil
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatalf("acornfox-executor: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("acornfox-executor: %v", err)
	}
}

func run(ctx context.Context, cfg config) error {
	id, err := layout.Resolve()
	if err != nil {
		return err
	}
	if uint32(os.Getuid()) != id.ExecutorUID {
		return fmt.Errorf("must run as %s", layout.AccountExecutor)
	}

	stopContainer, err := startContainer(cfg, id)
	if err != nil {
		return fmt.Errorf("container runtime: %w", err)
	}
	defer stopContainer()
	log.Print("container runtime ready")

	go keepStarting(ctx, "source build", cfg.retryInterval, func() (func(), error) { return startSourceBuild(cfg, id) })
	go keepStarting(ctx, "gateway", cfg.retryInterval, func() (func(), error) { return startGateway(cfg, id) })

	<-ctx.Done()
	log.Print("shutting down")
	return nil
}

// keepStarting retries start until it succeeds or ctx ends, then holds the
// subsystem open until shutdown.
func keepStarting(ctx context.Context, name string, every time.Duration, start func() (func(), error)) {
	for {
		stop, err := start()
		if err == nil {
			log.Printf("%s ready", name)
			<-ctx.Done()
			stop()
			return
		}
		log.Printf("%s unavailable, retrying in %s: %v", name, every, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func startContainer(cfg config, id layout.Identity) (func(), error) {
	for _, dir := range []string{layout.ContainerWorkDir, layout.ContainerImageStore} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	runtime, err := imageexecution.NewContainerRuntime(imageexecution.RuntimeConfig{
		TaskPrefix:          cfg.taskPrefix,
		WorkRoot:            layout.ContainerWorkDir,
		ImageStoreRoot:      layout.ContainerImageStore,
		RegistryBaseURL:     cfg.registryBaseURL,
		DockerSocketPath:    cfg.dockerSocket,
		AuthoritySocketPath: layout.ContainerAuthoritySocket,
		CoreUID:             id.CoreUID,
	})
	if err != nil {
		return nil, err
	}
	server, err := imageexecution.NewContainerServer(imageexecution.ContainerServerConfig{
		EnableLifecycle: true,
		Runtime:         runtime,
		SocketPath:      layout.ContainerSocket,
		SocketGID:       id.IPCGID,
		CoreUID:         id.CoreUID,
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = server.Close() }, nil
}

func startSourceBuild(cfg config, id layout.Identity) (func(), error) {
	for _, dir := range []string{layout.SourceUploadDir, layout.SourceWorkspaceDir, layout.BuildWorkDir, layout.BuildImageStore, layout.BuildLogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	authority, err := sourcebuildexecution.NewAuthorityClient(sourcebuildexecution.ClientConfig{SocketPath: layout.SourceAuthoritySocket, PeerUID: id.CoreUID})
	if err != nil {
		return nil, err
	}
	production := sourcebuildexecution.ProductionConfig{
		UploadRoot:           layout.SourceUploadDir,
		WorkspaceRoot:        layout.SourceWorkspaceDir,
		WorkRoot:             layout.BuildWorkDir,
		ImageStoreRoot:       layout.BuildImageStore,
		LogRoot:              layout.BuildLogDir,
		GitResolverEndpoints: cfg.gitResolvers,
		Authority:            authority,
	}
	runtime, archives, err := newSourceBuildRuntime(production)
	if err != nil {
		return nil, err
	}
	server, err := sourcebuildexecution.NewExecutionServer(sourcebuildexecution.ServerConfig{
		ArchiveStore: archives,
		SocketPath:   layout.SourceSocket,
		SocketGID:    id.IPCGID,
		PeerUID:      id.CoreUID,
	}, runtime)
	if err != nil {
		return nil, err
	}
	return func() { _ = server.Close() }, nil
}

func newSourceBuildRuntime(c sourcebuildexecution.ProductionConfig) (*sourcebuildexecution.Runtime, contracts.ImageStore, error) {
	if err := sourcebuildexecution.ValidateProductionConfig(c); err != nil {
		return nil, nil, err
	}
	binary, err := os.Stat(layout.BuildctlPath)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0o111 == 0 {
		return nil, nil, errors.New("BuildKit client is not installed")
	}
	for _, socket := range []string{buildnetwork.BuildkitSocketPath, buildnetwork.SocketPath} {
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("%s is not available", socket)
		}
	}
	source, err := sourceprovider.New(sourceprovider.Config{UploadRoot: c.UploadRoot, WorkspaceRoot: c.WorkspaceRoot, GitBinary: "/usr/bin/git", GitResolverEndpoints: c.GitResolverEndpoints})
	if err != nil {
		return nil, nil, err
	}
	images, err := imageprovider.New(imageprovider.Config{Root: c.ImageStoreRoot})
	if err != nil {
		return nil, nil, err
	}
	capacity, err := capacityprovider.New(capacityprovider.Config{DiskPath: c.WorkRoot})
	if err != nil {
		return nil, nil, err
	}
	logs, err := sourcebuildexecution.NewFileBuildLogSink(c.LogRoot, []string{c.UploadRoot, c.WorkspaceRoot, c.WorkRoot, c.ImageStoreRoot, c.LogRoot})
	if err != nil {
		return nil, nil, err
	}
	runtime, err := sourcebuildexecution.NewRuntime(sourcebuildexecution.Config{Source: source, Authority: c.Authority, Capacity: capacity, BuilderFactory: func(owner contracts.CapacityProvider) (contracts.BuildProvider, error) {
		return buildkit.New(buildkit.Config{
			Command:                    layout.BuildctlPath,
			Timeout:                    time.Hour,
			Builder:                    "acornfox-rootless",
			Address:                    "unix://" + buildnetwork.BuildkitSocketPath,
			WorkspaceRoot:              c.WorkspaceRoot,
			WorkRoot:                   c.WorkRoot,
			ImageStore:                 images,
			Capacity:                   owner,
			ProductionNetworkPolicyRaw: buildnetwork.CanonicalPolicy(),
			WorkerPolicyAttestor:       buildnetwork.Client{},
			LogSink:                    logs,
			RequireLogSink:             true,
		})
	}})
	return runtime, images, err
}

func startGateway(cfg config, id layout.Identity) (func(), error) {
	caddy, err := user.Lookup(cfg.caddyAccount)
	if err != nil {
		return nil, err
	}
	caddyUID, err := strconv.ParseUint(caddy.Uid, 10, 32)
	if err != nil || caddyUID == 0 {
		return nil, fmt.Errorf("account %s has an invalid uid", cfg.caddyAccount)
	}
	authority, err := gatewayexecution.NewAuthorityClient(gatewayexecution.ClientConfig{SocketPath: layout.GatewayAuthoritySocket, PeerUID: id.CoreUID})
	if err != nil {
		return nil, err
	}
	source := &gatewayexecution.Source{Authority: authority, Lock: application.GatewayProjectionLock{Path: layout.GatewayProjectionLock, ExpectedOwnerUID: 0, IPCGID: id.IPCGID}}
	provider, err := acornfoxroute.New(acornfoxroute.Config{CustomOnly: true, Source: source, AdminUnixSocket: acornfoxroute.NativeAdminSocketPath, AdminSocketUID: uint32(caddyUID), AdminSocketGID: id.IPCGID})
	if err != nil {
		return nil, err
	}
	server, err := gatewayexecution.NewExecutionServer(gatewayexecution.ServerConfig{SocketPath: layout.GatewaySocket, SocketGID: id.IPCGID, PeerUID: id.CoreUID}, &gatewayexecution.Runtime{Authority: authority, Projector: provider})
	if err != nil {
		provider.Close()
		return nil, err
	}
	return func() { _ = server.Close(); provider.Close() }, nil
}
