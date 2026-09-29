package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/buildnetwork"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/install"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/providers/buildkit"
	capacityprovider "github.com/acornfox/acornfox/internal/providers/capacity"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
	sourceprovider "github.com/acornfox/acornfox/internal/providers/source"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
)

// Native UR pins buildctl as a BuildKit dependency member under the active
// immutable release. This role has no caller-selectable executable path.
const nativeBuildctlPath = install.UnifiedCurrentSymlink + "/embedded/bin/buildctl"

type sourceConfig struct {
	bindingPath string
	socketGID   uint32
	production  sourcebuildexecution.ProductionConfig
}

func parseFlags(args []string) (sourceConfig, error) {
	var c sourceConfig
	var resolvers string
	fs := flag.NewFlagSet("acornfox-source-build", flag.ContinueOnError)
	fs.StringVar(&c.bindingPath, "runtime-binding", "", "Root-protected runtime binding")
	fs.StringVar(&c.production.UploadRoot, "upload-root", "", "Provisioned private input directory")
	fs.StringVar(&c.production.WorkspaceRoot, "workspace-root", "", "Provisioned bounded immutable source pool")
	fs.StringVar(&c.production.WorkRoot, "work-root", "", "Provisioned private BuildKit client work directory")
	fs.StringVar(&c.production.ImageStoreRoot, "image-store", "", "Provisioned private OCI store")
	fs.StringVar(&c.production.LogRoot, "log-root", "", "Provisioned private bounded build logs")
	fs.StringVar(&resolvers, "git-resolvers", "", "Explicit public IP:port resolver endpoints separated by commas")
	socketGID := fs.Uint64("socket-gid", 0, "Optional dedicated IPC group ID for the role socket; 0 keeps legacy mode and nonzero requires a publisher-prepared parent")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if *socketGID > math.MaxUint32 {
		return c, errors.New("socket-gid exceeds uint32 range")
	}
	c.socketGID = uint32(*socketGID)
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional source-build input")
	}
	for _, p := range []string{c.bindingPath, c.production.UploadRoot, c.production.WorkspaceRoot, c.production.WorkRoot, c.production.ImageStoreRoot, c.production.LogRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("all source-build paths must be explicit and canonical")
		}
	}
	if strings.TrimSpace(resolvers) == "" {
		return c, errors.New("explicit public Git resolvers required")
	}
	c.production.GitResolverEndpoints = strings.Split(resolvers, ",")
	return c, nil
}
func run(ctx context.Context, c sourceConfig) error {
	// A root publisher seals the already-started process tuple. No role writes
	// its own binding, chooses a peer, or weakens startup to an unattested daemon.
	var b *localpeer.RuntimePeerBinding
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	bootDeadline := time.NewTimer(30 * time.Second)
	defer bootDeadline.Stop()
	for b == nil {
		select {
		case <-bootDeadline.C:
			return errors.New("protected source-build startup binding unavailable")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			candidate, err := localpeer.LoadProtectedRuntimePeerBinding(c.bindingPath)
			if err == nil && candidate != nil && candidate.HasSourceBuild() {
				b = candidate
			}
		}
	}
	if b.SourceBuildPID != int32(os.Getpid()) || b.SourceBuildUID != uint32(os.Getuid()) {
		return errors.New("source-build self tuple does not match binding")
	}
	if err := localpeer.VerifyProcessIdentity(b.SourceBuildPID, b.SourceBuildUID, b.SourceBuildExeSHA, b.SourceBuildStartTime); err != nil {
		return errors.New("source-build executable identity does not match binding")
	}
	helper := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 3*time.Second)
	if err := sourcebuildexecution.VerifySourceBuildPeer(ctx, helper, b, "core", b.CorePID, b.CoreUID); err != nil {
		return errors.New("Core source-build peer attestation unavailable")
	}
	validator := func(pid int32, uid uint32) error {
		return sourcebuildexecution.VerifySourceBuildPeer(ctx, helper, b, "core", pid, uid)
	}
	authority, err := sourcebuildexecution.NewAuthorityClient(sourcebuildexecution.ClientConfig{SocketPath: b.SourceBuildAuthoritySocket, ExpectedPID: b.CorePID, ExpectedUID: b.CoreUID, PeerValidator: validator})
	if err != nil {
		return err
	}
	c.production.Authority = authority
	runtime, archiveStore, err := newProductionRuntime(c.production)
	if err != nil {
		return errors.New("source-build production dependencies unavailable")
	}
	server, err := sourcebuildexecution.NewExecutionServer(sourcebuildexecution.ServerConfig{ArchiveStore: archiveStore, SocketPath: b.SourceBuildSocket, SocketGID: c.socketGID, ExpectedPID: b.CorePID, ExpectedUID: b.CoreUID, PeerValidator: validator}, runtime)
	if err != nil {
		return errors.New("source-build execution listener unavailable")
	}
	defer server.Close()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			current, err := localpeer.LoadProtectedRuntimePeerBinding(c.bindingPath)
			if err != nil || current == nil || current.Digest() != b.Digest() {
				return errors.New("source-build binding changed; re-attested restart required")
			}
		}
	}
}
func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatal("invalid source-build configuration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := run(ctx, cfg); err != nil {
		log.Fatal("source-build role unavailable")
	}
}

// This composition root owns provider construction; the protocol package must
// not import installed-worker/installer packages back through application.
func newProductionRuntime(c sourcebuildexecution.ProductionConfig) (*sourcebuildexecution.Runtime, contracts.ImageStore, error) {
	if err := sourcebuildexecution.ValidateProductionConfig(c); err != nil {
		return nil, nil, err
	}
	paths := []string{c.UploadRoot, c.WorkspaceRoot, c.WorkRoot, c.ImageStoreRoot, c.LogRoot}
	binary, err := os.Stat(nativeBuildctlPath)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0111 == 0 {
		return nil, nil, errors.New("installed BuildKit client unavailable")
	}
	for _, socket := range []string{buildnetwork.BuildkitSocketPath, buildnetwork.SocketPath} {
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return nil, nil, errors.New("installed rootless worker or policy attestor unavailable")
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
	cap, err := capacityprovider.New(capacityprovider.Config{DiskPath: c.WorkRoot})
	if err != nil {
		return nil, nil, err
	}
	logs, err := sourcebuildexecution.NewFileBuildLogSink(c.LogRoot, paths)
	if err != nil {
		return nil, nil, err
	}
	runtime, err := sourcebuildexecution.NewRuntime(sourcebuildexecution.Config{Source: source, Authority: c.Authority, Capacity: cap, BuilderFactory: func(owner contracts.CapacityProvider) (contracts.BuildProvider, error) {
		return buildkit.New(buildkit.Config{Command: nativeBuildctlPath, Timeout: time.Hour, Builder: "acornfox-rootless", Address: "unix://" + buildnetwork.BuildkitSocketPath, WorkspaceRoot: c.WorkspaceRoot, WorkRoot: c.WorkRoot, ImageStore: images, Capacity: owner, ProductionNetworkPolicyRaw: buildnetwork.CanonicalPolicy(), WorkerPolicyAttestor: buildnetwork.Client{}, LogSink: logs, RequireLogSink: true})
	}})
	return runtime, images, err
}
