package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	"github.com/acornfox/acornfox/internal/gatewayexecution"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/providers/acornfoxroute"
)

type config struct {
	bindingPath string
	socketGID   uint32
	adminUID    uint32
	adminGID    uint32
}

func parseFlags(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("acornfox-gateway", flag.ContinueOnError)
	fs.StringVar(&c.bindingPath, "runtime-binding", "", "root-protected runtime peer binding")
	ipc := fs.Uint64("socket-gid", 0, "root-provisioned acornfox-ipc GID")
	adminUID := fs.Uint64("caddy-admin-uid", 0, "actual protected Caddy Unix Admin socket owner")
	adminGID := fs.Uint64("caddy-admin-gid", 0, "actual protected Caddy Unix Admin socket group")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || c.bindingPath != "/run/acornfox/trust/runtime-binding.json" || *ipc == 0 || *ipc > math.MaxUint32 || *adminUID == 0 || *adminUID > math.MaxUint32 || *adminGID != *ipc {
		return c, errors.New("Gateway requires fixed binding, IPC and protected Caddy Admin identities")
	}
	c.socketGID, c.adminUID, c.adminGID = uint32(*ipc), uint32(*adminUID), uint32(*adminGID)
	return c, nil
}

func run(ctx context.Context, c config) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	var binding *localpeer.RuntimePeerBinding
	for binding == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("protected Gateway binding unavailable")
		case <-ticker.C:
			candidate, err := localpeer.LoadProtectedRuntimePeerBinding(c.bindingPath)
			if err == nil && candidate != nil && candidate.HasGateway() {
				binding = candidate
			}
		}
	}
	if binding.GatewayPID != int32(os.Getpid()) || binding.GatewayUID != uint32(os.Getuid()) || localpeer.VerifyProcessIdentity(binding.GatewayPID, binding.GatewayUID, binding.GatewayExeSHA, binding.GatewayStartTime) != nil {
		return errors.New("Gateway self identity differs from root binding")
	}
	helper := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 3*time.Second)
	if err := gatewayexecution.VerifyGatewayPeer(ctx, helper, binding, "core", binding.CorePID, binding.CoreUID); err != nil {
		return err
	}
	validator := func(pid int32, uid uint32) error {
		return gatewayexecution.VerifyGatewayPeer(ctx, helper, binding, "core", pid, uid)
	}
	authority, err := gatewayexecution.NewAuthorityClient(gatewayexecution.ClientConfig{SocketPath: binding.GatewayAuthoritySocket, ExpectedPID: binding.CorePID, ExpectedUID: binding.CoreUID, PeerValidator: validator})
	if err != nil {
		return err
	}
	source := &gatewayexecution.Source{Authority: authority, Lock: application.GatewayProjectionLock{Path: application.GatewayProjectionLockPath, ExpectedOwnerUID: 0, IPCGID: c.socketGID}}
	provider, err := acornfoxroute.New(acornfoxroute.Config{CustomOnly: true, Source: source, AdminUnixSocket: acornfoxroute.NativeAdminSocketPath, AdminSocketUID: c.adminUID, AdminSocketGID: c.adminGID})
	if err != nil {
		return errors.New("protected custom-only Caddy Admin unavailable")
	}
	defer provider.Close()
	server, err := gatewayexecution.NewExecutionServer(gatewayexecution.ServerConfig{SocketPath: binding.GatewaySocket, SocketGID: c.socketGID, ExpectedPID: binding.CorePID, ExpectedUID: binding.CoreUID, PeerValidator: validator}, &gatewayexecution.Runtime{Authority: authority, Projector: provider})
	if err != nil {
		return err
	}
	defer server.Close()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			current, err := localpeer.LoadProtectedRuntimePeerBinding(c.bindingPath)
			if err != nil || current == nil || current.Digest() != binding.Digest() {
				return errors.New("Gateway binding changed; re-attested restart required")
			}
		}
	}
}

func main() {
	c, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatal("invalid Gateway configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c); err != nil {
		log.Fatal("Gateway role unavailable")
	}
}
