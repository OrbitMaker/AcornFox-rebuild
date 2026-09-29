package unifiedinstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-card/open-card/internal/buildnetwork"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

// hostFile is a fixed Native config or unit. path is always a product-owned
// absolute path; the private test root is applied only by the unexported writer.
type hostFile struct {
	path     string
	data     []byte
	mode     os.FileMode
	uid, gid int
}

type nativeHostIDs struct {
	IPC, CoreUID, CoreGID, ContainerUID, ContainerGID int
	SourceUID, SourceGID, GatewayUID, GatewayGID      int
	CaddyUID, CaddyGID, BuildkitUID, BuildkitGID      int
}

func nativeHostOwnedFilePaths() []string {
	return []string{
		"/etc/acornfox/build-network-policy.json", "/etc/acornfox/build-resolv.conf",
		"/etc/acornfox/rootlesskit.apparmor", "/etc/acornfox/buildkitd.toml",
		"/etc/acornfox/native-caddy.json",
		"/etc/systemd/system/acornfox-core.service", "/etc/systemd/system/acornfox-container.service",
		"/etc/systemd/system/acornfox-source-build.service", "/etc/systemd/system/acornfox-gateway.service",
		"/etc/systemd/system/acornfox-build-network.service", "/etc/systemd/system/acornfox-buildkit.service",
		"/etc/systemd/system/acornfox-caddy.service", "/etc/systemd/system/acornfox-host-helper.service",
	}
}

func nativeHostFiles(stagePath, releaseID string, ids nativeHostIDs) ([]hostFile, error) {
	if !strings.HasPrefix(filepath.Base(stagePath), "ready-") || ids.IPC <= 0 || ids.CoreGID <= 0 || ids.CaddyUID <= 0 || ids.BuildkitUID <= 0 {
		return nil, ErrIncomplete
	}
	caddy, err := acornfoxroute.CustomOnlyInitialConfig([]string{"1.1.1.1:53", "1.0.0.1:53"})
	if err != nil {
		return nil, err
	}
	config := []hostFile{
		{"/etc/acornfox/build-network-policy.json", buildnetwork.CanonicalPolicy(), 0o644, 0, 0},
		{"/etc/acornfox/build-resolv.conf", buildnetwork.ResolverConfig(), 0o644, 0, 0},
		{"/etc/acornfox/rootlesskit.apparmor", buildnetwork.NativeRootlessProfile(), 0o644, 0, 0},
		{"/etc/acornfox/buildkitd.toml", []byte(nativeBuildkitConfig), 0o644, 0, 0},
		{"/etc/acornfox/native-caddy.json", caddy, 0o644, 0, 0},
	}
	current := install.UnifiedCurrentSymlink
	units := []hostFile{
		{"/etc/systemd/system/acornfox-core.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native Core launcher
After=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart=%s/bin/acornfox-host-update native-core-launch --stage %s
LoadCredential=acornfox-setup-token:/etc/acornfox/trust/acornfox-setup-token
Restart=no
NoNewPrivileges=yes
UMask=0077
`, filepath.Join(install.UnifiedReleasesDir, releaseID), stagePath)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-container.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native container role
Requires=docker.service
After=docker.service

[Service]
Type=simple
User=acornfox-container
Group=acornfox-container
SupplementaryGroups=acornfox-ipc docker
ExecStart=%s/bin/acornfox-container --runtime-binding /run/acornfox/trust/runtime-binding.json --work-root /var/lib/acornfox/container/work --image-store /var/lib/acornfox/container/images --socket-gid %d
NoNewPrivileges=yes
UMask=0077
`, current, ids.IPC)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-source-build.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native Source adapter
Requires=acornfox-buildkit.service
After=acornfox-buildkit.service

[Service]
Type=simple
User=acornfox-build
Group=acornfox-build
SupplementaryGroups=acornfox-ipc acornfox-buildkit
ExecStart=%s/bin/acornfox-source-build --runtime-binding /run/acornfox/trust/runtime-binding.json --upload-root /var/lib/acornfox/build/uploads --workspace-root /var/lib/acornfox/build/source --work-root /var/lib/acornfox/build/work --image-store /var/lib/acornfox/build/images --log-root /var/lib/acornfox/build/logs --git-resolvers 1.1.1.1:53,1.0.0.1:53 --socket-gid %d
NoNewPrivileges=yes
UMask=0077
`, current, ids.IPC)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-gateway.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native Gateway adapter
Requires=acornfox-caddy.service
After=acornfox-caddy.service

[Service]
Type=simple
User=acornfox-gateway
Group=acornfox-gateway
SupplementaryGroups=acornfox-ipc
ExecStart=%s/bin/acornfox-gateway --runtime-binding /run/acornfox/trust/runtime-binding.json --socket-gid %d --caddy-admin-uid %d --caddy-admin-gid %d
NoNewPrivileges=yes
UMask=0077
`, current, ids.IPC, ids.CaddyUID, ids.IPC)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-build-network.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native root-owned build network policy
Requires=docker.service
After=docker.service
Before=acornfox-buildkit.service

[Service]
Type=notify
NotifyAccess=main
User=root
Group=root
ExecStart=%s/bin/acornfox-build-network serve
ExecStopPost=%s/bin/acornfox-build-network cleanup
NoNewPrivileges=yes
PrivateMounts=no
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_MAC_ADMIN
UMask=0077
`, current, current)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-buildkit.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native rootless BuildKit worker
Requires=acornfox-build-network.service
After=acornfox-build-network.service

[Service]
Type=simple
User=acornfox-buildkit
Group=acornfox-buildkit
WorkingDirectory=/var/lib/acornfox/buildkit
Environment=HOME=/var/lib/acornfox/buildkit
Environment=XDG_RUNTIME_DIR=/run/acornfox-buildkit
Environment=PATH=/opt/acornfox/current/embedded/bin:/usr/bin:/bin
NetworkNamespacePath=/run/netns/acornfox-buildkit
ExecStart=%s/embedded/bin/rootlesskit --state-dir=/var/lib/acornfox/buildkit/rootlesskit --net=host --copy-up=/etc --copy-up=/run --propagation=rslave %s/embedded/bin/buildkitd --config /etc/acornfox/buildkitd.toml --root /var/lib/acornfox/buildkit/buildkitd --addr unix:///run/acornfox-buildkit/buildkitd.sock --group 0
NoNewPrivileges=no
Delegate=yes
UMask=0077
`, current, current)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-caddy.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native independent Caddy edge
After=network-online.target

[Service]
Type=notify
User=acornfox-caddy
Group=acornfox-caddy
SupplementaryGroups=acornfox-ipc
Environment=XDG_DATA_HOME=/var/lib/acornfox/edge
Environment=XDG_CONFIG_HOME=/var/lib/acornfox/edge
ExecStart=%s/embedded/bin/caddy run --config /etc/acornfox/native-caddy.json
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/acornfox/edge /run/acornfox/edge-admin
UMask=0077
`, current)), 0o644, 0, 0},
		{"/etc/systemd/system/acornfox-host-helper.service", []byte(fmt.Sprintf(`[Unit]
Description=AcornFox Native protected peer helper
After=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart=%s/bin/acornfox-host-helper --readonly-peer --runtime-binding /run/acornfox/trust/runtime-binding.json --core-gid %d --socket-gid %d --socket /run/acornfox-helper/helper.sock
NoNewPrivileges=yes
UMask=0077
`, current, ids.CoreGID, ids.IPC)), 0o644, 0, 0},
	}
	return append(config, units...), nil
}

// This is a fixed worker config, not input from a Dockerfile or a release
// manifest. Its resolver and rootless choices match the policy executor.
const nativeBuildkitConfig = `root = "/var/lib/acornfox/buildkit/buildkitd"

[dns]
  nameservers = ["1.1.1.1", "1.0.0.1"]

[registry."docker.io"]
  mirrors = ["public.ecr.aws/docker"]

[worker.oci]
  enabled = true
  rootless = true
  snapshotter = "native"
  max-parallelism = 1

[worker.containerd]
  enabled = false
`
