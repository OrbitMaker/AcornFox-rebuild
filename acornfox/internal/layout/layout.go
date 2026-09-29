// Package layout fixes the on-host paths and accounts of an AcornFox installation.
//
// Two AcornFox processes run on a host:
//
//   - acornfox-core (account AccountCore): HTTP API, web console, authentication,
//     SQLite and task scheduling. It has no Docker, BuildKit or Caddy access.
//   - acornfox-executor (account AccountExecutor): container runtime, source
//     build and gateway execution. It is the only AcornFox process that can reach
//     Docker, BuildKit and the Caddy admin socket, and it accepts only typed,
//     validated requests from core.
//
// Both accounts are members of GroupIPC, which owns RunDir and the sockets in it.
// The installer (and systemd RuntimeDirectory) prepares every directory below.
package layout

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

const (
	AccountCore     = "acornfox"
	AccountExecutor = "acornfox-exec"
	GroupIPC        = "acornfox-ipc"

	CurrentRelease = "/opt/acornfox/current"
	ConfigDir      = "/etc/acornfox"

	CoreDataDir = "/var/lib/acornfox/core"
	CoreDBName  = "acornfox.db"

	ExecutorDataDir     = "/var/lib/acornfox/executor"
	ContainerWorkDir    = ExecutorDataDir + "/container-work"
	ContainerImageStore = ExecutorDataDir + "/container-images"
	SourceUploadDir     = ExecutorDataDir + "/source-uploads"
	SourceWorkspaceDir  = ExecutorDataDir + "/source-workspaces"
	BuildWorkDir        = ExecutorDataDir + "/build-work"
	BuildImageStore     = ExecutorDataDir + "/build-images"
	BuildLogDir         = ExecutorDataDir + "/build-logs"

	// RunDir holds every core/executor socket. Mode 0750, owner root, group GroupIPC.
	RunDir = "/run/acornfox"

	// Executor-served sockets (only AccountCore may connect).
	ContainerSocket = RunDir + "/container.sock"
	SourceSocket    = RunDir + "/source-build.sock"
	GatewaySocket   = RunDir + "/gateway.sock"

	// Core-served authority sockets (only AccountExecutor may connect).
	ContainerAuthoritySocket = RunDir + "/container-authority.sock"
	SourceAuthoritySocket    = RunDir + "/source-build-authority.sock"
	GatewayAuthoritySocket   = RunDir + "/gateway-authority.sock"

	// GatewayProjectionLock serializes core's route intent with executor's Caddy projection.
	GatewayProjectionLock = RunDir + "/gateway-projection.lock"

	// BuildctlPath is the BuildKit client shipped with the release.
	BuildctlPath = CurrentRelease + "/bin/buildctl"
)

// Identity is the resolved numeric identity of the host accounts.
type Identity struct {
	CoreUID     uint32
	ExecutorUID uint32
	IPCGID      uint32
}

// Resolve looks up the installed accounts. It fails when any is missing or root.
func Resolve() (Identity, error) {
	var id Identity
	var err error
	if id.CoreUID, err = lookupUser(AccountCore); err != nil {
		return id, err
	}
	if id.ExecutorUID, err = lookupUser(AccountExecutor); err != nil {
		return id, err
	}
	g, err := user.LookupGroup(GroupIPC)
	if err != nil {
		return id, fmt.Errorf("group %s: %w", GroupIPC, err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil || gid == 0 {
		return id, fmt.Errorf("group %s has an invalid gid", GroupIPC)
	}
	id.IPCGID = uint32(gid)
	if id.CoreUID == id.ExecutorUID {
		return id, errors.New("core and executor must run as different accounts")
	}
	return id, nil
}

func lookupUser(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("account %s: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, fmt.Errorf("account %s has an invalid uid", name)
	}
	return uint32(uid), nil
}
