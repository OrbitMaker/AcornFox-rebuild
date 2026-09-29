package unifiedinstall

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
)

// RuntimeIPCAccounts contains host-resolved identities, never assumed numeric
// IDs. This prepares directories only; it does not publish the root binding,
// install a service, start a role or open a live socket.
type RuntimeIPCAccounts struct {
	CoreUID, ContainerUID, SourceUID, GatewayUID, IPCGID int
}

func verifyRuntimeIPCAccounts(a RuntimeIPCAccounts) error {
	if a.CoreUID <= 0 || a.ContainerUID <= 0 || a.SourceUID <= 0 || a.GatewayUID <= 0 || a.IPCGID <= 0 ||
		a.CoreUID == a.ContainerUID || a.CoreUID == a.SourceUID || a.CoreUID == a.GatewayUID || a.ContainerUID == a.SourceUID || a.ContainerUID == a.GatewayUID || a.SourceUID == a.GatewayUID {
		return errors.New("distinct resolved non-root role UIDs and IPC GID are required")
	}
	group, err := user.LookupGroup(install.AccountPeerIPC)
	if err != nil || group.Gid != strconv.Itoa(a.IPCGID) {
		return errors.New("allocated IPC group does not match host identity")
	}
	for _, role := range []struct {
		name string
		uid  int
	}{{install.AccountCore, a.CoreUID}, {install.AccountContainerRuntime, a.ContainerUID}, {install.AccountSourceBuild, a.SourceUID}, {install.AccountGateway, a.GatewayUID}} {
		account, err := user.Lookup(role.name)
		if err != nil || account.Uid != strconv.Itoa(role.uid) {
			return fmt.Errorf("resolved %s UID does not match host account", role.name)
		}
		groups, err := account.GroupIds()
		if err != nil {
			return fmt.Errorf("read %s supplementary groups: %w", role.name, err)
		}
		member := false
		for _, id := range groups {
			if id == group.Gid {
				member = true
				break
			}
		}
		if !member {
			return fmt.Errorf("%s lacks the IPC group", role.name)
		}
	}
	return nil
}

func verifyRootRunAncestor(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(info, 0, 0) != nil {
			return errors.New("IPC run-root ancestry is not root-protected")
		}
		if parent == "/" {
			return nil
		}
	}
}

func ensureRuntimeIPCDir(path string, uid, gid int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return errors.New("existing IPC directory differs from the resolved role-owned layout")
	}
	return nil
}

// The one Gateway projection lock is root-published in the non-writable trust
// directory. Core and Gateway may flock its inode through the IPC group, but
// neither role can replace or create the lock path.
func ensureGatewayProjectionLock(gid int) (err error) {
	path := filepath.Join(install.UnifiedRunRootDir, "trust", "gateway-projection.lock")
	file, openErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	created := openErr == nil
	if os.IsExist(openErr) {
		file, openErr = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if openErr != nil {
		return openErr
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil && created {
			_ = os.Remove(path)
		}
	}()
	if created {
		if err := file.Chown(0, gid); err != nil {
			return err
		}
		if err := file.Chmod(0o660); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o660 || artifactio.CheckFileOwner(opened, 0, gid) != nil {
		return errors.New("Gateway projection lock identity differs from root:IPC 0660")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("Gateway projection lock is not a single protected inode")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return errors.New("Gateway projection lock path changed")
	}
	return nil
}

// PrepareUnifiedRuntimeIPCParents is an explicit root-publisher primitive.
// Role parents are owner-writable and group-traversable, never group-writable:
// IPC peers can connect to 0660 sockets but cannot replace another role's
// socket. The separate root-owned trust directory is suitable for a later
// root:IPC 0640 binding publication under the protected binding loader.
func PrepareUnifiedRuntimeIPCParents(a RuntimeIPCAccounts) error {
	if os.Geteuid() != 0 {
		return errors.New("root is required to publish role IPC parents")
	}
	if err := verifyRuntimeIPCAccounts(a); err != nil {
		return err
	}
	root := install.UnifiedRunRootDir
	if err := verifyRootRunAncestor(root); err != nil {
		return err
	}
	for _, dir := range []struct {
		path string
		uid  int
		mode os.FileMode
	}{
		{root, 0, 0o750},
		{filepath.Join(root, "trust"), 0, 0o750},
		{filepath.Join(root, "helper"), 0, 0o750},
		{filepath.Join(root, "core-ipc"), a.CoreUID, os.ModeSetgid | 0o750},
		{filepath.Join(root, "container-ipc"), a.ContainerUID, os.ModeSetgid | 0o750},
		{filepath.Join(root, "source-ipc"), a.SourceUID, os.ModeSetgid | 0o750},
		{filepath.Join(root, "gateway-ipc"), a.GatewayUID, os.ModeSetgid | 0o750},
	} {
		if err := ensureRuntimeIPCDir(dir.path, dir.uid, a.IPCGID, dir.mode); err != nil {
			return fmt.Errorf("publish %s: %w", filepath.Base(dir.path), err)
		}
	}
	return ensureGatewayProjectionLock(a.IPCGID)
}
