//go:build darwin || linux

package source

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func acquireWorkspaceRootLock(root string) (func(), error) {
	path := filepath.Join(root, workspaceLockName)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errWorkspaceUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		_ = file.Close()
		return nil, errWorkspaceUnavailable
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, errWorkspaceUnavailable
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
