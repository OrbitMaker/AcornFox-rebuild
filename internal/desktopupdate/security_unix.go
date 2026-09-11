//go:build !windows

package desktopupdate

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

// checkParentDirectoryPermissions verifies Unix directory permissions:
// Must be owned by current user (or root if running as root), and group/other must not be writable.
func checkParentDirectoryPermissions(ctx context.Context, info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot inspect unix stat for parent dir", ErrInvalidParentDir)
	}
	currentUID := uint32(os.Geteuid())
	if stat.Uid != currentUID && stat.Uid != 0 {
		return fmt.Errorf("%w: parent directory owner uid=%d does not match current euid=%d", ErrInvalidParentDir, stat.Uid, currentUID)
	}
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return fmt.Errorf("%w: parent directory has insecure permissions (%04o), group/other writable", ErrInvalidParentDir, perm)
	}
	return nil
}

// secureNewStageDirectory secures the newly created stage directory permissions (0700 on Unix).
func secureNewStageDirectory(ctx context.Context, stageDirPath string) error {
	return os.Chmod(stageDirPath, 0700)
}

func verifyStagedFileSecurity(ctx context.Context, stageDirPath, filePath string) error {
	di, err := os.Lstat(stageDirPath)
	if err != nil {
		return fmt.Errorf("%w: stat stage dir: %v", ErrDownloadFailed, err)
	}
	if di.Mode()&os.ModeSymlink != 0 || di.Mode().Perm() != 0700 {
		return fmt.Errorf("%w: unexpected stage dir mode %04o", ErrDownloadFailed, di.Mode().Perm())
	}
	fi, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("%w: stat staged payload: %v", ErrDownloadFailed, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0600 {
		return fmt.Errorf("%w: unexpected payload mode %04o", ErrDownloadFailed, fi.Mode().Perm())
	}
	return nil
}

// syncDirectory syncs directory changes to durable storage on Unix.
func syncDirectory(dirPath string) error {
	d, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("%w: open dir for sync failed: %v", ErrDownloadFailed, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("%w: dir sync failed: %v", ErrDownloadFailed, err)
	}
	return nil
}
