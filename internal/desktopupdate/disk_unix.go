//go:build !windows

package desktopupdate

import (
	"syscall"
)

func getFreeDiskSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	// Available blocks for unprivileged user * block size
	return stat.Bavail * uint64(stat.Bsize), nil
}
