//go:build darwin || linux

package source

import (
	"math"
	"syscall"
)

func workspaceFilesystemAvailabilityForRoot(root string) (workspaceFilesystemAvailability, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return workspaceFilesystemAvailability{}, errWorkspaceUnavailable
	}
	blocks := uint64(stat.Bavail)
	blockSize := uint64(stat.Bsize)
	if blockSize == 0 || blocks > uint64(math.MaxInt64)/blockSize || uint64(stat.Ffree) > uint64(math.MaxInt64) {
		return workspaceFilesystemAvailability{}, errWorkspaceUnavailable
	}
	return workspaceFilesystemAvailability{bytes: int64(blocks * blockSize), entries: int64(uint64(stat.Ffree))}, nil
}
