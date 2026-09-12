//go:build !windows

package desktopupdate

import (
	"os"
	"syscall"
)

func driverOpenExistingLock(root *os.Root, _ string) (*os.File, error) {
	return root.OpenFile("lock", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
