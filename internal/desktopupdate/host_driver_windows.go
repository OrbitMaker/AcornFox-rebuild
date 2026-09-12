//go:build windows

package desktopupdate

import (
	"os"
	"syscall"
)

func driverOpenExistingLock(_ *os.Root, p string) (*os.File, error) {
	return hostWindowsOpen(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, false)
}
