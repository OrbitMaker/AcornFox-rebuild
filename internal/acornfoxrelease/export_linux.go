//go:build linux && (amd64 || arm64)

package acornfoxrelease

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func renameDirectoryNoReplace(from *os.File, oldName string, to *os.File, newName string) error {
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	// Linux ABI: renameat2 syscall with RENAME_NOREPLACE (1).
	// Both directories are already-opened and verified descriptors.
	_, _, errno := syscall.Syscall6(sysRenameat2, from.Fd(), uintptr(unsafe.Pointer(old)), to.Fd(), uintptr(unsafe.Pointer(next)), 1, 0)
	runtime.KeepAlive(from)
	runtime.KeepAlive(to)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
}
