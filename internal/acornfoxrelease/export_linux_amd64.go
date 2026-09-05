//go:build linux && amd64

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
	// Linux x86-64 ABI: renameat2 is syscall 316; RENAME_NOREPLACE is 1.
	_, _, errno := syscall.Syscall6(316, from.Fd(), uintptr(unsafe.Pointer(old)), to.Fd(), uintptr(unsafe.Pointer(next)), 1, 0)
	runtime.KeepAlive(from)
	runtime.KeepAlive(to)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
}
