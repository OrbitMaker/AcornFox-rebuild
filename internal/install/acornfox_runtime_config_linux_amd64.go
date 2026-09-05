//go:build linux && amd64

package install

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func acornFoxRuntimeRenameNoReplace(parent *os.File, oldName, newName string) error {
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	// Linux x86-64 renameat2, RENAME_NOREPLACE. Both names are direct children of
	// the already-opened same-filesystem parent; no overwrite fallback exists.
	_, _, errno := syscall.Syscall6(316, parent.Fd(), uintptr(unsafe.Pointer(old)), parent.Fd(), uintptr(unsafe.Pointer(next)), 1, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
}
