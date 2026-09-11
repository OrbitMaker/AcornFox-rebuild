//go:build linux && (amd64 || arm64)

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
	// Linux renameat2, RENAME_NOREPLACE (flags=1). Both names are direct children of
	// the already-opened same-filesystem parent; no overwrite fallback exists.
	_, _, errno := syscall.Syscall6(acornFoxSysRenameat2, parent.Fd(), uintptr(unsafe.Pointer(old)), parent.Fd(), uintptr(unsafe.Pointer(next)), 1, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
}
