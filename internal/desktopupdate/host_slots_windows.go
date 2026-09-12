//go:build windows

package desktopupdate

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func slotPinExternal(ctx context.Context, p string) ([]*os.File, error) { return hostPinRoot(ctx, p) }
func slotCheckDirectory(p string, _ bool) error {
	f, e := hostWindowsOpen(p, 0x80|0x20000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, true)
	if e != nil {
		return e
	}
	defer f.Close()
	i, e := hostWindowsInfo(f)
	if e != nil || i.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrHostConflict
	}
	return checkWindowsObjectSecurity(context.Background(), p)
}
func slotCheckAsset(f *os.File, p string, _ int64, _ bool) error { return hostCheckFile(f, p) }
func slotFileKey(f *os.File) (string, error) {
	i, e := hostWindowsInfo(f)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%x-%x-%x", i.VolumeSerialNumber, i.FileIndexHigh, i.FileIndexLow), nil
}

// FileRenameInfoEx with an absolute DOS path and NULL RootDirectory preserves
// verified open old handles. No IGNORE_READONLY or close-before-replace race.
// The separate directory FlushFileBuffers gate may reject this platform before
// any ledger change; cross compilation is not Windows durability evidence.
func slotReplacePayload(_ *os.Root, p string) error {
	source := filepath.Join(p, "state.payload")
	f, e := hostWindowsOpen(source, 0x10000|0x80|0x20000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, syscall.OPEN_EXISTING, false)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = hostCheckFile(f, source); e != nil {
		return e
	}
	target := filepath.Join(p, "state.json")
	var old *os.File
	if _, e = os.Lstat(target); e == nil {
		old, e = hostWindowsOpen(target, 0x80|0x20000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, syscall.OPEN_EXISTING, false)
		if e != nil {
			return e
		}
		defer old.Close()
		if e = hostCheckFile(old, target); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	name, e := syscall.UTF16FromString(target)
	if e != nil {
		return e
	}
	name = name[:len(name)-1]
	// Windows amd64 and arm64 both use an 8-byte HANDLE aligned at offset 8.
	data := make([]byte, 20+2*len(name))
	binary.LittleEndian.PutUint32(data[0:4], 3)
	binary.LittleEndian.PutUint32(data[16:20], uint32(2*len(name)))
	for i, v := range name {
		binary.LittleEndian.PutUint16(data[20+i*2:], v)
	}
	ok, _, e := modkernel32.NewProc("SetFileInformationByHandle").Call(f.Fd(), 22, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if ok == 0 {
		return e
	}
	return hostSyncDirectory(p)
}

func slotValidatePin(f *os.File) error {
	v, e := hostWindowsInfo(f)
	if e != nil || v.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrHostConflict
	}
	return nil
}
