//go:build windows

package desktopupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func hostWindowsOpen(p string, access, share, creation uint32, dir bool) (*os.File, error) {
	n, e := syscall.UTF16PtrFromString(p)
	if e != nil {
		return nil, e
	}
	flags := uint32(0x00200000)
	if dir {
		flags |= 0x02000000
	}
	h, e := syscall.CreateFile(n, access, share, nil, creation, flags, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), p), nil
}
func hostWindowsInfo(f *os.File) (syscall.ByHandleFileInformation, error) {
	var v syscall.ByHandleFileInformation
	e := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &v)
	if e != nil || v.FileAttributes&0x400 != 0 {
		return v, ErrHostConflict
	}
	return v, nil
}
func hostPinRoot(ctx context.Context, p string) ([]*os.File, error) {
	var pins []*os.File
	fail := func() ([]*os.File, error) {
		for _, f := range pins {
			f.Close()
		}
		return nil, ErrHostConflict
	}
	if strings.HasPrefix(p, `\\`) {
		return fail()
	}
	var names []string
	for cur := p; ; cur = filepath.Dir(cur) {
		names = append(names, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	for i := len(names) - 1; i >= 0; i-- {
		f, e := hostWindowsOpen(names[i], 0x80|0x20000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, true)
		if e != nil {
			return fail()
		}
		pins = append(pins, f)
		v, e := hostWindowsInfo(f)
		if e != nil || v.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fail()
		}
	}
	if checkWindowsObjectSecurity(ctx, p) != nil {
		return fail()
	}
	return pins, nil
}
func hostCheckFile(f *os.File, p string) error { return hostCheckLinkedFile(f, p, 1) }
func hostCheckLinkedFile(f *os.File, p string, links uint64) error {
	v, e := hostWindowsInfo(f)
	if e != nil || uint64(v.NumberOfLinks) != links || v.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return ErrHostConflict
	}
	if checkWindowsObjectSecurity(context.Background(), p) != nil {
		return ErrHostConflict
	}
	other, e := hostWindowsOpen(p, 0x80, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, syscall.OPEN_EXISTING, false)
	if e != nil {
		return ErrHostConflict
	}
	defer other.Close()
	a, e := hostWindowsInfo(other)
	if e != nil || a.VolumeSerialNumber != v.VolumeSerialNumber || a.FileIndexHigh != v.FileIndexHigh || a.FileIndexLow != v.FileIndexLow {
		return ErrHostConflict
	}
	return nil
}
func hostOpenLock(_ *os.Root, p string) (*os.File, error) {
	return hostWindowsOpen(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_ALWAYS, false)
}
func hostLockFile(f *os.File) error {
	var ov syscall.Overlapped
	ok, _, e := modkernel32.NewProc("LockFileEx").Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if ok == 0 {
		if errors.Is(e, syscall.Errno(33)) {
			return ErrHostBusy
		}
		return ErrHostConflict
	}
	return nil
}
func hostDirectoryKey(p string) (string, error) {
	pins, e := hostPinRoot(context.Background(), p)
	if e != nil {
		return "", e
	}
	defer func() {
		for _, f := range pins {
			f.Close()
		}
	}()
	v, e := hostWindowsInfo(pins[len(pins)-1])
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%x-%x-%x", v.VolumeSerialNumber, v.FileIndexHigh, v.FileIndexLow), nil
}

// Directory FlushFileBuffers is not a portable Windows guarantee. State commit
// uses flushed file bytes plus MOVEFILE_WRITE_THROUGH; no empty success shim.
func hostSyncDirectory(p string) error {
	pins, e := hostPinRoot(context.Background(), p)
	if e != nil {
		return e
	}
	defer func() {
		for _, f := range pins {
			f.Close()
		}
	}()
	h, e := hostWindowsOpen(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, true)
	if e != nil {
		return fmt.Errorf("%w: %v", ErrHostDurabilityUnavailable, e)
	}
	defer h.Close()
	original, e := hostWindowsInfo(pins[len(pins)-1])
	actual, ae := hostWindowsInfo(h)
	if e != nil || ae != nil || original.VolumeSerialNumber != actual.VolumeSerialNumber || original.FileIndexHigh != actual.FileIndexHigh || original.FileIndexLow != actual.FileIndexLow {
		return ErrHostConflict
	}
	if e = syscall.FlushFileBuffers(syscall.Handle(h.Fd())); e != nil {
		return fmt.Errorf("%w: %v", ErrHostDurabilityUnavailable, e)
	}
	return nil
}
func hostReplacePayload(_ *os.Root, p string) error {
	from, e := syscall.UTF16PtrFromString(filepath.Join(p, "state.payload"))
	if e != nil {
		return e
	}
	to, e := syscall.UTF16PtrFromString(filepath.Join(p, "state.json"))
	if e != nil {
		return e
	}
	ok, _, e := modkernel32.NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 9)
	if ok == 0 {
		return e
	}
	return nil
}

func hostProbeDurability(p string) error { return hostSyncDirectory(p) }
