//go:build !windows

package desktopupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func hostPinRoot(_ context.Context, p string) ([]*os.File, error) {
	var pins []*os.File
	fail := func() ([]*os.File, error) {
		for _, f := range pins {
			f.Close()
		}
		return nil, ErrHostConflict
	}
	var paths []string
	for cur := p; ; cur = filepath.Dir(cur) {
		paths = append(paths, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		name := paths[i]
		f, e := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
		if e != nil {
			return fail()
		}
		pins = append(pins, f)
		info, e := f.Stat()
		if e != nil {
			return fail()
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (!info.IsDir()) || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return fail()
		}
		if name == p && (st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700) {
			return fail()
		}
	}
	return pins, nil
}
func hostCheckFile(f *os.File, p string) error { return hostCheckLinkedFile(f, p, 1) }
func hostCheckLinkedFile(f *os.File, p string, links uint64) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Uid != uint32(os.Geteuid()) || uint64(st.Nlink) != links {
		return ErrHostConflict
	}
	actual, e := os.Lstat(p)
	if e != nil || !os.SameFile(info, actual) || actual.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}
	return nil
}
func hostOpenLock(root *os.Root, _ string) (*os.File, error) {
	return root.OpenFile("lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
}
func hostLockFile(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(e, syscall.EWOULDBLOCK) {
		return ErrHostBusy
	}
	return e
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
	info, e := pins[len(pins)-1].Stat()
	if e != nil {
		return "", e
	}
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%x-%x", st.Dev, st.Ino), nil
}
func hostSyncDirectory(p string) error { return syncDirectory(p) }
func hostReplacePayload(root *os.Root, p string) error {
	if e := root.Rename("state.payload", "state.json"); e != nil {
		return e
	}
	return hostSyncDirectory(p)
}

func hostProbeDurability(p string) error { return hostSyncDirectory(p) }
