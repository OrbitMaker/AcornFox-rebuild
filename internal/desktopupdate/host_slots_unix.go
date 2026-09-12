//go:build !windows

package desktopupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func slotPinExternal(_ context.Context, p string) ([]*os.File, error) {
	var pins []*os.File
	var names []string
	for cur := p; ; cur = filepath.Dir(cur) {
		names = append(names, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	fail := func() ([]*os.File, error) {
		for _, f := range pins {
			f.Close()
		}
		return nil, ErrHostConflict
	}
	for i := len(names) - 1; i >= 0; i-- {
		f, e := os.OpenFile(names[i], os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
		if e != nil {
			return fail()
		}
		pins = append(pins, f)
		info, e := f.Stat()
		if e != nil {
			return fail()
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return fail()
		}
	}
	return pins, nil
}
func slotCheckDirectory(p string, managed bool) error {
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	actual, e := os.Lstat(p)
	if e != nil || !os.SameFile(info, actual) {
		return ErrHostConflict
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrHostConflict
	}
	if managed {
		if st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
			return ErrHostConflict
		}
	} else if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return ErrHostConflict
	}
	return nil
}
func slotCheckAsset(f *os.File, p string, mode int64, managed bool) error {
	i, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != os.FileMode(mode) || i.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Nlink != 1 {
		return ErrHostConflict
	}
	if managed {
		if st.Uid != uint32(os.Geteuid()) {
			return ErrHostConflict
		}
	} else if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return ErrHostConflict
	}
	a, e := os.Lstat(p)
	if e != nil || !os.SameFile(i, a) || a.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}
	return nil
}
func slotFileKey(f *os.File) (string, error) {
	i, e := f.Stat()
	if e != nil {
		return "", e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrHostConflict
	}
	return fmt.Sprintf("%x-%x", st.Dev, st.Ino), nil
}
func slotReplacePayload(root *os.Root, p string) error { return hostReplacePayload(root, p) }

func slotValidatePin(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
		return ErrHostConflict
	}
	return nil
}
