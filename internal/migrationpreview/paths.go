package migrationpreview

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func trustedAncestors(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute_trusted_path_required")
	}
	for parent := filepath.Dir(filepath.Clean(path)); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("untrusted_path_ancestor")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Getuid())) {
			return errors.New("untrusted_path_owner")
		}
		if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("writable_path_ancestor")
		}
		if parent == "/" {
			break
		}
	}
	return nil
}
func trustedDumpTool(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("absolute_dump_tool_required")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("dump_tool_rejected")
	}
	if err := trustedAncestors(canonical); err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("dump_tool_rejected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Getuid())) {
		return "", errors.New("dump_tool_owner_rejected")
	}
	return canonical, nil
}
