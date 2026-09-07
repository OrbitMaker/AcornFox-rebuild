package main

import (
	"io"
	"os"
	"path/filepath"
)

// Only systemd's private credential directory supplies setup credentials. A
// missing credential leaves web setup unavailable while existing logins work.
func acornFoxSetupCredential(directory string) []byte {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil
	}
	defer root.Close()
	const name = "acornfox-setup-token"
	// systemd may map a credential as root:service-group 0440 inside the
	// service mount namespace. Group read is valid; group write/execute and
	// every other-user permission remain forbidden.
	info, err = root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0027 != 0 || info.Size() > 44 {
		return nil
	}
	file, err := root.Open(name)
	if err != nil {
		return nil
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil
	}
	value, err := io.ReadAll(io.LimitReader(file, 45))
	if err != nil || len(value) > 44 {
		clear(value)
		return nil
	}
	return value
}
