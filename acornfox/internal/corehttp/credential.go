package corehttp

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// verifyTrustedCredentialDirectory verifies that directory and all its ancestors are
// safe, trusted paths: owned by root (uid 0) or current process UID, not symlinks,
// and not group- or world-writable (unless a root-owned directory with the sticky bit set,
// such as /tmp or /run). The target directory itself must be private (no group write,
// no other read/write/execute).
func verifyTrustedCredentialDirectory(cleanDir string) bool {
	if !filepath.IsAbs(cleanDir) {
		return false
	}

	currentUID := os.Getuid()

	// 1. Walk and verify all ancestors up to root
	parent := filepath.Dir(cleanDir)
	for p := parent; p != "/" && p != "."; p = filepath.Dir(p) {
		pFi, err := os.Lstat(p)
		if err != nil || !pFi.IsDir() || pFi.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := pFi.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		// Ancestor must be owned by current UID or root
		if stat.Uid != 0 && int(stat.Uid) != currentUID {
			return false
		}
		// Reject group- or world-writable ancestors unless root-owned with sticky bit set
		if pFi.Mode()&0022 != 0 {
			if stat.Uid != 0 || pFi.Mode()&os.ModeSticky == 0 {
				return false
			}
		}
	}

	// 2. Target credential directory verification
	fi, err := os.Lstat(cleanDir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if stat.Uid != 0 && int(stat.Uid) != currentUID {
		return false
	}
	// Must be private: no group write, no other permissions (perm & 0027 must be 0)
	if fi.Mode().Perm()&0027 != 0 {
		return false
	}

	return true
}

// AcornFoxSetupCredential loads the setup credential from a trusted private credential directory.
// Only systemd's private credential directory supplies setup credentials. A
// missing credential leaves web setup unavailable while existing logins work.
// Ownership, mode, size limits, symlink defenses, and credential clearing are preserved.
func AcornFoxSetupCredential(directory string) []byte {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil
	}
	cleanDir := filepath.Clean(directory)
	if !verifyTrustedCredentialDirectory(cleanDir) {
		return nil
	}

	root, err := os.OpenRoot(cleanDir)
	if err != nil {
		return nil
	}
	defer root.Close()

	const name = "acornfox-setup-token"
	// systemd may map a credential as root:service-group 0440 inside the
	// service mount namespace. User-private 0600/0400 and systemd 0440 are valid.
	// Group write/execute and all other-user permissions remain forbidden.
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0027 != 0 || info.Size() > 44 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int(stat.Uid) != os.Getuid()) {
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
