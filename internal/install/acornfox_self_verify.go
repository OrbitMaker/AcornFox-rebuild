package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// acornFoxSelfVerifier is a deliberately small test seam. Production uses the
// running executable; tests may instead pin a temporary regular file and its
// expected owner. It never executes or changes that file.
type acornFoxSelfVerifier struct {
	path     string
	uid, gid int
}

func newAcornFoxProductionSelfVerifier() acornFoxSelfVerifier {
	return acornFoxSelfVerifier{path: "/proc/self/exe", uid: os.Geteuid(), gid: os.Getegid()}
}

func (v acornFoxSelfVerifier) verify(expectedSHA256 string, manifestRaw []byte) error {
	if v.path == "" || v.uid < 0 || v.gid < 0 || !validSHA(expectedSHA256) {
		return errors.New("AcornFox self verifier is invalid")
	}
	var manifest Manifest
	if err := strictCanonicalJSON(manifestRaw, &manifest, "AcornFox manifest"); err != nil {
		return err
	}
	var upgradeSHA string
	for _, entry := range manifest.Files {
		if entry.Path == "bin/acornfox-upgrade" {
			upgradeSHA = entry.SHA256
			break
		}
	}
	if upgradeSHA != expectedSHA256 {
		return errors.New("AcornFox self digest does not match upgrade manifest")
	}
	file, opened, err := v.openPinnedSelf()
	if err != nil {
		return errors.New("AcornFox self executable is unsafe")
	}
	hasher := sha256.New()
	count, hashErr := io.Copy(hasher, io.LimitReader(file, acornFoxArchiveMaxBytes+1))
	hash := hex.EncodeToString(hasher.Sum(nil))
	closeErr := file.Close()
	if hashErr != nil || count != opened.Size() || closeErr != nil || hash != expectedSHA256 || !v.reopensSameSelf(opened) {
		return errors.New("AcornFox self executable changed or digest mismatched")
	}
	return nil
}

// openPinnedSelf makes one intentionally narrow exception for Linux procfs:
// /proc/self/exe is a kernel-provided symlink whose target is the currently
// executing file. Its authority is the opened descriptor and fstat result, not
// the symlink metadata. Any injected path still rejects a symlink before and
// during open.
func (v acornFoxSelfVerifier) openPinnedSelf() (*os.File, os.FileInfo, error) {
	if v.path == "/proc/self/exe" {
		file, err := os.Open(v.path)
		if err != nil {
			return nil, nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !safeAcornFoxSelfFile(info, v.uid, v.gid) {
			_ = file.Close()
			return nil, nil, errors.New("unsafe proc self")
		}
		return file, info, nil
	}
	before, err := os.Lstat(v.path)
	if err != nil || !safeAcornFoxSelfFile(before, v.uid, v.gid) {
		return nil, nil, errors.New("unsafe self")
	}
	file, err := os.OpenFile(v.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !safeAcornFoxSelfFile(opened, v.uid, v.gid) || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("changed self")
	}
	return file, opened, nil
}

func (v acornFoxSelfVerifier) reopensSameSelf(first os.FileInfo) bool {
	if v.path == "/proc/self/exe" {
		file, err := os.Open(v.path)
		if err != nil {
			return false
		}
		second, statErr := file.Stat()
		closeErr := file.Close()
		return statErr == nil && closeErr == nil && safeAcornFoxSelfFile(second, v.uid, v.gid) && os.SameFile(first, second)
	}
	after, err := os.Lstat(v.path)
	return err == nil && safeAcornFoxSelfFile(after, v.uid, v.gid) && os.SameFile(first, after)
}

func safeAcornFoxSelfFile(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || acornFoxRepoNlink(info) != 1 || info.Size() < 1 || info.Size() > acornFoxArchiveMaxBytes || verifyOwner(info, uid, gid) != nil {
		return false
	}
	_, ok := info.Sys().(*syscall.Stat_t)
	return ok
}
