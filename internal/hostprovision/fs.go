package hostprovision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// pinDirectoryChain opens each ancestor directory starting from / down to target path,
// asserting root ownership, absence of symlinks, and no group/world-writable permissions.
func pinDirectoryChain(p string, allowNonRoot bool) ([]*os.File, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid path %q", ErrInsecurePath, p)
	}

	var dirs []string
	for cur := abs; ; cur = filepath.Dir(cur) {
		dirs = append(dirs, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}

	var pins []*os.File
	closePins := func() {
		for _, f := range pins {
			_ = f.Close()
		}
	}

	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			closePins()
			return nil, fmt.Errorf("%w: failed to open ancestor %q: %v", ErrInsecurePath, dir, err)
		}
		pins = append(pins, f)

		info, err := f.Stat()
		if err != nil {
			closePins()
			return nil, fmt.Errorf("%w: failed to stat ancestor %q: %v", ErrInsecurePath, dir, err)
		}
		if !info.IsDir() {
			closePins()
			return nil, fmt.Errorf("%w: ancestor %q is not a directory", ErrInsecurePath, dir)
		}

		actual, err := os.Lstat(dir)
		if err != nil || !os.SameFile(info, actual) || actual.Mode()&os.ModeSymlink != 0 {
			closePins()
			return nil, fmt.Errorf("%w: ancestor %q is a symlink or replaced", ErrInsecurePath, dir)
		}

		if !allowNonRoot {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				closePins()
				return nil, ErrInsecurePath
			}
			if st.Uid != 0 {
				closePins()
				return nil, fmt.Errorf("%w: ancestor directory %q not owned by root", ErrInsecurePath, dir)
			}
			if info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
				closePins()
				return nil, fmt.Errorf("%w: ancestor directory %q is group/world writable", ErrInsecurePath, dir)
			}
		}
	}
	return pins, nil
}

func revalidatePins(pins []*os.File) error {
	for _, f := range pins {
		infoFromFD, err := f.Stat()
		if err != nil {
			return fmt.Errorf("%w: failed to stat pinned fd: %v", ErrInsecurePath, err)
		}
		actual, err := os.Lstat(f.Name())
		if err != nil || !os.SameFile(infoFromFD, actual) || actual.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: pinned directory %q modified or replaced", ErrInsecurePath, f.Name())
		}
	}
	return nil
}

func closePins(pins []*os.File) {
	for _, f := range pins {
		_ = f.Close()
	}
}

// openVerifiedRoot pins the directory chain to dirPath, binds an *os.Root,
// verifies that root.Stat(".") matches the pinned descriptor, and returns both.
func openVerifiedRoot(dirPath string, allowNonRoot bool) (*os.Root, []*os.File, error) {
	pins, err := pinDirectoryChain(dirPath, allowNonRoot)
	if err != nil {
		return nil, nil, err
	}

	root, err := os.OpenRoot(dirPath)
	if err != nil {
		closePins(pins)
		return nil, nil, fmt.Errorf("%w: os.OpenRoot failed on %q: %v", ErrInsecurePath, dirPath, err)
	}

	rStat, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		closePins(pins)
		return nil, nil, fmt.Errorf("%w: root.Stat failed on %q: %v", ErrInsecurePath, dirPath, err)
	}

	parentFD := pins[len(pins)-1]
	pStat, err := parentFD.Stat()
	if err != nil || !os.SameFile(rStat, pStat) {
		_ = root.Close()
		closePins(pins)
		return nil, nil, fmt.Errorf("%w: root descriptor mismatch with pinned parent for %q", ErrInsecurePath, dirPath)
	}

	if err := revalidatePins(pins); err != nil {
		_ = root.Close()
		closePins(pins)
		return nil, nil, err
	}

	return root, pins, nil
}

// readSourceFile securely opens, validates, and reads a source file with strict pinned ancestor checks.
func readSourceFile(path string, maxLimit int64, allowNonRoot bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: path %q must be clean absolute", ErrInsecurePath, path)
	}

	pins, err := pinDirectoryChain(filepath.Dir(path), allowNonRoot)
	if err != nil {
		return nil, err
	}
	defer closePins(pins)

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to open %q: %v", ErrInsecurePath, path, err)
	}
	defer f.Close()

	info1, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st1, ok := info1.Sys().(*syscall.Stat_t)
	if !ok || !info1.Mode().IsRegular() || info1.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q must be a regular file", ErrInsecurePath, path)
	}
	if st1.Nlink != 1 {
		return nil, fmt.Errorf("%w: %q must have exactly 1 link", ErrInsecurePath, path)
	}
	if info1.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, fmt.Errorf("%w: %q must not have special mode bits", ErrInsecurePath, path)
	}

	if !allowNonRoot {
		if st1.Uid != 0 {
			return nil, fmt.Errorf("%w: %q must be owned by root", ErrInsecurePath, path)
		}
		if info1.Mode().Perm()&0022 != 0 {
			return nil, fmt.Errorf("%w: %q is group/world writable", ErrInsecurePath, path)
		}
	}

	actual, err := os.Lstat(path)
	if err != nil || !os.SameFile(info1, actual) || actual.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q identity mismatch or symlink", ErrInsecurePath, path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxLimit {
		return nil, fmt.Errorf("%w: %q exceeds size limit of %d bytes", ErrInvalidRequest, path, maxLimit)
	}

	info2, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st2, ok := info2.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(info1, info2) || st1.Ino != st2.Ino || st1.Dev != st2.Dev || info2.Size() != int64(len(data)) {
		return nil, fmt.Errorf("%w: %q modified during read", ErrInsecurePath, path)
	}

	if err := revalidatePins(pins); err != nil {
		return nil, err
	}

	return data, nil
}

// ensureDirSafeExact ensures targetDir exists with exact wantMode using parent Root.Mkdir
// and verifies every directory component along the path.
func ensureDirSafeExact(targetDir string, wantMode os.FileMode, allowNonRoot bool) error {
	abs, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("%w: invalid directory %q", ErrInsecurePath, targetDir)
	}

	var parts []string
	for cur := abs; ; cur = filepath.Dir(cur) {
		parts = append(parts, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}

	// Create / verify from root downward using parent Root
	for i := len(parts) - 2; i >= 0; i-- {
		parentDir := parts[i+1]
		childBase := filepath.Base(parts[i])
		currentDir := parts[i]

		mode := wantMode
		if currentDir != targetDir {
			mode = 0755
		}

		parentRoot, parentPins, err := openVerifiedRoot(parentDir, allowNonRoot)
		if err != nil {
			return err
		}

		childInfo, err := parentRoot.Lstat(childBase)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Descriptor-relative Mkdir via parent Root
				if mkErr := parentRoot.Mkdir(childBase, mode); mkErr != nil {
					_ = parentRoot.Close()
					closePins(parentPins)
					return fmt.Errorf("parentRoot.Mkdir failed for %q in %q: %w", childBase, parentDir, mkErr)
				}

				// Open child through parentRoot with O_NOFOLLOW to set metadata
				cf, opErr := parentRoot.OpenFile(childBase, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if opErr != nil {
					_ = parentRoot.Close()
					closePins(parentPins)
					return fmt.Errorf("parentRoot.OpenFile failed on created child %q: %w", childBase, opErr)
				}
				if chErr := cf.Chmod(mode); chErr != nil {
					_ = cf.Close()
					_ = parentRoot.Close()
					closePins(parentPins)
					return fmt.Errorf("Chmod failed on created directory %q: %w", childBase, chErr)
				}
				if !allowNonRoot {
					if owErr := cf.Chown(0, 0); owErr != nil {
						_ = cf.Close()
						_ = parentRoot.Close()
						closePins(parentPins)
						return fmt.Errorf("Chown failed on created directory %q: %w", childBase, owErr)
					}
				}
				_ = cf.Close()
				_ = parentRoot.Close()
				closePins(parentPins)
				continue
			}
			_ = parentRoot.Close()
			closePins(parentPins)
			return err
		}

		_ = parentRoot.Close()
		closePins(parentPins)

		if !childInfo.IsDir() || childInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q is not a directory or is a symlink", ErrInsecurePath, currentDir)
		}

		if currentDir == targetDir {
			if childInfo.Mode().Perm() != wantMode {
				return fmt.Errorf("%w: directory %q mode mismatch: got %o, want %o", ErrInsecurePath, currentDir, childInfo.Mode().Perm(), wantMode)
			}
		}

		if !allowNonRoot {
			st, ok := childInfo.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || st.Gid != 0 {
				return fmt.Errorf("%w: directory %q not owned by root:root", ErrInsecurePath, currentDir)
			}
			if childInfo.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && childInfo.Mode()&os.ModeSticky != 0) {
				return fmt.Errorf("%w: directory %q is group/world writable", ErrInsecurePath, currentDir)
			}
		}
	}

	// Final fsync and pin verification of targetDir
	targetRoot, targetPins, err := openVerifiedRoot(targetDir, allowNonRoot)
	if err != nil {
		return err
	}
	defer func() {
		_ = targetRoot.Close()
		closePins(targetPins)
	}()

	parentFD := targetPins[len(targetPins)-1]
	if err := parentFD.Sync(); err != nil {
		return fmt.Errorf("failed to fsync directory %q: %w", targetDir, err)
	}

	return revalidatePins(targetPins)
}

// writeSafeFileRoot performs descriptor-relative creation, link, and cleanup
// under a retained *os.Root, passing only basenames to Root methods.
func writeSafeFileRoot(
	targetPath string,
	data []byte,
	mode os.FileMode,
	allowNonRoot bool,
	ancestorHook func(phase string, targetPath string) error,
) error {
	parentDir := filepath.Dir(targetPath)
	baseName := filepath.Base(targetPath)

	root, pins, err := openVerifiedRoot(parentDir, allowNonRoot)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
		closePins(pins)
	}()

	// Deterministic swap hook after root check but before mutation
	if ancestorHook != nil {
		if err := ancestorHook("after-check-before-write", targetPath); err != nil {
			return err
		}
		if err := revalidatePins(pins); err != nil {
			return err
		}
	}

	tmpBase := fmt.Sprintf(".%s.tmp.%d.%d", baseName, os.Getpid(), time.Now().UnixNano())

	// Descriptor-relative OpenFile on root with only temp basename
	f, err := root.OpenFile(tmpBase, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("root.OpenFile failed for temp file %q: %w", tmpBase, err)
	}
	defer func() {
		_ = root.Remove(tmpBase)
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write data to %q: %w", tmpBase, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to fsync %q: %w", tmpBase, err)
	}
	// Call Chmod/Chown directly on *os.File to avoid Root.Chmod race
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("f.Chmod failed on %q: %w", tmpBase, err)
	}
	if !allowNonRoot {
		if err := f.Chown(0, 0); err != nil {
			_ = f.Close()
			return fmt.Errorf("f.Chown failed on %q: %w", tmpBase, err)
		}
	}

	tmpInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	tmpStat, ok := tmpInfo.Sys().(*syscall.Stat_t)
	if !ok {
		_ = f.Close()
		return ErrInsecurePath
	}
	tmpIno := tmpStat.Ino
	tmpDev := tmpStat.Dev

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close %q: %w", tmpBase, err)
	}

	// Deterministic swap hook before link
	if ancestorHook != nil {
		if err := ancestorHook("before-link", targetPath); err != nil {
			return err
		}
		if err := revalidatePins(pins); err != nil {
			return err
		}
	}

	// Descriptor-relative Link on root with only basenames (no-clobber)
	if err := root.Link(tmpBase, baseName); err != nil {
		return fmt.Errorf("%w: root.Link failed for %q -> %q: %v", ErrProvisionConflict, tmpBase, baseName, err)
	}

	// Descriptor-relative Remove on root with only temp basename
	if err := root.Remove(tmpBase); err != nil {
		return fmt.Errorf("root.Remove failed for %q: %w", tmpBase, err)
	}

	// Fsync parent directory descriptor
	parentFD := pins[len(pins)-1]
	if err := parentFD.Sync(); err != nil {
		return fmt.Errorf("failed to fsync parent directory %q: %w", parentDir, err)
	}

	// Post-publication verification of published file descriptor relative to root
	tf, err := root.OpenFile(baseName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to open published file %q via root: %v", ErrInsecurePath, baseName, err)
	}
	defer tf.Close()

	tInfo, err := tf.Stat()
	if err != nil {
		return err
	}
	tStat, ok := tInfo.Sys().(*syscall.Stat_t)
	if !ok || !tInfo.Mode().IsRegular() || tInfo.Mode().Perm() != mode || tStat.Nlink != 1 || tStat.Ino != tmpIno || tStat.Dev != tmpDev {
		return fmt.Errorf("%w: published file %q failed post-open verification", ErrInsecurePath, targetPath)
	}
	if !allowNonRoot && (tStat.Uid != 0 || tStat.Gid != 0) {
		return fmt.Errorf("%w: published file %q not owned by root:root", ErrInsecurePath, targetPath)
	}

	return revalidatePins(pins)
}

// provisionLockOwner retains the locked file descriptor, the slots *os.Root,
// and all ancestor directory descriptors until Close() is called when the entire
// provisioning operation finishes.
type provisionLockOwner struct {
	file         *os.File
	slotsRoot    *os.Root
	pins         []*os.File
	allowNonRoot bool
}

func (l *provisionLockOwner) Close() error {
	if l == nil {
		return nil
	}
	var errs []error
	if l.file != nil {
		_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		if err := l.file.Close(); err != nil {
			errs = append(errs, err)
		}
		l.file = nil
	}
	if l.slotsRoot != nil {
		if err := l.slotsRoot.Close(); err != nil {
			errs = append(errs, err)
		}
		l.slotsRoot = nil
	}
	for _, f := range l.pins {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.pins = nil
	return errors.Join(errs...)
}

// Validate verifies the retained lock identity and ancestor path pins:
// 1. Revalidates all retained ancestor path pins against current filesystem paths.
// 2. Compares slotsRoot.Stat(".") with retained last parent pin and current pathname Lstat.
// 3. Compares held lock file.Stat with slotsRoot.Lstat("lock"), requiring same inode,
// current expected regular 0600 single link owner. Returns conflict if identity changed.
func (l *provisionLockOwner) Validate() error {
	if l == nil || l.file == nil || l.slotsRoot == nil || len(l.pins) == 0 {
		return fmt.Errorf("%w: provision lock owner is uninitialized", ErrProvisionConflict)
	}

	// 1. Revalidate all retained ancestor path pins
	if err := revalidatePins(l.pins); err != nil {
		return fmt.Errorf("%w: retained ancestor path pins invalid: %v", ErrInsecurePath, err)
	}

	// 2. Compare slotsRoot.Stat(".") with retained last parent pin
	parentFD := l.pins[len(l.pins)-1]
	pStat, err := parentFD.Stat()
	if err != nil {
		return fmt.Errorf("%w: failed to stat parent pin: %v", ErrInsecurePath, err)
	}
	rStat, err := l.slotsRoot.Stat(".")
	if err != nil || !os.SameFile(rStat, pStat) {
		return fmt.Errorf("%w: slotsRoot descriptor mismatch with parent pin", ErrProvisionConflict)
	}

	actualDir, err := os.Lstat(parentFD.Name())
	if err != nil || !os.SameFile(pStat, actualDir) || actualDir.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: slotsRoot pathname was replaced or is a symlink", ErrProvisionConflict)
	}

	// 3. Compare held lock file.Stat with slotsRoot.Lstat("lock")
	fStat, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: failed to stat held lock file: %v", ErrInsecurePath, err)
	}

	lockLstat, err := l.slotsRoot.Lstat("lock")
	if err != nil {
		return fmt.Errorf("%w: lockfile missing in slotsRoot: %v", ErrProvisionConflict, err)
	}

	if !os.SameFile(fStat, lockLstat) {
		return fmt.Errorf("%w: held lock file inode mismatch with slotsRoot Lstat(lock)", ErrProvisionConflict)
	}
	if !lockLstat.Mode().IsRegular() || lockLstat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: lockfile in slotsRoot is not regular file", ErrProvisionConflict)
	}
	if lockLstat.Mode().Perm() != 0600 {
		return fmt.Errorf("%w: lockfile in slotsRoot mode mismatch: got %o, want 0600", ErrProvisionConflict, lockLstat.Mode().Perm())
	}

	st, ok := lockLstat.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return fmt.Errorf("%w: lockfile in slotsRoot must have exactly 1 link", ErrProvisionConflict)
	}
	if !l.allowNonRoot && (st.Uid != 0 || st.Gid != 0) {
		return fmt.Errorf("%w: lockfile in slotsRoot must be owned by root:root", ErrProvisionConflict)
	}

	return nil
}

// acquireProvisionLock opens the slot lockfile relative to a verified, retained
// slotsRoot descriptor and acquires an exclusive flock. The returned provisionLockOwner
// retains slotsRoot and all ancestor directory pins throughout the operation.
func acquireProvisionLock(
	lockPath string,
	createPermitted bool,
	allowNonRoot bool,
) (*provisionLockOwner, error) {
	parentDir := filepath.Dir(lockPath)
	baseName := filepath.Base(lockPath)

	root, pins, err := openVerifiedRoot(parentDir, allowNonRoot)
	if err != nil {
		return nil, err
	}

	flags := os.O_RDWR | syscall.O_NOFOLLOW
	if createPermitted {
		flags |= os.O_CREATE
	}

	// Open lockfile relative to retained slots Root passing only basename
	f, err := root.OpenFile(baseName, flags, 0600)
	if err != nil {
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: failed to open lock %q via root (createPermitted=%v): %v", ErrProvisionConflict, baseName, createPermitted, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: lockfile %q must be regular 0600", ErrInsecurePath, lockPath)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: lockfile %q must have exactly 1 link", ErrInsecurePath, lockPath)
	}
	if !allowNonRoot && (st.Uid != 0 || st.Gid != 0) {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: lockfile %q not owned by root:root", ErrInsecurePath, lockPath)
	}

	lstatFromRoot, err := root.Lstat(baseName)
	if err != nil || !os.SameFile(info, lstatFromRoot) || lstatFromRoot.Mode()&os.ModeSymlink != 0 {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: lockfile %q identity mismatch or symlink in root", ErrInsecurePath, lockPath)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = root.Close()
		closePins(pins)
		return nil, fmt.Errorf("%w: failed to acquire flock on %q: %v", ErrProvisionConflict, lockPath, err)
	}

	owner := &provisionLockOwner{
		file:         f,
		slotsRoot:    root,
		pins:         pins,
		allowNonRoot: allowNonRoot,
	}

	if err := owner.Validate(); err != nil {
		_ = owner.Close()
		return nil, err
	}

	return owner, nil
}

// checkExistingTarget validates an existing target file for exact reentry or resume.
func checkExistingTarget(targetPath string, wantBytes []byte, wantMode os.FileMode, allowNonRoot bool) error {
	info, err := os.Lstat(targetPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %q is not a regular file", ErrProvisionConflict, targetPath)
	}
	if info.Mode().Perm() != wantMode {
		return fmt.Errorf("%w: %q mode mismatch: got %o, want %o", ErrProvisionConflict, targetPath, info.Mode().Perm(), wantMode)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%w: %q has special mode bits", ErrProvisionConflict, targetPath)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return fmt.Errorf("%w: %q must have exactly 1 link", ErrProvisionConflict, targetPath)
	}
	if !allowNonRoot && (st.Uid != 0 || st.Gid != 0) {
		return fmt.Errorf("%w: %q must be owned by root:root", ErrProvisionConflict, targetPath)
	}

	data, err := readSafeFileContent(targetPath, int64(len(wantBytes))+1024)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, wantBytes) {
		return fmt.Errorf("%w: %q bytes mismatch existing content", ErrProvisionConflict, targetPath)
	}
	return nil
}

func readSafeFileContent(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to open %q: %v", ErrInsecurePath, p, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds read limit", ErrInsecurePath, p)
	}
	return data, nil
}

// checkDistinctInodes ensures two paths have different inode numbers on the same or different devices.
func checkDistinctInodes(p1, p2 string) error {
	i1, err := os.Lstat(p1)
	if err != nil {
		return err
	}
	i2, err := os.Lstat(p2)
	if err != nil {
		return err
	}
	st1, ok1 := i1.Sys().(*syscall.Stat_t)
	st2, ok2 := i2.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return ErrInsecurePath
	}
	if st1.Dev == st2.Dev && st1.Ino == st2.Ino {
		return fmt.Errorf("%w: %q and %q share the same inode (must be distinct files)", ErrProvisionConflict, p1, p2)
	}
	return nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func isValidHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// publishSafeSymlink ensures parent directory exists with 0755 root ownership,
// opens verified parent *os.Root, checks for existing link (verifying canonical target/symlink/single-link),
// creates symlink descriptor-relative via root.Symlink if absent, sets Lchown if needed,
// fsyncs parent directory descriptor, post-verifies the created link, and revalidates pins.
func publishSafeSymlink(linkPath string, target string, allowNonRoot bool) error {
	parentDir := filepath.Dir(linkPath)
	baseName := filepath.Base(linkPath)

	if err := ensureDirSafeExact(parentDir, 0755, allowNonRoot); err != nil {
		return err
	}

	root, pins, err := openVerifiedRoot(parentDir, allowNonRoot)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
		closePins(pins)
	}()

	info, err := root.Lstat(baseName)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%w: enable link %q is not a symlink", ErrProvisionConflict, linkPath)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Nlink != 1 {
			return fmt.Errorf("%w: enable link %q nlink != 1", ErrProvisionConflict, linkPath)
		}
		if !allowNonRoot && (st.Uid != 0 || st.Gid != 0) {
			return fmt.Errorf("%w: enable link %q not owned by root:root", ErrInsecurePath, linkPath)
		}
		actualTarget, err := root.Readlink(baseName)
		if err != nil || actualTarget != target {
			return fmt.Errorf("%w: enable link %q target mismatch: got %q, want %q", ErrProvisionConflict, linkPath, actualTarget, target)
		}
		return revalidatePins(pins)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Link is absent: create descriptor-relative symlink via root
	if err := root.Symlink(target, baseName); err != nil {
		return fmt.Errorf("%w: root.Symlink failed for %q -> %q: %v", ErrProvisionConflict, baseName, target, err)
	}

	if !allowNonRoot {
		if err := root.Lchown(baseName, 0, 0); err != nil {
			_ = root.Remove(baseName)
			return fmt.Errorf("root.Lchown failed for %q: %w", baseName, err)
		}
	}

	parentFD := pins[len(pins)-1]
	if err := parentFD.Sync(); err != nil {
		return fmt.Errorf("failed to fsync parent directory %q: %w", parentDir, err)
	}

	infoAfter, err := root.Lstat(baseName)
	if err != nil {
		return fmt.Errorf("%w: failed to lstat created symlink %q: %v", ErrInsecurePath, baseName, err)
	}
	if infoAfter.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%w: created link %q is not a symlink", ErrInsecurePath, baseName)
	}
	stAfter, ok := infoAfter.Sys().(*syscall.Stat_t)
	if !ok || stAfter.Nlink != 1 {
		return fmt.Errorf("%w: created link %q nlink != 1", ErrInsecurePath, baseName)
	}
	if !allowNonRoot && (stAfter.Uid != 0 || stAfter.Gid != 0) {
		return fmt.Errorf("%w: created link %q not owned by root:root", ErrInsecurePath, baseName)
	}
	actualTarget, err := root.Readlink(baseName)
	if err != nil || actualTarget != target {
		return fmt.Errorf("%w: created link %q target mismatch: got %q, want %q", ErrInsecurePath, baseName, actualTarget, target)
	}

	return revalidatePins(pins)
}

// checkExistingEnableLink inspects an existing symlink to verify it matches
// canonical expectations without mutating anything.
func checkExistingEnableLink(linkPath, expectedTarget string, allowNonRoot bool) error {
	parentDir := filepath.Dir(linkPath)
	baseName := filepath.Base(linkPath)

	root, pins, err := openVerifiedRoot(parentDir, allowNonRoot)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
		closePins(pins)
	}()

	info, err := root.Lstat(baseName)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%w: link %q is not a symlink", ErrProvisionConflict, linkPath)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return fmt.Errorf("%w: link %q nlink != 1", ErrProvisionConflict, linkPath)
	}
	if !allowNonRoot && (st.Uid != 0 || st.Gid != 0) {
		return fmt.Errorf("%w: link %q not owned by root:root", ErrInsecurePath, linkPath)
	}
	actualTarget, err := root.Readlink(baseName)
	if err != nil || actualTarget != expectedTarget {
		return fmt.Errorf("%w: link %q target mismatch: got %q, want %q", ErrProvisionConflict, linkPath, actualTarget, expectedTarget)
	}
	return revalidatePins(pins)
}
