package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// acornFoxSubstrateFS is the deliberately narrow syscall boundary for the
// task-root publisher. It exists so durability tests can observe real partial
// writes and post-operation failures without giving production a second path.
// It is package-private and only covers operations this publisher performs.
type acornFoxSubstrateFile interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Seek(int64, int) (int64, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
	Chmod(os.FileMode) error
	Chown(int, int) error
	ReadDir(int) ([]os.DirEntry, error)
	Fd() uintptr
}

type acornFoxSubstrateFS struct {
	lstatPath    func(string) (os.FileInfo, error)
	openRootPath func(string) (*os.Root, error)
	openRoot     func(*os.Root, string) (*os.Root, error)
	readFile     func(*os.Root, string) ([]byte, error)
	openFile     func(*os.Root, string, int, os.FileMode) (acornFoxSubstrateFile, error)
	mkdir        func(*os.Root, string, os.FileMode) error
	lstat        func(*os.Root, string) (os.FileInfo, error)
	link         func(*os.Root, string, string) error
	remove       func(*os.Root, string) error
	flock        func(acornFoxSubstrateFile, int) error
}

func newAcornFoxSubstrateFS() acornFoxSubstrateFS {
	return acornFoxSubstrateFS{
		lstatPath:    os.Lstat,
		openRootPath: os.OpenRoot,
		openRoot:     func(root *os.Root, path string) (*os.Root, error) { return root.OpenRoot(path) },
		readFile:     func(root *os.Root, path string) ([]byte, error) { return root.ReadFile(path) },
		openFile: func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
			return root.OpenFile(path, flags, mode)
		},
		mkdir:  func(root *os.Root, path string, mode os.FileMode) error { return root.Mkdir(path, mode) },
		lstat:  func(root *os.Root, path string) (os.FileInfo, error) { return root.Lstat(path) },
		link:   func(root *os.Root, oldName, newName string) error { return root.Link(oldName, newName) },
		remove: func(root *os.Root, path string) error { return root.Remove(path) },
		flock:  func(file acornFoxSubstrateFile, operation int) error { return syscall.Flock(int(file.Fd()), operation) },
	}
}

func (fs acornFoxSubstrateFS) syncDirectory(root *os.Root, directory string) error {
	dir, err := fs.openFile(root, directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (fs acornFoxSubstrateFS) syncRoot(root *os.Root) error { return fs.syncDirectory(root, ".") }

type acornFoxSubstrateTaskLock struct {
	file acornFoxSubstrateFile
	fs   acornFoxSubstrateFS
}

const acornFoxSubstrateTempPrefix = ".acornfox-substrate.tmp-"

func (p *TaskAcornFoxSubstratePublisher) lock() (*acornFoxSubstrateTaskLock, error) {
	root, err := p.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, statErr := p.fs.lstat(root, acornFoxSubstrateLock)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, statErr
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := p.fs.openFile(root, acornFoxSubstrateLock, flags, 0o600)
	if created && errors.Is(err, os.ErrExist) {
		created = false
		info, statErr = p.fs.lstat(root, acornFoxSubstrateLock)
		if statErr != nil {
			return nil, statErr
		}
		file, err = p.fs.openFile(root, acornFoxSubstrateLock, os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if created {
		if err = file.Chmod(0o600); err == nil {
			err = file.Chown(p.uid, p.gid)
		}
	}
	if err == nil {
		openedInfo, openedErr := file.Stat()
		if created {
			info, statErr = openedInfo, openedErr
		}
		if statErr != nil || openedErr != nil || !info.Mode().IsRegular() || !openedInfo.Mode().IsRegular() || info.Mode().Perm() != 0o600 || openedInfo.Mode().Perm() != 0o600 || verifyOwner(info, p.uid, p.gid) != nil || verifyOwner(openedInfo, p.uid, p.gid) != nil || (!created && !os.SameFile(info, openedInfo)) {
			err = errors.New("AcornFox substrate lock is unsafe")
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := p.fs.flock(file, syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return &acornFoxSubstrateTaskLock{file: file, fs: p.fs}, nil
}

func (l *acornFoxSubstrateTaskLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := l.fs.flock(file, syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func sha256SubstrateOpenFile(file acornFoxSubstrateFile) string {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// acornFoxSubstrateEnsureDirectory changes metadata only for a directory this
// call created. Existing directories are read-only evidence, never repair
// targets.
func acornFoxSubstrateEnsureDirectory(fs acornFoxSubstrateFS, root *os.Root, path string, mode os.FileMode, uid, gid int) error {
	created := false
	err := fs.mkdir(root, path, mode)
	if err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	dir, err := fs.openFile(root, path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	if created {
		err = dir.Chmod(mode)
		if err == nil {
			err = dir.Chown(uid, gid)
		}
	}
	info, statErr := dir.Stat()
	if err == nil && (statErr != nil || !info.IsDir() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil) {
		err = errors.New("AcornFox substrate directory is unsafe")
	}
	if err == nil && created {
		err = dir.Sync()
	}
	if err != nil {
		return err
	}
	if created {
		parent := parentDirectory(path)
		if parent == "" {
			parent = "."
		}
		return fs.syncDirectory(root, parent)
	}
	return nil
}

func acornFoxSubstrateWriteIntent(fs acornFoxSubstrateFS, root *os.Root, intent AcornFoxInactiveSubstrateIntentV1, uid, gid int) error {
	if err := acornFoxSubstrateEnsureDirectory(fs, root, acornFoxSubstrateDir, 0o700, uid, gid); err != nil {
		return err
	}
	raw, err := MarshalAcornFoxInactiveSubstrateIntentV1(intent)
	if err != nil {
		return err
	}
	return acornFoxSubstrateAtomicFile(fs, root, acornFoxSubstrateIntent, raw, 0o600, uid, gid, func(got []byte) error {
		parsed, err := ParseAcornFoxInactiveSubstrateIntentV1(got)
		if err != nil || parsed.CandidateReceipt.BindingSHA256 != intent.CandidateReceipt.BindingSHA256 || parsed.ExpectedEntryEnvelopeSHA256 != intent.ExpectedEntryEnvelopeSHA256 || string(got) != string(raw) {
			return errors.New("AcornFox substrate intent is invalid")
		}
		return nil
	})
}

func acornFoxSubstrateCreateDirs(fs acornFoxSubstrateFS, root *os.Root, entries []SubstrateEntry, uid, gid int) error {
	if err := acornFoxSubstrateEnsureDirectory(fs, root, acornFoxSubstrateRootfs, 0o700, uid, gid); err != nil {
		return err
	}
	dirs := make([]SubstrateEntry, 0)
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryDirectory {
			dirs = append(dirs, entry)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path < dirs[j].Path })
	for _, entry := range dirs {
		if err := acornFoxSubstrateEnsureDirectory(fs, root, acornFoxSubstrateTarget(entry.Path), os.FileMode(entry.Mode), uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func acornFoxSubstrateCopyFiles(fs acornFoxSubstrateFS, ctx context.Context, target, source *os.Root, entries []SubstrateEntry, candidate AcornFoxStageReceiptV1, uid, gid int) error {
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	if err := acornFoxSubstrateRemoveOwnedTemps(fs, target, entries, uid, gid); err != nil {
		return err
	}
	for index := range entries {
		entry := &entries[index]
		if entry.Kind != SubstrateEntryFile {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		sourcePath := acornFoxInstalledSource(candidate, entry.Path)
		if strings.HasPrefix(entry.Path, prefix) {
			sourcePath = strings.TrimPrefix(entry.Path, prefix)
		}
		if sourcePath == "" {
			return errors.New("AcornFox substrate source mapping is invalid")
		}
		input, err := fs.openFile(source, sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := input.Stat()
		actual := sha256SubstrateOpenFile(input)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(entry.Mode) || actual != entry.SHA256 {
			input.Close()
			return errors.New("AcornFox substrate source entry is invalid")
		}
		entry.Size = info.Size()
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			input.Close()
			return err
		}
		err = acornFoxSubstrateAtomicCopy(fs, target, acornFoxSubstrateTarget(entry.Path), input, *entry, uid, gid)
		closeErr := input.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func acornFoxSubstrateWriteReceipt(fs acornFoxSubstrateFS, root *os.Root, receipt InactiveSubstrateReceiptV1, uid, gid int) error {
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		return err
	}
	return acornFoxSubstrateAtomicFile(fs, root, acornFoxSubstrateReceipt, raw, 0o600, uid, gid, func(got []byte) error {
		parsed, err := ParseInactiveSubstrateReceiptV1(got)
		if err != nil || parsed.CandidateReceipt.BindingSHA256 != receipt.CandidateReceipt.BindingSHA256 || string(got) != string(raw) {
			return errors.New("AcornFox substrate receipt is invalid")
		}
		return nil
	})
}

func acornFoxSubstrateWriteReleaseControl(fs acornFoxSubstrateFS, root *os.Root, receipt InactiveSubstrateReceiptV1, uid, gid int) error {
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		return err
	}
	path := acornFoxSubstrateTarget("var/lib/acornfox/install/releases/" + receipt.CandidateReceipt.ReleaseID + ".json")
	file, err := fs.openFile(root, path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := acornFoxSubstrateReadControl(fs, root, path, uid, gid)
		if readErr == nil && string(existing) == string(raw) {
			return nil
		}
		return ErrAcornFoxSubstrateConflict
	}
	if err != nil {
		return err
	}
	if err = acornFoxSubstrateWriteFully(file, raw); err == nil {
		err = file.Chmod(0o600)
	}
	if err == nil {
		err = file.Chown(uid, gid)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return fs.syncDirectory(root, parentDirectory(path))
}

func acornFoxSubstrateAtomicCopy(fs acornFoxSubstrateFS, root *os.Root, final string, input acornFoxSubstrateFile, entry SubstrateEntry, uid, gid int) error {
	return acornFoxSubstrateAtomic(fs, root, final, os.FileMode(entry.Mode), uid, gid, func(output acornFoxSubstrateFile) error {
		return acornFoxSubstrateCopyFully(output, input)
	}, func(file acornFoxSubstrateFile, info os.FileInfo) error {
		if !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, uid, gid) != nil || info.Size() != entry.Size || sha256SubstrateOpenFile(file) != entry.SHA256 {
			return errors.New("AcornFox substrate temporary file is invalid")
		}
		return nil
	}, func(file acornFoxSubstrateFile) error {
		return acornFoxSubstrateVerifyFileHandle(file, entry.Size, entry.SHA256, os.FileMode(entry.Mode), uid, gid)
	})
}

func acornFoxSubstrateAtomicFile(fs acornFoxSubstrateFS, root *os.Root, final string, raw []byte, mode os.FileMode, uid, gid int, parse func([]byte) error) error {
	return acornFoxSubstrateAtomic(fs, root, final, mode, uid, gid, func(output acornFoxSubstrateFile) error {
		return acornFoxSubstrateWriteFully(output, raw)
	}, func(file acornFoxSubstrateFile, info os.FileInfo) error {
		if !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || info.Size() != int64(len(raw)) || sha256SubstrateOpenFile(file) != sha256Hex(raw) {
			return errors.New("AcornFox substrate temporary control file is invalid")
		}
		return nil
	}, func(file acornFoxSubstrateFile) error {
		if err := acornFoxSubstrateVerifyFileHandle(file, int64(len(raw)), sha256Hex(raw), mode, uid, gid); err != nil {
			return err
		}
		got, err := readAcornFoxSubstrateFile(file)
		if err != nil {
			return err
		}
		return parse(got)
	})
}

// acornFoxSubstrateAtomic commits a fully checked, same-directory temporary
// inode using Link. Link has no replacement behavior; an existing final is
// only read and verified as replay evidence.
func acornFoxSubstrateAtomic(fs acornFoxSubstrateFS, root *os.Root, final string, mode os.FileMode, uid, gid int, write func(acornFoxSubstrateFile) error, validateTemp func(acornFoxSubstrateFile, os.FileInfo) error, verifyFinal func(acornFoxSubstrateFile) error) error {
	parent := parentDirectory(final)
	if parent == "" {
		return errors.New("AcornFox substrate final parent is invalid")
	}
	temp, err := durableTempName(parent, acornFoxSubstrateTempPrefix)
	if err != nil {
		return err
	}
	file, err := fs.openFile(root, temp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	closed := false
	closeTemp := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	err = write(file)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Chown(uid, gid)
	}
	var info os.FileInfo
	if err == nil {
		info, err = file.Stat()
	}
	if err == nil {
		err = validateTemp(file, info)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := closeTemp(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	linkErr := fs.link(root, temp, final)
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		return linkErr
	}
	if err = acornFoxSubstrateVerifyFinal(fs, root, final, verifyFinal); err != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return ErrAcornFoxSubstrateConflict
		}
		return err
	}
	if err = fs.syncDirectory(root, parent); err != nil {
		return err
	}
	if err = fs.remove(root, temp); err != nil {
		return err
	}
	return fs.syncDirectory(root, parent)
}

func acornFoxSubstrateVerifyFinal(fs acornFoxSubstrateFS, root *os.Root, path string, verify func(acornFoxSubstrateFile) error) error {
	file, err := fs.openFile(root, path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	verifyErr := verify(file)
	closeErr := file.Close()
	if verifyErr != nil {
		return verifyErr
	}
	return closeErr
}

func acornFoxSubstrateVerifyFileHandle(file acornFoxSubstrateFile, size int64, digest string, mode os.FileMode, uid, gid int) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || info.Size() != size || sha256SubstrateOpenFile(file) != digest {
		return errors.New("AcornFox substrate file evidence is invalid")
	}
	return nil
}

func readAcornFoxSubstrateFile(file acornFoxSubstrateFile) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func acornFoxSubstrateReadControl(fs acornFoxSubstrateFS, root *os.Root, path string, uid, gid int) ([]byte, error) {
	file, err := fs.openFile(root, path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !acornFoxSubstrateControlMetadata(info, uid, gid) || !acornFoxSubstrateSingleLink(info) {
		_ = file.Close()
		return nil, errors.New("AcornFox substrate control metadata is invalid")
	}
	raw, readErr := readAcornFoxSubstrateFileBounded(file, acornFoxHelperReceiptMaxBytes)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return raw, nil
}

// acornFoxSubstrateReadTerminalReceipt admits the one recoverable post-link
// state: receipt.json and its same-directory temporary name are two links to
// one authenticated inode. Inspection remains read-only; Publish or Resume
// later removes that owned temporary inode while holding the task lock.
func acornFoxSubstrateReadTerminalReceipt(fs acornFoxSubstrateFS, root *os.Root, uid, gid int) ([]byte, error) {
	file, err := fs.openFile(root, acornFoxSubstrateReceipt, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !acornFoxSubstrateControlMetadata(info, uid, gid) {
		_ = file.Close()
		return nil, errors.New("AcornFox substrate receipt metadata is invalid")
	}
	raw, readErr := readAcornFoxSubstrateFileBounded(file, acornFoxHelperReceiptMaxBytes)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if acornFoxSubstrateSingleLink(info) {
		return raw, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 2 {
		return nil, errors.New("AcornFox substrate receipt link count is invalid")
	}
	dir, err := fs.openFile(root, acornFoxSubstrateDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	children, readDirErr := dir.ReadDir(-1)
	closeDirErr := dir.Close()
	if readDirErr != nil {
		return nil, readDirErr
	}
	if closeDirErr != nil {
		return nil, closeDirErr
	}
	found := 0
	for _, child := range children {
		if !strings.HasPrefix(child.Name(), acornFoxSubstrateTempPrefix) {
			continue
		}
		path := filepath.ToSlash(filepath.Join(acornFoxSubstrateDir, child.Name()))
		tempInfo, lstatErr := fs.lstat(root, path)
		if lstatErr == nil && acornFoxSubstrateTerminalTemp(tempInfo, info, uid, gid) {
			found++
		}
	}
	if found != 1 {
		return nil, errors.New("AcornFox substrate receipt temporary link is invalid")
	}
	return raw, nil
}

func acornFoxSubstrateSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func acornFoxSubstrateControlMetadata(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && verifyOwner(info, uid, gid) == nil && info.Size() >= 1 && info.Size() <= acornFoxHelperReceiptMaxBytes
}

func acornFoxSubstrateOwnedTemp(info os.FileInfo, uid, gid int) bool {
	return acornFoxSubstrateControlMetadata(info, uid, gid) && info.Mode()&os.ModeSymlink == 0
}

func acornFoxSubstrateTerminalTemp(info, receipt os.FileInfo, uid, gid int) bool {
	if !acornFoxSubstrateOwnedTemp(info, uid, gid) || !acornFoxSubstrateControlMetadata(receipt, uid, gid) || !os.SameFile(info, receipt) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 2
}

// acornFoxSubstrateRemoveTerminalReceiptTemp only removes the same inode that
// a verified receipt proves was left behind by Link. It deliberately does not
// treat a prefix match as deletion authority for terminal substrate state.
func acornFoxSubstrateRemoveTerminalReceiptTemp(fs acornFoxSubstrateFS, root *os.Root, uid, gid int) error {
	receipt, err := fs.lstat(root, acornFoxSubstrateReceipt)
	if err != nil {
		return err
	}
	if !acornFoxSubstrateControlMetadata(receipt, uid, gid) {
		return ErrAcornFoxSubstrateConflict
	}
	if acornFoxSubstrateSingleLink(receipt) {
		return nil
	}
	stat, ok := receipt.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 2 {
		return ErrAcornFoxSubstrateConflict
	}
	dir, err := fs.openFile(root, acornFoxSubstrateDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	var temporary string
	for _, child := range children {
		if !strings.HasPrefix(child.Name(), acornFoxSubstrateTempPrefix) {
			continue
		}
		path := filepath.ToSlash(filepath.Join(acornFoxSubstrateDir, child.Name()))
		info, lstatErr := fs.lstat(root, path)
		if lstatErr != nil || !acornFoxSubstrateTerminalTemp(info, receipt, uid, gid) || temporary != "" {
			return ErrAcornFoxSubstrateConflict
		}
		temporary = path
	}
	if temporary == "" {
		return ErrAcornFoxSubstrateConflict
	}
	if err := fs.remove(root, temporary); err != nil {
		return err
	}
	return fs.syncDirectory(root, acornFoxSubstrateDir)
}

func readAcornFoxSubstrateFileBounded(file acornFoxSubstrateFile, maximum int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func acornFoxSubstrateWriteFully(file acornFoxSubstrateFile, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if written < 0 || written > len(raw) {
			return errors.New("AcornFox substrate write count is invalid")
		}
		if written == 0 && err == nil {
			return io.ErrShortWrite
		}
		raw = raw[written:]
		if err != nil {
			return err
		}
	}
	return nil
}

func acornFoxSubstrateCopyFully(output, input acornFoxSubstrateFile) error {
	buffer := make([]byte, 32*1024)
	for {
		read, readErr := input.Read(buffer)
		if read > 0 {
			if err := acornFoxSubstrateWriteFully(output, buffer[:read]); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// Only a regular temporary file owned by this task may be removed. Foreign
// files, symlinks, and final paths remain evidence and are never cleaned.
func acornFoxSubstrateRemoveOwnedTemps(fs acornFoxSubstrateFS, root *os.Root, entries []SubstrateEntry, uid, gid int) error {
	directories := map[string]struct{}{acornFoxSubstrateDir: {}, acornFoxSubstrateRootfs: {}}
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryDirectory {
			directories[acornFoxSubstrateTarget(entry.Path)] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Strings(ordered)
	for _, directory := range ordered {
		dir, err := fs.openFile(root, directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		children, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		for _, child := range children {
			if !strings.HasPrefix(child.Name(), acornFoxSubstrateTempPrefix) {
				continue
			}
			path := filepath.ToSlash(filepath.Join(directory, child.Name()))
			info, err := fs.lstat(root, path)
			if err != nil || !acornFoxSubstrateOwnedTemp(info, uid, gid) {
				return ErrAcornFoxSubstrateConflict
			}
			if err := fs.remove(root, path); err != nil {
				return err
			}
			if err := fs.syncDirectory(root, directory); err != nil {
				return err
			}
		}
	}
	return nil
}
