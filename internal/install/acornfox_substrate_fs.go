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

type acornFoxSubstrateTaskLock struct{ file *os.File }

const acornFoxSubstrateTempPrefix = ".acornfox-substrate.tmp-"

func (p *TaskAcornFoxSubstratePublisher) lock() (*acornFoxSubstrateTaskLock, error) {
	root, err := p.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, statErr := root.Lstat(acornFoxSubstrateLock)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, statErr
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := root.OpenFile(acornFoxSubstrateLock, flags, 0o600)
	if created && errors.Is(err, os.ErrExist) {
		created = false
		info, statErr = root.Lstat(acornFoxSubstrateLock)
		if statErr != nil {
			return nil, statErr
		}
		file, err = root.OpenFile(acornFoxSubstrateLock, os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
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
		if created {
			info, statErr = file.Stat()
		}
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || verifyOwner(info, p.uid, p.gid) != nil {
			err = errors.New("AcornFox substrate lock is unsafe")
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return &acornFoxSubstrateTaskLock{file: file}, nil
}

func (l *acornFoxSubstrateTaskLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func sha256SubstrateOpenFile(file *os.File) string {
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
func acornFoxSubstrateEnsureDirectory(root *os.Root, path string, mode os.FileMode, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	created := false
	err := root.Mkdir(path, mode)
	if err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	dir, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	if created {
		if err = fault(acornFoxSubstrateFaultDirectoryMetadata); err == nil {
			err = dir.Chmod(mode)
		}
		if err == nil {
			err = dir.Chown(uid, gid)
		}
	}
	info, statErr := dir.Stat()
	if err == nil {
		err = fault(acornFoxSubstrateFaultDirectoryStat)
	}
	if err == nil && (statErr != nil || !info.IsDir() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil) {
		err = errors.New("AcornFox substrate directory is unsafe")
	}
	if err == nil && created {
		if err = fault(acornFoxSubstrateFaultDirectorySync); err == nil {
			err = dir.Sync()
		}
	}
	if err != nil {
		return err
	}
	if created {
		if err = fault(acornFoxSubstrateFaultDirectoryParentSync); err != nil {
			return err
		}
		parent := parentDirectory(path)
		if parent == "" {
			parent = "."
		}
		return syncAcornFoxDirectory(root, parent)
	}
	return nil
}

func acornFoxSubstrateWriteIntent(root *os.Root, intent AcornFoxInactiveSubstrateIntentV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	if err := acornFoxSubstrateEnsureDirectory(root, acornFoxSubstrateDir, 0o700, uid, gid, fault); err != nil {
		return err
	}
	raw, err := MarshalAcornFoxInactiveSubstrateIntentV1(intent)
	if err != nil {
		return err
	}
	return acornFoxSubstrateAtomicFile(root, acornFoxSubstrateIntent, raw, 0o600, uid, gid, fault, acornFoxSubstrateFaultIntentWrite, acornFoxSubstrateFaultIntentSync, acornFoxSubstrateFaultIntentReadback, func(got []byte) error {
		parsed, err := ParseAcornFoxInactiveSubstrateIntentV1(got)
		if err != nil || parsed.CandidateReceipt.BindingSHA256 != intent.CandidateReceipt.BindingSHA256 || parsed.ExpectedEntryEnvelopeSHA256 != intent.ExpectedEntryEnvelopeSHA256 || string(got) != string(raw) {
			return errors.New("AcornFox substrate intent is invalid")
		}
		return nil
	})
}

func acornFoxSubstrateCreateDirs(root *os.Root, entries []SubstrateEntry, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	if err := acornFoxSubstrateEnsureDirectory(root, acornFoxSubstrateRootfs, 0o700, uid, gid, fault); err != nil {
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
		if err := acornFoxSubstrateEnsureDirectory(root, acornFoxSubstrateTarget(entry.Path), os.FileMode(entry.Mode), uid, gid, fault); err != nil {
			return err
		}
	}
	return nil
}

func acornFoxSubstrateCopyFiles(ctx context.Context, target, source *os.Root, entries []SubstrateEntry, candidate AcornFoxStageReceiptV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	if err := acornFoxSubstrateRemoveOwnedTemps(target, entries, uid, gid, fault); err != nil {
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
		if err := fault(acornFoxSubstrateFaultFileOpen); err != nil {
			return err
		}
		input, err := source.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
		err = acornFoxSubstrateAtomicCopy(target, acornFoxSubstrateTarget(entry.Path), input, *entry, uid, gid, fault)
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

func acornFoxSubstrateWriteReceipt(root *os.Root, receipt InactiveSubstrateReceiptV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		return err
	}
	return acornFoxSubstrateAtomicFile(root, acornFoxSubstrateReceipt, raw, 0o600, uid, gid, fault, acornFoxSubstrateFaultReceiptWrite, acornFoxSubstrateFaultReceiptSync, acornFoxSubstrateFaultReceiptReadback, func(got []byte) error {
		parsed, err := ParseInactiveSubstrateReceiptV1(got)
		if err != nil || parsed.CandidateReceipt.BindingSHA256 != receipt.CandidateReceipt.BindingSHA256 || string(got) != string(raw) {
			return errors.New("AcornFox substrate receipt is invalid")
		}
		return nil
	})
}

func acornFoxSubstrateAtomicCopy(root *os.Root, final string, input *os.File, entry SubstrateEntry, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	return acornFoxSubstrateAtomic(root, final, os.FileMode(entry.Mode), uid, gid, fault, acornFoxSubstrateFaultFileSync, func(output *os.File) error {
		if err := fault(acornFoxSubstrateFaultFileWrite); err != nil {
			return err
		}
		if err := fault(acornFoxSubstrateFaultTempShortWrite); err != nil {
			return err
		}
		return acornFoxSubstrateCopyFully(output, input)
	}, func(file *os.File, info os.FileInfo) error {
		if !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, uid, gid) != nil || info.Size() != entry.Size || sha256SubstrateOpenFile(file) != entry.SHA256 {
			return errors.New("AcornFox substrate temporary file is invalid")
		}
		return nil
	}, func(file *os.File) error {
		if err := fault(acornFoxSubstrateFaultFileReadback); err != nil {
			return err
		}
		return acornFoxSubstrateVerifyFileHandle(file, entry.Size, entry.SHA256, os.FileMode(entry.Mode), uid, gid)
	})
}

func acornFoxSubstrateAtomicFile(root *os.Root, final string, raw []byte, mode os.FileMode, uid, gid int, fault func(acornFoxSubstrateFaultStep) error, writeStep, syncStep, readbackStep acornFoxSubstrateFaultStep, parse func([]byte) error) error {
	return acornFoxSubstrateAtomic(root, final, mode, uid, gid, fault, syncStep, func(output *os.File) error {
		if err := fault(writeStep); err != nil {
			return err
		}
		if err := fault(acornFoxSubstrateFaultTempShortWrite); err != nil {
			return err
		}
		return acornFoxSubstrateWriteFully(output, raw)
	}, func(file *os.File, info os.FileInfo) error {
		if !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || info.Size() != int64(len(raw)) || sha256SubstrateOpenFile(file) != sha256Hex(raw) {
			return errors.New("AcornFox substrate temporary control file is invalid")
		}
		return nil
	}, func(file *os.File) error {
		if err := acornFoxSubstrateVerifyFileHandle(file, int64(len(raw)), sha256Hex(raw), mode, uid, gid); err != nil {
			return err
		}
		if err := fault(readbackStep); err != nil {
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
func acornFoxSubstrateAtomic(root *os.Root, final string, mode os.FileMode, uid, gid int, fault func(acornFoxSubstrateFaultStep) error, legacySync acornFoxSubstrateFaultStep, write func(*os.File) error, validateTemp func(*os.File, os.FileInfo) error, verifyFinal func(*os.File) error) error {
	parent := parentDirectory(final)
	if parent == "" {
		return errors.New("AcornFox substrate final parent is invalid")
	}
	temp, err := durableTempName(parent, acornFoxSubstrateTempPrefix)
	if err != nil {
		return err
	}
	if err := fault(acornFoxSubstrateFaultTempCreate); err != nil {
		return err
	}
	file, err := root.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
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
	if err = fault(acornFoxSubstrateFaultTempWrite); err == nil {
		err = write(file)
	}
	if err == nil {
		err = fault(acornFoxSubstrateFaultTempMetadata)
	}
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Chown(uid, gid)
	}
	var info os.FileInfo
	if err == nil {
		err = fault(acornFoxSubstrateFaultTempStat)
	}
	if err == nil {
		info, err = file.Stat()
	}
	if err == nil {
		err = validateTemp(file, info)
	}
	if err == nil {
		err = fault(legacySync)
	}
	if err == nil {
		err = fault(acornFoxSubstrateFaultTempSync)
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = fault(acornFoxSubstrateFaultTempClose)
	}
	if closeErr := closeTemp(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = fault(acornFoxSubstrateFaultTempLink); err != nil {
		return err
	}
	linkErr := root.Link(temp, final)
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		return linkErr
	}
	if err = fault(acornFoxSubstrateFaultFinalReadback); err != nil {
		return err
	}
	if err = acornFoxSubstrateVerifyFinal(root, final, verifyFinal); err != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return ErrAcornFoxSubstrateConflict
		}
		return err
	}
	if err = fault(acornFoxSubstrateFaultTempParentSync); err != nil {
		return err
	}
	if err = syncAcornFoxDirectory(root, parent); err != nil {
		return err
	}
	if err = fault(acornFoxSubstrateFaultTempRemove); err != nil {
		return err
	}
	if err = root.Remove(temp); err != nil {
		return err
	}
	if err = fault(acornFoxSubstrateFaultTempRemoveParentSync); err != nil {
		return err
	}
	return syncAcornFoxDirectory(root, parent)
}

func acornFoxSubstrateVerifyFinal(root *os.Root, path string, verify func(*os.File) error) error {
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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

func acornFoxSubstrateVerifyFileHandle(file *os.File, size int64, digest string, mode os.FileMode, uid, gid int) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || verifyOwner(info, uid, gid) != nil || info.Size() != size || sha256SubstrateOpenFile(file) != digest {
		return errors.New("AcornFox substrate file evidence is invalid")
	}
	return nil
}

func readAcornFoxSubstrateFile(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func acornFoxSubstrateReadControl(root *os.Root, path string, uid, gid int) ([]byte, error) {
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	raw, readErr := readAcornFoxSubstrateFile(file)
	closeErr := file.Close()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || verifyOwner(info, uid, gid) != nil {
		return nil, errors.New("AcornFox substrate control metadata is invalid")
	}
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return raw, nil
}

func acornFoxSubstrateWriteFully(file *os.File, raw []byte) error {
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

func acornFoxSubstrateCopyFully(output, input *os.File) error {
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
func acornFoxSubstrateRemoveOwnedTemps(root *os.Root, entries []SubstrateEntry, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
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
		dir, err := root.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
			info, err := root.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || verifyOwner(info, uid, gid) != nil {
				return ErrAcornFoxSubstrateConflict
			}
			if err := fault(acornFoxSubstrateFaultTempRemove); err != nil {
				return err
			}
			if err := root.Remove(path); err != nil {
				return err
			}
			if err := fault(acornFoxSubstrateFaultTempRemoveParentSync); err != nil {
				return err
			}
			if err := syncAcornFoxDirectory(root, directory); err != nil {
				return err
			}
		}
	}
	return nil
}
