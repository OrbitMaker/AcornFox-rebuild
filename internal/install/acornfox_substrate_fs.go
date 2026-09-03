package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
)

type acornFoxSubstrateTaskLock struct{ file *os.File }

func (p *TaskAcornFoxSubstratePublisher) lock() (*acornFoxSubstrateTaskLock, error) {
	root, err := os.OpenRoot(p.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.Mkdir(acornFoxSubstrateDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	file, err := root.OpenFile(acornFoxSubstrateLock, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		if mkdirErr := root.Mkdir(acornFoxSubstrateDir, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return nil, mkdirErr
		}
		file, err = root.OpenFile(acornFoxSubstrateLock, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if err = file.Chmod(0o600); err == nil {
		err = file.Chown(p.uid, p.gid)
	}
	if err == nil {
		info, statErr := file.Stat()
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

func acornFoxSubstrateWriteIntent(root *os.Root, intent AcornFoxInactiveSubstrateIntentV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	if err := root.Mkdir(acornFoxSubstrateDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	raw, err := MarshalAcornFoxInactiveSubstrateIntentV1(intent)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(acornFoxSubstrateIntent, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := root.ReadFile(acornFoxSubstrateIntent)
		if readErr == nil && string(existing) == string(raw) {
			return nil
		}
		return errors.New("AcornFox substrate intent conflicts")
	}
	if err != nil {
		return err
	}
	if err = fault(acornFoxSubstrateFaultIntentWrite); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Chmod(0o600)
	}
	if err == nil {
		err = fault(acornFoxSubstrateFaultIntentSync)
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
	if err = fault(acornFoxSubstrateFaultIntentReadback); err != nil {
		return err
	}
	return syncAcornFoxRoot(root)
}

func acornFoxSubstrateCreateDirs(root *os.Root, entries []SubstrateEntry, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	if err := root.Mkdir(acornFoxSubstrateRootfs, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
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
		path := acornFoxSubstrateTarget(entry.Path)
		if err := root.Mkdir(path, os.FileMode(entry.Mode)); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		if err = file.Chmod(os.FileMode(entry.Mode)); err == nil {
			err = file.Chown(uid, gid)
		}
		if err == nil {
			err = fault(acornFoxSubstrateFaultDirectorySync)
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
	}
	return syncAcornFoxRoot(root)
}

func acornFoxSubstrateCopyFiles(ctx context.Context, target, source *os.Root, entries []SubstrateEntry, candidate AcornFoxStageReceiptV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
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
		info, err := input.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(entry.Mode) || sha256SubstrateOpenFile(input) != entry.SHA256 {
			input.Close()
			return errors.New("AcornFox substrate source entry is invalid")
		}
		entry.Size = info.Size()
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			input.Close()
			return err
		}
		output, err := target.OpenFile(acornFoxSubstrateTarget(entry.Path), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, os.FileMode(entry.Mode))
		if err != nil {
			input.Close()
			return err
		}
		copyErr := fault(acornFoxSubstrateFaultFileWrite)
		if copyErr == nil {
			_, copyErr = io.CopyBuffer(output, input, make([]byte, 32*1024))
		}
		if copyErr == nil {
			copyErr = fault(acornFoxSubstrateFaultFileSync)
		}
		if copyErr == nil {
			copyErr = output.Chmod(os.FileMode(entry.Mode))
		}
		if copyErr == nil {
			copyErr = output.Chown(uid, gid)
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		outClose := output.Close()
		inClose := input.Close()
		if copyErr == nil {
			copyErr = outClose
		}
		if copyErr == nil {
			copyErr = inClose
		}
		if copyErr != nil {
			return copyErr
		}
		if err := fault(acornFoxSubstrateFaultFileReadback); err != nil {
			return err
		}
		read, err := target.ReadFile(acornFoxSubstrateTarget(entry.Path))
		if err != nil || sha256Hex(read) != entry.SHA256 {
			return errors.New("AcornFox substrate copy digest is invalid")
		}
	}
	return syncAcornFoxRoot(target)
}

func acornFoxSubstrateWriteReceipt(root *os.Root, receipt InactiveSubstrateReceiptV1, uid, gid int, fault func(acornFoxSubstrateFaultStep) error) error {
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(acornFoxSubstrateReceipt, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err = fault(acornFoxSubstrateFaultReceiptWrite); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Chmod(0o600)
	}
	if err == nil {
		err = fault(acornFoxSubstrateFaultReceiptSync)
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
	if err = fault(acornFoxSubstrateFaultReceiptReadback); err != nil {
		return err
	}
	if err = syncAcornFoxRoot(root); err != nil {
		return err
	}
	read, err := root.ReadFile(acornFoxSubstrateReceipt)
	if err != nil {
		return err
	}
	var reread InactiveSubstrateReceiptV1
	if err := json.Unmarshal(read, &reread); err != nil || reread.Validate() != nil || string(read) != string(raw) {
		return errors.New("AcornFox substrate receipt reread is invalid")
	}
	return nil
}
