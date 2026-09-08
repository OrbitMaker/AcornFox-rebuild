package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
)

const (
	acornFoxBindingStoreDir      = "bindings"
	acornFoxBindingStoreLockPath = "bindings/.lock"
	acornFoxBindingStoreMaxFiles = 256
)

var acornFoxBindingStoreName = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

type acornFoxBindingStore struct{ store *TaskAcornFoxRepoStore }

func newAcornFoxBindingStore(store *TaskAcornFoxRepoStore) *acornFoxBindingStore {
	return &acornFoxBindingStore{store: store}
}

type acornFoxBindingStoreLock struct{ file *os.File }

func (l *acornFoxBindingStoreLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	if syscall.Flock(int(file.Fd()), syscall.LOCK_UN) != nil {
		_ = file.Close()
		return ErrAcornFoxRepoConflict
	}
	if err := file.Close(); err != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}

func (b *acornFoxBindingStore) Put(raw []byte) error {
	if b == nil || b.store == nil || len(raw) == 0 || len(raw) > acornFoxCandidateBindingMaxBytes {
		return ErrAcornFoxRepoConflict
	}
	digest := sha256Hex(raw)
	if _, err := ParseAcornFoxCandidateBindingV1(raw, digest); err != nil {
		return ErrAcornFoxRepoConflict
	}
	root, err := b.store.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := b.ensure(root); err != nil {
		return err
	}
	lock, err := b.lock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := b.reconcile(root, digest, raw); err != nil {
		return err
	}
	return b.validate(root)
}
func (b *acornFoxBindingStore) Read(digest string) ([]byte, error) {
	if b == nil || b.store == nil || !validSHA(digest) {
		return nil, ErrAcornFoxRepoConflict
	}
	root, err := b.store.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := b.ensure(root); err != nil {
		return nil, err
	}
	lock, err := b.lock(root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if raw, err := b.readTemporary(root, digest); err == nil {
		if err := b.reconcile(root, digest, raw); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrAcornFoxRepoConflict
	}
	if err := b.validate(root); err != nil {
		return nil, err
	}
	raw, err := b.read(root, digest)
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	return raw, nil
}
func (b *acornFoxBindingStore) predecessor(binding VerifiedAcornFoxBindingV1) ([]byte, error) {
	if !binding.valid() {
		return nil, ErrAcornFoxRepoConflict
	}
	if binding.binding.NMinusOne == nil {
		return nil, nil
	}
	return b.Read(binding.binding.NMinusOne.BindingSHA256)
}
func safeAcornFoxBindingFile(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && acornFoxRepoNlink(info) == 1 && info.Size() > 0 && info.Size() <= acornFoxCandidateBindingMaxBytes && verifyOwner(info, uid, gid) == nil
}
func safeAcornFoxBindingTemporary(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && (acornFoxRepoNlink(info) == 1 || acornFoxRepoNlink(info) == 2) && info.Size() > 0 && info.Size() <= acornFoxCandidateBindingMaxBytes && verifyOwner(info, uid, gid) == nil
}
func safeAcornFoxBindingLock(info os.FileInfo, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == durableFileMode && acornFoxRepoNlink(info) == 1 && info.Size() == 0 && verifyOwner(info, uid, gid) == nil
}

func (b *acornFoxBindingStore) ensure(root *os.Root) error {
	info, err := root.Lstat(acornFoxBindingStoreDir)
	if errors.Is(err, os.ErrNotExist) {
		if err = root.Mkdir(acornFoxBindingStoreDir, durableDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrAcornFoxRepoConflict
		}
		info, err = root.Lstat(acornFoxBindingStoreDir)
		if err == nil {
			dir, openErr := root.OpenFile(acornFoxBindingStoreDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if openErr != nil {
				return ErrAcornFoxRepoConflict
			}
			changeErr := dir.Chmod(durableDirMode)
			if changeErr == nil {
				changeErr = b.store.ownership.chown(dir, b.store.uid, b.store.gid)
			}
			if changeErr == nil {
				changeErr = dir.Sync()
			}
			closeErr := dir.Close()
			if changeErr != nil || closeErr != nil || b.store.syncDirectory(root, ".") != nil {
				return ErrAcornFoxRepoConflict
			}
		}
	}
	if err != nil || !safeAcornFoxRepoDir(info, b.store.uid, b.store.gid) {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func (b *acornFoxBindingStore) lock(root *os.Root) (*acornFoxBindingStoreLock, error) {
	before, statErr := root.Lstat(acornFoxBindingStoreLockPath)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, ErrAcornFoxRepoConflict
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := root.OpenFile(acornFoxBindingStoreLockPath, flags, durableFileMode)
	if created && errors.Is(err, os.ErrExist) {
		created = false
		file, err = root.OpenFile(acornFoxBindingStoreLockPath, os.O_RDWR|syscall.O_NOFOLLOW, durableFileMode)
	}
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	if created {
		if err = file.Chmod(durableFileMode); err == nil {
			err = b.store.ownership.chown(file, b.store.uid, b.store.gid)
		}
		if err == nil {
			err = file.Sync()
		}
		if err == nil {
			err = b.sync(root)
		}
	}
	opened, openErr := file.Stat()
	if err != nil || openErr != nil || !safeAcornFoxBindingLock(opened, b.store.uid, b.store.gid) || (!created && (statErr != nil || !safeAcornFoxBindingLock(before, b.store.uid, b.store.gid) || !os.SameFile(before, opened))) {
		_ = file.Close()
		return nil, ErrAcornFoxRepoConflict
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, ErrAcornFoxRepoConflict
	}
	return &acornFoxBindingStoreLock{file: file}, nil
}

// validate accepts only the fixed lock and canonical final evidence. A temp is
// reconciled under lock by Put/Read before this predicate is allowed to pass.
func (b *acornFoxBindingStore) validate(root *os.Root) error {
	info, err := root.Lstat(acornFoxBindingStoreDir)
	if err != nil || !safeAcornFoxRepoDir(info, b.store.uid, b.store.gid) {
		return ErrAcornFoxRepoConflict
	}
	dir, err := root.OpenFile(acornFoxBindingStoreDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRepoConflict
	}
	children, readErr := dir.ReadDir(acornFoxBindingStoreMaxFiles + 2)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return ErrAcornFoxRepoConflict
	}
	jsonCount := 0
	seenLock := false
	for _, child := range children {
		if child.Name() == ".lock" {
			lockInfo, err := root.Lstat(acornFoxBindingStoreLockPath)
			if err != nil || !safeAcornFoxBindingLock(lockInfo, b.store.uid, b.store.gid) {
				return ErrAcornFoxRepoConflict
			}
			seenLock = true
			continue
		}
		if !acornFoxBindingStoreName.MatchString(child.Name()) {
			return ErrAcornFoxRepoConflict
		}
		jsonCount++
		if jsonCount > acornFoxBindingStoreMaxFiles {
			return ErrAcornFoxRepoConflict
		}
		if _, err := b.read(root, child.Name()[:64]); err != nil {
			return ErrAcornFoxRepoConflict
		}
	}
	if !seenLock {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func (b *acornFoxBindingStore) reconcile(root *os.Root, digest string, raw []byte) error {
	if !validSHA(digest) || sha256Hex(raw) != digest {
		return ErrAcornFoxRepoConflict
	}
	if _, err := ParseAcornFoxCandidateBindingV1(raw, digest); err != nil {
		return ErrAcornFoxRepoConflict
	}
	name, tmp := acornFoxBindingStoreDir+"/"+digest+".json", acornFoxBindingStoreDir+"/"+digest+".tmp"
	if existing, err := b.read(root, digest); err == nil {
		if !bytes.Equal(existing, raw) {
			return ErrAcornFoxRepoConflict
		}
		if temp, tempErr := b.readTemporary(root, digest); tempErr == nil {
			if !bytes.Equal(temp, raw) || root.Remove(tmp) != nil || b.sync(root) != nil {
				return ErrAcornFoxRepoConflict
			}
		} else if !errors.Is(tempErr, os.ErrNotExist) {
			return ErrAcornFoxRepoConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxRepoConflict
	}
	if _, err := b.readTemporary(root, digest); errors.Is(err, os.ErrNotExist) {
		file, openErr := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
		if openErr != nil {
			return ErrAcornFoxRepoConflict
		}
		writeErr := writeAcornFoxRepoAll(file, raw)
		if writeErr == nil {
			writeErr = file.Chmod(durableFileMode)
		}
		if writeErr == nil {
			writeErr = b.store.ownership.chown(file, b.store.uid, b.store.gid)
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return ErrAcornFoxRepoConflict
		}
	} else if err != nil {
		return ErrAcornFoxRepoConflict
	}
	if temp, err := b.readTemporary(root, digest); err != nil || !bytes.Equal(temp, raw) {
		return ErrAcornFoxRepoConflict
	}
	if err := root.Link(tmp, name); err != nil {
		if final, readErr := b.read(root, digest); readErr != nil || !bytes.Equal(final, raw) {
			return ErrAcornFoxRepoConflict
		}
	}
	if err := b.sync(root); err != nil {
		return ErrAcornFoxRepoConflict
	}
	final, err := b.readNamed(root, name, digest, true)
	if err != nil || !bytes.Equal(final, raw) || root.Remove(tmp) != nil || b.sync(root) != nil {
		return ErrAcornFoxRepoConflict
	}
	return nil
}
func (b *acornFoxBindingStore) readTemporary(root *os.Root, digest string) ([]byte, error) {
	return b.readNamed(root, acornFoxBindingStoreDir+"/"+digest+".tmp", digest, true)
}
func (b *acornFoxBindingStore) read(root *os.Root, digest string) ([]byte, error) {
	return b.readNamed(root, acornFoxBindingStoreDir+"/"+digest+".json", digest, false)
}
func (b *acornFoxBindingStore) readNamed(root *os.Root, name, digest string, temporary bool) ([]byte, error) {
	if !validSHA(digest) {
		return nil, ErrAcornFoxRepoConflict
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	safe := safeAcornFoxBindingFile
	if temporary {
		safe = safeAcornFoxBindingTemporary
	}
	if !safe(before, b.store.uid, b.store.gid) {
		return nil, ErrAcornFoxRepoConflict
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxRepoConflict
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxCandidateBindingMaxBytes+1))
	closeErr := file.Close()
	after, afterErr := root.Lstat(name)
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || !safe(opened, b.store.uid, b.store.gid) || !safe(after, b.store.uid, b.store.gid) || !os.SameFile(before, opened) || !os.SameFile(before, after) || int64(len(raw)) != before.Size() || sha256Hex(raw) != digest {
		return nil, ErrAcornFoxRepoConflict
	}
	if _, err = ParseAcornFoxCandidateBindingV1(raw, digest); err != nil {
		// Historic bindings remain immutable catalog records after a schema
		// upgrade. They are readable only when the validated upgrade journal
		// names these exact bytes; they are never accepted as new candidates.
		if temporary || !b.retainedUpgradeBinding(raw, digest) {
			return nil, ErrAcornFoxRepoConflict
		}
	}
	return raw, nil
}
func (b *acornFoxBindingStore) sync(root *os.Root) error {
	return b.store.syncDirectory(root, acornFoxBindingStoreDir)
}

func (b *acornFoxBindingStore) retainedUpgradeBinding(raw []byte, digest string) bool {
	if _, err := verifiedAcornFoxUpgradePredecessor(raw, digest); err != nil {
		return false
	}
	reader := &acornFoxUpgrade{layout: b.store.layout, ownership: b.store.ownership}
	journal, err := reader.load(b.store)
	if err != nil {
		return false
	}
	matches := func(image acornFoxUpgradeImage) bool {
		return image.Repo.BindingSHA256 == digest && bytes.Equal(image.Binding, raw)
	}
	for depth := 0; depth <= acornFoxPostCrossMaxDepth; depth++ {
		if matches(journal.Old) || matches(journal.Next) {
			return true
		}
		if journal.Retired0039 != nil {
			old, err := journal.Retired0039.decode(journal, b.store.layout)
			if err != nil {
				return false
			}
			if matches(old.Old) || matches(old.Next) {
				return true
			}
		}
		if journal.PostCross == nil {
			return false
		}
		journal, err = journal.PostCross.previous(journal)
		if err != nil {
			return false
		}
	}
	return false
}
