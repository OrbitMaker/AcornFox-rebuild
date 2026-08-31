package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// ErrPlatformBackupLocal is deliberately content-free so local filesystem,
// provider, key, and plaintext details do not cross the coordinator boundary.
var ErrPlatformBackupLocal = errors.New("platform backup local storage failed")

type platformBackupLocalLeaf uint8

const (
	platformBackupLocalControlPlaneDump platformBackupLocalLeaf = iota + 1
	platformBackupLocalConfigCaddyfile
	platformBackupLocalConfigEdgeCaddyfile
	platformBackupLocalConfigRuntimeJSON
	platformBackupLocalEdgeTLSJSON
	platformBackupLocalFactsAuditJSON
	platformBackupLocalFactsKeyReferencesJSON
	platformBackupLocalFactsReleaseJSON
	platformBackupLocalFactsRoutesJSON
	platformBackupLocalFactsTasksOutboxJSON
	platformBackupLocalPackage
	platformBackupLocalPackagePartial
	platformBackupLocalEncrypted
	platformBackupLocalEncryptedPartial
	platformBackupLocalReadback
)

type platformBackupLocalLeafSpec struct {
	name      string
	maxSize   int64
	plaintext bool
	accepted  bool
	partial   bool
}

const platformBackupEncryptedMaxSize int64 = PlatformBackupV3MaxPackageSize + ((PlatformBackupV3MaxPackageSize/backupEncryptionChunkSize)+2)*(int64(12+16)+8) + 4096

func platformBackupLocalSpec(leaf platformBackupLocalLeaf) (platformBackupLocalLeafSpec, bool) {
	text := PlatformBackupV3MaxTextMemberSize
	switch leaf {
	case platformBackupLocalControlPlaneDump:
		return platformBackupLocalLeafSpec{"control-plane.dump", PlatformBackupV3MaxDumpSize, true, true, false}, true
	case platformBackupLocalConfigCaddyfile:
		return platformBackupLocalLeafSpec{"config-caddyfile", text, true, true, false}, true
	case platformBackupLocalConfigEdgeCaddyfile:
		return platformBackupLocalLeafSpec{"config-edge-caddyfile", text, true, true, false}, true
	case platformBackupLocalConfigRuntimeJSON:
		return platformBackupLocalLeafSpec{"config-runtime.json", text, true, true, false}, true
	case platformBackupLocalEdgeTLSJSON:
		return platformBackupLocalLeafSpec{"edge-tls.json", text, true, true, false}, true
	case platformBackupLocalFactsAuditJSON:
		return platformBackupLocalLeafSpec{"facts-audit.json", text, true, true, false}, true
	case platformBackupLocalFactsKeyReferencesJSON:
		return platformBackupLocalLeafSpec{"facts-key-references.json", text, true, true, false}, true
	case platformBackupLocalFactsReleaseJSON:
		return platformBackupLocalLeafSpec{"facts-release.json", text, true, true, false}, true
	case platformBackupLocalFactsRoutesJSON:
		return platformBackupLocalLeafSpec{"facts-routes.json", text, true, true, false}, true
	case platformBackupLocalFactsTasksOutboxJSON:
		return platformBackupLocalLeafSpec{"facts-tasks-outbox.json", text, true, true, false}, true
	case platformBackupLocalPackage:
		return platformBackupLocalLeafSpec{"package.tar", PlatformBackupV3MaxPackageSize, true, true, false}, true
	case platformBackupLocalPackagePartial:
		return platformBackupLocalLeafSpec{"package.tar.partial", PlatformBackupV3MaxPackageSize, true, false, true}, true
	case platformBackupLocalEncrypted:
		return platformBackupLocalLeafSpec{"encrypted.ocbkp", platformBackupEncryptedMaxSize, false, true, false}, true
	case platformBackupLocalEncryptedPartial:
		return platformBackupLocalLeafSpec{"encrypted.ocbkp.partial", platformBackupEncryptedMaxSize, false, false, true}, true
	case platformBackupLocalReadback:
		return platformBackupLocalLeafSpec{"readback.tmp", platformBackupEncryptedMaxSize, false, false, false}, true
	default:
		return platformBackupLocalLeafSpec{}, false
	}
}

type platformBackupLocalStore struct{ transaction *DurableWriter }

func newPlatformBackupLocalStore(transaction *DurableWriter) (*platformBackupLocalStore, error) {
	if transaction == nil || transaction.VerifyLiveRoot() != nil || transaction.rootInfo == nil || transaction.rootInfo.Mode().Perm() != durableDirMode {
		return nil, ErrPlatformBackupLocal
	}
	root, err := transaction.ops.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	info, statErr := transaction.ops.Stat(root)
	closeErr := transaction.ops.CloseFile(root)
	if statErr != nil || closeErr != nil || !info.IsDir() || info.Mode().Perm() != durableDirMode || !os.SameFile(info, transaction.rootInfo) || verifyOwner(info, transaction.uid, transaction.gid) != nil {
		return nil, ErrPlatformBackupLocal
	}
	return &platformBackupLocalStore{transaction: transaction}, nil
}

type platformBackupLocalReadSeeker interface {
	io.ReadSeeker
	io.Closer
}

func (s *platformBackupLocalStore) openAccepted(leaf platformBackupLocalLeaf, expectedSize int64, expectedSHA string) (platformBackupLocalReadSeeker, error) {
	spec, ok := platformBackupLocalSpec(leaf)
	if !ok || !spec.accepted || expectedSize <= 0 || expectedSize > spec.maxSize || !validSHA(expectedSHA) {
		return nil, ErrPlatformBackupLocal
	}
	file, err := s.openSecure(spec, os.O_RDONLY)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	valid := false
	defer func() {
		if !valid {
			_ = s.transaction.ops.CloseFile(file)
		}
	}()
	info, err := s.transaction.ops.Stat(file)
	if err != nil || !platformBackupLocalFileValid(info, s.transaction, spec.maxSize) || info.Size() != expectedSize {
		return nil, ErrPlatformBackupLocal
	}
	hash := sha256.New()
	if copied, err := io.Copy(hash, io.LimitReader(file, expectedSize+1)); err != nil || copied != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return nil, ErrPlatformBackupLocal
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		return nil, ErrPlatformBackupLocal
	}
	valid = true
	return &platformBackupLocalReader{store: s, file: file}, nil
}

type platformBackupLocalReader struct {
	store *platformBackupLocalStore
	file  *os.File
}

func (r *platformBackupLocalReader) Read(value []byte) (int, error) {
	if r == nil || r.store == nil || r.store.transaction == nil || r.file == nil || r.store.transaction.VerifyLiveRoot() != nil {
		return 0, ErrPlatformBackupLocal
	}
	n, err := r.file.Read(value)
	if err != nil && err != io.EOF {
		return n, ErrPlatformBackupLocal
	}
	return n, err
}
func (r *platformBackupLocalReader) Seek(offset int64, whence int) (int64, error) {
	if r == nil || r.store == nil || r.store.transaction == nil || r.file == nil || r.store.transaction.VerifyLiveRoot() != nil {
		return 0, ErrPlatformBackupLocal
	}
	position, err := r.file.Seek(offset, whence)
	if err != nil {
		return 0, ErrPlatformBackupLocal
	}
	return position, nil
}
func (r *platformBackupLocalReader) Close() error {
	if r == nil || r.file == nil {
		return ErrPlatformBackupLocal
	}
	file := r.file
	r.file = nil
	if r.store == nil || r.store.transaction == nil {
		_ = file.Close()
		return ErrPlatformBackupLocal
	}
	live := r.store.transaction.VerifyLiveRoot() == nil
	closeErr := r.store.transaction.ops.CloseFile(file)
	if !live || closeErr != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

type platformBackupLocalCandidate struct {
	store   *platformBackupLocalStore
	partial platformBackupLocalLeaf
	final   platformBackupLocalLeaf
	file    *os.File
	size    int64
	linked  bool
	closed  bool
	failed  bool
}

func (s *platformBackupLocalStore) beginStream(partial, final platformBackupLocalLeaf) (*platformBackupLocalCandidate, error) {
	partialSpec, partialOK := platformBackupLocalSpec(partial)
	finalSpec, finalOK := platformBackupLocalSpec(final)
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || !partialOK || !finalOK || !partialSpec.partial || finalSpec.partial || !finalSpec.accepted || !((partial == platformBackupLocalPackagePartial && final == platformBackupLocalPackage) || (partial == platformBackupLocalEncryptedPartial && final == platformBackupLocalEncrypted)) {
		return nil, ErrPlatformBackupLocal
	}
	file, err := s.transaction.ops.OpenFile(partialSpec.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, durableFileMode)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	valid := false
	defer func() {
		if !valid {
			live := s.transaction.VerifyLiveRoot() == nil
			_ = s.transaction.ops.CloseFile(file)
			if live {
				_ = s.transaction.ops.Remove(partialSpec.name)
			}
		}
	}()
	if s.transaction.ops.Chmod(file, durableFileMode) != nil || s.transaction.ops.Chown(file, s.transaction.uid, s.transaction.gid) != nil {
		return nil, ErrPlatformBackupLocal
	}
	info, err := s.transaction.ops.Stat(file)
	if err != nil || !platformBackupLocalFileValid(info, s.transaction, partialSpec.maxSize) || info.Size() != 0 {
		return nil, ErrPlatformBackupLocal
	}
	valid = true
	return &platformBackupLocalCandidate{store: s, partial: partial, final: final, file: file}, nil
}

func (c *platformBackupLocalCandidate) Write(value []byte) (int, error) {
	if c == nil || c.store == nil || c.file == nil || c.closed || c.linked || c.failed || c.store.transaction.VerifyLiveRoot() != nil {
		return 0, ErrPlatformBackupLocal
	}
	spec, _ := platformBackupLocalSpec(c.partial)
	if int64(len(value)) > spec.maxSize-c.size {
		c.failed = true
		return 0, ErrPlatformBackupLocal
	}
	n, err := c.store.transaction.ops.Write(c.file, value)
	if n > 0 {
		c.size += int64(n)
	}
	if err != nil || n != len(value) {
		c.failed = true
		return n, ErrPlatformBackupLocal
	}
	return n, nil
}

func (c *platformBackupLocalCandidate) Commit(verify func(io.ReadSeeker) error) error {
	if c == nil || c.store == nil || c.file == nil || c.closed || c.linked || c.failed || verify == nil || c.store.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	partialSpec, _ := platformBackupLocalSpec(c.partial)
	finalSpec, _ := platformBackupLocalSpec(c.final)
	if c.store.transaction.VerifyLiveRoot() != nil {
		c.failed = true
		return ErrPlatformBackupLocal
	}
	syncErr := c.store.transaction.ops.Sync(c.file)
	closeErr := c.store.transaction.ops.CloseFile(c.file)
	c.file = nil
	c.closed = true
	if syncErr != nil || closeErr != nil {
		c.failed = true
		return ErrPlatformBackupLocal
	}
	if c.verify(partialSpec, verify) != nil {
		return ErrPlatformBackupLocal
	}
	if c.store.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	if c.store.transaction.ops.Link(partialSpec.name, finalSpec.name) != nil {
		linked, reconcileErr := c.reconcileLinked(partialSpec, finalSpec, verify)
		if linked {
			c.linked = true
		}
		if reconcileErr != nil {
			return ErrPlatformBackupLocal
		}
	}
	c.linked = true
	if c.store.syncRoot() != nil {
		_ = c.verifyLinkedFinal(finalSpec, verify)
		return ErrPlatformBackupLocal
	}
	if c.store.transaction.VerifyLiveRoot() != nil || c.store.transaction.ops.Remove(partialSpec.name) != nil || c.store.syncRoot() != nil {
		return ErrPlatformBackupLocal
	}
	return c.verify(finalSpec, verify)
}

func (c *platformBackupLocalCandidate) verifyLinkedFinal(spec platformBackupLocalLeafSpec, verify func(io.ReadSeeker) error) error {
	file, err := c.store.openSecure(spec, os.O_RDONLY)
	if err != nil {
		return ErrPlatformBackupLocal
	}
	info, err := c.store.transaction.ops.Stat(file)
	verifyErr := error(nil)
	if err != nil || !platformBackupLocalLinkedFileValid(info, c.store.transaction, spec.maxSize) || info.Size() <= 0 {
		verifyErr = ErrPlatformBackupLocal
	} else if verify(file) != nil {
		verifyErr = ErrPlatformBackupLocal
	}
	closeErr := c.store.transaction.ops.CloseFile(file)
	if verifyErr != nil || closeErr != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (c *platformBackupLocalCandidate) verify(spec platformBackupLocalLeafSpec, verify func(io.ReadSeeker) error) error {
	file, err := c.store.openSecure(spec, os.O_RDONLY)
	if err != nil {
		return ErrPlatformBackupLocal
	}
	info, err := c.store.transaction.ops.Stat(file)
	verifyErr := error(nil)
	if err != nil || !platformBackupLocalFileValid(info, c.store.transaction, spec.maxSize) || info.Size() <= 0 {
		verifyErr = ErrPlatformBackupLocal
	} else if verify(file) != nil {
		verifyErr = ErrPlatformBackupLocal
	} else if _, err := file.Seek(0, io.SeekStart); err != nil {
		verifyErr = ErrPlatformBackupLocal
	}
	closeErr := c.store.transaction.ops.CloseFile(file)
	if verifyErr != nil || closeErr != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (c *platformBackupLocalCandidate) reconcileLinked(partial, final platformBackupLocalLeafSpec, verify func(io.ReadSeeker) error) (bool, error) {
	if c == nil || c.store == nil || c.store.transaction.VerifyLiveRoot() != nil {
		return true, ErrPlatformBackupLocal
	}
	finalLstat, lstatErr := c.store.transaction.ops.Lstat(final.name)
	if errors.Is(lstatErr, os.ErrNotExist) {
		return false, ErrPlatformBackupLocal
	}
	if lstatErr != nil {
		return true, ErrPlatformBackupLocal
	}
	if !finalLstat.Mode().IsRegular() {
		return false, ErrPlatformBackupLocal
	}
	partialFile, err := c.store.openSecure(partial, os.O_RDONLY)
	if err != nil {
		return true, ErrPlatformBackupLocal
	}
	finalFile, err := c.store.openSecure(final, os.O_RDONLY)
	if err != nil {
		_ = c.store.transaction.ops.CloseFile(partialFile)
		return true, ErrPlatformBackupLocal
	}
	partialInfo, partialErr := c.store.transaction.ops.Stat(partialFile)
	finalInfo, finalErr := c.store.transaction.ops.Stat(finalFile)
	linked := partialErr == nil && finalErr == nil && platformBackupLocalLinkedFileValid(partialInfo, c.store.transaction, partial.maxSize) && platformBackupLocalLinkedFileValid(finalInfo, c.store.transaction, final.maxSize) && os.SameFile(partialInfo, finalInfo)
	verifyErr := error(nil)
	if !linked || verify(finalFile) != nil {
		verifyErr = ErrPlatformBackupLocal
	}
	partialCloseErr := c.store.transaction.ops.CloseFile(partialFile)
	finalCloseErr := c.store.transaction.ops.CloseFile(finalFile)
	if verifyErr != nil || partialCloseErr != nil || finalCloseErr != nil {
		return linked, ErrPlatformBackupLocal
	}
	return true, nil
}

func (c *platformBackupLocalCandidate) Abort() error {
	if c == nil || c.store == nil {
		return ErrPlatformBackupLocal
	}
	if c.file != nil {
		if c.store.transaction.ops.CloseFile(c.file) != nil {
			c.file = nil
			c.closed = true
			return ErrPlatformBackupLocal
		}
		c.file = nil
		c.closed = true
	}
	if c.linked || c.store.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	spec, ok := platformBackupLocalSpec(c.partial)
	if !ok || !spec.partial || c.store.transaction.RemoveMetadata(spec.name) != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (s *platformBackupLocalStore) removeUncommitted(leaf platformBackupLocalLeaf) error {
	spec, ok := platformBackupLocalSpec(leaf)
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || !ok || !spec.partial {
		return ErrPlatformBackupLocal
	}
	if s.transaction.RemoveMetadata(spec.name) != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

type platformBackupLocalReadbackFile struct {
	store   *platformBackupLocalStore
	file    *os.File
	maxSize int64
	failed  bool
}

func (s *platformBackupLocalStore) openReadback() (*platformBackupLocalReadbackFile, error) {
	spec, _ := platformBackupLocalSpec(platformBackupLocalReadback)
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil {
		return nil, ErrPlatformBackupLocal
	}
	file, err := s.openReadbackFile(spec)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil || file.Truncate(0) != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	return &platformBackupLocalReadbackFile{store: s, file: file, maxSize: spec.maxSize}, nil
}

func (s *platformBackupLocalStore) openReadbackFile(spec platformBackupLocalLeafSpec) (*os.File, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil {
		return nil, ErrPlatformBackupLocal
	}
	info, lstatErr := s.transaction.ops.Lstat(spec.name)
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		return nil, ErrPlatformBackupLocal
	}
	if lstatErr == nil && !platformBackupLocalFileValid(info, s.transaction, spec.maxSize) {
		return nil, ErrPlatformBackupLocal
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW
	created := lstatErr != nil
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := s.transaction.ops.OpenFile(spec.name, flags, durableFileMode)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	valid := false
	defer func() {
		if !valid {
			_ = s.transaction.ops.CloseFile(file)
		}
	}()
	if created && (s.transaction.ops.Chmod(file, durableFileMode) != nil || s.transaction.ops.Chown(file, s.transaction.uid, s.transaction.gid) != nil) {
		return nil, ErrPlatformBackupLocal
	}
	info, err = s.transaction.ops.Stat(file)
	if err != nil || !platformBackupLocalFileValid(info, s.transaction, spec.maxSize) {
		return nil, ErrPlatformBackupLocal
	}
	valid = true
	return file, nil
}

func (r *platformBackupLocalReadbackFile) Read(value []byte) (int, error) {
	if r == nil || r.file == nil || r.failed {
		return 0, ErrPlatformBackupLocal
	}
	n, err := r.file.Read(value)
	if err != nil && err != io.EOF {
		return n, ErrPlatformBackupLocal
	}
	return n, err
}
func (r *platformBackupLocalReadbackFile) Write(value []byte) (int, error) {
	if r == nil || r.file == nil || r.failed || r.store == nil || r.store.transaction.VerifyLiveRoot() != nil {
		return 0, ErrPlatformBackupLocal
	}
	position, err := r.file.Seek(0, io.SeekCurrent)
	if err != nil || position < 0 || position > r.maxSize || int64(len(value)) > r.maxSize-position {
		r.failed = true
		return 0, ErrPlatformBackupLocal
	}
	n, err := r.file.Write(value)
	if err != nil || n != len(value) {
		r.failed = true
		return n, ErrPlatformBackupLocal
	}
	return n, nil
}
func (r *platformBackupLocalReadbackFile) Seek(offset int64, whence int) (int64, error) {
	if r == nil || r.file == nil || r.failed || r.store == nil || r.store.transaction.VerifyLiveRoot() != nil {
		return 0, ErrPlatformBackupLocal
	}
	current, err := r.file.Seek(0, io.SeekCurrent)
	if err != nil {
		r.failed = true
		return 0, ErrPlatformBackupLocal
	}
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = current + offset
	case io.SeekEnd:
		info, statErr := r.file.Stat()
		if statErr != nil {
			r.failed = true
			return 0, ErrPlatformBackupLocal
		}
		target = info.Size() + offset
	default:
		r.failed = true
		return 0, ErrPlatformBackupLocal
	}
	if target < 0 || target > r.maxSize {
		r.failed = true
		return 0, ErrPlatformBackupLocal
	}
	position, err := r.file.Seek(target, io.SeekStart)
	if err != nil {
		r.failed = true
		return 0, ErrPlatformBackupLocal
	}
	return position, nil
}
func (r *platformBackupLocalReadbackFile) Close() error {
	if r == nil || r.store == nil || r.file == nil {
		return ErrPlatformBackupLocal
	}
	file := r.file
	r.file = nil
	if r.store.transaction.VerifyLiveRoot() != nil {
		_ = r.store.transaction.ops.CloseFile(file)
		return ErrPlatformBackupLocal
	}
	truncateErr := file.Truncate(0)
	syncErr := r.store.transaction.ops.Sync(file)
	closeErr := r.store.transaction.ops.CloseFile(file)
	if truncateErr != nil || syncErr != nil || closeErr != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (s *platformBackupLocalStore) openSecure(spec platformBackupLocalLeafSpec, flags int) (*os.File, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil {
		return nil, ErrPlatformBackupLocal
	}
	file, err := s.transaction.ops.OpenFile(spec.name, flags|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		_ = s.transaction.ops.CloseFile(file)
		return nil, ErrPlatformBackupLocal
	}
	return file, nil
}

// syncRoot synchronizes the pinned transaction root and treats descriptor
// close as part of the durability result; DurableWriter.syncParent cannot be
// used here because its deferred close is intentionally best effort.
func (s *platformBackupLocalStore) syncRoot() error {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	root, err := s.transaction.ops.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPlatformBackupLocal
	}
	info, statErr := s.transaction.ops.Stat(root)
	if statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != durableDirMode || !os.SameFile(info, s.transaction.rootInfo) || verifyOwner(info, s.transaction.uid, s.transaction.gid) != nil) {
		statErr = ErrPlatformBackupLocal
	}
	syncErr := error(nil)
	if statErr == nil {
		syncErr = s.transaction.ops.Sync(root)
	}
	closeErr := s.transaction.ops.CloseFile(root)
	if statErr != nil || syncErr != nil || closeErr != nil || s.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

func platformBackupLocalFileValid(info os.FileInfo, transaction *DurableWriter, maxSize int64) bool {
	if info == nil || transaction == nil || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode || info.Size() < 0 || info.Size() > maxSize || verifyOwner(info, transaction.uid, transaction.gid) != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func platformBackupLocalLinkedFileValid(info os.FileInfo, transaction *DurableWriter, maxSize int64) bool {
	if info == nil || transaction == nil || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode || info.Size() < 0 || info.Size() > maxSize || verifyOwner(info, transaction.uid, transaction.gid) != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 2
}
