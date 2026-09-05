package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"
)

// Only these two names use fixed metadata temporaries. Existing C1/general
// DurableWriter behavior is unchanged. An unparseable incomplete temporary is
// preserved and rejected; it is never deleted or replaced to generate new keys.
func acornFoxRuntimeMetadataTemporary(name string) string {
	if name == acornFoxRuntimeIntentName || name == acornFoxRuntimeReceiptName {
		return "." + name + ".pending"
	}
	return ""
}
func acornFoxRuntimeMetadataFile(store *TaskAcornFoxRepoStore, name string) (string, os.FileInfo, error) {
	info, err := store.root.Lstat(name)
	temp := acornFoxRuntimeMetadataTemporary(name)
	safe := func(i os.FileInfo) bool {
		return i != nil && verifyDurableFile(i, store.uid, store.gid) == nil && i.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && i.Size() <= acornFoxRuntimeMaxIntent
	}
	if temp == "" {
		if err != nil {
			return "", nil, err
		}
		if !safe(info) || acornFoxRepoNlink(info) != 1 {
			return "", nil, ErrAcornFoxRuntimeConfigConflict
		}
		return name, info, nil
	}
	pending, perr := store.root.Lstat(temp)
	if err != nil && !errors.Is(err, os.ErrNotExist) || perr != nil && !errors.Is(perr, os.ErrNotExist) {
		return "", nil, ErrAcornFoxRuntimeConfigConflict
	}
	if errors.Is(err, os.ErrNotExist) {
		if errors.Is(perr, os.ErrNotExist) {
			return "", nil, os.ErrNotExist
		}
		if !safe(pending) || acornFoxRepoNlink(pending) != 1 {
			return "", nil, ErrAcornFoxRuntimeConfigConflict
		}
		return temp, pending, nil
	}
	if !safe(info) {
		return "", nil, ErrAcornFoxRuntimeConfigConflict
	}
	if errors.Is(perr, os.ErrNotExist) {
		if acornFoxRepoNlink(info) != 1 {
			return "", nil, ErrAcornFoxRuntimeConfigConflict
		}
		return name, info, nil
	}
	if !safe(pending) || acornFoxRepoNlink(info) != 2 || acornFoxRepoNlink(pending) != 2 || !os.SameFile(info, pending) {
		return "", nil, ErrAcornFoxRuntimeConfigConflict
	}
	return name, info, nil
}

// createMetadata shares the existing pinned DurableWriter root, file ownership
// checks and fsync contract, but closes only this leaf's two fixed no-replace
// namespaces. Recoverable prefixes are a complete validated temporary, its
// exact two-link final pair, and the final single-link file.
func (s *acornFoxRuntimeConfig) createMetadata(w *DurableWriter, store *TaskAcornFoxRepoStore, name string, raw []byte) error {
	temp := acornFoxRuntimeMetadataTemporary(name)
	if temp == "" || !store.ownsLock() || w.VerifyLiveRoot() != nil || s.syncMetadata == nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	if name == acornFoxRuntimeIntentName {
		if _, err := parseAcornFoxRuntimeIntent(raw); err != nil {
			return err
		}
	} else {
		if _, err := ParseAcornFoxRuntimeConfigReceiptV1(raw); err != nil {
			return err
		}
	}
	observed, err := acornFoxRuntimeReadState(store, name)
	if err == nil && !bytes.Equal(observed, raw) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	if errors.Is(err, os.ErrNotExist) {
		f, err := w.ops.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		// No deferred Remove: a partial write is evidence, not disposable scratch.
		if err = w.ops.Chown(f, w.uid, w.gid); err == nil {
			err = w.ops.Chmod(f, 0600)
		}
		if err == nil {
			var n int
			n, err = w.ops.Write(f, raw)
			if err == nil && n != len(raw) {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = s.step("metadata-written:" + name)
		}
		if err == nil {
			err = w.ops.Sync(f)
		}
		cerr := w.ops.CloseFile(f)
		if err != nil || cerr != nil || w.syncParent(".") != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		if s.step("metadata-temp:"+name) != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
	}
	// Reopen and compare before accepting either a surviving temporary or pair.
	observed, err = acornFoxRuntimeReadState(store, name)
	if err != nil || !bytes.Equal(observed, raw) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	// A complete temporary can survive Write but precede file fsync. Reopen
	// the selected inode, verify its bytes through that descriptor, and sync
	// its data before publishing a link or removing a surviving pair's temp.
	path, before, err := acornFoxRuntimeMetadataFile(store, name)
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	f, err := store.root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	opened, statErr := f.Stat()
	content, readErr := io.ReadAll(io.LimitReader(f, int64(len(raw))+1))
	if statErr != nil || readErr != nil || !os.SameFile(before, opened) || verifyDurableFile(opened, store.uid, store.gid) != nil || !bytes.Equal(content, raw) {
		f.Close()
		return ErrAcornFoxRuntimeConfigConflict
	}
	syncErr := s.syncMetadata(f)
	closeErr := f.Close()
	if syncErr != nil || closeErr != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	if _, err = store.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		if w.ops.Link(temp, name) != nil || w.syncParent(".") != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		if s.step("metadata-linked:"+name) != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
	} else if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	observed, err = acornFoxRuntimeReadState(store, name)
	if err != nil || !bytes.Equal(observed, raw) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	if _, err = store.root.Lstat(temp); err == nil {
		// MetadataFile has just proved the exact inode pair, not merely same bytes.
		if w.ops.Remove(temp) != nil || w.syncParent(".") != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	observed, err = acornFoxRuntimeReadState(store, name)
	if err != nil || !bytes.Equal(observed, raw) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	return nil
}
