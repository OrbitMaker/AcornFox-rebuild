package install

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// acornFoxValidateProductionManagedScope is the narrow L3B host preflight.
// It deliberately enumerates only AcornFox-owned roots and AcornFox-named
// units; it never walks a host root.  It is pure validation: callers decide
// separately whether a production materialization gate may ever open.
func acornFoxValidateProductionManagedScope(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry) error {
	if root == nil || store == nil || store.layout.mode != acornFoxInstallLayoutProduction || store.layout.validate() != nil || !store.layout.hostRootPinned() {
		return ErrAcornFoxLiveConflict
	}
	if err := acornFoxValidatePinnedProductionState(root, store); err != nil {
		return err
	}
	want := make(map[string]SubstrateEntry, len(entries))
	for _, entry := range entries {
		if validateRelativePath(entry.Path) != nil || entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory {
			return ErrAcornFoxLiveConflict
		}
		if _, exists := want[entry.Path]; exists {
			return ErrAcornFoxLiveConflict
		}
		want[entry.Path] = entry
	}
	seen := make(map[string]bool, len(want))
	for _, managed := range acornFoxProductionManagedRoots() {
		if err := acornFoxValidateProductionTree(root, store, managed, want, seen); err != nil {
			return err
		}
	}
	if err := acornFoxValidateProductionSystemd(root, store, want, seen); err != nil {
		return err
	}
	for path := range want {
		if acornFoxProductionStateChild(path) || acornFoxProductionSharedParent(path) {
			continue // validated by the independently pinned state store above.
		}
		if !seen[path] {
			return ErrAcornFoxLiveConflict
		}
	}
	return nil
}

func acornFoxProductionSharedParent(path string) bool {
	switch path {
	case "opt", "etc", "var", "var/lib", "var/log", "etc/systemd", "etc/systemd/system":
		return true
	default:
		return false
	}
}

func acornFoxProductionStateChild(path string) bool {
	return strings.HasPrefix(path, "var/lib/acornfox/install/")
}

func acornFoxValidatePinnedProductionState(root *os.Root, store *TaskAcornFoxRepoStore) error {
	if store == nil || store.layout.mode != acornFoxInstallLayoutProduction || store.layout.stateRootPath != filepath.Join(store.layout.hostRootPath, "var", "lib", "acornfox", "install") {
		return ErrAcornFoxLiveConflict
	}
	info, err := root.Lstat("var/lib/acornfox/install")
	if err != nil || !os.SameFile(info, store.layout.stateRootInfo) || !safeAcornFoxInstallRoot(info, store.layout.stateOwner.uid, store.layout.stateOwner.gid, true) {
		return ErrAcornFoxLiveConflict
	}
	state, err := store.openRoot()
	if err != nil {
		return ErrAcornFoxLiveConflict
	}
	if closeErr := state.Close(); closeErr != nil {
		return ErrAcornFoxLiveConflict
	}
	return nil
}

func acornFoxValidateProductionTree(root *os.Root, store *TaskAcornFoxRepoStore, path string, want map[string]SubstrateEntry, seen map[string]bool) error {
	entry, ok := want[path]
	if !ok || entry.Kind != SubstrateEntryDirectory || !acornFoxProductionEntryMatches(root, store, path, entry) {
		return ErrAcornFoxLiveConflict
	}
	seen[path] = true
	if path == "var/lib/acornfox/install" {
		return nil // exact, pinned state subtree is not a path-prefix exemption.
	}
	dir, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxLiveConflict
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return ErrAcornFoxLiveConflict
	}
	for _, child := range children {
		childPath := filepath.ToSlash(filepath.Join(path, child.Name()))
		entry, ok := want[childPath]
		if !ok {
			return ErrAcornFoxLiveConflict
		}
		if entry.Kind == SubstrateEntryDirectory {
			if err := acornFoxValidateProductionTree(root, store, childPath, want, seen); err != nil {
				return err
			}
			continue
		}
		if !acornFoxProductionEntryMatches(root, store, childPath, entry) {
			return ErrAcornFoxLiveConflict
		}
		seen[childPath] = true
	}
	return nil
}

func acornFoxValidateProductionSystemd(root *os.Root, store *TaskAcornFoxRepoStore, want map[string]SubstrateEntry, seen map[string]bool) error {
	const systemdRoot = "etc/systemd/system"
	dir, err := root.OpenFile(systemdRoot, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		for path := range want {
			if strings.HasPrefix(path, systemdRoot+"/acornfox-") {
				return ErrAcornFoxLiveConflict
			}
		}
		return nil
	}
	if err != nil {
		return ErrAcornFoxLiveConflict
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return ErrAcornFoxLiveConflict
	}
	for _, child := range children {
		if !strings.HasPrefix(child.Name(), "acornfox-") {
			continue
		}
		path := systemdRoot + "/" + child.Name()
		entry, ok := want[path]
		if !ok {
			return ErrAcornFoxLiveConflict
		}
		if entry.Kind == SubstrateEntryDirectory {
			if err := acornFoxValidateProductionTree(root, store, path, want, seen); err != nil {
				return err
			}
			continue
		}
		if !acornFoxProductionEntryMatches(root, store, path, entry) {
			return ErrAcornFoxLiveConflict
		}
		seen[path] = true
	}
	return nil
}

func acornFoxProductionEntryMatches(root *os.Root, store *TaskAcornFoxRepoStore, path string, entry SubstrateEntry) bool {
	info, err := root.Lstat(path)
	principal := acornFoxLivePrincipalForEntry(store.layout, entry)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(entry.Mode) || !acornFoxLiveObservedOwner(store, info, principal) || (entry.Kind == SubstrateEntryDirectory) != info.IsDir() {
		return false
	}
	if entry.Kind == SubstrateEntryDirectory {
		return true
	}
	if !info.Mode().IsRegular() || acornFoxRepoNlink(info) != 1 || info.Size() != entry.Size {
		return false
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, entry.Size+1))
	closeErr := file.Close()
	return statErr == nil && readErr == nil && closeErr == nil && os.SameFile(info, opened) && len(raw) == int(entry.Size) && sha256Hex(raw) == entry.SHA256
}
