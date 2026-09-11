package install

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
)

type acornFoxLocalGarbageEntry struct {
	entry SubstrateEntry
	owner acornFoxInstallPrincipal
	link  string
}
type acornFoxLocalGarbageTree struct {
	host     bool
	path     string
	entries  map[string]acornFoxLocalGarbageEntry
	optional bool
}

// Every path comes from a validated image or a fixed control path. No path in
// the journal can add arbitrary deletion authority. The image receipt binds
// the whole inventory even after some files have already been removed.
func (u *acornFoxUpgrade) localGarbageInventory(s *TaskAcornFoxRepoStore, image acornFoxUpgradeImage, stash string, removeStash bool) ([]acornFoxLocalGarbageTree, error) {
	if image.validate(u.layout, false) != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	private := acornFoxInstallPrincipal{s.uid, s.gid}
	add := func(m map[string]acornFoxLocalGarbageEntry, e SubstrateEntry, owner acornFoxInstallPrincipal) {
		m[e.Path] = acornFoxLocalGarbageEntry{entry: e, owner: owner}
	}
	file := func(path string, raw []byte, mode uint32) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Size: int64(len(raw)), SHA256: sha256Hex(raw)}
	}
	dir := func(path string, mode uint32) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: mode}
	}
	release := "opt/acornfox/releases/" + image.Activation.ReleaseID
	releaseEntries := map[string]acornFoxLocalGarbageEntry{}
	for _, e := range image.Substrate.Entries {
		if e.Path == release || strings.HasPrefix(e.Path, release+"/") {
			add(releaseEntries, e, acornFoxLivePrincipalForEntry(u.layout, e))
		}
	}
	activation := u.layout.activationDir(image.Activation.ActivationID)
	activationEntries := map[string]acornFoxLocalGarbageEntry{}
	add(activationEntries, dir(activation, uint32(u.layout.activationDirectoryMode())), acornFoxInstallPrincipal{})
	add(activationEntries, file(u.layout.activationReceiptPath(image.Activation.ActivationID), acornFoxUpgradeJSON(image.Activation), 0600), acornFoxInstallPrincipal{})
	env := image.DatabaseEnv
	if len(env) == 0 {
		var err error
		env, err = u.read(s.root, acornFoxControlPlaneStateEnv, 0600, 16384)
		if err != nil {
			return nil, err
		}
	}
	database, err := acornFoxControlPlaneDatabaseName(env)
	if err != nil || !validAcornFoxBoundControlPlaneEnvironment(env, image.ControlPlane, database) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	add(activationEntries, file(activation+"/database.env", env, 0600), acornFoxInstallPrincipal{})
	linkPath := u.layout.activationReleasePath(image.Activation.ActivationID)
	activationEntries[linkPath] = acornFoxLocalGarbageEntry{entry: SubstrateEntry{Path: linkPath}, owner: acornFoxInstallPrincipal{}, link: "../../releases/" + image.Activation.ReleaseID}
	receiptRaw := acornFoxUpgradeJSON(image.Substrate)
	substrateEntries := func(prefix string) map[string]acornFoxLocalGarbageEntry {
		m := map[string]acornFoxLocalGarbageEntry{}
		add(m, dir(prefix+"/substrate", 0700), private)
		add(m, dir(prefix+"/substrate/rootfs", 0700), private)
		intent := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: 1, LayoutVersion: 1, CandidateReceipt: image.Substrate.CandidateReceipt, ExpectedEntryEnvelopeSHA256: image.Substrate.InstalledTreeSHA256}
		add(m, file(prefix+"/"+acornFoxSubstrateIntent, acornFoxUpgradeJSON(intent), 0600), private)
		add(m, file(prefix+"/"+acornFoxSubstrateReceipt, receiptRaw, 0600), private)
		for _, e := range image.Substrate.Entries {
			e.Path = prefix + "/substrate/rootfs/" + e.Path
			add(m, e, private)
		}
		add(m, file(prefix+"/substrate/rootfs/var/lib/acornfox/install/releases/"+image.Activation.ReleaseID+".json", receiptRaw, 0600), private)
		return m
	}
	stashEntries := substrateEntries(stash)
	stashRoot := stash + "/substrate"
	if removeStash {
		stashRoot = stash
		add(stashEntries, dir(stash, 0700), private)
	}
	receiptPath := "releases/" + image.Activation.ReleaseID + ".json"
	receiptEntries := map[string]acornFoxLocalGarbageEntry{}
	add(receiptEntries, file(receiptPath, receiptRaw, 0600), private)
	bindingPath := "bindings/" + image.Repo.BindingSHA256 + ".json"
	bindingEntries := map[string]acornFoxLocalGarbageEntry{}
	add(bindingEntries, file(bindingPath, image.Binding, 0600), private)
	stage := "var/tmp/acornfox-upgrade/" + image.Repo.BindingSHA256
	stageEntries := substrateEntries(stage)
	add(stageEntries, dir(stage, 0700), private)
	add(stageEntries, file(stage+"/"+acornFoxSubstrateLock, nil, 0600), private)
	return []acornFoxLocalGarbageTree{
		{host: true, path: release, entries: releaseEntries},
		{host: true, path: activation, entries: activationEntries},
		{path: receiptPath, entries: receiptEntries},
		{path: bindingPath, entries: bindingEntries},
		{host: true, path: stage, entries: stageEntries, optional: true},
		{path: stashRoot, entries: stashEntries},
	}, nil
}
func (u *acornFoxUpgrade) validateLocalGarbageEntry(root *os.Root, path string, want acornFoxLocalGarbageEntry) error {
	info, err := root.Lstat(path)
	if err != nil {
		return err
	}
	owner, ownerOK := u.ownership.observe(info)
	if want.owner == (acornFoxInstallPrincipal{u.layout.stateOwner.uid, u.layout.stateOwner.gid}) {
		ownerOK = verifyOwner(info, want.owner.uid, want.owner.gid) == nil
		owner = want.owner
	}
	if !ownerOK || owner != want.owner {
		return ErrAcornFoxUpgradeConflict
	}
	if want.link != "" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		link, err := root.Readlink(path)
		if err != nil || !ok || stat.Nlink != 1 || info.Mode()&os.ModeSymlink == 0 || link != want.link {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	}
	e := want.entry
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(e.Mode) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrAcornFoxUpgradeConflict
	}
	if e.Kind == SubstrateEntryDirectory {
		if !info.IsDir() {
			return ErrAcornFoxUpgradeConflict
		}
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Size() != e.Size {
		return ErrAcornFoxUpgradeConflict
	}
	principal := &want.owner
	if want.owner == (acornFoxInstallPrincipal{u.layout.stateOwner.uid, u.layout.stateOwner.gid}) {
		principal = nil
	}
	raw, err := u.readOwnership(root, path, os.FileMode(e.Mode), acornFoxArchiveMaxBytes, principal)
	if err != nil || sha256Hex(raw) != e.SHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
func (u *acornFoxUpgrade) validateLocalGarbage(s *TaskAcornFoxRepoStore, trees []acornFoxLocalGarbageTree, allowMissing bool) error {
	if !s.ownsLock() {
		return ErrAcornFoxUpgradeConflict
	}
	for _, tree := range trees {
		root := s.root
		if tree.host {
			root = s.hostRoot
		}
		seen := map[string]bool{}
		var walk func(string) error
		walk = func(path string) error {
			want, ok := tree.entries[path]
			if !ok {
				return ErrAcornFoxUpgradeConflict
			}
			if err := u.validateLocalGarbageEntry(root, path, want); err != nil {
				return err
			}
			seen[path] = true
			if want.entry.Kind != SubstrateEntryDirectory {
				return nil
			}
			f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			children, err := f.ReadDir(-1)
			f.Close()
			if err != nil {
				return err
			}
			for _, child := range children {
				if err := walk(path + "/" + child.Name()); err != nil {
					return err
				}
			}
			return nil
		}
		if _, err := root.Lstat(tree.path); errors.Is(err, os.ErrNotExist) && (allowMissing || tree.optional) {
			continue
		}
		if err := walk(tree.path); err != nil {
			return fmt.Errorf("local collection inventory %s: %w", tree.path, err)
		}
		if !allowMissing && len(seen) != len(tree.entries) {
			return fmt.Errorf("local collection incomplete %s: %w", tree.path, ErrAcornFoxUpgradeConflict)
		}
	}
	return nil
}
func (u *acornFoxUpgrade) deleteLocalGarbage(s *TaskAcornFoxRepoStore, trees []acornFoxLocalGarbageTree) error {
	// Validate every target before the first unlink, including any still present
	// children on a repeated invocation. Unknown children never get removed.
	if err := u.validateLocalGarbage(s, trees, true); err != nil {
		return err
	}
	for _, tree := range trees {
		root := s.root
		if tree.host {
			root = s.hostRoot
		}
		paths := make([]string, 0, len(tree.entries))
		for path := range tree.entries {
			paths = append(paths, path)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(paths)))
		for _, path := range paths {
			if err := u.validateLocalGarbageEntry(root, path, tree.entries[path]); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			if err := root.Remove(path); err != nil {
				return err
			}
			if err := acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)); err != nil {
				return err
			}
			if err := u.fault("local-collection-unlinked"); err != nil {
				return err
			}
		}
	}
	return nil
}
func (u *acornFoxUpgrade) removeLocalEmptyDirectory(s *TaskAcornFoxRepoStore, path string) error {
	info, err := s.root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := s.root.Remove(path); err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	return acornFoxLiveSyncDir(s.root, parentDirectory(path))
}
