package install

import (
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// acornFoxValidateProductionManagedScope is the narrow L3B host preflight.
// It deliberately enumerates only AcornFox-owned roots and AcornFox-named
// units; it never walks a host root.  It is pure validation: callers decide
// separately whether a production materialization gate may ever open.
func acornFoxValidateProductionManagedScope(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry) error {
	return acornFoxValidateProductionManagedScopePrefix(root, store, entries, AcornFoxRepoActivationV1{}, nil, acornFoxRepoPrefixStatic)
}

// acornFoxValidateProductionManagedScopePrefix validates the whole fixed
// AcornFox scope at every repository-preparation boundary.  The activation
// pointers are not an exception to the scope check: they are a small,
// transaction-bound extension of the otherwise static inventory.
func acornFoxValidateProductionManagedScopePrefix(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry, activation AcornFoxRepoActivationV1, activationRaw []byte, state acornFoxRepoPrefixState) error {
	return acornFoxValidateProductionManagedScopePrefixWithRuntimePolicy(root, store, entries, activation, activationRaw, state, true)
}

// acornFoxValidateProductionManagedScopePrefixForLegacyUpgrade admits only a
// tokenless, otherwise fully verified predecessor while an upgrade journal is
// being created. Ordinary host validation remains token-strict.
func acornFoxValidateProductionManagedScopePrefixForLegacyUpgrade(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry, activation AcornFoxRepoActivationV1, activationRaw []byte, state acornFoxRepoPrefixState) error {
	return acornFoxValidateProductionManagedScopePrefixWithRuntimePolicy(root, store, entries, activation, activationRaw, state, false)
}

func acornFoxValidateProductionManagedScopePrefixWithRuntimePolicy(root *os.Root, store *TaskAcornFoxRepoStore, entries []SubstrateEntry, activation AcornFoxRepoActivationV1, activationRaw []byte, state acornFoxRepoPrefixState, requireSetupToken bool) error {
	if root == nil || store == nil || store.layout.mode != acornFoxInstallLayoutProduction || store.layout.validate() != nil || !store.layout.hostRootPinned() {
		return ErrAcornFoxLiveConflict
	}
	if err := acornFoxValidatePinnedProductionState(root, store); err != nil {
		return err
	}
	for _, parent := range []string{"opt", "etc", "var", "var/lib", "var/log", "etc/systemd", "etc/systemd/system"} {
		if !acornFoxSharedParentSafe(root, store, parent) {
			return ErrAcornFoxLiveConflict
		}
	}
	if state == acornFoxRepoPrefixCurrent {
		if handled, err := acornFoxUpgradeRetainedScope(root, store, activation); handled || err != nil {
			return err
		}
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
	if state == acornFoxRepoPrefixCurrent {
		configuration, err := acornFoxRuntimeConfigScopeWithTokenPolicy(root, store, activation, requireSetupToken)
		if err != nil {
			return ErrAcornFoxLiveConflict
		}
		for _, entry := range configuration {
			if _, exists := want[entry.Path]; exists {
				return ErrAcornFoxLiveConflict
			}
			want[entry.Path] = entry
		}
		assistant, err := acornFoxAssistantConfigScope(root, store)
		if err != nil {
			return ErrAcornFoxLiveConflict
		}
		for _, entry := range assistant {
			if _, exists := want[entry.Path]; exists {
				return ErrAcornFoxLiveConflict
			}
			want[entry.Path] = entry
		}
	}
	seen := make(map[string]bool, len(want))
	for _, managed := range acornFoxProductionManagedRoots() {
		if managed == "opt/acornfox" {
			if err := acornFoxValidateProductionAcornFoxTree(root, store, want, seen, activation, activationRaw, state); err != nil {
				return err
			}
			continue
		}
		if err := acornFoxValidateProductionTreeWithRuntime(root, store, managed, want, seen, state == acornFoxRepoPrefixCurrent); err != nil {
			return err
		}
	}
	if err := acornFoxValidateProductionSystemdWithBootLinks(root, store, want, seen, state == acornFoxRepoPrefixCurrent); err != nil {
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

type acornFoxProductionPointer struct {
	target   string
	allowTwo bool
}

// acornFoxValidateProductionAcornFoxTree is intentionally limited to the
// one owned root whose contents vary during activation. It walks neither the
// host root nor an unbounded prefix, and every permitted child is derived from
// the journal-bound activation record.
func acornFoxValidateProductionAcornFoxTree(root *os.Root, store *TaskAcornFoxRepoStore, want map[string]SubstrateEntry, seen map[string]bool, activation AcornFoxRepoActivationV1, activationRaw []byte, state acornFoxRepoPrefixState) error {
	if state < acornFoxRepoPrefixStatic || state > acornFoxRepoPrefixCurrent {
		return ErrAcornFoxLiveConflict
	}
	pointers := map[string]acornFoxProductionPointer{}
	directories := map[string]bool{}
	files := map[string][]byte{}
	controlPlaneFiles := map[string][]byte{}
	if state != acornFoxRepoPrefixStatic {
		if activation.Validate() != nil || len(activationRaw) == 0 || activation.Mode != "production_host" || activation.LayoutSHA256 != store.layout.evidence() {
			return ErrAcornFoxLiveConflict
		}
		activationDir := store.layout.activationDir(activation.ActivationID)
		directories[store.layout.livePath("opt/acornfox/activations")] = true
		if state >= acornFoxRepoPrefixActivationDir {
			directories[activationDir] = true
		}
		if state >= acornFoxRepoPrefixActivationJSON {
			files[store.layout.activationReceiptPath(activation.ActivationID)] = activationRaw
		}
		// The control-plane migration owns exactly one root-only activation
		// file: database.env. Its completion receipt stays in the fixed state
		// root, so an activation remains unable to carry arbitrary receipts.
		if state >= acornFoxRepoPrefixActivationDir {
			principal, ownerOK := store.layout.owner(AcornFoxLiveRootRole)
			envPath := activationDir + "/database.env"
			envRaw, envOK := acornFoxReadControlPlaneScopedFile(root, store, envPath, principal)
			if !ownerOK {
				return ErrAcornFoxLiveConflict
			}
			if envOK {
				database, databaseErr := acornFoxControlPlaneDatabaseName(envRaw)
				if databaseErr != nil || !validAcornFoxControlPlaneEnvironmentForDatabase(envRaw, database) || (database != acornFoxControlPlaneDatabase && !acornFoxUpgradeShadowName.MatchString(database)) {
					return ErrAcornFoxLiveConflict
				}
				controlPlaneFiles[envPath] = envRaw
			}
		}
		addPointer := func(path, target string, allowTwo bool) {
			pointers[path] = acornFoxProductionPointer{target: target, allowTwo: allowTwo}
		}
		release := store.layout.activationReleasePath(activation.ActivationID)
		if state == acornFoxRepoPrefixReleaseTemp {
			addPointer(acornFoxRepoTemp(activation.TransactionID, release), "../../releases/"+activation.ReleaseID, true)
			if _, err := root.Lstat(release); err == nil {
				addPointer(release, "../../releases/"+activation.ReleaseID, true)
			}
		} else if state >= acornFoxRepoPrefixRelease {
			addPointer(release, "../../releases/"+activation.ReleaseID, false)
		}
		active := store.layout.activePath()
		if state == acornFoxRepoPrefixActiveTemp {
			addPointer(acornFoxRepoTemp(activation.TransactionID, active), "activations/"+activation.ActivationID, true)
			if _, err := root.Lstat(active); err == nil {
				addPointer(active, "activations/"+activation.ActivationID, true)
			}
		} else if state >= acornFoxRepoPrefixActive {
			addPointer(active, "activations/"+activation.ActivationID, false)
		}
		current := store.layout.currentPath()
		if state == acornFoxRepoPrefixCurrentTemp {
			addPointer(acornFoxRepoTemp(activation.TransactionID, current), "active/release", true)
			if _, err := root.Lstat(current); err == nil {
				addPointer(current, "active/release", true)
			}
		} else if state >= acornFoxRepoPrefixCurrent {
			addPointer(current, "active/release", false)
		}
	}

	var walk func(string) error
	walk = func(path string) error {
		entry, static := want[path]
		if static {
			if entry.Kind != SubstrateEntryDirectory || !acornFoxProductionEntryMatches(root, store, path, entry) {
				return ErrAcornFoxLiveConflict
			}
			seen[path] = true
		} else if !directories[path] {
			return ErrAcornFoxLiveConflict
		} else {
			info, err := root.Lstat(path)
			principal, ok := store.layout.owner(AcornFoxLiveRootRole)
			modeOK := err == nil && (info.Mode().Perm() == store.layout.activationDirectoryMode() || acornFoxPrivateActivationPrefix(root, store, store.layout, path, info))
			if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !modeOK || !acornFoxLiveObservedOwner(store, info, principal) {
				return ErrAcornFoxLiveConflict
			}
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
			if entry, ok := want[childPath]; ok {
				if entry.Kind == SubstrateEntryDirectory {
					if err := walk(childPath); err != nil {
						return err
					}
					continue
				}
				if !acornFoxProductionEntryMatches(root, store, childPath, entry) {
					return ErrAcornFoxLiveConflict
				}
				seen[childPath] = true
				continue
			}
			if directories[childPath] {
				if err := walk(childPath); err != nil {
					return err
				}
				continue
			}
			if raw, ok := files[childPath]; ok {
				principal, ownerOK := store.layout.owner(AcornFoxLiveRootRole)
				if !ownerOK || !acornFoxLiveExactFileOwned(root, store, childPath, raw, durableFileMode, principal, false) {
					return ErrAcornFoxLiveConflict
				}
				continue
			}
			if raw, ok := controlPlaneFiles[childPath]; ok {
				principal, ownerOK := store.layout.owner(AcornFoxLiveRootRole)
				if !ownerOK || !acornFoxLiveExactFileOwned(root, store, childPath, raw, durableFileMode, principal, false) {
					return ErrAcornFoxLiveConflict
				}
				continue
			}
			if pointer, ok := pointers[childPath]; ok && acornFoxRepoPointerForLayout(root, store, store.layout, childPath, pointer.target, pointer.allowTwo) {
				continue
			}
			return ErrAcornFoxLiveConflict
		}
		return nil
	}
	return walk("opt/acornfox")
}

func acornFoxReadControlPlaneScopedFile(root *os.Root, store *TaskAcornFoxRepoStore, path string, principal acornFoxInstallPrincipal) ([]byte, bool) {
	if root == nil || store == nil {
		return nil, false
	}
	info, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != durableFileMode || acornFoxRepoNlink(info) != 1 || !acornFoxLiveObservedOwner(store, info, principal) {
		return nil, false
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	raw, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, false
	}
	return raw, true
}

func acornFoxProductionSharedParent(path string) bool {
	switch path {
	case "opt", "etc", "var", "var/lib", "var/log", "etc/systemd", "etc/systemd/system":
		return true
	default:
		return false
	}
}

func acornFoxSharedParentSafe(root *os.Root, store *TaskAcornFoxRepoStore, path string) bool {
	if !acornFoxProductionSharedParent(path) {
		return false
	}
	info, err := root.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != store.uid {
		return false
	}
	if path != "var/log" {
		return info.Mode().Perm() == 0o755 && int(stat.Gid) == store.gid
	}
	if info.Mode().Perm() != 0o755 && info.Mode().Perm() != 0o775 {
		return false
	}
	if int(stat.Gid) == store.gid {
		return true
	}
	// Ubuntu owns /var/log as root:syslog 0775. This is an OS ancestor,
	// not a directory whose ownership the product may take over.
	if store.layout.hostRootPath != "/" || store.uid != 0 {
		return false
	}
	group, err := user.LookupGroup("syslog")
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(group.Gid)
	return err == nil && gid == int(stat.Gid)
}

func acornFoxServiceDataRoot(path string) bool {
	switch path {
	case "var/lib/acornfox/uploads", "var/lib/acornfox/workspaces", "var/lib/acornfox/build-work", "var/lib/acornfox/oci", "var/lib/acornfox/secrets", "var/lib/acornfox/secret-materials", "var/lib/acornfox/health-secret-materials", "var/lib/acornfox/agent", "var/lib/acornfox/buildkit", "var/lib/acornfox/pi", "var/lib/acornfox/pi/work", "var/lib/acornfox/pi/agent", "var/lib/acornfox/pi/sessions", "var/lib/acornfox/caddy", "var/lib/acornfox/edge", "var/lib/acornfox/edge/home", "var/lib/acornfox/edge/data", "var/lib/acornfox/edge/config", "var/lib/acornfox/healthcheck", "var/log/acornfox/server", "var/log/acornfox/agent", "var/log/acornfox/caddy", "var/log/acornfox/edge":
		return true
	}
	return false
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
	// `bindings` is a closed state namespace, not a path-prefix exemption.
	// Validate every retained raw witness through its typed store before the
	// host scope accepts any activation prefix.
	bindingErr := newAcornFoxBindingStore(store).validate(state)
	controlErr := acornFoxValidateControlPlaneState(state, store)
	if closeErr := state.Close(); closeErr != nil || bindingErr != nil || controlErr != nil {
		return ErrAcornFoxLiveConflict
	}
	return nil
}

// acornFoxValidateControlPlaneState recognizes only the two direct state
// witnesses added by the migration leaf. They are optional before the leaf
// starts; a receipt cannot exist without a valid matching environment.
func acornFoxValidateControlPlaneState(root *os.Root, store *TaskAcornFoxRepoStore) error {
	if root == nil || store == nil {
		return ErrAcornFoxLiveConflict
	}
	read := func(name string) ([]byte, bool, error) {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil || !safeAcornFoxRepoFile(info, store.uid, store.gid) {
			return nil, false, ErrAcornFoxLiveConflict
		}
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, false, ErrAcornFoxLiveConflict
		}
		raw, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, false, ErrAcornFoxLiveConflict
		}
		return raw, true, nil
	}
	env, envOK, err := read(acornFoxControlPlaneStateEnv)
	if err != nil {
		return err
	}
	receiptRaw, receiptOK, err := read(acornFoxControlPlaneReceipt)
	if err != nil {
		return err
	}
	if receiptOK && !envOK {
		return ErrAcornFoxLiveConflict
	}
	if receiptOK {
		receipt, parseErr := ParseAcornFoxControlPlaneMigrationReceiptV1(receiptRaw)
		expectedDatabase := acornFoxControlPlaneDatabase
		observedDatabase, databaseErr := acornFoxControlPlaneDatabaseName(env)
		if databaseErr == nil && observedDatabase != acornFoxControlPlaneDatabase {
			expectedDatabase, databaseErr = acornFoxExpectedCurrentDatabase(store, receipt.BindingSHA256)
		}
		if parseErr != nil || databaseErr != nil || observedDatabase != expectedDatabase || !validAcornFoxBoundControlPlaneEnvironment(env, receipt, expectedDatabase) {
			return ErrAcornFoxLiveConflict
		}
	}
	return nil
}

func acornFoxValidateProductionTree(root *os.Root, store *TaskAcornFoxRepoStore, path string, want map[string]SubstrateEntry, seen map[string]bool) error {
	return acornFoxValidateProductionTreeWithRuntime(root, store, path, want, seen, false)
}

func acornFoxValidateProductionTreeWithRuntime(root *os.Root, store *TaskAcornFoxRepoStore, path string, want map[string]SubstrateEntry, seen map[string]bool, runtimeData bool) error {
	entry, ok := want[path]
	if !ok || entry.Kind != SubstrateEntryDirectory || !acornFoxProductionEntryMatches(root, store, path, entry) {
		return ErrAcornFoxLiveConflict
	}
	seen[path] = true
	if path == "var/lib/acornfox/install" {
		return nil // exact, pinned state subtree is not a path-prefix exemption.
	}
	if runtimeData && acornFoxServiceDataRoot(path) {
		// Check only fixed scaffolding (notably edge/home,data,config).
		// Never enumerate an unbounded directory of service-created data.
		for childPath, child := range want {
			if parentDirectory(childPath) != path {
				continue
			}
			if child.Kind == SubstrateEntryDirectory {
				if err := acornFoxValidateProductionTreeWithRuntime(root, store, childPath, want, seen, true); err != nil {
					return err
				}
			} else {
				if !acornFoxProductionEntryMatches(root, store, childPath, child) {
					return ErrAcornFoxLiveConflict
				}
				seen[childPath] = true
			}
		}
		return nil
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
			if err := acornFoxValidateProductionTreeWithRuntime(root, store, childPath, want, seen, runtimeData); err != nil {
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
	return acornFoxValidateProductionSystemdWithBootLinks(root, store, want, seen, false)
}

func acornFoxValidateProductionSystemdWithBootLinks(root *os.Root, store *TaskAcornFoxRepoStore, want map[string]SubstrateEntry, seen map[string]bool, bootLinks bool) error {
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
			if bootLinks && acornFoxBootRequiresDirectory(root, store, path) {
				continue
			}
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

func acornFoxBootRequiresDirectory(root *os.Root, store *TaskAcornFoxRepoStore, path string) bool {
	switch path {
	case "etc/systemd/system/acornfox-buildkit.service.requires", "etc/systemd/system/acornfox-caddy.service.requires", "etc/systemd/system/acornfox-server.service.requires", "etc/systemd/system/acornfox-agent.service.requires", "etc/systemd/system/acornfox-edge.service.requires":
	default:
		return false
	}
	info, err := root.Lstat(path)
	principal, ok := store.layout.owner(AcornFoxLiveRootRole)
	if !ok || err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 || !acornFoxLiveObservedOwner(store, info, principal) {
		return false
	}
	dir, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	children, readErr := dir.ReadDir(2)
	closeErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(children) > 1 {
		return false
	}
	if len(children) == 0 {
		return true
	} // Interrupted enable may leave an empty fixed directory.
	if children[0].Name() != "acornfox-upgrade-safe.target" {
		return false
	}
	link := path + "/" + children[0].Name()
	info, err = root.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 || acornFoxRepoNlink(info) != 1 || !acornFoxLiveObservedOwner(store, info, principal) {
		return false
	}
	target, err := root.Readlink(link)
	return err == nil && (target == "../acornfox-upgrade-safe.target" || target == "/etc/systemd/system/acornfox-upgrade-safe.target")
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
