package unifiedinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/sqlite"
	"golang.org/x/sys/unix"
)

const nativeIncomingRoot = UnifiedPrivateStageRoot + "/incoming"

var nativeBundleID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func ValidNativeBundleID(value string) bool { return nativeBundleID.MatchString(value) }

// LoadedNativeStageInput retains every observed artifact descriptor until the
// caller finishes the real StageProductionCandidate transaction.
type LoadedNativeStageInput struct {
	Intake IntakeInput
	files  []*os.File
}

func (loaded *LoadedNativeStageInput) Close() error {
	if loaded == nil {
		return nil
	}
	var result error
	for _, file := range loaded.files {
		result = errors.Join(result, file.Close())
	}
	loaded.files = nil
	return result
}

// LoadProductionNativeStageInput is the one root-only loader. BundleID cannot
// escape the fixed private incoming root, and the pin is never caller data.
func LoadProductionNativeStageInput(ctx context.Context, bundleID string) (*LoadedNativeStageInput, error) {
	return loadProductionNativeStageInputWithCollector(ctx, bundleID, collectNativeHostFacts)
}

func loadProductionNativeStageInputWithCollector(ctx context.Context, bundleID string, collector func(context.Context, acornfoxrelease.UnifiedReleaseManifestV1) (HostFacts, error)) (*LoadedNativeStageInput, error) {
	if ctx == nil || collector == nil || os.Geteuid() != 0 || os.Getegid() != 0 || !nativeBundleID.MatchString(bundleID) {
		return nil, ErrIncomplete
	}
	for _, path := range []string{UnifiedPrivateStageRoot, nativeIncomingRoot} {
		if err := verifyNativeBundleDir(path, 0, 0); err != nil {
			return nil, err
		}
	}
	bundle := filepath.Join(nativeIncomingRoot, bundleID)
	if err := verifyRootRunAncestor(bundle); err != nil {
		return nil, err
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return nil, err
	}
	return loadNativeStageInput(ctx, bundle, pin, 0, 0, collector)
}

func verifyNativeBundleDir(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != 0o700 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrIncomplete
	}
	return nil
}

func bundleEntries(root *os.Root, rel string, uid, gid int) ([]os.DirEntry, error) {
	before, err := root.Lstat(rel)
	if err != nil || !before.IsDir() || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Mode().Perm() != 0o700 || artifactio.CheckFileOwner(before, uid, gid) != nil {
		return nil, ErrIncomplete
	}
	dir, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	opened, statErr := dir.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = dir.Close()
		return nil, ErrIncomplete
	}
	items, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	after, statErr := root.Lstat(rel)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) {
		return nil, ErrIncomplete
	}
	return items, nil
}

func inspectNativeBundleTree(ctx context.Context, root *os.Root, rel string, wanted map[string]acornfoxrelease.UnifiedArtifactV1, seen map[string]bool, uid, gid, depth int) error {
	if depth > 16 {
		return ErrIncomplete
	}
	items, err := bundleEntries(root, rel, uid, gid)
	if err != nil {
		return err
	}
	for _, entry := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.ToSlash(filepath.Join(rel, entry.Name()))
		if err := artifactio.CleanRelative(path); err != nil {
			return err
		}
		info, err := root.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || artifactio.CheckFileOwner(info, uid, gid) != nil {
			return ErrIncomplete
		}
		member := strings.TrimPrefix(path, "payload/")
		if info.IsDir() {
			allowed := false
			for wantedPath := range wanted {
				allowed = allowed || strings.HasPrefix(wantedPath, member+"/")
			}
			if !allowed || inspectNativeBundleTree(ctx, root, path, wanted, seen, uid, gid, depth+1) != nil {
				return ErrIncomplete
			}
			continue
		}
		artifact, ok := wanted[member]
		mode := os.FileMode(0o644)
		if artifact.Executable {
			mode = 0o755
		}
		if !ok || seen[member] || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != mode || info.Size() != artifact.SizeBytes {
			return ErrIncomplete
		}
		seen[member] = true
	}
	return nil
}

// The collector is injected only into same-package disposable fixtures; the
// exported production entry always uses collectNativeHostFacts.
func loadNativeStageInput(ctx context.Context, bundle string, pin acornfoxrelease.TrustedReleasePinV1, uid, gid int, collector func(context.Context, acornfoxrelease.UnifiedReleaseManifestV1) (HostFacts, error)) (loaded *LoadedNativeStageInput, err error) {
	if ctx == nil || ctx.Err() != nil || collector == nil || !filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle {
		return nil, ErrIncomplete
	}
	if err := verifyNativeBundleDir(bundle, uid, gid); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(bundle)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	items, err := bundleEntries(root, ".", uid, gid)
	if err != nil || len(items) != 2 {
		return nil, ErrIncomplete
	}
	names := map[string]bool{}
	for _, item := range items {
		names[item.Name()] = true
	}
	if !names["manifest.json"] || !names["payload"] {
		return nil, ErrIncomplete
	}
	manifestInfo, err := root.Lstat("manifest.json")
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || manifestInfo.Mode().Perm() != 0o600 || manifestInfo.Size() < 1 || manifestInfo.Size() > 64<<10 || artifactio.CheckFileOwner(manifestInfo, uid, gid) != nil {
		return nil, ErrIncomplete
	}
	manifestFile, err := root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened, statErr := manifestFile.Stat()
	if statErr != nil || !os.SameFile(manifestInfo, opened) {
		_ = manifestFile.Close()
		return nil, ErrIncomplete
	}
	raw, readErr := io.ReadAll(io.LimitReader(manifestFile, 64<<10+1))
	closeErr := manifestFile.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != manifestInfo.Size() {
		return nil, ErrIncomplete
	}
	witness, err := acornfoxrelease.ParseUnifiedManifestV1(raw)
	if err != nil || acornfoxrelease.VerifyUnifiedManifestTrust(witness, pin) != nil {
		return nil, ErrIncomplete
	}
	manifest, err := witness.Snapshot()
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		wanted[artifact.RelativePath] = artifact
	}
	seen := make(map[string]bool, len(wanted))
	if err := inspectNativeBundleTree(ctx, root, "payload", wanted, seen, uid, gid, 0); err != nil || len(seen) != len(wanted) {
		return nil, ErrIncomplete
	}
	candidate := &LoadedNativeStageInput{}
	defer func() {
		if err != nil {
			_ = candidate.Close()
		}
	}()
	for _, artifact := range manifest.Artifacts {
		path := "payload/" + artifact.RelativePath
		before, err := root.Lstat(path)
		if err != nil {
			return nil, err
		}
		file, openErr := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, openErr
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, opened) || artifactio.CheckFileOwner(opened, uid, gid) != nil {
			_ = file.Close()
			return nil, ErrIncomplete
		}
		candidate.files = append(candidate.files, file)
		candidate.Intake.Inventory = append(candidate.Intake.Inventory, ArtifactFile{ArtifactID: artifact.ID, RelativePath: artifact.RelativePath, File: file})
	}
	facts, err := collector(ctx, manifest)
	if err != nil {
		return nil, err
	}
	candidate.Intake.Witness = witness
	candidate.Intake.TrustedPin = pin
	candidate.Intake.InventoryUID, candidate.Intake.InventoryGID = uid, gid
	candidate.Intake.Facts = facts
	return candidate, nil
}

func collectNativeHostFacts(ctx context.Context, manifest acornfoxrelease.UnifiedReleaseManifestV1) (HostFacts, error) {
	facts, err := collectNativeArtifactHostFacts(ctx, manifest)
	if err != nil {
		return facts, err
	}
	for _, policy := range manifest.Dependencies {
		var fact DependencyFact
		switch policy.Name {
		case acornfoxrelease.DependencyGit:
			fact, err = observeNativeGitHost(ctx, policy)
		case acornfoxrelease.DependencyDocker:
			var observation nativeDockerObservation
			var absent bool
			observation, absent, err = observeNativeDockerHost(ctx)
			if err == nil {
				if absent {
					fact = DependencyFact{Name: policy.Name, Ownership: "absent"}
				} else {
					ownedPartial := false
					for _, path := range []string{nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot} {
						if _, e := os.Lstat(path); e == nil || !os.IsNotExist(e) {
							ownedPartial = true
						}
					}
					if observation.UnitPath == nativeDockerUnitPath || observation.DataRoot == nativeDockerDataRoot || ownedPartial {
						err = ErrIncompatible
					} else {
						fact = DependencyFact{Name: policy.Name, Ownership: "external", Version: observation.Version, ProbeSocket: nativeDockerSocket}
					}
				}
			}
		case acornfoxrelease.DependencyBuildKit:
			fact, err = absentOrUnprovedNativeDependency(policy.Name, []string{"buildkitd", "buildctl", "rootlesskit"}, "/run/acornfox-buildkit/buildkitd.sock", "/usr/bin/buildkitd", "/usr/local/bin/buildkitd", "/etc/systemd/system/acornfox-buildkit.service", "/opt/acornfox/current/bin/buildkitd", "/opt/acornfox/current/embedded/bin/buildkitd", "/opt/acornfox/current/embedded/bin/buildctl", "/opt/acornfox/current/embedded/bin/rootlesskit")
		case acornfoxrelease.DependencyCaddy:
			fact, err = absentOrUnprovedNativeDependency(policy.Name, []string{"caddy"}, "/run/acornfox/edge-admin/admin.sock", "/usr/bin/caddy", "/usr/local/bin/caddy", "/etc/systemd/system/acornfox-caddy.service", "/opt/acornfox/current/bin/caddy", "/opt/acornfox/current/embedded/bin/caddy")
		default:
			return HostFacts{}, ErrIncomplete
		}
		if err != nil {
			return HostFacts{}, err
		}
		facts.Dependencies = append(facts.Dependencies, fact)
	}
	return facts, nil
}

// The repair byte-stage records only independently observed host identity and
// compiled schema. It makes no dependency ownership or readiness assertion.
func collectNativeArtifactHostFacts(ctx context.Context, manifest acornfoxrelease.UnifiedReleaseManifestV1) (HostFacts, error) {
	var facts HostFacts
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return facts, fmt.Errorf("%w: Native stage requires linux/amd64 host", ErrIncompatible)
	}
	var uts unix.Utsname
	if unix.Uname(&uts) != nil || unix.ByteSliceToString(uts.Machine[:]) != "x86_64" {
		return facts, fmt.Errorf("%w: actual host architecture differs", ErrIncompatible)
	}
	version, err := readNativeUbuntuVersion()
	if err != nil || version != "24.04" {
		return facts, fmt.Errorf("%w: actual Ubuntu 24.04 identity unavailable", ErrIncompatible)
	}
	facts.OS, facts.Distribution, facts.DistributionVersion, facts.Architecture = "linux", "ubuntu", version, "amd64"
	for _, pin := range sqlite.CompiledNativeMigrationPins() {
		facts.SQLiteTarget = append(facts.SQLiteTarget, acornfoxrelease.SQLiteMigrationPinV1{Version: pin.Version, Checksum: pin.Checksum})
	}
	return facts, nil
}

func readNativeUbuntuVersion() (string, error) {
	const path = "/usr/lib/os-release"
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 16<<10 || before.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return "", ErrIncompatible
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", ErrIncompatible
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return "", ErrIncompatible
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		if key == "ID" || key == "VERSION_ID" {
			if _, duplicate := fields[key]; duplicate {
				return "", ErrIncompatible
			}
			fields[key] = strings.Trim(value, `"`)
		}
	}
	if fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
		return "", ErrIncompatible
	}
	return fields["VERSION_ID"], nil
}

func absentOrUnprovedDependency(name string, paths ...string) (DependencyFact, error) {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return DependencyFact{}, fmt.Errorf("%w: %s exists without complete compatible runtime proof at %s", ErrIncompatible, name, path)
		} else if !os.IsNotExist(err) {
			return DependencyFact{}, fmt.Errorf("%w: cannot observe %s at %s", ErrIncompatible, name, path)
		}
	}
	return DependencyFact{Name: name, Ownership: "absent"}, nil
}

func absentOrUnprovedNativeDependency(name string, embedded []string, paths ...string) (DependencyFact, error) {
	fact, err := absentOrUnprovedDependency(name, paths...)
	if err != nil {
		return fact, err
	}
	releases, err := os.ReadDir(install.UnifiedReleasesDir)
	if os.IsNotExist(err) {
		return fact, nil
	}
	if err != nil || len(releases) > 64 {
		return DependencyFact{}, fmt.Errorf("%w: installed release inventory unavailable", ErrIncompatible)
	}
	rootInfo, err := os.Lstat(install.UnifiedReleasesDir)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(rootInfo, 0, 0) != nil || verifyRootRunAncestor(install.UnifiedReleasesDir) != nil {
		return DependencyFact{}, fmt.Errorf("%w: installed release root is untrusted", ErrIncompatible)
	}
	for _, release := range releases {
		if !release.IsDir() || release.Type()&os.ModeSymlink != 0 {
			return DependencyFact{}, fmt.Errorf("%w: installed release entry is untrusted", ErrIncompatible)
		}
		for _, binary := range embedded {
			path := filepath.Join(install.UnifiedReleasesDir, release.Name(), "embedded", "bin", binary)
			if _, err := os.Lstat(path); err == nil {
				return DependencyFact{}, fmt.Errorf("%w: %s installed release bytes require provenance", ErrIncompatible, name)
			} else if !os.IsNotExist(err) {
				return DependencyFact{}, fmt.Errorf("%w: %s installed release inventory unavailable", ErrIncompatible, name)
			}
		}
	}
	return fact, nil
}

type boundedCommandOutput struct {
	data  bytes.Buffer
	limit int
}

func (w *boundedCommandOutput) Write(p []byte) (int, error) {
	if w.data.Len()+len(p) > w.limit {
		return 0, ErrIncompatible
	}
	return w.data.Write(p)
}

func runFixedNativeProbe(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return runFixedNativeProbeBounded(ctx, binary, 32<<10, args...)
}

func runFixedNativeProbeBounded(ctx context.Context, binary string, limit int, args ...string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil || filepath.Clean(resolved) != resolved || !strings.HasPrefix(resolved, "/usr/bin/") && !strings.HasPrefix(resolved, "/usr/sbin/") {
		return nil, ErrIncompatible
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return nil, fmt.Errorf("%w: host package probe binary unavailable", ErrIncompatible)
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, resolved, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/"}
	command.Dir = "/"
	output := &boundedCommandOutput{limit: limit}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: host package probe failed", ErrIncompatible)
	}
	return append([]byte(nil), output.data.Bytes()...), nil
}

type nativeInstalledPackage struct{ Name, Version, Architecture string }

func readNativePackageStatus(name string) (nativeInstalledPackage, bool, error) {
	const path = "/var/lib/dpkg/status"
	var zero nativeInstalledPackage
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 16<<20 || before.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return zero, false, ErrIncompatible
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return zero, false, ErrIncompatible
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16<<20+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return zero, false, ErrIncompatible
	}
	found := false
	for _, stanza := range strings.Split(string(raw), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			key, value, ok := strings.Cut(line, ": ")
			if ok && (key == "Package" || key == "Status" || key == "Version" || key == "Architecture") {
				if fields[key] != "" {
					return zero, false, ErrIncompatible
				}
				fields[key] = value
			}
		}
		if fields["Package"] != name {
			continue
		}
		if found || fields["Status"] != "install ok installed" || fields["Version"] == "" || fields["Architecture"] == "" {
			return zero, false, fmt.Errorf("%w: Git package %s is not a unique installed Ubuntu package", ErrIncompatible, name)
		}
		found = true
		zero = nativeInstalledPackage{name, fields["Version"], fields["Architecture"]}
	}
	return zero, found, nil
}

func verifyNativeAptUbuntuOrigin(ctx context.Context, name, version string) error {
	// apt-cache reads the host's local package indices; it must not download or
	// change package state. An installed-only /var/lib/dpkg/status entry is not
	// enough evidence of the Ubuntu package origin.
	packagePolicy, err := runFixedNativeProbe(ctx, "/usr/bin/apt-cache", "policy", name)
	if err != nil {
		return err
	}
	globalPolicy, err := runFixedNativeProbe(ctx, "/usr/bin/apt-cache", "policy")
	if err != nil {
		return err
	}
	if !nativeAptInstalledVersionHasUbuntuSources(packagePolicy, globalPolicy, version) || !nativeUbuntuAptIndexPresent() {
		return fmt.Errorf("%w: installed Git package %s lacks local Ubuntu apt provenance", ErrIncompatible, name)
	}
	return nil
}

// The package view omits release tags on Ubuntu 24.04. Join only its selected
// installed-version source rows to the same rows in the global local APT view.
func nativeAptInstalledVersionHasUbuntuSources(packagePolicy, globalPolicy []byte, version string) bool {
	global := map[string]bool{}
	inFiles, haveFiles, haveEnd := false, false, false
	pending := ""
	for _, line := range strings.Split(string(globalPolicy), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Package files:" {
			if haveFiles {
				return false
			}
			haveFiles, inFiles = true, true
			continue
		}
		if trimmed == "Pinned packages:" && inFiles {
			if pending != "" {
				return false
			}
			inFiles, haveEnd = false, true
			continue
		}
		if !inFiles {
			continue
		}
		if pending != "" {
			if !strings.HasPrefix(trimmed, "release ") {
				return false
			}
			ubuntu, noble := false, false
			for _, attr := range strings.Split(strings.TrimPrefix(trimmed, "release "), ",") {
				attr = strings.TrimSpace(attr)
				ubuntu = ubuntu || attr == "o=Ubuntu"
				noble = noble || attr == "n=noble"
			}
			global[pending] = ubuntu && noble
			pending = ""
			continue
		}
		if key, ok := nativeAptSourceRow(trimmed); ok {
			if _, duplicate := global[key]; duplicate {
				return false
			}
			pending = key
		} else if trimmed != "" && !strings.HasPrefix(trimmed, "origin ") {
			return false
		}
	}
	if !haveFiles || !haveEnd || pending != "" {
		return false
	}
	installed, inVersionTable, selected, selectedCount := false, false, false, 0
	sources := map[string]bool{}
	for _, line := range strings.Split(string(packagePolicy), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Installed: "+version {
			installed = true
		}
		if trimmed == "Version table:" {
			inVersionTable = true
			continue
		}
		if !inVersionTable {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 3 && fields[0] == "***" {
			if _, err := strconv.Atoi(fields[2]); err != nil {
				return false
			}
			selected = fields[1] == version
			selectedCount++
			continue
		}
		if len(fields) == 2 && strings.ContainsAny(fields[0], ".:-") {
			if _, err := strconv.Atoi(fields[1]); err == nil {
				selected = false
				continue
			}
		}
		if !selected {
			continue
		}
		if key, ok := nativeAptSourceRow(trimmed); ok && !strings.HasSuffix(key, " /var/lib/dpkg/status") {
			if sources[key] || !global[key] {
				return false
			}
			sources[key] = true
		}
	}
	return installed && selectedCount == 1 && len(sources) > 0
}

func nativeAptSourceRow(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	if _, err := strconv.Atoi(fields[0]); err != nil {
		return "", false
	}
	return strings.Join(fields, " "), true
}

// This is a local root-owned APT metadata observation, not a signature check.
func nativeUbuntuAptIndexPresent() bool {
	const directory = "/var/lib/apt/lists"
	items, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	for _, item := range items {
		if !strings.HasSuffix(item.Name(), "_InRelease") || item.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(directory, item.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 || info.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(info, 0, 0) != nil {
			continue
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
		_ = file.Close()
		if err == nil && bytes.Contains(raw, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) && bytes.Contains(raw, []byte("Origin: Ubuntu")) {
			return true
		}
	}
	return false
}

func hashNativeGitExecutable(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || path == "/usr/lib/git-core/git-remote-https" && !strings.HasPrefix(resolved, "/usr/lib/git-core/") || path == "/usr/bin/git" && resolved != path {
		return "", ErrIncompatible
	}
	before, err := os.Lstat(resolved)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o022 != 0 || before.Size() < 1 || before.Size() > 128<<20 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return "", ErrIncompatible
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", ErrIncompatible
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	after, err := os.Lstat(resolved)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", ErrIncompatible
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nativeGitExecutionIdentity(ctx context.Context, path string) (resolved, linkTarget string, err error) {
	const alias = "/usr/lib/git-core/git-remote-https"
	const target = "/usr/lib/git-core/git-remote-http"
	if path == "/usr/bin/git" {
		if verifyRootRunAncestor(path) != nil || nativeGitFileOwner(ctx, path) != nil {
			return "", "", ErrIncompatible
		}
		return path, "", nil
	}
	if path != alias || verifyRootRunAncestor(alias) != nil {
		return "", "", ErrIncompatible
	}
	info, err := os.Lstat(alias)
	if err != nil || info.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return "", "", ErrIncompatible
	}
	link, err := os.Readlink(alias)
	if err != nil || link != "git-remote-http" {
		return "", "", ErrIncompatible
	}
	targetInfo, err := os.Lstat(target)
	if err != nil || !targetInfo.Mode().IsRegular() || artifactio.CheckFileOwner(targetInfo, 0, 0) != nil {
		return "", "", ErrIncompatible
	}
	for _, path := range []string{alias, target} {
		if nativeGitFileOwner(ctx, path) != nil {
			return "", "", fmt.Errorf("%w: Git HTTPS alias package provenance differs", ErrIncompatible)
		}
	}
	return target, link, nil
}

func nativeGitFileOwner(ctx context.Context, path string) error {
	raw, err := runFixedNativeProbe(ctx, "/usr/bin/dpkg-query", "-S", path)
	if err != nil || strings.TrimSpace(string(raw)) != "git: "+path {
		return ErrIncompatible
	}
	return nil
}

func nativeGitNeededLibraries(path string) ([]string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || path == "/usr/bin/git" && resolved != path || path == "/usr/lib/git-core/git-remote-https" && !strings.HasPrefix(resolved, "/usr/lib/git-core/") {
		return nil, ErrIncompatible
	}
	file, err := elf.Open(resolved)
	if err != nil {
		return nil, ErrIncompatible
	}
	defer file.Close()
	if file.Machine != elf.EM_X86_64 || file.Class != elf.ELFCLASS64 || file.Type != elf.ET_DYN && file.Type != elf.ET_EXEC {
		return nil, ErrIncompatible
	}
	if rpath, err := file.DynString(elf.DT_RPATH); err != nil || len(rpath) != 0 {
		return nil, fmt.Errorf("%w: Git executable has unsupported RPATH", ErrIncompatible)
	}
	if runpath, err := file.DynString(elf.DT_RUNPATH); err != nil || len(runpath) != 0 {
		return nil, fmt.Errorf("%w: Git executable has unsupported RUNPATH", ErrIncompatible)
	}
	needed, err := file.ImportedLibraries()
	if err != nil || len(needed) == 0 || len(needed) > 32 {
		return nil, ErrIncompatible
	}
	seen := map[string]bool{}
	for _, name := range needed {
		if name == "" || strings.ContainsAny(name, "/\\\x00") || seen[name] {
			return nil, ErrIncompatible
		}
		seen[name] = true
	}
	sort.Strings(needed)
	return needed, nil
}

func nativeGitLoaderReadback(ctx context.Context, executable, targetSHA string) (*GitLoaderReadbackFact, error) {
	const loader = "/lib64/ld-linux-x86-64.so.2"
	if executable != "/usr/bin/git" && executable != "/usr/lib/git-core/git-remote-http" || !nativeGitLoaderAncestorsProtected() {
		return nil, ErrIncompatible
	}
	loaderInfo, err := os.Lstat(loader)
	if err != nil || loaderInfo.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(loaderInfo, 0, 0) != nil {
		return nil, ErrIncompatible
	}
	resolvedLoader, err := filepath.EvalSymlinks(loader)
	if err != nil || !nativeGitLibraryPath(resolvedLoader) || verifyRootRunAncestor(resolvedLoader) != nil {
		return nil, ErrIncompatible
	}
	loaderSHA, err := hashNativeGitLibrary(resolvedLoader)
	if err != nil {
		return nil, err
	}
	loaderTargetInfo, err := os.Lstat(resolvedLoader)
	if err != nil || !loaderTargetInfo.Mode().IsRegular() || artifactio.CheckFileOwner(loaderTargetInfo, 0, 0) != nil {
		return nil, ErrIncompatible
	}
	loaderELF, err := elf.Open(resolvedLoader)
	if err != nil {
		return nil, ErrIncompatible
	}
	validELF := loaderELF.Class == elf.ELFCLASS64 && loaderELF.Machine == elf.EM_X86_64 && loaderELF.Type == elf.ET_DYN
	closeErr := loaderELF.Close()
	if !validELF || closeErr != nil {
		return nil, ErrIncompatible
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, loader, "--list", executable)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/"}
	command.Dir = "/"
	output := &boundedCommandOutput{limit: 64 << 10}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.data.Len() == 0 {
		return nil, fmt.Errorf("%w: fixed Git loader readback failed", ErrIncompatible)
	}
	raw := output.data.Bytes()
	sum := sha256.Sum256(raw)
	readback := &GitLoaderReadbackFact{LoaderPath: loader, LoaderResolvedPath: resolvedLoader, LoaderSHA256: loaderSHA, LoaderOwnerUID: 0, LoaderMode: uint32(loaderTargetInfo.Mode().Perm()), LoaderELFClass: "ELF64", LoaderELFMachine: "x86-64", TargetPath: executable, TargetSHA256: targetSHA, OutputSHA256: hex.EncodeToString(sum[:]), OutputSizeBytes: int64(len(raw)), ExitCode: 0}
	seen := map[string]bool{}
	loaderLine, vdsoLine := false, false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "linux-vdso.so.1 (") && strings.HasSuffix(line, ")") {
			if vdsoLine {
				return nil, ErrIncompatible
			}
			vdsoLine = true
			continue
		}
		if strings.HasPrefix(line, loader+" (") && strings.HasSuffix(line, ")") {
			if loaderLine {
				return nil, ErrIncompatible
			}
			loaderLine = true
			continue
		}
		soname, tail, ok := strings.Cut(line, " => ")
		if !ok || soname == "" || strings.ContainsAny(soname, "/\\\x00 \t\r\n") || seen[soname] {
			return nil, ErrIncompatible
		}
		path, _, ok := strings.Cut(tail, " (")
		if !ok || !strings.HasSuffix(tail, ")") || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrIncompatible
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !nativeGitLibraryPath(resolved) || verifyRootRunAncestor(resolved) != nil {
			return nil, ErrIncompatible
		}
		libraryInfo, err := os.Lstat(resolved)
		if err != nil || !libraryInfo.Mode().IsRegular() || libraryInfo.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(libraryInfo, 0, 0) != nil {
			return nil, ErrIncompatible
		}
		seen[soname] = true
		readback.Resolved = append(readback.Resolved, GitLoaderLibraryFact{SONAME: soname, ResolvedPath: resolved})
	}
	if !loaderLine || len(readback.Resolved) == 0 || len(readback.Resolved) > 64 {
		return nil, ErrIncompatible
	}
	return readback, nil
}

func nativeGitLoaderAncestorsProtected() bool {
	info, err := os.Lstat("/lib64")
	if err != nil || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink("/lib64")
		return err == nil && link == "usr/lib64" && verifyRootRunAncestor("/usr/lib64/ld-linux-x86-64.so.2") == nil
	}
	return info.IsDir() && info.Mode().Perm()&0o022 == 0 && verifyRootRunAncestor("/lib64/ld-linux-x86-64.so.2") == nil
}

func hashNativeGitLibrary(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !nativeGitLibraryPath(path) {
		return "", ErrIncompatible
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || before.Size() < 1 || before.Size() > 128<<20 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return "", ErrIncompatible
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", ErrIncompatible
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", ErrIncompatible
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nativeGitLibraryPath(path string) bool {
	return strings.HasPrefix(path, "/lib/x86_64-linux-gnu/") || strings.HasPrefix(path, "/usr/lib/x86_64-linux-gnu/")
}

func observeNativeGitHost(ctx context.Context, policy acornfoxrelease.UnifiedDependencyPolicyV1) (DependencyFact, error) {
	var zero DependencyFact
	if policy.GitHostPackages == nil {
		return zero, ErrIncompatible
	}
	git, hasGit, err := readNativePackageStatus("git")
	if err != nil {
		return zero, err
	}
	man, hasMan, err := readNativePackageStatus("git-man")
	if err != nil {
		return zero, err
	}
	if !hasGit && !hasMan {
		for _, path := range []string{"/usr/bin/git", "/usr/lib/git-core/git-remote-https"} {
			if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
				return zero, fmt.Errorf("%w: Git files exist without installed package provenance", ErrIncompatible)
			}
		}
		return DependencyFact{Name: acornfoxrelease.DependencyGit, Ownership: "absent"}, nil
	}
	if !hasGit || !hasMan || git.Version != man.Version || git.Architecture != "amd64" || man.Architecture != "all" {
		return zero, fmt.Errorf("%w: installed Git package pair incomplete", ErrIncompatible)
	}
	for _, pkg := range []nativeInstalledPackage{git, man} {
		if err := verifyNativeAptUbuntuOrigin(ctx, pkg.Name, pkg.Version); err != nil {
			return zero, err
		}
		query, err := runFixedNativeProbe(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n", pkg.Name)
		if err != nil || strings.TrimSpace(string(query)) != pkg.Name+"\t"+pkg.Version+"\t"+pkg.Architecture+"\tinstalled" {
			return zero, fmt.Errorf("%w: dpkg Git package readback differs", ErrIncompatible)
		}
	}
	const supportedExecPath = "/usr/lib/git-core"
	execDirectory, err := os.Lstat(supportedExecPath)
	if err != nil || !execDirectory.IsDir() || execDirectory.Mode().Perm()&0o022 != 0 || artifactio.CheckFileOwner(execDirectory, 0, 0) != nil || verifyRootRunAncestor(filepath.Join(supportedExecPath, "git-remote-https")) != nil {
		return zero, fmt.Errorf("%w: fixed Git helper directory is untrusted", ErrIncompatible)
	}
	// GitExecPath denotes the verified supported package directory, not output
	// from executing the Git program. Actual Git behavior needs a later task.
	readback := &GitHostReadbackFact{GitExecPath: supportedExecPath, PresentBeforeInstall: true}
	for _, pkg := range []nativeInstalledPackage{git, man} {
		readback.Packages = append(readback.Packages, GitInstalledPackageFact{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture, Origin: "Ubuntu"})
	}
	loadedUnion := map[string]string{}
	for _, path := range []string{"/usr/bin/git", "/usr/lib/git-core/git-remote-https"} {
		resolved, linkTarget, err := nativeGitExecutionIdentity(ctx, path)
		if err != nil {
			return zero, err
		}
		sha, err := hashNativeGitExecutable(path)
		if err != nil {
			return zero, err
		}
		needed, err := nativeGitNeededLibraries(path)
		if err != nil {
			return zero, err
		}
		loader, err := nativeGitLoaderReadback(ctx, resolved, sha)
		if err != nil {
			return zero, err
		}
		observed := map[string]bool{}
		for _, library := range loader.Resolved {
			observed[library.SONAME] = true
			if old, exists := loadedUnion[library.SONAME]; exists && old != library.ResolvedPath {
				return zero, ErrIncompatible
			}
			loadedUnion[library.SONAME] = library.ResolvedPath
		}
		for _, soname := range needed {
			if !observed[soname] {
				return zero, fmt.Errorf("%w: direct Git library missing from loader", ErrIncompatible)
			}
		}
		readback.Executables = append(readback.Executables, GitExecutionFact{Path: path, ResolvedPath: resolved, LinkTarget: linkTarget, LinkOwnerPackage: "git", TargetOwnerPackage: "git", SHA256: sha, NeededLibraries: needed, Loader: loader})
	}
	if len(loadedUnion) == 0 || len(loadedUnion) > 64 {
		return zero, ErrIncompatible
	}
	version := git.Version
	if _, tail, found := strings.Cut(version, ":"); found {
		version = tail
	}
	version, _, _ = strings.Cut(version, "-")
	return DependencyFact{Name: acornfoxrelease.DependencyGit, Ownership: "preexisting_external", Version: version, GitHost: readback}, nil
}
