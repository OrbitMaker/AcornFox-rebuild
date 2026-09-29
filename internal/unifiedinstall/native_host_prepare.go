package unifiedinstall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/buildnetwork"
	"github.com/open-card/open-card/internal/hosthelper"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"golang.org/x/sys/unix"
)

var ErrNativeHostPrepareUnknown = errors.New("Native host preparation outcome unknown; preserve private intent and inspect before retry")
var nativeReadyName = regexp.MustCompile(`^ready-[0-9a-f]{32}$`)

const nativeHostPrepareRecords = "host-prepare"

type NativeHostPrepareResult struct {
	InstallationID                 string   `json:"installation_id"`
	ReleaseID                      string   `json:"release_id"`
	ManifestSHA256                 string   `json:"manifest_sha256"`
	StagePath                      string   `json:"stage_path"`
	Status                         string   `json:"status"`
	DependencyEvidencePending      []string `json:"dependency_evidence_pending"`
	RuntimeParentsRequireReprepare bool     `json:"runtime_parents_require_reprepare"`
}

type nativeHostReceipt struct {
	Result   NativeHostPrepareResult `json:"result"`
	Accounts nativeHostIDs           `json:"accounts"`
	Files    map[string]string       `json:"files"`
}

type nativeHostDeps struct {
	root               string // empty in production; a private prefix only in same-package tests
	stageRoot          string
	ownerUID, ownerGID int
	production         bool
	lookupGroup        func(string) (int, bool, error)
	lookupUser         func(string) (int, int, bool, error)
	inspectUser        func(string) (nativeHostAccountFact, error)
	createGroup        func(context.Context, string) error
	createUser         func(context.Context, string, string, []string) error
}

type nativeHostAccountFact struct {
	UID, GID    int
	Home, Shell string
	Groups      []int
}

func (d nativeHostDeps) path(absolute string) string {
	if d.root == "" {
		return absolute
	}
	return filepath.Join(d.root, strings.TrimPrefix(absolute, "/"))
}

func productionNativeHostDeps() nativeHostDeps {
	return nativeHostDeps{stageRoot: UnifiedPrivateStageRoot, production: true,
		lookupGroup: func(name string) (int, bool, error) {
			g, err := user.LookupGroup(name)
			if _, ok := err.(user.UnknownGroupError); ok {
				return 0, false, nil
			}
			if err != nil {
				return 0, false, err
			}
			id, e := strconv.Atoi(g.Gid)
			if e != nil || id <= 0 {
				return 0, false, ErrIncomplete
			}
			return id, true, nil
		},
		lookupUser: func(name string) (int, int, bool, error) {
			u, err := user.Lookup(name)
			if _, ok := err.(user.UnknownUserError); ok {
				return 0, 0, false, nil
			}
			if err != nil {
				return 0, 0, false, err
			}
			uid, e := strconv.Atoi(u.Uid)
			if e != nil || uid <= 0 {
				return 0, 0, false, ErrIncomplete
			}
			gid, e := strconv.Atoi(u.Gid)
			if e != nil || gid <= 0 {
				return 0, 0, false, ErrIncomplete
			}
			return uid, gid, true, nil
		},
		inspectUser: inspectProductionNativeHostAccount,
		createGroup: func(ctx context.Context, name string) error {
			if err := exec.CommandContext(ctx, "/usr/sbin/groupadd", "--system", name).Run(); err != nil {
				return errors.New("fixed Native group creation failed")
			}
			return nil
		},
		createUser: func(ctx context.Context, name, group string, extra []string) error {
			args := []string{"--system", "--gid", group, "--shell", "/usr/sbin/nologin", "--home-dir", "/nonexistent", "--no-create-home"}
			if len(extra) > 0 {
				args = append(args, "--groups", strings.Join(extra, ","))
			}
			args = append(args, name)
			if err := exec.CommandContext(ctx, "/usr/sbin/useradd", args...).Run(); err != nil {
				return errors.New("fixed Native role creation failed")
			}
			return nil
		},
	}
}

func verifyNativeHostPrepareSelf(stagePath string, stage verifiedStage) error {
	artifact, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || artifact.RelativePath != "bin/acornfox-host-update" || !artifact.Executable {
		return ErrIncomplete
	}
	att, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil || att.UID != 0 || att.PID != int32(os.Getpid()) || att.ExecutableSHA256 != artifact.SHA256 {
		return ErrIncomplete
	}
	readyExe := filepath.Join(stagePath, "payload", artifact.RelativePath)
	installedExe := filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, artifact.RelativePath)
	if att.ExecutablePath != readyExe && att.ExecutablePath != installedExe {
		return ErrIncomplete
	}
	if err := verifyNativeCoreBinary(att.ExecutablePath, artifact.SHA256); err != nil {
		return ErrIncomplete
	}
	return nil
}

func inspectProductionNativeHostAccount(name string) (nativeHostAccountFact, error) {
	var result nativeHostAccountFact
	account, err := user.Lookup(name)
	if err != nil {
		return result, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return result, ErrIncomplete
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return result, ErrIncomplete
	}
	groups, err := account.GroupIds()
	if err != nil {
		return result, err
	}
	for _, text := range groups {
		id, e := strconv.Atoi(text)
		if e != nil || id <= 0 {
			return result, ErrIncomplete
		}
		result.Groups = append(result.Groups, id)
	}
	result.UID, result.GID, result.Home = uid, gid, account.HomeDir
	// user.User has no shell field. The fixed local useradd path must create an
	// exact local passwd record; do not infer a disabled login from nologin intent.
	const path = "/etc/passwd"
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || before.Size() > 1<<20 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return result, ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return result, ErrIncomplete
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || int64(len(raw)) != before.Size() {
		return result, ErrIncomplete
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != name {
			continue
		}
		if found || fields[2] != account.Uid || fields[3] != account.Gid || fields[5] != account.HomeDir {
			return result, ErrIncomplete
		}
		result.Shell = fields[6]
		found = true
	}
	if !found {
		return result, ErrIncomplete
	}
	return result, nil
}

func verifyNativeHostAccountFacts(d nativeHostDeps, ids nativeHostIDs) error {
	people := []struct {
		name     string
		uid, gid int
		ipc      bool
	}{
		{install.AccountCore, ids.CoreUID, ids.CoreGID, true},
		{install.AccountContainerRuntime, ids.ContainerUID, ids.ContainerGID, true},
		{install.AccountSourceBuild, ids.SourceUID, ids.SourceGID, true},
		{install.AccountGateway, ids.GatewayUID, ids.GatewayGID, true},
		{"acornfox-caddy", ids.CaddyUID, ids.CaddyGID, true},
		{"acornfox-buildkit", ids.BuildkitUID, ids.BuildkitGID, false},
	}
	for _, p := range people {
		got, err := d.inspectUser(p.name)
		if err != nil || got.UID != p.uid || got.GID != p.gid || got.Home != "/nonexistent" || got.Shell != "/usr/sbin/nologin" {
			return ErrIncomplete
		}
		want := []int{p.gid}
		if p.ipc {
			want = append(want, ids.IPC)
		}
		if p.name == install.AccountSourceBuild {
			want = append(want, ids.BuildkitGID)
		}
		sort.Ints(want)
		sort.Ints(got.Groups)
		if len(want) != len(got.Groups) {
			return ErrIncomplete
		}
		for i := range want {
			if want[i] != got.Groups[i] {
				return ErrIncomplete
			}
		}
	}
	return nil
}

// PrepareNativeHost is the only production caller. Paths, commands and users
// cannot be selected by a release manifest or CLI beyond the trusted ready ID.
func PrepareNativeHost(ctx context.Context, stagePath string) (NativeHostPrepareResult, error) {
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return NativeHostPrepareResult{}, ErrIncomplete
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return NativeHostPrepareResult{}, err
	}
	return prepareNativeHostAt(ctx, stagePath, pin, productionNativeHostDeps())
}

func prepareNativeHostAt(ctx context.Context, stagePath string, pin acornfoxrelease.TrustedReleasePinV1, d nativeHostDeps) (result NativeHostPrepareResult, err error) {
	if ctx == nil || ctx.Err() != nil || !nativeReadyName.MatchString(filepath.Base(stagePath)) || filepath.Dir(stagePath) != d.stageRoot || d.lookupGroup == nil || d.lookupUser == nil || d.inspectUser == nil || d.createGroup == nil || d.createUser == nil {
		return result, ErrIncomplete
	}
	stage, err := verifyStagedRelease(ctx, stagePath, d.stageRoot, pin, d.ownerUID, d.ownerGID)
	if err != nil {
		return result, err
	}
	if d.production {
		if err := verifyNativeHostPrepareSelf(stagePath, stage); err != nil {
			return result, err
		}
	}
	release, err := install.ReleaseDirectory(install.UnifiedReleasesDir, stage.manifest.ReleaseID)
	if err != nil {
		return result, err
	}
	key := "prepare-" + stage.sha256
	completePath := filepath.Join(d.stageRoot, nativeHostPrepareRecords, key+"-complete.json")
	if info, e := os.Lstat(completePath); e == nil {
		if !info.Mode().IsRegular() {
			return result, ErrNativeHostPrepareUnknown
		}
		return readCompletedHostPreparation(ctx, stagePath, stage, d, completePath)
	} else if !os.IsNotExist(e) {
		return result, e
	}
	intentPath := filepath.Join(d.stageRoot, nativeHostPrepareRecords, key+"-intent.json")
	if _, e := os.Lstat(intentPath); e == nil {
		return result, ErrNativeHostPrepareUnknown
	} else if !os.IsNotExist(e) {
		return result, e
	}
	if err := preflightNativeForeign(d, release); err != nil {
		return result, err
	}
	installationID, err := plannedNativeInstallationID(d)
	if err != nil {
		return result, err
	}
	result = NativeHostPrepareResult{InstallationID: installationID, ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, StagePath: stagePath, Status: "prepared_not_started", DependencyEvidencePending: []string{"docker", "git", "buildkit", "caddy"}, RuntimeParentsRequireReprepare: true}
	if err := publishHostRecord(d, key+"-intent.json", result); err != nil {
		return NativeHostPrepareResult{}, errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	unknown := func(e error) (NativeHostPrepareResult, error) {
		return NativeHostPrepareResult{}, errors.Join(ErrNativeHostPrepareUnknown, e)
	}
	if err := ensureHostBases(d); err != nil {
		return unknown(err)
	}
	if err := publishNativeInstallationID(d, installationID); err != nil {
		return unknown(err)
	}
	ids, err := createNativeAccounts(ctx, d)
	if err != nil {
		return unknown(err)
	}
	if err := prepareNativeDirectories(d, ids); err != nil {
		return unknown(err)
	}
	if err := installNativeRelease(ctx, d, stagePath, stage, release); err != nil {
		return unknown(err)
	}
	files, err := nativeHostFiles(stagePath, stage.manifest.ReleaseID, ids)
	if err != nil {
		return unknown(err)
	}
	fileHashes := map[string]string{}
	for _, file := range files {
		if err := publishHostFile(d.path(file.path), file.data, file.mode, d.ownerUID, d.ownerGID); err != nil {
			return unknown(err)
		}
		sum := sha256.Sum256(file.data)
		fileHashes[file.path] = hex.EncodeToString(sum[:])
	}
	receipt := nativeHostReceipt{Result: result, Accounts: ids, Files: fileHashes}
	if err := publishHostRecord(d, key+"-complete.json", receipt); err != nil {
		return unknown(err)
	}
	if _, err := readCompletedHostPreparation(ctx, stagePath, stage, d, completePath); err != nil {
		return unknown(err)
	}
	return result, nil
}

func fixedHostGroups() []string {
	return []string{install.AccountPeerIPC, install.AccountCore, install.AccountContainerRuntime, install.AccountSourceBuild, install.AccountGateway, "acornfox-caddy", "acornfox-buildkit"}
}
func fixedHostUsers() []string {
	return []string{install.AccountCore, install.AccountContainerRuntime, install.AccountSourceBuild, install.AccountGateway, "acornfox-caddy", "acornfox-buildkit"}
}

func preflightNativeForeign(d nativeHostDeps, release string) error {
	for _, v := range nativeHostBaseSpecs() {
		info, err := os.Lstat(d.path(v.path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != v.mode || artifactio.CheckFileOwner(info, d.ownerUID, d.ownerGID) != nil {
			return ErrIncomplete
		}
	}
	for _, name := range fixedHostGroups() {
		_, found, err := d.lookupGroup(name)
		if err != nil {
			return err
		}
		if found {
			return ErrIncomplete
		}
	}
	for _, name := range fixedHostUsers() {
		_, _, found, err := d.lookupUser(name)
		if err != nil {
			return err
		}
		if found {
			return ErrIncomplete
		}
	}
	for _, path := range []string{release, install.UnifiedCurrentSymlink, "/opt/acornfox", install.UnifiedReleasesDir} {
		if _, err := os.Lstat(d.path(path)); err == nil || !os.IsNotExist(err) {
			return ErrIncomplete
		}
	}
	for _, path := range append(nativeHostOwnedFilePaths(), nativeHostPrivatePaths()...) {
		if _, err := os.Lstat(d.path(path)); err == nil || !os.IsNotExist(err) {
			return ErrIncomplete
		}
	}
	for _, name := range []string{"acornfox-core", "acornfox-container", "acornfox-source-build", "acornfox-gateway", "acornfox-build-network", "acornfox-buildkit", "acornfox-caddy", "acornfox-host-helper", "acornfox-server", "acornfox-agent", "acornfox-edge"} {
		for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
			if _, err := os.Lstat(d.path(filepath.Join(dir, name+".service"))); err == nil || !os.IsNotExist(err) {
				return ErrIncomplete
			}
		}
	}
	return nil
}

func nativeHostPrivatePaths() []string {
	return []string{install.UnifiedCoreDataDir, install.UnifiedBackupDir, install.UnifiedContainerStateDir,
		install.UnifiedBuildStateDir, install.UnifiedGatewayStateDir, "/var/lib/acornfox/edge", "/var/lib/acornfox/buildkit",
		install.UnifiedRunRootDir, filepath.Dir(hosthelper.DefaultHelperSocketPath), buildnetwork.RunRoot, "/run/acornfox-buildkit"}
}

func createNativeAccounts(ctx context.Context, d nativeHostDeps) (nativeHostIDs, error) {
	var ids nativeHostIDs
	for _, name := range fixedHostGroups() {
		if err := d.createGroup(ctx, name); err != nil {
			return ids, err
		}
	}
	for _, name := range fixedHostUsers() {
		extra := []string{}
		if name != "acornfox-buildkit" {
			extra = []string{install.AccountPeerIPC}
		}
		if name == install.AccountSourceBuild {
			extra = append(extra, "acornfox-buildkit")
		}
		if err := d.createUser(ctx, name, name, extra); err != nil {
			return ids, err
		}
	}
	group := func(name string) (int, error) {
		id, found, err := d.lookupGroup(name)
		if err != nil || !found || id <= 0 {
			return 0, ErrIncomplete
		}
		return id, nil
	}
	account := func(name string) (int, int, error) {
		uid, gid, found, err := d.lookupUser(name)
		if err != nil || !found || uid <= 0 || gid <= 0 {
			return 0, 0, ErrIncomplete
		}
		return uid, gid, nil
	}
	var err error
	if ids.IPC, err = group(install.AccountPeerIPC); err != nil {
		return ids, err
	}
	if ids.CoreUID, ids.CoreGID, err = account(install.AccountCore); err != nil {
		return ids, err
	}
	if ids.ContainerUID, ids.ContainerGID, err = account(install.AccountContainerRuntime); err != nil {
		return ids, err
	}
	if ids.SourceUID, ids.SourceGID, err = account(install.AccountSourceBuild); err != nil {
		return ids, err
	}
	if ids.GatewayUID, ids.GatewayGID, err = account(install.AccountGateway); err != nil {
		return ids, err
	}
	if ids.CaddyUID, ids.CaddyGID, err = account("acornfox-caddy"); err != nil {
		return ids, err
	}
	if ids.BuildkitUID, ids.BuildkitGID, err = account("acornfox-buildkit"); err != nil {
		return ids, err
	}
	if d.production {
		seen := map[int]bool{}
		for _, uid := range []int{ids.CoreUID, ids.ContainerUID, ids.SourceUID, ids.GatewayUID, ids.CaddyUID, ids.BuildkitUID} {
			if uid <= 0 || seen[uid] {
				return ids, ErrIncomplete
			}
			seen[uid] = true
		}
		for _, gid := range []int{ids.CoreGID, ids.ContainerGID, ids.SourceGID, ids.GatewayGID, ids.CaddyGID, ids.BuildkitGID} {
			if gid == ids.IPC {
				return ids, ErrIncomplete
			}
		}
	}
	if err := verifyNativeHostAccountFacts(d, ids); err != nil {
		return ids, err
	}
	return ids, nil
}

func nativeHostBaseSpecs() []struct {
	path string
	mode os.FileMode
} {
	return []struct {
		path string
		mode os.FileMode
	}{
		{"/opt", 0o755}, {"/opt/acornfox", 0o755}, {install.UnifiedReleasesDir, 0o755}, {"/etc", 0o755}, {"/etc/acornfox", 0o755}, {"/etc/acornfox/trust", 0o755},
		{"/etc/systemd", 0o755}, {"/etc/systemd/system", 0o755}, {"/var", 0o755}, {"/var/lib", 0o755}, {install.UnifiedDataRootDir, 0o755}, {"/run", 0o755},
	}
}

func ensureHostBases(d nativeHostDeps) error {
	for _, v := range nativeHostBaseSpecs() {
		if err := ensureNativeDirectory(d.path(v.path), d.ownerUID, d.ownerGID, v.mode, true); err != nil {
			return err
		}
	}
	return nil
}

func ensureNativeDirectory(path string, uid, gid int, mode os.FileMode, allowExisting bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		created, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		if artifactio.CheckFileOwner(created, uid, gid) != nil {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	} else if err == nil && !allowExisting {
		return ErrIncomplete
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrIncomplete
	}
	return nil
}

func prepareNativeDirectories(d nativeHostDeps, ids nativeHostIDs) error {
	dirs := []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{install.UnifiedCoreDataDir, ids.CoreUID, ids.CoreGID, 0o700},
		{install.UnifiedBackupDir, ids.CoreUID, ids.CoreGID, 0o700},
		{install.UnifiedContainerStateDir, ids.ContainerUID, ids.ContainerGID, 0o700},
		{"/var/lib/acornfox/container/work", ids.ContainerUID, ids.ContainerGID, 0o700},
		{"/var/lib/acornfox/container/images", ids.ContainerUID, ids.ContainerGID, 0o700},
		{install.UnifiedBuildStateDir, ids.SourceUID, ids.SourceGID, 0o700},
		{install.UnifiedGatewayStateDir, ids.GatewayUID, ids.GatewayGID, 0o700},
		{"/var/lib/acornfox/edge", ids.CaddyUID, ids.CaddyGID, 0o700},
		{"/var/lib/acornfox/edge/data", ids.CaddyUID, ids.CaddyGID, 0o700},
		{"/var/lib/acornfox/buildkit", ids.BuildkitUID, ids.BuildkitGID, 0o700},
	}
	for _, name := range []string{"uploads", "source", "work", "images", "logs"} {
		dirs = append(dirs, struct {
			path     string
			uid, gid int
			mode     os.FileMode
		}{filepath.Join(install.UnifiedBuildStateDir, name), ids.SourceUID, ids.SourceGID, 0o700})
	}
	for _, v := range dirs {
		if err := ensureNativeDirectory(d.path(v.path), v.uid, v.gid, v.mode, false); err != nil {
			return err
		}
	}
	if d.production {
		if err := PrepareUnifiedRuntimeIPCParents(RuntimeIPCAccounts{CoreUID: ids.CoreUID, ContainerUID: ids.ContainerUID, SourceUID: ids.SourceUID, GatewayUID: ids.GatewayUID, IPCGID: ids.IPC}); err != nil {
			return err
		}
	}
	run := []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{install.UnifiedRunRootDir, d.ownerUID, ids.IPC, 0o750},
		{"/run/acornfox/trust", d.ownerUID, ids.IPC, 0o750},
		{"/run/acornfox/helper", d.ownerUID, ids.IPC, 0o750},
		{"/run/acornfox/core-ipc", ids.CoreUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/container-ipc", ids.ContainerUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/source-ipc", ids.SourceUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/gateway-ipc", ids.GatewayUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/edge-admin", ids.CaddyUID, ids.IPC, os.ModeSetgid | 0o750},
		{filepath.Dir(hosthelper.DefaultHelperSocketPath), d.ownerUID, ids.IPC, 0o750},
		{buildnetwork.RunRoot, d.ownerUID, ids.SourceGID, 0o750},
		{"/run/acornfox-buildkit", ids.BuildkitUID, ids.BuildkitGID, 0o750},
	}
	if d.production {
		run = run[7:]
	} // the accepted root publisher already verified the first seven parents
	for _, v := range run {
		if err := ensureNativeDirectory(d.path(v.path), v.uid, v.gid, v.mode, false); err != nil {
			return err
		}
	}
	return nil
}

func plannedNativeInstallationID(d nativeHostDeps) (string, error) {
	path := d.path(UnifiedInstallationIDPath)
	if _, err := os.Lstat(path); err == nil {
		return "", ErrIncomplete // a first install cannot adopt an unreceipted identity
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "inst_" + hex.EncodeToString(nonce[:]), nil
}

func publishNativeInstallationID(d nativeHostDeps, id string) error {
	path := d.path(UnifiedInstallationIDPath)
	raw, _ := json.Marshal(struct {
		ID string `json:"installation_id"`
	}{id})
	if err := publishHostFile(path, raw, 0o600, d.ownerUID, d.ownerGID); err != nil {
		return err
	}
	actual, err := readNativeInstallationID(d)
	if err != nil || actual != id {
		return ErrNativeHostPrepareUnknown
	}
	return nil
}

func readNativeInstallationID(d nativeHostDeps) (string, error) {
	var value struct {
		ID string `json:"installation_id"`
	}
	if err := readHostJSON(d.path(UnifiedInstallationIDPath), d.ownerUID, d.ownerGID, &value); err != nil {
		return "", err
	}
	if len(value.ID) < 8 || len(value.ID) > 128 || strings.ContainsAny(value.ID, "/\\\x00 \t\r\n") {
		return "", ErrIncomplete
	}
	return value.ID, nil
}

func readHostJSON(path string, uid, gid int, out any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Size() < 1 || info.Size() > 64<<10 {
		return ErrIncomplete
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || int64(len(data)) != info.Size() {
		return ErrIncomplete
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrIncomplete
	}
	return nil
}

func publishHostRecord(d nativeHostDeps, name string, value any) error {
	directory := filepath.Join(d.stageRoot, nativeHostPrepareRecords)
	if err := ensureNativeDirectory(directory, d.ownerUID, d.ownerGID, 0o700, true); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return publishHostFile(filepath.Join(directory, name), raw, 0o600, d.ownerUID, d.ownerGID)
}

func publishHostFile(path string, data []byte, mode os.FileMode, uid, gid int) (resultErr error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return ErrIncomplete
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrIncomplete
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return ErrIncomplete
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, ErrNativeHostPrepareUnknown, closeErr)
		}
	}()
	temp, err := artifactio.DurableTempName("", ".native-host-")
	if err != nil {
		return err
	}
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = root.Remove(temp)
		}
	}()
	fileInfo, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return statErr
	}
	if artifactio.CheckFileOwner(fileInfo, uid, gid) != nil {
		if err := file.Chown(uid, gid); err != nil {
			file.Close()
			return err
		}
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		file.Close()
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	name := filepath.Base(path)
	if err := root.Link(temp, name); err != nil {
		return err
	}
	committed = true
	if err := root.Remove(temp); err != nil {
		return errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	if err := artifactio.SyncDirectory(parent); err != nil {
		return errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrNativeHostPrepareUnknown
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return ErrNativeHostPrepareUnknown
	}
	opened, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrNativeHostPrepareUnknown
	}
	observed, readErr := io.ReadAll(io.LimitReader(opened, int64(len(data)+1)))
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil || string(observed) != string(data) {
		return ErrNativeHostPrepareUnknown
	}
	return nil
}

func installNativeRelease(ctx context.Context, d nativeHostDeps, stagePath string, stage verifiedStage, release string) error {
	root := d.path(install.UnifiedReleasesDir)
	if _, err := os.Lstat(d.path(release)); err == nil || !os.IsNotExist(err) {
		return ErrIncomplete
	}
	partial, err := artifactio.DurableTempName("", ".native-release-")
	if err != nil {
		return err
	}
	partialPath := filepath.Join(root, partial)
	if err := ensureNativeDirectory(partialPath, d.ownerUID, d.ownerGID, 0o700, false); err != nil {
		return err
	}
	// Partial bytes intentionally remain for root reconciliation on failure.
	manifest, err := acornfoxrelease.CanonicalUnifiedManifestV1(stage.manifest)
	if err != nil {
		return err
	}
	if err := publishHostFile(filepath.Join(partialPath, "manifest.json"), manifest, 0o644, d.ownerUID, d.ownerGID); err != nil {
		return err
	}
	for _, artifact := range stage.manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		source := filepath.Join(stagePath, "payload", filepath.FromSlash(artifact.RelativePath))
		dest := filepath.Join(partialPath, filepath.FromSlash(artifact.RelativePath))
		if err := ensureReleaseParents(partialPath, filepath.Dir(dest), d.ownerUID, d.ownerGID); err != nil {
			return err
		}
		if err := copyHostArtifact(ctx, source, dest, artifact, d.ownerUID, d.ownerGID); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncNativeReleaseDirectories(partialPath); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, partialPath, unix.AT_FDCWD, d.path(release), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	// The incomplete tree remains 0700 until the no-replace commit. Only the
	// now-fixed version path becomes traversable by non-root role executables.
	if err := os.Chmod(d.path(release), 0o755); err != nil {
		return errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	if err := artifactio.SyncDirectory(d.path(release)); err != nil {
		return errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	if err := artifactio.SyncDirectory(root); err != nil {
		return errors.Join(ErrNativeHostPrepareUnknown, err)
	}
	return verifyInstalledRelease(ctx, d.path(release), stage, d.ownerUID, d.ownerGID)
}

func syncNativeReleaseDirectories(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrIncomplete
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := artifactio.SyncDirectory(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func ensureReleaseParents(root, path string, uid, gid int) error {
	if path == root {
		return nil
	}
	if err := ensureReleaseParents(root, filepath.Dir(path), uid, gid); err != nil {
		return err
	}
	return ensureNativeDirectory(path, uid, gid, 0o755, true)
}

func copyHostArtifact(ctx context.Context, source, dest string, a acornfoxrelease.UnifiedArtifactV1, uid, gid int) error {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Size() != a.SizeBytes {
		return ErrIncomplete
	}
	in, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ErrIncomplete
	}
	mode := os.FileMode(0o644)
	if a.Executable {
		mode = 0o755
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, in}, a.SizeBytes+1))
	if copyErr == nil {
		info, statErr := out.Stat()
		if statErr != nil {
			copyErr = statErr
		} else if artifactio.CheckFileOwner(info, uid, gid) != nil {
			copyErr = out.Chown(uid, gid)
		}
	}
	if copyErr == nil {
		copyErr = out.Chmod(mode)
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || n != a.SizeBytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return ErrIncomplete
	}
	return nil
}

func verifyInstalledRelease(ctx context.Context, release string, stage verifiedStage, uid, gid int) error {
	manifestInfo, err := os.Lstat(filepath.Join(release, "manifest.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm() != 0o644 || artifactio.CheckFileOwner(manifestInfo, uid, gid) != nil {
		return ErrIncomplete
	}
	manifest, err := os.ReadFile(filepath.Join(release, "manifest.json"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != stage.sha256 {
		return ErrIncomplete
	}
	wanted := map[string]bool{"manifest.json": true}
	for _, a := range stage.manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(release, filepath.FromSlash(a.RelativePath))
		info, err := os.Lstat(path)
		mode := os.FileMode(0o644)
		if a.Executable {
			mode = 0o755
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() != a.SizeBytes || artifactio.CheckFileOwner(info, uid, gid) != nil {
			return ErrIncomplete
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, e := io.Copy(h, file)
		closeErr := file.Close()
		if e != nil || closeErr != nil || n != a.SizeBytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return ErrIncomplete
		}
		wanted[filepath.ToSlash(a.RelativePath)] = true
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(release, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrIncomplete
		}
		info, e := os.Lstat(path)
		if e != nil || artifactio.CheckFileOwner(info, uid, gid) != nil {
			return ErrIncomplete
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0o755 {
				return ErrIncomplete
			}
			return nil
		}
		rel, e := filepath.Rel(release, path)
		if e != nil || !wanted[filepath.ToSlash(rel)] || !info.Mode().IsRegular() {
			return ErrIncomplete
		}
		seen[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil || len(seen) != len(wanted) {
		return ErrIncomplete
	}
	return nil
}

func readCompletedHostPreparation(ctx context.Context, stagePath string, stage verifiedStage, d nativeHostDeps, path string) (NativeHostPrepareResult, error) {
	var record nativeHostReceipt
	if err := readHostJSON(path, d.ownerUID, d.ownerGID, &record); err != nil {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	r := record.Result
	if r.StagePath != stagePath || r.ManifestSHA256 != stage.sha256 || r.ReleaseID != stage.manifest.ReleaseID || r.Status != "prepared_not_started" || r.InstallationID == "" {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	installedID, err := readNativeInstallationID(d)
	if err != nil || installedID != r.InstallationID {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	if err := verifyCompletedHostAccounts(d, record.Accounts); err != nil {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	if err := verifyInstalledRelease(ctx, d.path(filepath.Join(install.UnifiedReleasesDir, r.ReleaseID)), stage, d.ownerUID, d.ownerGID); err != nil {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	files, err := nativeHostFiles(stagePath, r.ReleaseID, record.Accounts)
	if err != nil || len(files) != len(record.Files) {
		return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
	}
	for _, file := range files {
		sum := sha256.Sum256(file.data)
		if record.Files[file.path] != hex.EncodeToString(sum[:]) {
			return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
		}
		info, e := os.Lstat(d.path(file.path))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != file.mode || artifactio.CheckFileOwner(info, d.ownerUID, d.ownerGID) != nil {
			return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
		}
		data, e := os.ReadFile(d.path(file.path))
		if e != nil || string(data) != string(file.data) {
			return NativeHostPrepareResult{}, ErrNativeHostPrepareUnknown
		}
	}
	return r, nil
}

func verifyCompletedHostAccounts(d nativeHostDeps, ids nativeHostIDs) error {
	if err := verifyNativeHostAccountFacts(d, ids); err != nil {
		return err
	}
	groups := map[string]int{install.AccountPeerIPC: ids.IPC, install.AccountCore: ids.CoreGID, install.AccountContainerRuntime: ids.ContainerGID, install.AccountSourceBuild: ids.SourceGID, install.AccountGateway: ids.GatewayGID, "acornfox-caddy": ids.CaddyGID, "acornfox-buildkit": ids.BuildkitGID}
	for name, want := range groups {
		got, found, err := d.lookupGroup(name)
		if err != nil || !found || got != want || got <= 0 {
			return ErrIncomplete
		}
	}
	users := map[string][2]int{install.AccountCore: {ids.CoreUID, ids.CoreGID}, install.AccountContainerRuntime: {ids.ContainerUID, ids.ContainerGID}, install.AccountSourceBuild: {ids.SourceUID, ids.SourceGID}, install.AccountGateway: {ids.GatewayUID, ids.GatewayGID}, "acornfox-caddy": {ids.CaddyUID, ids.CaddyGID}, "acornfox-buildkit": {ids.BuildkitUID, ids.BuildkitGID}}
	for name, want := range users {
		uid, gid, found, err := d.lookupUser(name)
		if err != nil || !found || uid != want[0] || gid != want[1] || uid <= 0 {
			return ErrIncomplete
		}
	}
	if d.production {
		if err := verifyRuntimeIPCAccounts(RuntimeIPCAccounts{CoreUID: ids.CoreUID, ContainerUID: ids.ContainerUID, SourceUID: ids.SourceUID, GatewayUID: ids.GatewayUID, IPCGID: ids.IPC}); err != nil {
			return err
		}
	}
	dirs := []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{install.UnifiedCoreDataDir, ids.CoreUID, ids.CoreGID, 0o700}, {install.UnifiedBackupDir, ids.CoreUID, ids.CoreGID, 0o700},
		{install.UnifiedContainerStateDir, ids.ContainerUID, ids.ContainerGID, 0o700}, {"/var/lib/acornfox/container/work", ids.ContainerUID, ids.ContainerGID, 0o700}, {"/var/lib/acornfox/container/images", ids.ContainerUID, ids.ContainerGID, 0o700},
		{install.UnifiedBuildStateDir, ids.SourceUID, ids.SourceGID, 0o700}, {install.UnifiedGatewayStateDir, ids.GatewayUID, ids.GatewayGID, 0o700},
		{"/var/lib/acornfox/edge", ids.CaddyUID, ids.CaddyGID, 0o700}, {"/var/lib/acornfox/edge/data", ids.CaddyUID, ids.CaddyGID, 0o700}, {"/var/lib/acornfox/buildkit", ids.BuildkitUID, ids.BuildkitGID, 0o700},
		{install.UnifiedRunRootDir, d.ownerUID, ids.IPC, 0o750}, {"/run/acornfox/trust", d.ownerUID, ids.IPC, 0o750}, {"/run/acornfox/helper", d.ownerUID, ids.IPC, 0o750},
		{"/run/acornfox/core-ipc", ids.CoreUID, ids.IPC, os.ModeSetgid | 0o750}, {"/run/acornfox/container-ipc", ids.ContainerUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/source-ipc", ids.SourceUID, ids.IPC, os.ModeSetgid | 0o750}, {"/run/acornfox/gateway-ipc", ids.GatewayUID, ids.IPC, os.ModeSetgid | 0o750},
		{"/run/acornfox/edge-admin", ids.CaddyUID, ids.IPC, os.ModeSetgid | 0o750},
		{filepath.Dir(hosthelper.DefaultHelperSocketPath), d.ownerUID, ids.IPC, 0o750}, {buildnetwork.RunRoot, d.ownerUID, ids.SourceGID, 0o750}, {"/run/acornfox-buildkit", ids.BuildkitUID, ids.BuildkitGID, 0o750},
	}
	for _, name := range []string{"uploads", "source", "work", "images", "logs"} {
		dirs = append(dirs, struct {
			path     string
			uid, gid int
			mode     os.FileMode
		}{filepath.Join(install.UnifiedBuildStateDir, name), ids.SourceUID, ids.SourceGID, 0o700})
	}
	for _, v := range dirs {
		info, err := os.Lstat(d.path(v.path))
		if strings.HasPrefix(v.path, "/run/") && os.IsNotExist(err) {
			continue
		} // tmpfs is deliberately republished before any later start
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != v.mode.Perm() || info.Mode()&os.ModeSetgid != v.mode&os.ModeSetgid || artifactio.CheckFileOwner(info, v.uid, v.gid) != nil {
			return ErrIncomplete
		}
	}
	return nil
}
