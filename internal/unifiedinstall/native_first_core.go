package unifiedinstall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
)

var ErrNativeFirstCoreUnknown = errors.New("Native first Core start outcome unknown; inspect current, credential and unit state before retry")

const nativeCoreSetupTokenSource = "/etc/acornfox/trust/acornfox-setup-token"

type nativeFirstCoreIntent struct {
	InstallationID string `json:"installation_id"`
	StagePath      string `json:"stage_path"`
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TokenSHA256    string `json:"token_sha256"`
}

type NativeFirstCoreResult struct {
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	CorePID        int32  `json:"core_pid"`
	CoreStartTime  string `json:"core_start_time"`
	Status         string `json:"status"`
}

type nativeCoreUnitState struct {
	Loaded, Active bool
	MainPID        int32
	Job            string
}
type nativeCoreChildFacts struct {
	PID, ParentPID                                                int32
	UID, GID                                                      uint32
	ExecutablePath, ExecutableSHA256, StartTime                   string
	ParentUID                                                     uint32
	ParentExecutablePath, ParentExecutableSHA256, ParentStartTime string
}

type nativeFirstCoreDeps struct {
	host         nativeHostDeps
	unitState    func(context.Context) (nativeCoreUnitState, error)
	daemonReload func(context.Context) error
	startCore    func(context.Context) error
	childFacts   func(int32) (nativeCoreChildFacts, error)
	ownsLoopback func(int32) error
	setupState   func(context.Context) error
}

func productionFirstCoreDeps() nativeFirstCoreDeps {
	return nativeFirstCoreDeps{host: productionNativeHostDeps(), unitState: readNativeCoreUnitState,
		daemonReload: func(ctx context.Context) error { return nativeFirstCoreSystemctl(ctx, "daemon-reload") },
		startCore:    func(ctx context.Context) error { return nativeFirstCoreSystemctl(ctx, "start", NativeCoreUnit) },
		childFacts:   readNativeCoreChildFacts, ownsLoopback: nativeCoreOwnsLoopbackListener, setupState: readNativeCoreSetupState}
}

// StartNativeFirstCore is only a Core-first new-install step. Other roles and
// dependency services are deliberately absent; their later binding is separate.
func StartNativeFirstCore(ctx context.Context, stagePath string) (NativeFirstCoreResult, error) {
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return NativeFirstCoreResult{}, ErrIncomplete
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return NativeFirstCoreResult{}, err
	}
	return startNativeFirstCoreAt(ctx, stagePath, pin, productionFirstCoreDeps())
}

func startNativeFirstCoreAt(ctx context.Context, stagePath string, pin acornfoxrelease.TrustedReleasePinV1, d nativeFirstCoreDeps) (NativeFirstCoreResult, error) {
	var zero NativeFirstCoreResult
	if ctx == nil || ctx.Err() != nil || d.unitState == nil || d.daemonReload == nil || d.startCore == nil || d.childFacts == nil || d.ownsLoopback == nil || d.setupState == nil || filepath.Dir(stagePath) != d.host.stageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return zero, ErrIncomplete
	}
	stage, err := verifyStagedRelease(ctx, stagePath, d.host.stageRoot, pin, d.host.ownerUID, d.host.ownerGID)
	if err != nil {
		return zero, err
	}
	if d.host.production {
		if err := verifyNativeHostPrepareSelf(stagePath, stage); err != nil {
			return zero, err
		}
	}
	key := "prepare-" + stage.sha256
	var hostReceipt nativeHostReceipt
	if err := readHostJSON(filepath.Join(d.host.stageRoot, nativeHostPrepareRecords, key+"-complete.json"), d.host.ownerUID, d.host.ownerGID, &hostReceipt); err != nil {
		return zero, err
	}
	hostResult, err := readCompletedHostPreparation(ctx, stagePath, stage, d.host, filepath.Join(d.host.stageRoot, nativeHostPrepareRecords, key+"-complete.json"))
	if err != nil {
		return zero, err
	}
	coreArtifact, err := componentArtifact(stage.manifest, stage.manifest.Components.Core.ArtifactID)
	if err != nil || coreArtifact.RelativePath != "bin/acornfox-core" {
		return zero, ErrIncomplete
	}
	hostArtifact, err := componentArtifact(stage.manifest, stage.manifest.Components.HostUpdate.ArtifactID)
	if err != nil || hostArtifact.RelativePath != "bin/acornfox-host-update" {
		return zero, ErrIncomplete
	}
	release := filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID)
	intentPath := filepath.Join(d.host.stageRoot, nativeHostPrepareRecords, "first-core-"+stage.sha256+"-intent.json")
	wantIntent := nativeFirstCoreIntent{InstallationID: hostResult.InstallationID, StagePath: stagePath, ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256}
	_, intentErr := os.Lstat(intentPath)
	currentPath, tokenPath := d.host.path(install.UnifiedCurrentSymlink), d.host.path(nativeCoreSetupTokenSource)
	_, currentErr := os.Lstat(currentPath)
	_, tokenErr := os.Lstat(tokenPath)
	if currentErr == nil || tokenErr == nil || intentErr == nil {
		if intentErr != nil {
			return zero, ErrIncomplete
		} // an unreceipted current/token pair is foreign
		var actual nativeFirstCoreIntent
		if err := readHostJSON(intentPath, d.host.ownerUID, d.host.ownerGID, &actual); err != nil || actual.InstallationID != wantIntent.InstallationID || actual.StagePath != wantIntent.StagePath || actual.ReleaseID != wantIntent.ReleaseID || actual.ManifestSHA256 != wantIntent.ManifestSHA256 || len(actual.TokenSHA256) != 64 {
			return zero, ErrNativeFirstCoreUnknown
		}
		if currentErr != nil || tokenErr != nil {
			return zero, ErrNativeFirstCoreUnknown
		}
		return readExistingNativeFirstCore(ctx, d, stage, hostReceipt, coreArtifact.SHA256, hostArtifact.SHA256, actual.TokenSHA256, false)
	}
	if !os.IsNotExist(currentErr) || !os.IsNotExist(tokenErr) || !os.IsNotExist(intentErr) {
		return zero, ErrNativeFirstCoreUnknown
	}
	db := d.host.path(filepath.Join(install.UnifiedCoreDataDir, install.UnifiedDefaultDBName))
	for _, path := range []string{db, db + "-wal", db + "-shm"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return zero, ErrIncomplete
		}
	}
	state, err := d.unitState(ctx)
	if err != nil || state.Active || state.MainPID != 0 || !nativeNoUnitJob(state.Job) {
		return zero, ErrIncomplete
	}
	token, err := acornfoxsetup.GenerateSetupToken(rand.Reader)
	if err != nil {
		return zero, err
	}
	defer clear(token)
	tokenDigest := sha256.Sum256(token)
	wantIntent.TokenSHA256 = hex.EncodeToString(tokenDigest[:])
	rawIntent, err := json.Marshal(wantIntent)
	if err != nil {
		return zero, err
	}
	if err := publishHostFile(intentPath, rawIntent, 0o600, d.host.ownerUID, d.host.ownerGID); err != nil {
		return zero, errors.Join(ErrNativeFirstCoreUnknown, err)
	}
	unknown := func(e error) (NativeFirstCoreResult, error) { return zero, errors.Join(ErrNativeFirstCoreUnknown, e) }
	if d.host.production {
		ids := hostReceipt.Accounts
		if err := PrepareUnifiedRuntimeIPCParents(RuntimeIPCAccounts{CoreUID: ids.CoreUID, ContainerUID: ids.ContainerUID, SourceUID: ids.SourceUID, GatewayUID: ids.GatewayUID, IPCGID: ids.IPC}); err != nil {
			return unknown(err)
		}
	}
	if err := publishHostFile(tokenPath, token, 0o600, d.host.ownerUID, d.host.ownerGID); err != nil {
		return unknown(err)
	}
	if err := publishNativeFirstCurrent(currentPath, d.host.path(release), d.host.ownerUID, d.host.ownerGID, d.host.production); err != nil {
		return unknown(err)
	}
	if err := d.daemonReload(ctx); err != nil {
		return unknown(err)
	}
	state, err = d.unitState(ctx)
	if err != nil || !state.Loaded || state.Active || state.MainPID != 0 || !nativeNoUnitJob(state.Job) {
		return unknown(ErrIncomplete)
	}
	if err := d.startCore(ctx); err != nil {
		return unknown(err)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := readExistingNativeFirstCore(ctx, d, stage, hostReceipt, coreArtifact.SHA256, hostArtifact.SHA256, wantIntent.TokenSHA256, true)
		if err == nil {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return unknown(ctx.Err())
		case <-deadline.C:
			return unknown(ErrIncomplete)
		case <-ticker.C:
		}
	}
}

func publishNativeFirstCurrent(path, target string, uid, gid int, production bool) error {
	if !filepath.IsAbs(path) || !filepath.IsAbs(target) || production && verifyRootRunAncestor(path) != nil {
		return ErrIncomplete
	}
	if err := os.Symlink(target, path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(info, uid, gid) != nil {
		return ErrNativeFirstCoreUnknown
	}
	link, err := os.Readlink(path)
	if err != nil || link != target {
		return ErrNativeFirstCoreUnknown
	}
	if err := artifactio.SyncDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrNativeFirstCoreUnknown, err)
	}
	return nil
}

func readExistingNativeFirstCore(ctx context.Context, d nativeFirstCoreDeps, stage verifiedStage, host nativeHostReceipt, coreSHA, hostSHA, tokenSHA string, requireSetup bool) (NativeFirstCoreResult, error) {
	var zero NativeFirstCoreResult
	currentPath := d.host.path(install.UnifiedCurrentSymlink)
	info, err := os.Lstat(currentPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 || artifactio.CheckFileOwner(info, d.host.ownerUID, d.host.ownerGID) != nil {
		return zero, ErrNativeFirstCoreUnknown
	}
	link, err := os.Readlink(currentPath)
	if err != nil || link != d.host.path(filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID)) {
		return zero, ErrNativeFirstCoreUnknown
	}
	tokenPath := d.host.path(nativeCoreSetupTokenSource)
	before, err := os.Lstat(tokenPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || artifactio.CheckFileOwner(before, d.host.ownerUID, d.host.ownerGID) != nil {
		return zero, ErrNativeFirstCoreUnknown
	}
	file, err := os.OpenFile(tokenPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, ErrNativeFirstCoreUnknown
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return zero, ErrNativeFirstCoreUnknown
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 45))
	closeErr := file.Close()
	sum := sha256.Sum256(token)
	valid := readErr == nil && closeErr == nil && acornfoxsetup.ValidateSetupToken(token) == nil && hex.EncodeToString(sum[:]) == tokenSHA
	clear(token)
	if !valid {
		return zero, ErrNativeFirstCoreUnknown
	}
	state, err := d.unitState(ctx)
	if err != nil || !state.Loaded || !state.Active || state.MainPID <= 0 {
		return NativeFirstCoreResult{}, ErrNativeFirstCoreUnknown
	}
	child, err := d.childFacts(state.MainPID)
	if err != nil || validateNativeCoreChildFacts(child, state.MainPID, uint32(host.Accounts.CoreUID), uint32(host.Accounts.CoreGID), d.host.path(filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, "bin/acornfox-core")), coreSHA, d.host.path(filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, "bin/acornfox-host-update")), hostSHA) != nil {
		return zero, ErrNativeFirstCoreUnknown
	}
	status := "core_running"
	if requireSetup {
		if err := d.ownsLoopback(child.PID); err != nil {
			return zero, ErrNativeFirstCoreUnknown
		}
		if err := d.setupState(ctx); err != nil {
			return zero, ErrNativeFirstCoreUnknown
		}
		again, err := d.childFacts(state.MainPID)
		if err != nil || again.PID != child.PID || again.StartTime != child.StartTime || again.ExecutableSHA256 != child.ExecutableSHA256 || d.ownsLoopback(child.PID) != nil {
			return zero, ErrNativeFirstCoreUnknown
		}
		status = "core_started_setup_required"
	}
	return NativeFirstCoreResult{ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, CorePID: child.PID, CoreStartTime: child.StartTime, Status: status}, nil
}

func validateNativeCoreChildFacts(child nativeCoreChildFacts, launcherPID int32, uid, gid uint32, exePath, exeSHA, parentPath, parentSHA string) error {
	if launcherPID <= 0 || child.PID <= 0 || child.PID == launcherPID || child.ParentPID != launcherPID || child.UID != uid || child.GID != gid || child.ExecutablePath != exePath || child.ExecutableSHA256 != exeSHA || child.StartTime == "" || child.ParentUID != 0 || child.ParentExecutablePath != parentPath || child.ParentExecutableSHA256 != parentSHA || child.ParentStartTime == "" {
		return ErrIncomplete
	}
	return nil
}

func nativeNoUnitJob(job string) bool { return job == "" || job == "0" }

func nativeFirstCoreSystemctl(ctx context.Context, args ...string) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/systemctl", args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	return command.Run()
}

func readNativeCoreUnitState(ctx context.Context) (nativeCoreUnitState, error) {
	var out nativeCoreUnitState
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", NativeCoreUnit, "--property=Id,LoadState,ActiveState,MainPID,Job")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := command.Output()
	if err != nil || len(raw) > 2048 {
		return out, ErrIncomplete
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[key] != "" {
			return out, ErrIncomplete
		}
		values[key] = value
	}
	if len(values) != 5 || values["Id"] != NativeCoreUnit {
		return out, ErrIncomplete
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil {
		return out, ErrIncomplete
	}
	out.Loaded = values["LoadState"] == "loaded"
	out.Active = values["ActiveState"] == "active"
	out.MainPID = int32(pid)
	out.Job = values["Job"]
	return out, nil
}

func readNativeCoreChildFacts(parent int32) (nativeCoreChildFacts, error) {
	var out nativeCoreChildFacts
	if parent <= 0 {
		return out, ErrIncomplete
	}
	parentAtt, err := localpeer.AttestLinuxProcess(parent)
	if err != nil || parentAtt.UID != 0 {
		return out, ErrIncomplete
	}
	path := filepath.Join("/proc", strconv.FormatInt(int64(parent), 10), "task", strconv.FormatInt(int64(parent), 10), "children")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 128 {
		return out, ErrIncomplete
	}
	children := strings.Fields(string(raw))
	if len(children) != 1 {
		return out, ErrIncomplete
	}
	pid, err := strconv.ParseInt(children[0], 10, 32)
	if err != nil || pid <= 0 {
		return out, ErrIncomplete
	}
	att, err := localpeer.AttestLinuxProcess(int32(pid))
	if err != nil {
		return out, err
	}
	status, err := os.ReadFile(filepath.Join("/proc", children[0], "status"))
	if err != nil || len(status) > 64<<10 {
		return out, ErrIncomplete
	}
	parentSeen, gidSeen := false, false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "PPid:\t") {
			got, e := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t")), 10, 32)
			if e != nil || got != int64(parent) {
				return out, ErrIncomplete
			}
			parentSeen = true
		}
		if strings.HasPrefix(line, "Gid:\t") {
			parts := strings.Fields(strings.TrimPrefix(line, "Gid:\t"))
			if len(parts) != 4 {
				return out, ErrIncomplete
			}
			value, e := strconv.ParseUint(parts[0], 10, 32)
			if e != nil {
				return out, ErrIncomplete
			}
			out.GID = uint32(value)
			gidSeen = true
		}
	}
	if !parentSeen || !gidSeen {
		return out, ErrIncomplete
	}
	out.PID, out.ParentPID, out.UID, out.ExecutablePath, out.ExecutableSHA256, out.StartTime = att.PID, parent, att.UID, att.ExecutablePath, att.ExecutableSHA256, att.StartTime
	out.ParentUID, out.ParentExecutablePath, out.ParentExecutableSHA256, out.ParentStartTime = parentAtt.UID, parentAtt.ExecutablePath, parentAtt.ExecutableSHA256, parentAtt.StartTime
	return out, nil
}

// A loopback response is only evidence for the attested Core child when that
// child's own FD table holds the exact listening socket inode.
func nativeCoreOwnsLoopbackListener(pid int32) error {
	if pid <= 0 {
		return ErrIncomplete
	}
	proc := filepath.Join("/proc", strconv.FormatInt(int64(pid), 10))
	raw, err := os.ReadFile(filepath.Join(proc, "net/tcp"))
	if err != nil || len(raw) > 1<<20 {
		return ErrIncomplete
	}
	const loopback = "0100007F:1F90" // 127.0.0.1:8080 in /proc/net/tcp
	inode := ""
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[1] != loopback || fields[3] != "0A" {
			continue
		}
		if inode != "" || fields[9] == "0" {
			return ErrIncomplete
		}
		inode = fields[9]
	}
	if inode == "" {
		return ErrIncomplete
	}
	entries, err := os.ReadDir(filepath.Join(proc, "fd"))
	if err != nil || len(entries) > 8192 {
		return ErrIncomplete
	}
	want := "socket:[" + inode + "]"
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(proc, "fd", entry.Name()))
		if err == nil && link == want {
			return nil
		}
	}
	return ErrIncomplete
}

func readNativeCoreSetupState(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "http://127.0.0.1:8080/api/v1/acornfox/setup", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrIncomplete
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return err
	}
	var state struct {
		State string `json:"state"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.State != "uninitialized" {
		return ErrIncomplete
	}
	return nil
}
