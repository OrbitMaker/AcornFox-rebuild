package unifiedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
	"golang.org/x/sys/unix"
)

const nativeDockerSocket = "/var/run/docker.sock"
const nativeDockerGroup = "docker"
const nativeDockerUnitPath = "/etc/systemd/system/docker.service"
const nativeDockerConfigPath = "/etc/acornfox/docker/daemon.json"
const nativeDockerDataRoot = "/var/lib/acornfox/docker"
const nativeDockerExecRoot = "/run/acornfox-docker"

var ErrNativeDockerPrepareUnknown = errors.New("Native Docker preparation outcome unknown; inspect fixed receipt and actual daemon before retry")

type NativeDockerPrepareResult struct {
	Ownership       string `json:"ownership"`
	Status          string `json:"status"`
	ReleaseID       string `json:"release_id"`
	ManifestSHA256  string `json:"manifest_sha256"`
	Version         string `json:"version"`
	DockerID        string `json:"docker_id"`
	SocketPath      string `json:"socket_path"`
	DockerGID       int    `json:"docker_gid"`
	DaemonPID       int32  `json:"daemon_pid"`
	DaemonStartTime string `json:"daemon_start_time"`
}

type nativeDockerReceipt struct {
	Result                                                             NativeDockerPrepareResult
	InstallationID, StagePath, ArchiveSHA256, UnitSHA256, ConfigSHA256 string
	Members                                                            map[string]string
	SocketDevice, SocketInode                                          uint64
	APIPeerPID                                                         int32
	APIPeerUID                                                         uint32
	DaemonExecutablePath, DaemonExecutableSHA256, DataRoot, UnitPath   string
}

type nativeDockerIntent struct{ InstallationID, StagePath, ReleaseID, ManifestSHA256, ArchiveSHA256 string }

type nativeDockerObservation struct {
	Version, DockerID, DataRoot, SocketPath, UnitPath, UnitSHA256, ConfigSHA256 string
	GroupGID                                                                    int
	SocketDevice, SocketInode                                                   uint64
	APIPeerPID                                                                  int32
	APIPeerUID                                                                  uint32
	Daemon                                                                      localpeer.ProcessAttestation
}

type nativeDockerDeps struct {
	host        nativeHostDeps
	observe     func(context.Context) (nativeDockerObservation, bool, error)
	createGroup func(context.Context) error
	reload      func(context.Context) error
	start       func(context.Context) error
}

func productionNativeDockerDeps() nativeDockerDeps {
	return nativeDockerDeps{host: productionNativeHostDeps(), observe: observeNativeDockerHost,
		createGroup: func(ctx context.Context) error {
			return exec.CommandContext(ctx, "/usr/sbin/groupadd", "--system", nativeDockerGroup).Run()
		},
		reload: func(ctx context.Context) error { return nativeDockerSystemctl(ctx, "daemon-reload") },
		start:  func(ctx context.Context) error { return nativeDockerSystemctl(ctx, "start", "docker.service") }}
}

func PrepareNativeDocker(ctx context.Context, stagePath string) (NativeDockerPrepareResult, error) {
	if ctx == nil || os.Geteuid() != 0 || os.Getegid() != 0 || filepath.Dir(stagePath) != UnifiedPrivateStageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return NativeDockerPrepareResult{}, ErrIncomplete
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return NativeDockerPrepareResult{}, err
	}
	return prepareNativeDockerAt(ctx, stagePath, pin, productionNativeDockerDeps())
}

func prepareNativeDockerAt(ctx context.Context, stagePath string, pin acornfoxrelease.TrustedReleasePinV1, d nativeDockerDeps) (NativeDockerPrepareResult, error) {
	var zero NativeDockerPrepareResult
	if ctx == nil || ctx.Err() != nil || d.observe == nil || d.createGroup == nil || d.reload == nil || d.start == nil || filepath.Dir(stagePath) != d.host.stageRoot || !nativeReadyName.MatchString(filepath.Base(stagePath)) {
		return zero, ErrIncomplete
	}
	stage, err := verifyStagedRelease(ctx, stagePath, d.host.stageRoot, pin, d.host.ownerUID, d.host.ownerGID)
	if err != nil {
		return zero, err
	}
	if d.host.production && verifyNativeHostPrepareSelf(stagePath, stage) != nil {
		return zero, ErrIncomplete
	}
	key := "prepare-" + stage.sha256
	completeHost := filepath.Join(d.host.stageRoot, nativeHostPrepareRecords, key+"-complete.json")
	hostResult, err := readCompletedHostPreparation(ctx, stagePath, stage, d.host, completeHost)
	if err != nil {
		return zero, err
	}
	policy, err := nativeDockerPolicy(stage.manifest)
	if err != nil {
		return zero, err
	}
	if err := verifyInstalledRelease(ctx, d.host.path(filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID)), stage, d.host.ownerUID, d.host.ownerGID); err != nil {
		return zero, err
	}
	members, err := nativeDockerMemberDigests(stage.manifest, policy)
	if err != nil {
		return zero, err
	}
	unitDir := filepath.Join(d.host.stageRoot, nativeHostPrepareRecords)
	receiptPath := filepath.Join(unitDir, "docker-"+stage.sha256+"-complete.json")
	intentPath := filepath.Join(unitDir, "docker-"+stage.sha256+"-intent.json")
	if _, err := os.Lstat(receiptPath); err == nil {
		return replayNativeDocker(ctx, d, stage, hostResult, policy, members, receiptPath)
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	if _, err := os.Lstat(intentPath); err == nil {
		return zero, ErrNativeDockerPrepareUnknown
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	observed, absent, err := d.observe(ctx)
	if err != nil {
		return zero, err
	}
	if !absent {
		if !supportedVersion(observed.Version, policy.SupportedCondition.MinVersion) || observed.DockerID == "" || observed.SocketPath != nativeDockerSocket || observed.UnitPath == nativeDockerUnitPath || observed.DataRoot == nativeDockerDataRoot {
			return zero, ErrIncompatible
		}
		for _, path := range []string{nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot} {
			if _, e := os.Lstat(d.host.path(path)); !os.IsNotExist(e) {
				return zero, ErrIncompatible
			}
		}
		result := nativeDockerResult(stage, "external", observed)
		receipt := nativeDockerReceipt{Result: result, InstallationID: hostResult.InstallationID, StagePath: stagePath, ArchiveSHA256: policy.PinnedProvisioning.SourceSHA256, Members: members, SocketDevice: observed.SocketDevice, SocketInode: observed.SocketInode, APIPeerPID: observed.APIPeerPID, APIPeerUID: observed.APIPeerUID, DaemonExecutablePath: observed.Daemon.ExecutablePath, DaemonExecutableSHA256: observed.Daemon.ExecutableSHA256, DataRoot: observed.DataRoot, UnitPath: observed.UnitPath, UnitSHA256: observed.UnitSHA256, ConfigSHA256: observed.ConfigSHA256}
		if err := publishNativeDockerRecord(d.host, receiptPath, receipt); err != nil {
			return zero, errors.Join(ErrNativeDockerPrepareUnknown, err)
		}
		return replayNativeDocker(ctx, d, stage, hostResult, policy, members, receiptPath)
	}
	// The observer proves all standard foreign entry points absent, not merely
	// the Unix socket. Only this branch may create the standard docker group/unit.
	for _, path := range []string{nativeDockerUnitPath, nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot, nativeDockerSocket} {
		if _, err := os.Lstat(d.host.path(path)); !os.IsNotExist(err) {
			return zero, ErrIncompatible
		}
	}
	intent := nativeDockerIntent{hostResult.InstallationID, stagePath, stage.manifest.ReleaseID, stage.sha256, policy.PinnedProvisioning.SourceSHA256}
	if err := publishNativeDockerRecord(d.host, intentPath, intent); err != nil {
		return zero, errors.Join(ErrNativeDockerPrepareUnknown, err)
	}
	unknown := func(e error) (NativeDockerPrepareResult, error) {
		return zero, errors.Join(ErrNativeDockerPrepareUnknown, e)
	}
	if err := d.createGroup(ctx); err != nil {
		return unknown(err)
	}
	groupGID, found, err := d.host.lookupGroup(nativeDockerGroup)
	if err != nil {
		return unknown(err)
	}
	if !found || groupGID <= 0 {
		return unknown(ErrIncomplete)
	}
	for _, path := range []string{d.host.path("/etc/acornfox/docker"), d.host.path(nativeDockerDataRoot), d.host.path(nativeDockerExecRoot)} {
		mode := os.FileMode(0o700)
		if strings.HasSuffix(path, "/etc/acornfox/docker") {
			mode = 0o755
		}
		if err := ensureNativeDirectory(path, d.host.ownerUID, d.host.ownerGID, mode, false); err != nil {
			return unknown(err)
		}
	}
	config := []byte("{}\n")
	if err := publishHostFile(d.host.path(nativeDockerConfigPath), config, 0o644, d.host.ownerUID, d.host.ownerGID); err != nil {
		return unknown(err)
	}
	unit := nativeManagedDockerUnit(stage.manifest.ReleaseID)
	if err := publishHostFile(d.host.path(nativeDockerUnitPath), unit, 0o644, d.host.ownerUID, d.host.ownerGID); err != nil {
		return unknown(err)
	}
	if err := d.reload(ctx); err != nil {
		return unknown(err)
	}
	if err := d.start(ctx); err != nil {
		return unknown(err)
	}
	var ready nativeDockerObservation
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		value, missing, e := d.observe(ctx)
		if e == nil && !missing && nativeManagedDockerMatches(value, stage, policy, groupGID, unit, config) {
			ready = value
			break
		}
		select {
		case <-ctx.Done():
			return unknown(ctx.Err())
		case <-deadline.C:
			return unknown(ErrIncomplete)
		case <-ticker.C:
		}
	}
	result := nativeDockerResult(stage, "managed", ready)
	receipt := nativeDockerReceipt{Result: result, InstallationID: hostResult.InstallationID, StagePath: stagePath, ArchiveSHA256: policy.PinnedProvisioning.SourceSHA256, Members: members, SocketDevice: ready.SocketDevice, SocketInode: ready.SocketInode, APIPeerPID: ready.APIPeerPID, APIPeerUID: ready.APIPeerUID, DaemonExecutablePath: ready.Daemon.ExecutablePath, DaemonExecutableSHA256: ready.Daemon.ExecutableSHA256, DataRoot: ready.DataRoot, UnitPath: ready.UnitPath, UnitSHA256: ready.UnitSHA256, ConfigSHA256: ready.ConfigSHA256}
	if err := publishNativeDockerRecord(d.host, receiptPath, receipt); err != nil {
		return unknown(err)
	}
	return replayNativeDocker(ctx, d, stage, hostResult, policy, members, receiptPath)
}

func nativeDockerPolicy(manifest acornfoxrelease.UnifiedReleaseManifestV1) (acornfoxrelease.UnifiedDependencyPolicyV1, error) {
	for _, dep := range manifest.Dependencies {
		if dep.Name == acornfoxrelease.DependencyDocker {
			return dep, nil
		}
	}
	return acornfoxrelease.UnifiedDependencyPolicyV1{}, ErrIncomplete
}

func nativeDockerMemberDigests(manifest acornfoxrelease.UnifiedReleaseManifestV1, policy acornfoxrelease.UnifiedDependencyPolicyV1) (map[string]string, error) {
	if len(policy.RuntimeArtifactIDs) != 6 {
		return nil, ErrIncomplete
	}
	members := map[string]string{}
	for _, id := range policy.RuntimeArtifactIDs {
		member, err := componentArtifact(manifest, id)
		if err != nil || !member.Executable || !strings.HasPrefix(member.RelativePath, "embedded/bin/") || members[member.RelativePath] != "" {
			return nil, ErrIncomplete
		}
		members[member.RelativePath] = member.SHA256
	}
	for _, name := range []string{"docker", "dockerd", "containerd", "containerd-shim-runc-v2", "runc", "docker-proxy"} {
		if members["embedded/bin/"+name] == "" {
			return nil, ErrIncomplete
		}
	}
	return members, nil
}

func nativeDockerArtifactAtPath(manifest acornfoxrelease.UnifiedReleaseManifestV1, path string) (acornfoxrelease.UnifiedArtifactV1, error) {
	var found acornfoxrelease.UnifiedArtifactV1
	for _, artifact := range manifest.Artifacts {
		if artifact.RelativePath != path {
			continue
		}
		if found.ID != "" {
			return found, ErrIncomplete
		}
		found = artifact
	}
	if found.ID == "" {
		return found, ErrIncomplete
	}
	return found, nil
}

func nativeManagedDockerUnit(releaseID string) []byte {
	release := filepath.Join(install.UnifiedReleasesDir, releaseID)
	return []byte(fmt.Sprintf(`[Unit]
Description=AcornFox-owned Docker Engine
After=network-online.target

[Service]
Type=notify
User=root
Group=root
Environment=PATH=%s/embedded/bin:/usr/bin:/bin
ExecStart=%s/embedded/bin/dockerd --config-file /etc/acornfox/docker/daemon.json -H unix:///var/run/docker.sock --data-root /var/lib/acornfox/docker --exec-root /run/acornfox-docker --pidfile /run/acornfox-docker/dockerd.pid --group docker --userland-proxy-path %s/embedded/bin/docker-proxy
Restart=no
Delegate=yes
UMask=0077
`, release, release, release))
}

func nativeManagedDockerMatches(o nativeDockerObservation, stage verifiedStage, policy acornfoxrelease.UnifiedDependencyPolicyV1, gid int, unit, config []byte) bool {
	dockerd := filepath.Join(install.UnifiedReleasesDir, stage.manifest.ReleaseID, "embedded/bin/dockerd")
	artifact, err := nativeDockerArtifactAtPath(stage.manifest, "embedded/bin/dockerd")
	u := sha256.Sum256(unit)
	c := sha256.Sum256(config)
	return err == nil && o.DockerID != "" && o.SocketPath == nativeDockerSocket && o.GroupGID == gid && o.DataRoot == nativeDockerDataRoot && o.UnitPath == nativeDockerUnitPath && o.UnitSHA256 == hex.EncodeToString(u[:]) && o.ConfigSHA256 == hex.EncodeToString(c[:]) && o.Daemon.UID == 0 && o.Daemon.ExecutablePath == dockerd && o.Daemon.ExecutableSHA256 == artifact.SHA256 && supportedVersion(o.Version, policy.SupportedCondition.MinVersion)
}

func nativeDockerResult(stage verifiedStage, ownership string, o nativeDockerObservation) NativeDockerPrepareResult {
	return NativeDockerPrepareResult{Ownership: ownership, Status: "docker_ready", ReleaseID: stage.manifest.ReleaseID, ManifestSHA256: stage.sha256, Version: o.Version, DockerID: o.DockerID, SocketPath: o.SocketPath, DockerGID: o.GroupGID, DaemonPID: o.Daemon.PID, DaemonStartTime: o.Daemon.StartTime}
}

func publishNativeDockerRecord(d nativeHostDeps, path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return publishHostFile(path, raw, 0o600, d.ownerUID, d.ownerGID)
}

func replayNativeDocker(ctx context.Context, d nativeDockerDeps, stage verifiedStage, host NativeHostPrepareResult, policy acornfoxrelease.UnifiedDependencyPolicyV1, members map[string]string, path string) (NativeDockerPrepareResult, error) {
	var receipt nativeDockerReceipt
	if err := readHostJSON(path, d.host.ownerUID, d.host.ownerGID, &receipt); err != nil {
		return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
	}
	if receipt.InstallationID != host.InstallationID || receipt.StagePath != host.StagePath || receipt.ArchiveSHA256 != policy.PinnedProvisioning.SourceSHA256 || receipt.Result.ReleaseID != stage.manifest.ReleaseID || receipt.Result.ManifestSHA256 != stage.sha256 || len(receipt.Members) != len(members) {
		return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
	}
	for name, sha := range members {
		if receipt.Members[name] != sha {
			return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
		}
	}
	o, missing, err := d.observe(ctx)
	if err != nil || missing || o.SocketDevice != receipt.SocketDevice || o.SocketInode != receipt.SocketInode || o.APIPeerPID != receipt.APIPeerPID || o.APIPeerUID != receipt.APIPeerUID || o.Daemon.PID != receipt.Result.DaemonPID || o.Daemon.StartTime != receipt.Result.DaemonStartTime || o.Daemon.ExecutablePath != receipt.DaemonExecutablePath || o.Daemon.ExecutableSHA256 != receipt.DaemonExecutableSHA256 || o.UnitPath != receipt.UnitPath || o.UnitSHA256 != receipt.UnitSHA256 || o.ConfigSHA256 != receipt.ConfigSHA256 || o.GroupGID != receipt.Result.DockerGID || o.Version != receipt.Result.Version || o.DockerID != receipt.Result.DockerID || o.DataRoot != receipt.DataRoot {
		return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
	}
	if receipt.Result.Ownership == "managed" {
		if !nativeManagedDockerMatches(o, stage, policy, o.GroupGID, nativeManagedDockerUnit(stage.manifest.ReleaseID), []byte("{}\n")) {
			return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
		}
	} else if receipt.Result.Ownership != "external" || !supportedVersion(o.Version, policy.SupportedCondition.MinVersion) || o.UnitPath == nativeDockerUnitPath || o.DataRoot == nativeDockerDataRoot {
		return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
	} else {
		for _, owned := range []string{nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot} {
			if _, e := os.Lstat(d.host.path(owned)); !os.IsNotExist(e) {
				return NativeDockerPrepareResult{}, ErrNativeDockerPrepareUnknown
			}
		}
	}
	return receipt.Result, nil
}

func nativeDockerSystemctl(ctx context.Context, args ...string) error {
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	return cmd.Run()
}

// observeNativeDockerHost is read-only. A partial installation is an error,
// never evidence that it is safe to create standard Docker names.
func observeNativeDockerHost(ctx context.Context) (nativeDockerObservation, bool, error) {
	var zero nativeDockerObservation
	paths := []string{nativeDockerSocket, "/var/run/docker.pid", "/usr/bin/docker", "/usr/bin/dockerd", "/usr/local/bin/docker", "/usr/local/bin/dockerd", "/etc/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service", "/lib/systemd/system/docker.service", "/etc/systemd/system/docker.socket", "/usr/lib/systemd/system/docker.socket", "/etc/systemd/system/docker.service.d", "/etc/docker", "/var/lib/docker", "/run/docker", "/run/containerd/containerd.sock", nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot}
	present := false
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			present = true
		} else if !os.IsNotExist(err) {
			return zero, false, ErrIncompatible
		}
	}
	group, groupErr := user.LookupGroup(nativeDockerGroup)
	if groupErr == nil {
		present = true
	} else if _, ok := groupErr.(user.UnknownGroupError); !ok {
		return zero, false, ErrIncompatible
	}
	if !present {
		if !nativeDockerUnitsAbsent(ctx) {
			return zero, false, ErrIncompatible
		}
		return zero, true, nil
	}
	if groupErr != nil {
		return zero, false, ErrIncompatible
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid <= 0 {
		return zero, false, ErrIncompatible
	}
	info, err := os.Lstat(nativeDockerSocket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || artifactio.CheckFileOwner(info, 0, gid) != nil {
		return zero, false, ErrIncompatible
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return zero, false, ErrIncompatible
	}
	unitPath, pid, err := nativeDockerSystemdState(ctx)
	if err != nil {
		return zero, false, ErrIncompatible
	}
	unitSHA, err := nativeDockerProtectedHash(unitPath)
	if err != nil {
		return zero, false, ErrIncompatible
	}
	configSHA := ""
	for _, path := range []string{nativeDockerConfigPath, "/etc/docker/daemon.json"} {
		if _, err := os.Lstat(path); err == nil {
			configSHA, err = nativeDockerProtectedHash(path)
			if err != nil {
				return zero, false, ErrIncompatible
			}
			break
		} else if !os.IsNotExist(err) {
			return zero, false, ErrIncompatible
		}
	}
	dropInsSHA, err := nativeDockerDropInsHash(ctx)
	if err != nil {
		return zero, false, ErrIncompatible
	}
	if dropInsSHA != "" {
		sum := sha256.Sum256([]byte(configSHA + "\n" + dropInsSHA))
		configSHA = hex.EncodeToString(sum[:])
	}
	att, err := localpeer.AttestLinuxProcess(pid)
	if err != nil || att.UID != 0 || att.PID != pid || verifyNativeCoreBinary(att.ExecutablePath, att.ExecutableSHA256) != nil {
		return zero, false, ErrIncompatible
	}
	// An inactive socket-activated unit is not probed: connecting could start it.
	version, dockerID, root, peerPID, peerUID, err := nativeDockerAPI(ctx, nativeDockerSocket)
	if err != nil || peerUID != 0 || peerPID <= 0 {
		return zero, false, ErrIncompatible
	}
	if peerPID != pid && (peerPID != 1 || !nativeDockerSocketUnitActive(ctx)) {
		return zero, false, ErrIncompatible
	}
	unitAgain, pidAgain, err := nativeDockerSystemdState(ctx)
	if err != nil || unitAgain != unitPath || pidAgain != pid {
		return zero, false, ErrIncompatible
	}
	attAgain, err := localpeer.AttestLinuxProcess(pidAgain)
	if err != nil || attAgain.StartTime != att.StartTime || attAgain.ExecutableSHA256 != att.ExecutableSHA256 {
		return zero, false, ErrIncompatible
	}
	return nativeDockerObservation{Version: version, DockerID: dockerID, DataRoot: root, SocketPath: nativeDockerSocket, UnitPath: unitPath, UnitSHA256: unitSHA, ConfigSHA256: configSHA, GroupGID: gid, SocketDevice: uint64(stat.Dev), SocketInode: stat.Ino, APIPeerPID: peerPID, APIPeerUID: peerUID, Daemon: att}, false, nil
}

func nativeDockerDropInsHash(ctx context.Context) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "docker.service", "--property=DropInPaths")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 2048 || !strings.HasPrefix(string(raw), "DropInPaths=") {
		return "", ErrIncomplete
	}
	paths := strings.Fields(strings.TrimSpace(strings.TrimPrefix(string(raw), "DropInPaths=")))
	if len(paths) > 8 {
		return "", ErrIncomplete
	}
	if len(paths) == 0 {
		return "", nil
	}
	h := sha256.New()
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] || !strings.HasPrefix(path, "/etc/systemd/system/docker.service.d/") {
			return "", ErrIncomplete
		}
		seen[path] = true
		digest, err := nativeDockerProtectedHash(path)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(h, path+"\n"+digest+"\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nativeDockerUnitsAbsent(ctx context.Context) bool {
	for _, unit := range []string{"docker.service", "docker.socket", "containerd.service"} {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		properties := "--property=Id,LoadState,ActiveState,MainPID,Job"
		if unit == "docker.socket" {
			// MainPID is a service property. A missing socket unit does not emit it.
			properties = "--property=Id,LoadState,ActiveState,Job"
		}
		cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", unit, properties)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		raw, err := cmd.Output()
		cancel()
		if err != nil || !nativeDockerAbsentUnitReadback(unit, raw) {
			return false
		}
	}
	return true
}

func nativeDockerAbsentUnitReadback(unit string, raw []byte) bool {
	if len(raw) == 0 || len(raw) > 1024 || raw[len(raw)-1] != '\n' {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := 5
	if unit == "docker.socket" {
		want = 4
	} else if unit != "docker.service" && unit != "containerd.service" {
		return false
	}
	if len(lines) != want {
		return false
	}
	values := make(map[string]string, want)
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return false
		}
		if _, duplicate := values[key]; duplicate {
			return false
		}
		values[key] = value
	}
	for _, key := range []string{"Id", "LoadState", "ActiveState", "Job"} {
		if _, present := values[key]; !present {
			return false
		}
	}
	if values["Id"] != unit || values["LoadState"] != "not-found" || values["ActiveState"] != "inactive" ||
		values["Job"] != "" && values["Job"] != "0" {
		return false
	}
	if unit != "docker.socket" && values["MainPID"] != "0" {
		return false
	}
	return true
}

func nativeDockerSocketUnitActive(ctx context.Context) bool {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "docker.socket", "--property=Id,LoadState,ActiveState")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 1024 {
		return false
	}
	return strings.Contains(string(raw), "Id=docker.socket\n") && strings.Contains(string(raw), "LoadState=loaded\n") && strings.Contains(string(raw), "ActiveState=active\n")
}

func nativeDockerProtectedHash(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrIncomplete
	}
	if path == "/lib/systemd/system/docker.service" {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != "/usr/lib/systemd/system/docker.service" {
			return "", ErrIncomplete
		}
		path = resolved
	}
	if verifyRootRunAncestor(path) != nil {
		return "", ErrIncomplete
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 1<<20 || artifactio.CheckFileOwner(info, 0, 0) != nil {
		return "", ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", ErrIncomplete
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, 1<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nativeDockerSystemdState(ctx context.Context) (string, int32, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "show", "docker.service", "--property=Id,LoadState,ActiveState,MainPID,FragmentPath")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil || len(raw) > 2048 {
		return "", 0, ErrIncomplete
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", 0, ErrIncomplete
		}
		if _, dup := values[key]; dup {
			return "", 0, ErrIncomplete
		}
		values[key] = value
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid <= 0 || values["Id"] != "docker.service" || values["LoadState"] != "loaded" || values["ActiveState"] != "active" || len(values) != 5 {
		return "", 0, ErrIncomplete
	}
	return values["FragmentPath"], int32(pid), nil
}

func nativeDockerAPI(ctx context.Context, socket string) (string, string, string, int32, uint32, error) {
	var peerPID int32
	var peerUID uint32
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, ErrIncompatible
		}
		raw, err := unixConn.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, err
		}
		var cred *unix.Ucred
		var controlErr error
		if err := raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || controlErr != nil || cred == nil || cred.Pid <= 0 || cred.Uid != 0 {
			conn.Close()
			return nil, ErrIncompatible
		}
		if peerPID != 0 && (peerPID != cred.Pid || peerUID != cred.Uid) {
			conn.Close()
			return nil, ErrIncompatible
		}
		peerPID, peerUID = cred.Pid, cred.Uid
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	read := func(path string, into any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ErrIncompatible
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
		if err != nil || len(body) > 64<<10 {
			return ErrIncompatible
		}
		return json.Unmarshal(body, into)
	}
	var version struct{ Version string }
	var info struct{ ID, DockerRootDir string }
	if read("/version", &version) != nil || read("/info", &info) != nil || version.Version == "" || info.ID == "" || info.DockerRootDir == "" || peerPID <= 0 {
		return "", "", "", 0, 0, ErrIncompatible
	}
	return version.Version, info.ID, info.DockerRootDir, peerPID, peerUID, nil
}
