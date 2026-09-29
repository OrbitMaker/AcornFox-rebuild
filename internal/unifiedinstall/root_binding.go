package unifiedinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/hosthelper"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
)

const (
	UnifiedTrustedPinPath        = "/etc/acornfox/trust/unified-release-pin.json"
	UnifiedInstallationIDPath    = "/etc/acornfox/installation-id.json"
	UnifiedRuntimeBindingPath    = "/run/acornfox/trust/runtime-binding.json"
	containerPeerSocket          = "/run/acornfox/container-ipc/container.sock"
	coreContainerAuthoritySocket = "/run/acornfox/core-ipc/container-authority.sock"
	sourcePeerSocket             = "/run/acornfox/source-ipc/source-build.sock"
	coreSourceAuthoritySocket    = "/run/acornfox/core-ipc/source-build-authority.sock"
	gatewayPeerSocket            = "/run/acornfox/gateway-ipc/gateway.sock"
	coreGatewayAuthoritySocket   = "/run/acornfox/core-ipc/gateway-authority.sock"
)

var ErrBindingCommitUnknown = errors.New("unified runtime binding publication outcome is unknown")

type NativeBindingRequest struct {
	StagePath                                    string
	CorePID, ContainerPID, SourcePID, GatewayPID int32
}

type NativeBindingResult struct {
	Path, Digest, ReleaseID, SourceCommit string
}

type roleProcess struct {
	pid int32
	uid uint32
	att localpeer.ProcessAttestation
}

type releaseRoleSubject struct {
	pid      int32
	uid, gid uint32
	groups   []uint32
	artifact acornfoxrelease.UnifiedArtifactV1
}

// PublishNativeBinding is the root-only Native CLI consumer. A PID is merely a
// subject selector; neither a caller's role assertion nor a staged path is trust.
func PublishNativeBinding(ctx context.Context, req NativeBindingRequest) (NativeBindingResult, error) {
	var zero NativeBindingResult
	if ctx == nil {
		return zero, ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 || req.CorePID <= 0 || req.ContainerPID <= 0 || req.SourcePID <= 0 || req.GatewayPID <= 0 || req.CorePID == req.ContainerPID || req.CorePID == req.SourcePID || req.CorePID == req.GatewayPID || req.ContainerPID == req.SourcePID || req.ContainerPID == req.GatewayPID || req.SourcePID == req.GatewayPID {
		return zero, ErrIncomplete
	}
	var pin acornfoxrelease.TrustedReleasePinV1
	if err := readProtectedPublisherJSON(UnifiedTrustedPinPath, 4096, &pin); err != nil {
		return zero, err
	}
	var installation struct {
		ID string `json:"installation_id"`
	}
	if err := readProtectedPublisherJSON(UnifiedInstallationIDPath, 1024, &installation); err != nil {
		return zero, err
	}
	if len(installation.ID) < 8 || len(installation.ID) > 128 || strings.ContainsAny(installation.ID, "/\\\x00 \t\r\n") {
		return zero, ErrIncomplete
	}
	stage, err := reopenProductionStage(ctx, req.StagePath, pin)
	if err != nil {
		return zero, err
	}
	if _, err := os.Lstat(UnifiedRuntimeBindingPath); err == nil || !os.IsNotExist(err) {
		return zero, fmt.Errorf("%w: runtime binding already exists or cannot be checked", ErrIncomplete)
	}
	coreArtifact, err := componentArtifact(stage.manifest, stage.manifest.Components.Core.ArtifactID)
	if err != nil {
		return zero, err
	}
	if coreArtifact.RelativePath != "bin/acornfox-core" {
		return zero, ErrIncomplete
	}
	containerArtifact, err := stageRoleArtifact(stage.manifest, acornfoxrelease.RoleContainerRuntime)
	if err != nil {
		return zero, err
	}
	sourceArtifact, err := stageRoleArtifact(stage.manifest, acornfoxrelease.RoleSourceBuild)
	if err != nil {
		return zero, err
	}
	gatewayArtifact, err := stageRoleArtifact(stage.manifest, acornfoxrelease.RoleApplicationGateway)
	if err != nil || gatewayArtifact.RelativePath != "bin/acornfox-gateway" {
		return zero, ErrIncomplete
	}
	coreUID, coreGID, err := resolvedRoleOwner(install.AccountCore)
	if err != nil {
		return zero, err
	}
	containerUID, containerGID, err := resolvedRoleOwner(install.AccountContainerRuntime)
	if err != nil {
		return zero, err
	}
	sourceUID, sourceGID, err := resolvedRoleOwner(install.AccountSourceBuild)
	if err != nil {
		return zero, err
	}
	gatewayUID, gatewayGID, err := resolvedRoleOwner(install.AccountGateway)
	if err != nil {
		return zero, err
	}
	ipc, err := user.LookupGroup(install.AccountPeerIPC)
	if err != nil {
		return zero, err
	}
	ipcGID, err := strconv.Atoi(ipc.Gid)
	if err != nil || ipcGID <= 0 || uint32(ipcGID) == coreGID || uint32(ipcGID) == containerGID || uint32(ipcGID) == sourceGID || uint32(ipcGID) == gatewayGID {
		return zero, ErrIncomplete
	}
	docker, err := user.LookupGroup("docker")
	if err != nil {
		return zero, err
	}
	dockerNumber, err := strconv.ParseUint(docker.Gid, 10, 32)
	if err != nil || dockerNumber == 0 || dockerNumber == uint64(ipcGID) {
		return zero, ErrIncomplete
	}
	accounts := RuntimeIPCAccounts{CoreUID: int(coreUID), ContainerUID: int(containerUID), SourceUID: int(sourceUID), GatewayUID: int(gatewayUID), IPCGID: ipcGID}
	if err := verifyRuntimeIPCAccounts(accounts); err != nil {
		return zero, err
	}
	subjects := []releaseRoleSubject{
		{req.CorePID, coreUID, coreGID, []uint32{coreGID, uint32(ipcGID)}, coreArtifact},
		{req.ContainerPID, containerUID, containerGID, []uint32{containerGID, uint32(ipcGID), uint32(dockerNumber)}, containerArtifact},
		{req.SourcePID, sourceUID, sourceGID, []uint32{sourceGID, uint32(ipcGID)}, sourceArtifact},
		{req.GatewayPID, gatewayUID, gatewayGID, []uint32{gatewayGID, uint32(ipcGID)}, gatewayArtifact},
	}
	core, err := attestReleaseRole(subjects[0], stage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	container, err := attestReleaseRole(subjects[1], stage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	source, err := attestReleaseRole(subjects[2], stage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	gateway, err := attestReleaseRole(subjects[3], stage.manifest.ReleaseID)
	if err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	binding := &localpeer.RuntimePeerBinding{
		Version: localpeer.BindingVersion1, InstallationID: installation.ID,
		ContainerSocket: containerPeerSocket, AuthoritySocket: coreContainerAuthoritySocket,
		CoreUID: core.uid, CorePID: core.pid, CoreExeSHA: core.att.ExecutableSHA256, CoreStartTime: core.att.StartTime,
		ContainerUID: container.uid, ContainerPID: container.pid, ContainerExeSHA: container.att.ExecutableSHA256, ContainerStartTime: container.att.StartTime,
		SourceBuildUID: source.uid, SourceBuildPID: source.pid, SourceBuildExeSHA: source.att.ExecutableSHA256, SourceBuildStartTime: source.att.StartTime,
		SourceBuildSocket: sourcePeerSocket, SourceBuildAuthoritySocket: coreSourceAuthoritySocket,
		GatewayUID: gateway.uid, GatewayPID: gateway.pid, GatewayExeSHA: gateway.att.ExecutableSHA256, GatewayStartTime: gateway.att.StartTime,
		GatewaySocket: gatewayPeerSocket, GatewayAuthoritySocket: coreGatewayAuthoritySocket,
	}
	if err := binding.Validate(); err != nil {
		return zero, err
	}
	if err := PrepareUnifiedRuntimeIPCParents(accounts); err != nil {
		return zero, err
	}
	// Existing role clients use this fixed helper path, rather than the optional
	// /run/acornfox/helper placeholder. The helper itself starts after binding.
	helperParent := filepath.Dir(hosthelper.DefaultHelperSocketPath)
	if err := verifyRootRunAncestor(helperParent); err != nil {
		return zero, err
	}
	if err := ensureRuntimeIPCDir(helperParent, 0, ipcGID, 0750); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return publishBindingBytes(ctx, binding, accounts, stage, subjects)
}

func componentArtifact(m acornfoxrelease.UnifiedReleaseManifestV1, id string) (acornfoxrelease.UnifiedArtifactV1, error) {
	for _, item := range m.Artifacts {
		if item.ID == id {
			return item, nil
		}
	}
	return acornfoxrelease.UnifiedArtifactV1{}, ErrIncomplete
}

func resolvedRoleOwner(name string) (uint32, uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, ErrIncomplete
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return 0, 0, ErrIncomplete
	}
	return uint32(uid), uint32(gid), nil
}

func attestReleaseRole(subject releaseRoleSubject, releaseID string) (roleProcess, error) {
	var zero roleProcess
	att, err := localpeer.AttestLinuxProcess(subject.pid)
	if err != nil {
		return zero, err
	}
	installed := filepath.Join(install.UnifiedReleasesDir, releaseID, subject.artifact.RelativePath)
	if err := checkAttestedRole(att, subject, installed); err != nil {
		return zero, err
	}
	if err := verifyProcessIPCGroup(subject.pid, subject.gid, subject.groups); err != nil {
		return zero, err
	}
	return roleProcess{pid: subject.pid, uid: subject.uid, att: att}, nil
}

func checkAttestedRole(att localpeer.ProcessAttestation, subject releaseRoleSubject, installed string) error {
	if att.PID != subject.pid || att.UID != subject.uid || att.StartTime == "" || att.ExecutablePath != installed || att.ExecutableSHA256 != subject.artifact.SHA256 {
		return fmt.Errorf("%w: real role process differs from trusted installed release", ErrIncomplete)
	}
	return nil
}

func verifyProcessIPCGroup(pid int32, primaryGID uint32, allowed []uint32) error {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	gotGID, gotGroups := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Gid:":
			if len(fields) != 5 {
				return ErrIncomplete
			}
			gotGID = true
			for _, field := range fields[1:] {
				if field != strconv.FormatUint(uint64(primaryGID), 10) {
					return ErrIncomplete
				}
			}
		case "Groups:":
			gotGroups = true
			actual := make([]uint32, 0, len(fields)-1)
			for _, field := range fields[1:] {
				value, parseErr := strconv.ParseUint(field, 10, 32)
				if parseErr != nil {
					return ErrIncomplete
				}
				actual = append(actual, uint32(value))
			}
			expected := append([]uint32(nil), allowed...)
			slices.Sort(actual)
			slices.Sort(expected)
			if !slices.Equal(actual, expected) {
				return ErrIncomplete
			}
		}
	}
	if !gotGID || !gotGroups {
		return ErrIncomplete
	}
	return nil
}

func readProtectedPublisherJSON(path string, maximum int64, out any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || verifyRootRunAncestor(path) != nil {
		return ErrIncomplete
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || artifactio.CheckFileOwner(before, 0, 0) != nil {
		return ErrIncomplete
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || artifactio.CheckFileOwner(opened, 0, 0) != nil {
		_ = file.Close()
		return ErrIncomplete
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || int64(len(raw)) > maximum || int64(len(raw)) != before.Size() {
		return ErrIncomplete
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrIncomplete
	}
	return nil
}

func publishBindingBytes(ctx context.Context, binding *localpeer.RuntimePeerBinding, accounts RuntimeIPCAccounts, stage verifiedStage, subjects []releaseRoleSubject) (result NativeBindingResult, err error) {
	dir := filepath.Dir(UnifiedRuntimeBindingPath)
	before, err := os.Lstat(dir)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0750 || artifactio.CheckFileOwner(before, 0, accounts.IPCGID) != nil {
		return result, ErrIncomplete
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return result, err
	}
	temp, err := artifactio.DurableTempName("", ".runtime-binding-")
	if err != nil {
		_ = root.Close()
		return result, err
	}
	created, committed := false, false
	defer func() {
		if err != nil && created && !committed {
			if cleanupErr := root.Remove(temp); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
		if closeErr := root.Close(); closeErr != nil {
			if committed {
				err = errors.Join(err, ErrBindingCommitUnknown, closeErr)
			} else {
				err = errors.Join(err, closeErr)
			}
		}
		if err != nil {
			result = NativeBindingResult{}
		}
	}()
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return result, err
	}
	created = true
	raw, err := json.Marshal(binding)
	if err != nil {
		_ = file.Close()
		return result, err
	}
	if len(raw) > localpeer.MaxBindingFileBytes {
		_ = file.Close()
		return result, ErrIncomplete
	}
	writeErr := file.Chown(0, accounts.IPCGID)
	if writeErr == nil {
		writeErr = file.Chmod(0640)
	}
	if writeErr == nil {
		n, e := file.Write(raw)
		if e != nil {
			writeErr = e
		} else if n != len(raw) {
			writeErr = io.ErrShortWrite
		}
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return result, errors.Join(writeErr, closeErr)
	}
	opened, err := root.OpenFile(temp, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, err
	}
	info, statErr := opened.Stat()
	actual, readErr := io.ReadAll(io.LimitReader(opened, localpeer.MaxBindingFileBytes+1))
	closeErr = opened.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || artifactio.CheckFileOwner(info, 0, accounts.IPCGID) != nil || !bytes.Equal(actual, raw) {
		return result, ErrIncomplete
	}
	parsed, err := localpeer.ParseRuntimePeerBinding(actual)
	if err != nil || parsed.Digest() != binding.Digest() {
		return result, ErrIncomplete
	}
	for _, subject := range subjects {
		if _, err := attestReleaseRole(subject, stage.manifest.ReleaseID); err != nil {
			return result, err
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Link is the no-replace publication primitive: even a competing root
	// publisher creating final after an earlier check cannot be overwritten.
	if err := linkBindingNoReplace(root, temp, filepath.Base(UnifiedRuntimeBindingPath)); err != nil {
		return result, err
	}
	committed = true
	if err := root.Remove(temp); err != nil {
		return result, errors.Join(ErrBindingCommitUnknown, err)
	}
	directory, err := root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, errors.Join(ErrBindingCommitUnknown, err)
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	after, statErr := os.Lstat(dir)
	if syncErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) {
		return result, errors.Join(ErrBindingCommitUnknown, syncErr, closeErr, statErr)
	}
	loaded, err := localpeer.LoadProtectedRuntimePeerBinding(UnifiedRuntimeBindingPath)
	if err != nil || loaded == nil || loaded.Digest() != binding.Digest() {
		return result, ErrBindingCommitUnknown
	}
	return NativeBindingResult{Path: UnifiedRuntimeBindingPath, Digest: binding.Digest(), ReleaseID: stage.manifest.ReleaseID, SourceCommit: stage.manifest.Provenance.SourceCommit}, nil
}

func linkBindingNoReplace(root *os.Root, temporary, final string) error {
	return root.Link(temporary, final)
}
