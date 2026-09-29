package unifiedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/localpeer"
)

func dockerPrepareFixture(t *testing.T) (context.Context, StagedRelease, acornfoxrelease.TrustedReleasePinV1, nativeHostDeps, acornfoxrelease.UnifiedReleaseManifestV1) {
	t.Helper()
	ctx := context.Background()
	input, _ := intakeFixture(t)
	manifest, err := input.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	stageRoot := t.TempDir()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := stageCandidate(ctx, input, stageRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	host := fixtureNativeHostDeps(t, stageRoot)
	if _, err := prepareNativeHostAt(ctx, stage.Path, input.TrustedPin, host); err != nil {
		t.Fatal(err)
	}
	return ctx, stage, input.TrustedPin, host, manifest
}

func TestNativeDockerPrepareUsesSixInstalledMembersAndNoReplace(t *testing.T) {
	ctx, stage, pin, host, manifest := dockerPrepareFixture(t)
	var created, started bool
	originalLookup := host.lookupGroup
	host.lookupGroup = func(name string) (int, bool, error) {
		if name == nativeDockerGroup {
			return 1909, created, nil
		}
		return originalLookup(name)
	}
	member, err := nativeDockerArtifactAtPath(manifest, "embedded/bin/dockerd")
	if err != nil {
		t.Fatal(err)
	}
	unit := nativeManagedDockerUnit(stage.ReleaseID)
	unitSum := sha256.Sum256(unit)
	configSum := sha256.Sum256([]byte("{}\n"))
	ready := nativeDockerObservation{Version: "29.1.3", DockerID: "managed-docker-fixture", DataRoot: nativeDockerDataRoot, SocketPath: nativeDockerSocket, UnitPath: nativeDockerUnitPath, UnitSHA256: hex.EncodeToString(unitSum[:]), ConfigSHA256: hex.EncodeToString(configSum[:]), GroupGID: 1909, SocketDevice: 4, SocketInode: 7, APIPeerPID: 440, APIPeerUID: 0, Daemon: localpeer.ProcessAttestation{PID: 440, UID: 0, StartTime: "123456", ExecutablePath: filepath.Join(install.UnifiedReleasesDir, stage.ReleaseID, "embedded/bin/dockerd"), ExecutableSHA256: member.SHA256}}
	d := nativeDockerDeps{host: host,
		observe: func(context.Context) (nativeDockerObservation, bool, error) {
			if !started {
				return nativeDockerObservation{}, true, nil
			}
			return ready, false, nil
		},
		createGroup: func(context.Context) error {
			if created {
				return errors.New("duplicate docker group")
			}
			created = true
			return nil
		},
		reload: func(context.Context) error { return nil }, start: func(context.Context) error { started = true; return nil },
	}
	result, err := prepareNativeDockerAt(ctx, stage.Path, pin, d)
	if err != nil || result.Ownership != "managed" || result.Status != "docker_ready" || !started {
		t.Fatalf("managed fixed Docker not prepared: %+v %v", result, err)
	}
	if _, err := os.Lstat(host.path("/var/lib/docker")); !os.IsNotExist(err) {
		t.Fatal("managed Docker touched foreign data root")
	}
	for _, path := range []string{nativeDockerUnitPath, nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot} {
		if _, err := os.Lstat(host.path(path)); err != nil {
			t.Fatalf("missing owned Docker path %s: %v", path, err)
		}
	}
	replay, err := prepareNativeDockerAt(ctx, stage.Path, pin, d)
	if err != nil || replay != result {
		t.Fatalf("same receipt replay differs: %+v %v", replay, err)
	}
}

func TestNativeDockerForeignIncompatibleIsZeroWrite(t *testing.T) {
	ctx, stage, pin, host, _ := dockerPrepareFixture(t)
	calls := 0
	d := nativeDockerDeps{host: host,
		observe: func(context.Context) (nativeDockerObservation, bool, error) {
			return nativeDockerObservation{}, false, ErrIncompatible
		},
		createGroup: func(context.Context) error { calls++; return nil }, reload: func(context.Context) error { calls++; return nil }, start: func(context.Context) error { calls++; return nil },
	}
	if _, err := prepareNativeDockerAt(ctx, stage.Path, pin, d); err == nil {
		t.Fatal("incompatible foreign Docker accepted")
	}
	if calls != 0 {
		t.Fatal("foreign Docker triggered host effects")
	}
	for _, path := range []string{nativeDockerUnitPath, nativeDockerConfigPath, nativeDockerDataRoot, nativeDockerExecRoot} {
		if _, err := os.Lstat(host.path(path)); !os.IsNotExist(err) {
			t.Fatalf("foreign Docker path %s changed", path)
		}
	}
	intent := filepath.Join(host.stageRoot, nativeHostPrepareRecords, "docker-"+stage.ManifestSHA256+"-intent.json")
	if _, err := os.Lstat(intent); !os.IsNotExist(err) {
		t.Fatal("foreign Docker created ownership intent")
	}
	compatible := nativeDockerObservation{Version: "29.1.3", DockerID: "external-docker-fixture", DataRoot: "/var/lib/docker", SocketPath: nativeDockerSocket, UnitPath: "/usr/lib/systemd/system/docker.service", UnitSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), GroupGID: 1909, SocketDevice: 11, SocketInode: 22, APIPeerPID: 405, APIPeerUID: 0, Daemon: localpeer.ProcessAttestation{PID: 405, UID: 0, StartTime: "3344", ExecutablePath: "/usr/bin/dockerd", ExecutableSHA256: strings.Repeat("c", 64)}}
	d.observe = func(context.Context) (nativeDockerObservation, bool, error) { return compatible, false, nil }
	accepted, err := prepareNativeDockerAt(ctx, stage.Path, pin, d)
	if err != nil || accepted.Ownership != "external" || calls != 0 {
		t.Fatalf("compatible external Docker was changed or refused: %+v %v", accepted, err)
	}
	ownedConfig := host.path(nativeDockerConfigPath)
	if err := os.MkdirAll(filepath.Dir(ownedConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownedConfig, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeDockerAt(ctx, stage.Path, pin, d); err == nil {
		t.Fatal("external receipt adopted later own partial config")
	}
	if calls != 0 {
		t.Fatal("partial external replay invoked host effects")
	}
}

func TestNativeDockerAbsentUnitReadbackUsesSocketProperties(t *testing.T) {
	service := "MainPID=0\nId=docker.service\nLoadState=not-found\nActiveState=inactive\nJob=\n"
	socket := "Id=docker.socket\nLoadState=not-found\nActiveState=inactive\nJob=\n"
	containerd := "MainPID=0\nId=containerd.service\nLoadState=not-found\nActiveState=inactive\nJob=\n"
	for _, item := range []struct {
		name, unit, output string
		want               bool
	}{
		{"service_absent", "docker.service", service, true},
		{"socket_absent_without_main_pid", "docker.socket", socket, true},
		{"containerd_absent", "containerd.service", containerd, true},
		{"socket_loaded", "docker.socket", strings.Replace(socket, "not-found", "loaded", 1), false},
		{"socket_active", "docker.socket", strings.Replace(socket, "inactive", "active", 1), false},
		{"socket_job", "docker.socket", strings.Replace(socket, "Job=\n", "Job=123\n", 1), false},
		{"socket_extra_main_pid", "docker.socket", "MainPID=0\n" + socket, false},
		{"service_missing_main_pid", "docker.service", strings.Replace(service, "MainPID=0\n", "", 1), false},
		{"service_live_pid", "docker.service", strings.Replace(service, "MainPID=0", "MainPID=42", 1), false},
		{"socket_unknown_field", "docker.socket", socket + "Foreign=1\n", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if got := nativeDockerAbsentUnitReadback(item.unit, []byte(item.output)); got != item.want {
				t.Fatalf("unit %s: got %t, want %t", item.unit, got, item.want)
			}
		})
	}
}
