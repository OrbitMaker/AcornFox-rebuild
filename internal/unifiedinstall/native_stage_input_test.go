package unifiedinstall

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxrelease"
)

// The dependency facts are the existing synthetic intake fixture; the bundle
// loader, every artifact FD, Stage transaction and reopen are real filesystem
// code paths. This is not a root/live Ubuntu installation acceptance.
func TestNativeStageLoaderToExistingStageAndReopen(t *testing.T) {
	input, _ := intakeFixture(t)
	manifest, err := input.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := acornfoxrelease.CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(private, "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(bundle, "payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range input.Inventory {
		path := filepath.Join(bundle, "payload", filepath.FromSlash(artifact.RelativePath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		info, err := artifact.File.Stat()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.NewSectionReader(artifact.File, 0, info.Size()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	collect := func(context.Context, acornfoxrelease.UnifiedReleaseManifestV1) (HostFacts, error) {
		return input.Facts, nil
	}
	load := func() (*LoadedNativeStageInput, error) {
		return loadNativeStageInput(context.Background(), bundle, input.TrustedPin, os.Getuid(), os.Getgid(), collect)
	}
	loaded, err := load()
	if err != nil {
		t.Fatalf("real protected bundle loader: %v", err)
	}
	stageRoot := t.TempDir()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCandidate(context.Background(), loaded.Intake, stageRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyStagedRelease(context.Background(), staged.Path, stageRoot, input.TrustedPin, os.Getuid(), os.Getgid())
	if err != nil || verified.manifest.ReleaseID != staged.ReleaseID || verified.sha256 != staged.ManifestSHA256 {
		t.Fatalf("loader did not reach durable inactive stage/reopen: %v", err)
	}
	member := filepath.Join(bundle, "payload", filepath.FromSlash(input.Inventory[0].RelativePath))
	memberInfo, err := input.Inventory[0].File.Stat()
	if err != nil {
		t.Fatal(err)
	}
	memberMode := memberInfo.Mode().Perm()
	original, err := os.ReadFile(member)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(member); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Fatal("missing bundle member accepted")
	}
	if err := os.WriteFile(member, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(member, memberMode); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(bundle, "payload", "unlisted-file")
	if err := os.WriteFile(extra, []byte("not in manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Fatal("extra bundle file accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	extraTop := filepath.Join(bundle, "unlisted-top-level")
	if err := os.WriteFile(extraTop, []byte("not in bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(); err == nil {
		t.Fatal("extra top-level bundle file accepted")
	}
	if err := os.Remove(extraTop); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if err := os.WriteFile(member, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(member, memberMode); err != nil {
		t.Fatal(err)
	}
	loaded, err = load()
	if err != nil {
		t.Fatalf("same-size changed bytes should reach exact stage preflight: %v", err)
	}
	if _, err := stageCandidate(context.Background(), loaded.Intake, stageRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("changed bundle bytes were staged")
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	ready, err := os.ReadDir(stageRoot)
	if err != nil || len(ready) != 1 {
		t.Fatalf("failed bundle changed prior ready tree: count=%d err=%v", len(ready), err)
	}
}

func TestNativeAptPolicyJoinsOnlyInstalledVersionSource(t *testing.T) {
	const version = "1:2.43.0-1ubuntu7.3"
	const packagePolicy = `git:
  Installed: 1:2.43.0-1ubuntu7.3
  Candidate: 1:2.43.0-1ubuntu7.3
  Version table:
 *** 1:2.43.0-1ubuntu7.3 500
        500 http://archive.example/ubuntu noble-updates/main amd64 Packages
        100 /var/lib/dpkg/status
     1:2.42.0-1ubuntu1 500
        500 http://archive.example/ubuntu noble/main amd64 Packages
`
	const globalPolicy = `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://archive.example/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.example
 500 http://archive.example/ubuntu noble/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.example
Pinned packages:
`
	if !nativeAptInstalledVersionHasUbuntuSources([]byte(packagePolicy), []byte(globalPolicy), version) {
		t.Fatal("installed-version source did not join its exact Ubuntu/noble global source row")
	}
	if nativeAptInstalledVersionHasUbuntuSources([]byte(packagePolicy), []byte(globalPolicy), "1:2.42.0-1ubuntu1") {
		t.Fatal("another package version borrowed installed source evidence")
	}
	foreign := `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://archive.example/ubuntu noble-updates/main amd64 Packages
     release o=Foreign,n=noble
 500 http://archive.example/ubuntu noble/main amd64 Packages
     release o=Ubuntu,n=noble
Pinned packages:
`
	if nativeAptInstalledVersionHasUbuntuSources([]byte(packagePolicy), []byte(foreign), version) {
		t.Fatal("unrelated Ubuntu source hid the installed version's foreign origin")
	}
}
