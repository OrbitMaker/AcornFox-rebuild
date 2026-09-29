package unifiedinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/localpeer"
)

func TestVerifiedStageReopensAndRealProcessDigestDriftRejects(t *testing.T) {
	input, _ := intakeFixture(t)
	privateRoot := t.TempDir()
	if err := os.Chmod(privateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCandidate(context.Background(), input, privateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyStagedRelease(context.Background(), staged.Path, privateRoot, input.TrustedPin, os.Getuid(), os.Getgid())
	if err != nil || verified.manifest.ReleaseID != staged.ReleaseID || verified.sha256 != staged.ManifestSHA256 {
		t.Fatalf("real staged bytes did not reopen: %v", err)
	}
	gatewayArtifact, err := stageRoleArtifact(verified.manifest, acornfoxrelease.RoleApplicationGateway)
	if err != nil || gatewayArtifact.RelativePath != "bin/acornfox-gateway" {
		t.Fatalf("complete trusted stage lacks fixed Gateway runner: %v", err)
	}
	extra := filepath.Join(staged.Path, "payload", "unlisted-empty")
	if err := os.Mkdir(extra, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStagedRelease(context.Background(), staged.Path, privateRoot, input.TrustedPin, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("unlisted stage directory was accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	att, err := localpeer.AttestLinuxProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("0", 64)
	if wrong == att.ExecutableSHA256 {
		wrong = strings.Repeat("1", 64)
	}
	subject := releaseRoleSubject{pid: int32(os.Getpid()), uid: att.UID}
	subject.artifact.SHA256 = wrong
	if err := checkAttestedRole(att, subject, att.ExecutablePath); !errors.Is(err, ErrIncomplete) {
		t.Fatal("actual process with a wrong pinned executable digest was accepted")
	}
	// The private tree remains inactive; corrupting its bytes must be rejected
	// independently of the manifest's self-declared trusted pin.
	file := filepath.Join(staged.Path, "payload", "bin", "core")
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 1
	if err := os.WriteFile(file, body, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStagedRelease(context.Background(), staged.Path, privateRoot, input.TrustedPin, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("changed stage member was accepted")
	}
}

func TestBindingNoReplacePreservesExistingIdentity(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "old-binding"), []byte("protected old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".new-binding"), []byte("new candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := linkBindingNoReplace(root, ".new-binding", "old-binding"); err == nil {
		t.Fatal("published binding replaced an existing one")
	}
	body, err := os.ReadFile(filepath.Join(directory, "old-binding"))
	if err != nil || string(body) != "protected old" {
		t.Fatal("existing binding bytes changed", err)
	}
}
