package unifiedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxrelease"
)

// This context cancels only after the disposable private stage has received a
// first file. It exercises partial cleanup without a timing race or live host.
type cancelDuringStage struct {
	context.Context
	root string
}

func (c cancelDuringStage) Err() error {
	entries, _ := os.ReadDir(c.root)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".partial-") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(c.root, entry.Name(), "payload", "bin", "core")); err == nil {
			return context.Canceled
		}
	}
	return c.Context.Err()
}

func TestStageCandidateDurableInactiveTreeAndPartialFailure(t *testing.T) {
	input, inputRoot := intakeFixture(t)
	privateRoot := t.TempDir()
	if err := os.Chmod(privateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(privateRoot, "old-ready"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateRoot, "old-ready", "sentinel"), []byte("keep old staged bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Inventory[0].File.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	staged, err := stageCandidate(context.Background(), input, privateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(staged.Path) != privateRoot || !strings.HasPrefix(filepath.Base(staged.Path), "ready-") || len(staged.Artifacts) != len(input.Inventory) {
		t.Fatal("stage did not return an inactive private tree")
	}
	if offset, err := input.Inventory[0].File.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
		t.Fatal("input FD offset changed", err, offset)
	}
	manifest, err := os.ReadFile(filepath.Join(staged.Path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(manifest); hex.EncodeToString(digest[:]) != staged.ManifestSHA256 {
		t.Fatal("staged manifest bytes differ from trusted witness")
	}
	if _, err := acornfoxrelease.ParseUnifiedManifestV1(manifest); err != nil {
		t.Fatal("staged manifest is not canonical valid JSON", err)
	}
	for _, artifact := range staged.Artifacts {
		path := filepath.Join(staged.Path, "payload", artifact.RelativePath)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || int64(len(body)) != artifact.SizeBytes || hex.EncodeToString(sum[:]) != artifact.SHA256 {
			t.Fatalf("staged file differs: %s %v", artifact.ID, err)
		}
		mode := os.FileMode(0644)
		if artifact.Executable {
			mode = 0755
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("staged mode differs: %s", artifact.ID)
		}
	}
	// A complete, trusted release can be safely staged before its own roles
	// and Native updater have started. Absent dependencies still say provision.
	unstarted := input
	unstarted.Facts.Roles = nil
	unstarted.Facts.HostUpdate = RoleFact{}
	unstarted.Facts.Dependencies = append([]DependencyFact(nil), input.Facts.Dependencies...)
	for i := range unstarted.Facts.Dependencies {
		unstarted.Facts.Dependencies[i] = DependencyFact{Name: unstarted.Facts.Dependencies[i].Name, Ownership: "absent"}
	}
	pre, err := InspectArtifactCandidate(context.Background(), unstarted)
	if err != nil || len(pre.Artifacts) != len(input.Inventory) || len(pre.Dependencies) != 4 {
		t.Fatalf("trusted artifact preflight with roles absent: %+v %v", pre, err)
	}
	for _, decision := range pre.Dependencies {
		if decision.Action != "provision_required" {
			t.Fatalf("absent dependency was declared ready: %+v", decision)
		}
	}
	if got, err := InspectCandidate(context.Background(), unstarted); !errors.Is(err, ErrIncomplete) || len(got.Artifacts) != 0 {
		t.Fatalf("strict role/updater composition accepted pre-install facts: %+v %v", got, err)
	}
	stagedBeforeRoles, err := stageCandidate(context.Background(), unstarted, privateRoot, os.Getuid(), os.Getgid())
	if err != nil || stagedBeforeRoles.Path == staged.Path || len(stagedBeforeRoles.Artifacts) != len(input.Inventory) {
		t.Fatalf("safe inactive pre-role stage failed: %+v %v", stagedBeforeRoles, err)
	}
	before, err := os.ReadDir(privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := unstarted
	untrusted.TrustedPin.ExpectedManifestSHA256 = strings.Repeat("0", 64)
	if _, err := stageCandidate(context.Background(), untrusted, privateRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("untrusted complete release was staged")
	}
	damaged, damagedRoot := intakeFixture(t)
	damaged.Facts.Roles = nil
	damaged.Facts.HostUpdate = RoleFact{}
	path := filepath.Join(damagedRoot, "bin", "cli")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCandidate(context.Background(), damaged, privateRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("corrupted artifact bytes were staged")
	}
	second, _ := intakeFixture(t)
	if _, err := stageCandidate(cancelDuringStage{Context: context.Background(), root: privateRoot}, second, privateRoot, os.Getuid(), os.Getgid()); !errors.Is(err, context.Canceled) {
		t.Fatal("partial stage cancellation not reported", err)
	}
	after, err := os.ReadDir(privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stageNames(before), stageNames(after)) {
		t.Fatal("failed stage changed old stage or left partial bytes")
	}
	if body, err := os.ReadFile(filepath.Join(privateRoot, "old-ready", "sentinel")); err != nil || string(body) != "keep old staged bytes" {
		t.Fatal("old private bytes changed", err)
	}
	if body, err := os.ReadFile(filepath.Join(inputRoot, "bin", "core")); err != nil || string(body) != "fixture bytes for core" {
		t.Fatal("original input changed", err)
	}
}

func stageNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}
