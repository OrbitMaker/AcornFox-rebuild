//go:build linux && amd64

package acornfoxrelease

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportCandidateNeverOverwritesAndSurvivesSourceCleanup(t *testing.T) {
	stage := releaseArtifactFixture(t)
	verified, err := VerifyReleaseCandidateV1(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	parent := buildTaskRoot(t)
	output := filepath.Join(parent, "candidate")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "foreign")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportVerifiedCandidateV1(verified, output); err == nil {
		t.Fatal("existing output overwritten")
	}
	if raw, err := os.ReadFile(sentinel); err != nil || string(raw) != "keep" {
		t.Fatal("foreign output changed")
	}
	output = filepath.Join(parent, "new-candidate")
	r, err := ExportVerifiedCandidateV1(verified, output)
	if err != nil {
		t.Fatal(err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyFlatCandidateRoot(output, r.Artifact) != nil {
		t.Fatal("exported files lost after cleanup")
	}
	if _, err := os.Stat(stage.root); !os.IsNotExist(err) {
		t.Fatal("private stage remained after export")
	}
}
