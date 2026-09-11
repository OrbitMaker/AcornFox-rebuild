//go:build linux && (amd64 || arm64)

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
	if verifyFlatCandidateRoot(output, r.Artifact, nil) != nil {
		t.Fatal("exported files lost after cleanup")
	}
	if _, err := os.Stat(stage.root); !os.IsNotExist(err) {
		t.Fatal("private stage remained after export")
	}
}

func TestExportSuccessorKeepsSixFilesAndRequiresPinnedPredecessor(t *testing.T) {
	stage, predecessor := successorArtifactFixture(t)
	verified, err := VerifyReleaseCandidateV1(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	output := filepath.Join(buildTaskRoot(t), "successor")
	r, err := ExportVerifiedCandidateV1(verified, output)
	if err != nil {
		t.Fatal(err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 6 {
		t.Fatal("export must remain a flat six-file candidate set", err)
	}
	if _, err := os.Lstat(filepath.Join(output, predecessorBindingFile)); !os.IsNotExist(err) {
		t.Fatal("private predecessor was exported")
	}
	if err := verifyFlatCandidateRoot(output, r.Artifact, predecessor); err != nil {
		t.Fatal("exported successor failed real installer verification", err)
	}
	if err := verifyFlatCandidateRoot(output, r.Artifact, nil); err == nil {
		t.Fatal("exported successor accepted missing predecessor")
	}
	predecessor[0] = '!'
	if err := verifyFlatCandidateRoot(output, r.Artifact, predecessor); err == nil {
		t.Fatal("exported successor accepted changed predecessor")
	}
}
