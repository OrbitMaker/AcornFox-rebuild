package install

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskAcornFoxStagerStagesOneConsumedStream(t *testing.T) {
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	input := fixture.input(nil)
	reader := &acornFoxChunkReader{data: append([]byte(nil), fixture.archive...), max: 5}
	input.Archive = reader
	handle, receipt, err := stager.Stage(input)
	if err != nil || !handle.valid() {
		t.Fatalf("stage=%#v receipt=%#v err=%v", handle, receipt, err)
	}
	defer handle.Close()
	if len(reader.data) != 0 {
		t.Fatal("caller archive reader was not consumed exactly once")
	}
	if receipt.Product != AcornFoxV1Product || receipt.FileCount != len(AcornFoxV1RequiredFiles())+1 || strings.Contains(receipt.TreeSHA256, taskRoot) {
		t.Fatalf("receipt=%#v", receipt)
	}
	rawReceipt, err := json.Marshal(receipt)
	if err != nil || bytes.Contains(rawReceipt, []byte(taskRoot)) || bytes.Contains(rawReceipt, []byte("postgresql://")) {
		t.Fatalf("receipt leaked private data: %q %v", rawReceipt, err)
	}
	info, err := handle.root.Lstat("bin/acornfox-server")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || verifyOwner(info, os.Getuid(), os.Getgid()) != nil {
		t.Fatalf("staged server=%#v err=%v", info, err)
	}
	for _, forbidden := range []string{"current", "previous", "activations", "journal", "marker"} {
		if _, err := os.Lstat(filepath.Join(taskRoot, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("forbidden task state %q exists: %v", forbidden, err)
		}
	}
	entries, err := os.ReadDir(taskRoot)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() || strings.Contains(entries[0].Name(), "spool") {
		t.Fatalf("task entries=%#v err=%v", entries, err)
	}
}

func TestTaskAcornFoxStagerRejectsUnsafeRootsAndCleansFailure(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, candidate := range []struct {
		name    string
		prepare func(*testing.T, string) (string, int, int)
		input   func(VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input
	}{
		{"symlink_root", func(t *testing.T, root string) (string, int, int) {
			link := root + "-link"
			if err := os.Symlink(root, link); err != nil {
				t.Fatal(err)
			}
			return link, os.Getuid(), os.Getgid()
		}, func(in VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input { return in }},
		{"world_writable_root", func(t *testing.T, root string) (string, int, int) {
			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
			return root, os.Getuid(), os.Getgid()
		}, func(in VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input { return in }},
		{"wrong_owner", func(t *testing.T, root string) (string, int, int) { return root, os.Getuid() + 1, os.Getgid() }, func(in VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input { return in }},
		{"short_stream", func(t *testing.T, root string) (string, int, int) { return root, os.Getuid(), os.Getgid() }, func(in VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input {
			in.Archive = &acornFoxChunkReader{data: fixture.archive[:len(fixture.archive)-1], max: 3}
			return in
		}},
		{"long_stream", func(t *testing.T, root string) (string, int, int) { return root, os.Getuid(), os.Getgid() }, func(in VerifyAcornFoxCandidateArtifactsV1Input) VerifyAcornFoxCandidateArtifactsV1Input {
			in.Archive = &acornFoxChunkReader{data: append(append([]byte(nil), fixture.archive...), 'x'), max: 3}
			return in
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			path, uid, gid := candidate.prepare(t, root)
			stager, err := NewTaskAcornFoxStager(path, uid, gid)
			if err == nil {
				defer stager.Close()
				if _, _, err := stager.Stage(candidate.input(fixture.input(nil))); err == nil {
					t.Fatal("unsafe stage accepted")
				}
			}
			if path == root {
				entries, readErr := os.ReadDir(root)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("failure cleanup entries=%#v err=%v", entries, readErr)
				}
			}
		})
	}
}

func TestTaskAcornFoxStagerRejectsTaskRootReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	old := root + "-old"
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil)); err == nil {
		t.Fatal("replaced task root accepted")
	}
}

func TestTaskAcornFoxStagerRejectsProductionRootsAndCloseDiscardsStage(t *testing.T) {
	for _, root := range []string{string(filepath.Separator), AcornFoxV1InstallPrefix, AcornFoxV1ConfigDir, AcornFoxV1DataDir, AcornFoxV1LogDir, AcornFoxV1DataDir + "/task"} {
		if _, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid()); err == nil {
			t.Fatalf("production root accepted: %s", root)
		}
	}
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	handle, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(taskRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("discard entries=%#v err=%v", entries, err)
	}
	if err := stager.Close(); err != nil {
		t.Fatal(err)
	}
}
