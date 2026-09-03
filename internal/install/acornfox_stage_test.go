package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var errAcornFoxStageInjected = errors.New("injected AcornFox stage fault")

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
	for _, root := range []string{
		string(filepath.Separator), AcornFoxV1InstallPrefix, AcornFoxV1ConfigDir, AcornFoxV1DataDir, AcornFoxV1LogDir, AcornFoxV1DataDir + "/task",
		"/opt/open-card", "/opt/open-card/task", "/etc/open-card", "/etc/open-card/task", "/var/lib/open-card", "/var/lib/open-card/task", "/var/log/open-card", "/var/log/open-card/task", "/etc/systemd/system", "/etc/systemd/system/open-card.service",
	} {
		if !forbiddenAcornFoxStageRoot(root) {
			t.Fatalf("production root policy allowed: %s", root)
		}
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

func TestTaskAcornFoxStagerFaultsDiscardEveryOrdinaryFailure(t *testing.T) {
	for _, step := range []acornFoxStageFaultStep{
		acornFoxStageFaultSpoolWrite,
		acornFoxStageFaultSpoolSync,
		acornFoxStageFaultSpoolSeek,
		acornFoxStageFaultSpoolClose,
		acornFoxStageFaultSpoolRemove,
		acornFoxStageFaultStageMkdir,
		acornFoxStageFaultStageOpen,
		acornFoxStageFaultStageMetadata,
		acornFoxStageFaultStageParentEntrySync,
		acornFoxStageFaultParentMkdir,
		acornFoxStageFaultParentEntrySync,
		acornFoxStageFaultParentMetadata,
		acornFoxStageFaultParentDirectorySync,
		acornFoxStageFaultStageDirectorySync,
		acornFoxStageFaultMemberWrite,
		acornFoxStageFaultMemberSync,
		acornFoxStageFaultMemberDirectorySync,
		acornFoxStageFaultMemberClose,
		acornFoxStageFaultReceiptCreate,
		acornFoxStageFaultReceiptWrite,
		acornFoxStageFaultReceiptSync,
		acornFoxStageFaultReceiptRootSync,
		acornFoxStageFaultReceiptReread,
		acornFoxStageFaultReceiptClose,
		acornFoxStageFaultFinalRootSync,
		acornFoxStageFaultFinalStageSync,
	} {
		t.Run(acornFoxStageFaultName(step), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			hit := false
			stager.fault = func(candidate acornFoxStageFaultStep) error {
				if candidate == step {
					hit = true
					return errAcornFoxStageInjected
				}
				return nil
			}
			handle, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err == nil || !hit || handle.valid() || receipt != (AcornFoxStageReceiptV1{}) {
				t.Fatalf("step=%s handle=%#v receipt=%#v err=%v", acornFoxStageFaultName(step), handle, receipt, err)
			}
			assertAcornFoxStageRootEmpty(t, root)
		})
	}
}

func TestTaskAcornFoxStagerShortWritesDiscardStage(t *testing.T) {
	for _, step := range []acornFoxStageFaultStep{acornFoxStageFaultSpoolWrite, acornFoxStageFaultMemberWrite, acornFoxStageFaultReceiptWrite} {
		t.Run(acornFoxStageFaultName(step), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			hit := false
			stager.fault = func(candidate acornFoxStageFaultStep) error {
				if candidate == step {
					hit = true
					return errAcornFoxStageShortWrite
				}
				return nil
			}
			handle, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err == nil || !hit || handle.valid() || receipt != (AcornFoxStageReceiptV1{}) {
				t.Fatalf("step=%s handle=%#v receipt=%#v err=%v", acornFoxStageFaultName(step), handle, receipt, err)
			}
			assertAcornFoxStageRootEmpty(t, root)
		})
	}
}

func TestTaskAcornFoxStagerCleanupFaultIsUnknownAndReturnsNoCapability(t *testing.T) {
	for _, cleanup := range []acornFoxStageFaultStep{
		acornFoxStageFaultCleanupSpoolClose,
		acornFoxStageFaultCleanupSpoolRemove,
		acornFoxStageFaultCleanupStageClose,
		acornFoxStageFaultCleanupStageRemove,
		acornFoxStageFaultCleanupRootSync,
	} {
		t.Run(acornFoxStageFaultName(cleanup), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			stager.fault = func(step acornFoxStageFaultStep) error {
				if step == acornFoxStageFaultMemberWrite || step == cleanup {
					return errAcornFoxStageInjected
				}
				return nil
			}
			handle, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if !errors.Is(err, ErrAcornFoxStageCleanupUnknown) || handle.valid() || receipt != (AcornFoxStageReceiptV1{}) {
				t.Fatalf("cleanup=%s handle=%#v receipt=%#v err=%v", acornFoxStageFaultName(cleanup), handle, receipt, err)
			}
		})
	}
}

func TestStagedAcornFoxCandidateRequiresMintedSealedReceipt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	forged := AcornFoxStageReceiptV1{
		SchemaVersion: 1, Product: AcornFoxV1Product, ManifestSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("b", 64), TreeSHA256: strings.Repeat("c", 64), FileCount: 1,
	}
	if (StagedAcornFoxCandidateV1{root: root, parent: root, stageName: "forged", receipt: forged}).valid() {
		t.Fatal("unsealed forged receipt formed a valid handle")
	}

	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.root.Remove(".acornfox-stage-complete.json"); err != nil {
		t.Fatal(err)
	}
	if handle.valid() {
		t.Fatal("complete tree without receipt formed a valid handle")
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStagedAcornFoxCandidateCloseFailuresAreUnknown(t *testing.T) {
	for _, step := range []acornFoxStageFaultStep{acornFoxStageFaultHandleClose, acornFoxStageFaultHandleRemove, acornFoxStageFaultHandleSync, acornFoxStageFaultHandleParentClose} {
		t.Run(acornFoxStageFaultName(step), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err != nil {
				t.Fatal(err)
			}
			handle.state.fault = func(candidate acornFoxStageFaultStep) error {
				if candidate == step {
					return errAcornFoxStageInjected
				}
				return nil
			}
			if err := handle.Close(); !errors.Is(err, ErrAcornFoxStageCleanupUnknown) {
				t.Fatalf("step=%s close=%v", acornFoxStageFaultName(step), err)
			}
			handle.state.fault = nil
			if err := handle.Close(); err != nil {
				t.Fatalf("step=%s retry close=%v", acornFoxStageFaultName(step), err)
			}
		})
	}
}

func TestWriteAcornFoxStageCompletionNeverReplacesReceipt(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt := AcornFoxStageReceiptV1{SchemaVersion: 1, Product: AcornFoxV1Product, Version: "1.2.3-test.1"}
	if err := writeAcornFoxStageCompletion(root, receipt, os.Getuid(), os.Getgid(), nil); err != nil {
		t.Fatal(err)
	}
	changed := receipt
	changed.Version = "1.2.3-test.2"
	if err := writeAcornFoxStageCompletion(root, changed, os.Getuid(), os.Getgid(), nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("receipt replacement err=%v", err)
	}
	if !acornFoxStageCompletionMatches(root, receipt, os.Getuid(), os.Getgid()) {
		t.Fatal("original completion receipt was replaced")
	}
}

func TestTaskAcornFoxStagerHandlesOwnIndependentParents(t *testing.T) {
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	stageA, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	stageB, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	if stageA.parent == stager.root || stageB.parent == stager.root || stageA.parent == stageB.parent {
		t.Fatal("handles borrowed or shared the stager parent descriptor")
	}
	if err := stageA.Close(); err != nil {
		t.Fatal(err)
	}
	if !stageB.valid() {
		t.Fatal("closing stage A invalidated stage B")
	}
	if err := stager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stageB.Close(); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxStageRootEmpty(t, taskRoot)
}

func TestTaskAcornFoxStagerHandlesCloseInReverseOrder(t *testing.T) {
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
	stageA, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	stageB, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := stageB.Close(); err != nil {
		t.Fatal(err)
	}
	if !stageA.valid() {
		t.Fatal("closing stage B invalidated stage A")
	}
	if err := stageA.Close(); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxStageRootEmpty(t, taskRoot)
}

func TestStagedAcornFoxCandidateCloseCanRetryAfterInjectedFailure(t *testing.T) {
	for _, failedStep := range []acornFoxStageFaultStep{acornFoxStageFaultHandleClose, acornFoxStageFaultHandleRemove, acornFoxStageFaultHandleSync, acornFoxStageFaultHandleParentClose} {
		t.Run(acornFoxStageFaultName(failedStep), func(t *testing.T) {
			taskRoot := t.TempDir()
			if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err != nil {
				t.Fatal(err)
			}
			handle.state.fault = func(step acornFoxStageFaultStep) error {
				if step == failedStep {
					return errAcornFoxStageInjected
				}
				return nil
			}
			if err := handle.Close(); !errors.Is(err, ErrAcornFoxStageCleanupUnknown) || handle.parent == nil || (failedStep == acornFoxStageFaultHandleClose && handle.root == nil) {
				t.Fatalf("first close err=%v handle=%#v", err, handle)
			}
			handle.state.fault = nil
			if err := handle.Close(); err != nil {
				t.Fatalf("retry close=%v", err)
			}
			assertAcornFoxStageRootEmpty(t, taskRoot)
		})
	}
}

func TestAcornFoxStageCompletionRejectsCanonicalAndMetadataTampering(t *testing.T) {
	for _, variant := range []struct {
		name   string
		mutate func(*testing.T, *StagedAcornFoxCandidateV1)
	}{
		{"whitespace", func(t *testing.T, handle *StagedAcornFoxCandidateV1) {
			overwriteAcornFoxStageCompletion(t, handle.root, append([]byte(" "), mustMarshalAcornFoxReceipt(t, handle.receipt)...))
		}},
		{"unknown_field", func(t *testing.T, handle *StagedAcornFoxCandidateV1) {
			raw := mustMarshalAcornFoxReceipt(t, handle.receipt)
			overwriteAcornFoxStageCompletion(t, handle.root, append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...))
		}},
		{"duplicate_field", func(t *testing.T, handle *StagedAcornFoxCandidateV1) {
			raw := bytes.Replace(mustMarshalAcornFoxReceipt(t, handle.receipt), []byte(`"schema_version":1,`), []byte(`"schema_version":1,"schema_version":1,`), 1)
			overwriteAcornFoxStageCompletion(t, handle.root, raw)
		}},
		{"field_order", func(t *testing.T, handle *StagedAcornFoxCandidateV1) {
			var object map[string]any
			if err := json.Unmarshal(mustMarshalAcornFoxReceipt(t, handle.receipt), &object); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			overwriteAcornFoxStageCompletion(t, handle.root, raw)
		}},
		{"mode", func(t *testing.T, handle *StagedAcornFoxCandidateV1) {
			file, err := handle.root.OpenFile(".acornfox-stage-complete.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Chmod(0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			taskRoot := t.TempDir()
			if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			handle, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err != nil {
				t.Fatal(err)
			}
			if acornFoxStageCompletionMatches(handle.root, receipt, os.Getuid()+1, os.Getgid()) {
				t.Fatal("valid receipt accepted mismatched expected owner")
			}
			variant.mutate(t, &handle)
			if handle.valid() {
				t.Fatalf("tampered receipt %s remained valid", variant.name)
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTaskAcornFoxStagerFaultStepsReachDistinctDurabilityBoundaries(t *testing.T) {
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	hits := make(map[acornFoxStageFaultStep]int)
	stager.fault = func(step acornFoxStageFaultStep) error { hits[step]++; return nil }
	handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	for _, step := range []acornFoxStageFaultStep{
		acornFoxStageFaultStageParentEntrySync, acornFoxStageFaultStageDirectorySync, acornFoxStageFaultFinalStageSync,
		acornFoxStageFaultParentEntrySync, acornFoxStageFaultParentDirectorySync, acornFoxStageFaultMemberDirectorySync,
		acornFoxStageFaultReceiptRootSync, acornFoxStageFaultFinalRootSync,
	} {
		if hits[step] == 0 {
			t.Fatalf("durability boundary %s was not reached", acornFoxStageFaultName(step))
		}
	}
	if hits[acornFoxStageFaultParentEntrySync] < 2 || hits[acornFoxStageFaultParentDirectorySync] < 2 {
		t.Fatalf("nested parent durability operations not independently reached: %#v", hits)
	}
}

func TestStagedAcornFoxCandidateSharedClaimLeaseAndCopies(t *testing.T) {
	taskRoot := t.TempDir()
	if err := os.Chmod(taskRoot, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(taskRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := handle
	lease, err := handle.claimForPublish()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := copyHandle.claimForPublish(); !errors.Is(err, ErrAcornFoxStageClaimed) {
		t.Fatalf("double claim err=%v", err)
	}
	if err := copyHandle.Close(); !errors.Is(err, ErrAcornFoxStageClaimed) {
		t.Fatalf("close while claimed err=%v", err)
	}
	lease.releaseFailure()
	if !copyHandle.valid() {
		t.Fatal("failed claim did not restore live stage")
	}
	if err := copyHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	assertAcornFoxStageRootEmpty(t, taskRoot)
}

func TestStagedAcornFoxCandidateClaimConsumeAndUnknownFreeze(t *testing.T) {
	for _, finish := range []struct {
		name  string
		apply func(*acornFoxStagePublishLease)
		want  acornFoxStagePhase
	}{
		{"consume", func(lease *acornFoxStagePublishLease) { lease.consume() }, acornFoxStageConsumed},
		{"unknown", func(lease *acornFoxStagePublishLease) { lease.freezeUnknown() }, acornFoxStageUnknown},
	} {
		t.Run(finish.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err != nil {
				t.Fatal(err)
			}
			lease, err := handle.claimForPublish()
			if err != nil {
				t.Fatal(err)
			}
			finish.apply(lease)
			handle.state.mu.Lock()
			phase := handle.state.phase
			handle.state.mu.Unlock()
			if phase != finish.want || handle.valid() {
				t.Fatalf("phase=%d valid=%t", phase, handle.valid())
			}
			if _, err := handle.claimForPublish(); err == nil {
				t.Fatal("terminal lease phase allowed a second claim")
			}
		})
	}
}

func TestStagedAcornFoxCandidateConcurrentCloseCopies(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	handle, _, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := handle
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for _, candidate := range []*StagedAcornFoxCandidateV1{&handle, &copyHandle} {
		group.Add(1)
		go func(candidate *StagedAcornFoxCandidateV1) {
			defer group.Done()
			errs <- candidate.Close()
		}(candidate)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertAcornFoxStageRootEmpty(t, root)
}

func mustMarshalAcornFoxReceipt(t *testing.T, receipt AcornFoxStageReceiptV1) []byte {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func overwriteAcornFoxStageCompletion(t *testing.T, root *os.Root, raw []byte) {
	t.Helper()
	file, err := root.OpenFile(".acornfox-stage-complete.json", os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if written, err := file.Write(raw); err != nil || written != len(raw) {
		_ = file.Close()
		t.Fatalf("write completion written=%d err=%v", written, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertAcornFoxStageRootEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unclean stage root entries=%#v err=%v", entries, err)
	}
}

func acornFoxStageFaultName(step acornFoxStageFaultStep) string {
	return fmt.Sprintf("step_%d", step)
}
