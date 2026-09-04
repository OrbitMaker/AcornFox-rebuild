package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestTaskAcornFoxSubstratePublisherSerializesConcurrentSameBinding(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	first, receipt, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	outcomes := make(chan AcornFoxSubstratePublishResult, 2)
	failures := make(chan error, 2)
	for _, stage := range []*StagedAcornFoxCandidateV1{&first, &second} {
		wait.Add(1)
		go func(stage *StagedAcornFoxCandidateV1) {
			defer wait.Done()
			result, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256)
			outcomes <- result
			failures <- err
		}(stage)
	}
	wait.Wait()
	close(outcomes)
	close(failures)
	cleanupUnknown := 0
	for err := range failures {
		if err != nil && !errors.Is(err, ErrAcornFoxStageCleanupUnknown) {
			t.Fatal(err)
		}
		if errors.Is(err, ErrAcornFoxStageCleanupUnknown) {
			cleanupUnknown++
		}
	}
	for result := range outcomes {
		if result.Outcome != AcornFoxReconcileCompleted && result.Outcome != AcornFoxReconcileCleanupUnknown {
			t.Fatalf("outcome=%s", result.Outcome)
		}
	}
	if cleanupUnknown != 1 {
		t.Fatalf("cleanup unknown=%d", cleanupUnknown)
	}
}

func TestTaskAcornFoxSubstratePublisherSerializesConcurrentDifferentBindings(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	first, firstReceipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	second, secondReceipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.4-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, candidate := range []struct {
		stage   *StagedAcornFoxCandidateV1
		binding string
	}{{&first, firstReceipt.BindingSHA256}, {&second, secondReceipt.BindingSHA256}} {
		wait.Add(1)
		go func(stage *StagedAcornFoxCandidateV1, binding string) {
			defer wait.Done()
			_, err := publisher.Publish(context.Background(), stage, binding)
			results <- err
		}(candidate.stage, candidate.binding)
	}
	wait.Wait()
	close(results)
	completed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			completed++
		} else if errors.Is(err, ErrAcornFoxSubstrateConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent publish error: %v", err)
		}
	}
	if completed != 1 || conflicts != 1 {
		t.Fatalf("completed=%d conflicts=%d", completed, conflicts)
	}
}

func TestTaskAcornFoxSubstratePublisherPublishesAndReopensInactiveRootfs(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	stage, staged, err := stager.Stage(fixture.input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if inspection, err := publisher.Inspect(staged.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileAbsent {
		t.Fatalf("empty inspect=%#v err=%v", inspection, err)
	}
	result, err := publisher.Publish(context.Background(), &stage, staged.BindingSHA256)
	if err != nil || result.Outcome != AcornFoxReconcileCompleted || result.Receipt.Validate() != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	reopened, err := publisher.Reopen(staged.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Verify(); err != nil {
		t.Fatal(err)
	}
	if inspection, err := publisher.Inspect(staged.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileCompleted {
		t.Fatalf("completed inspect=%#v err=%v", inspection, err)
	}
	if replay, err := publisher.Publish(context.Background(), &stage, staged.BindingSHA256); err != nil || replay.Outcome != AcornFoxReconcileCompleted {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	if _, err := os.Stat(root + "/substrate/rootfs/opt/acornfox/releases/" + staged.ReleaseID + "/bin/acornfox-server"); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"current", "active", ".wants", "database.env", "server.env", "agent.env", "install-id"} {
		if _, err := os.Stat(root + "/substrate/rootfs/" + forbidden); !os.IsNotExist(err) {
			t.Fatalf("forbidden published path %q err=%v", forbidden, err)
		}
	}
}

func TestTaskAcornFoxSubstratePublisherRejectsConflictingBindingWithoutOverwrite(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	first, firstReceipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), &first, firstReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	second, secondReceipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.4-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), &second, secondReceipt.BindingSHA256); err == nil {
		t.Fatal("conflicting binding overwrote inactive substrate")
	}
	reopened, err := publisher.Reopen(firstReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.receipt.CandidateReceipt.BindingSHA256 != firstReceipt.BindingSHA256 {
		t.Fatal("conflicting publish changed terminal receipt")
	}
}

func TestTaskAcornFoxSubstratePublisherRejectsDifferentTaskRootBeforePublisherState(t *testing.T) {
	stageRoot, publisherRoot := t.TempDir(), t.TempDir()
	for _, root := range []string{stageRoot, publisherRoot} {
		if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
			t.Fatal(err)
		}
	}
	stager, err := NewTaskAcornFoxStager(stageRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	publisher, err := NewTaskAcornFoxSubstratePublisher(publisherRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if _, err := publisher.Publish(context.Background(), &stage, receipt.BindingSHA256); err == nil {
		t.Fatal("publisher accepted a stage from another task root")
	}
	for _, root := range []string{stageRoot, publisherRoot} {
		for _, relative := range []string{acornFoxSubstrateLock, acornFoxSubstrateDir, acornFoxSubstrateIntent, acornFoxSubstrateRootfs} {
			if _, err := os.Lstat(filepath.Join(root, relative)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("root=%s publisher state %s err=%v", root, relative, err)
			}
		}
	}
}

func TestTaskAcornFoxSubstratePublisherResumeFindsOnlyMatchingFreshStage(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, staged, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := stage.claimForPublish()
	if err != nil {
		t.Fatal(err)
	}
	candidate, ok := lease.receipt()
	if !ok {
		t.Fatal("lease receipt unavailable")
	}
	source, err := lease.openSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := acornFoxSubstrateManifest(source, candidate)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	source, err = lease.openSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := acornFoxSubstrateEntries(source, candidate, manifest)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ComputeAcornFoxSubstrateTreeSHA256(entries)
	if err != nil {
		t.Fatal(err)
	}
	taskRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := acornFoxSubstrateWriteIntent(newAcornFoxSubstrateFS(), taskRoot, AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: candidate, ExpectedEntryEnvelopeSHA256: digest}, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	taskRoot.Close()
	lease.releaseFailure()
	result, err := publisher.Resume(context.Background(), staged.BindingSHA256)
	if err != nil || result.Outcome != AcornFoxReconcileCompleted {
		t.Fatalf("resume=%#v err=%v", result, err)
	}
}

func TestTaskAcornFoxSubstratePublisherResumeRejectsTamperedSourceBeforeRootfs(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, staged, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := stage.claimForPublish()
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := lease.receipt()
	source, err := lease.openSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := acornFoxSubstrateManifest(source, candidate)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	source, err = lease.openSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := acornFoxSubstrateEntries(source, candidate, manifest)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := ComputeAcornFoxSubstrateTreeSHA256(entries)
	task, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := acornFoxSubstrateWriteIntent(newAcornFoxSubstrateFS(), task, AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: candidate, ExpectedEntryEnvelopeSHA256: digest}, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	task.Close()
	file, err := stage.state.root.OpenFile("bin/acornfox-server", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	lease.releaseFailure()
	if _, err := publisher.Resume(context.Background(), staged.BindingSHA256); err == nil {
		t.Fatal("tampered source resumed into rootfs")
	}
	if _, err := os.Stat(root + "/substrate/rootfs"); !os.IsNotExist(err) {
		t.Fatalf("tampered resume created rootfs: %v", err)
	}
}

func TestPublishedAcornFoxSubstrateRejectsExtraRootfsEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), &stage, receipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	published, err := publisher.Reopen(receipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer published.Close()
	if err := os.WriteFile(root+"/substrate/rootfs/foreign", []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root+"/substrate/rootfs/foreign-dir", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := published.Verify(); err == nil {
		t.Fatal("extra rootfs file verified")
	}
	fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileConflict {
		t.Fatalf("inspection=%#v err=%v", inspection, err)
	}
}

func TestTaskAcornFoxSubstratePublisherClassifiesTerminalDriftAsConflict(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(string, AcornFoxStageReceiptV1) error
	}{
		{"missing", func(root string, receipt AcornFoxStageReceiptV1) error {
			return os.Remove(root + "/substrate/rootfs/opt/acornfox/releases/" + receipt.ReleaseID + "/manifest.json")
		}},
		{"mode", func(root string, receipt AcornFoxStageReceiptV1) error {
			return os.Chmod(root+"/substrate/rootfs/opt/acornfox/releases/"+receipt.ReleaseID+"/manifest.json", 0o600)
		}},
		{"digest", func(root string, receipt AcornFoxStageReceiptV1) error {
			return os.WriteFile(root+"/substrate/rootfs/opt/acornfox/releases/"+receipt.ReleaseID+"/manifest.json", []byte("drift"), 0o644)
		}},
		{"control", func(root string, _ AcornFoxStageReceiptV1) error {
			return os.Chmod(root+"/substrate/intent.json", 0o644)
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err != nil {
				t.Fatal(err)
			}
			if err := mutate.apply(root, receipt); err != nil {
				t.Fatal(err)
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileConflict {
				t.Fatalf("inspection=%#v err=%v", inspection, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherRejectsExistingFinalWithoutMutation(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("truncated")} {
		t.Run(fmt.Sprintf("bytes_%d", len(payload)), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
				t.Fatal(err)
			}
			stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer stager.Close()
			stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			final := root + "/substrate/rootfs/opt/acornfox/releases/" + receipt.ReleaseID + "/manifest.json"
			planted := false
			base := publisher.fs
			publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				if !planted && path == "manifest.json" && flags&os.O_WRONLY == 0 {
					planted = true
					if err := os.WriteFile(final, payload, 0o600); err != nil {
						return nil, err
					}
				}
				return base.openFile(handle, path, flags, mode)
			}
			if _, err := publisher.Publish(context.Background(), &stage, receipt.BindingSHA256); !errors.Is(err, ErrAcornFoxSubstrateConflict) {
				t.Fatalf("publish error=%v", err)
			}
			got, err := os.ReadFile(final)
			if err != nil || string(got) != string(payload) {
				t.Fatalf("existing final mutated: bytes=%q err=%v", got, err)
			}
			info, err := os.Stat(final)
			if err != nil || info.Mode().Perm() != 0o600 || info.Size() != int64(len(payload)) {
				t.Fatalf("existing final metadata mutated: info=%v err=%v", info, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherPinsTaskRootIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Inspect(strings.Repeat("a", 64)); err == nil {
		t.Fatal("replacement task root was accepted")
	}
}

func TestTaskAcornFoxSubstratePublisherNeverReacquiresReplacementPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	publisher.afterRootPathCheck = func() {
		publisher.afterRootPathCheck = nil
		if err := os.Rename(root, root+"-original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, acornFoxStageDirMode); err != nil {
			t.Fatal(err)
		}
	}
	owned, err := publisher.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	if err := owned.Mkdir("original-only", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root + "/original-only"); !os.IsNotExist(err) {
		t.Fatalf("replacement pathname received authority: %v", err)
	}
}

func TestTaskAcornFoxSubstratePublisherCloseIsIdempotentAndFinal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Inspect(strings.Repeat("a", 64)); err == nil {
		t.Fatal("closed publisher reopened task root")
	}
}

var errAcornFoxSubstrateInjected = errors.New("injected AcornFox substrate syscall result")

type acornFoxSubstrateTestFile struct {
	acornFoxSubstrateFile
	read  func(acornFoxSubstrateFile, []byte) (int, error)
	write func(acornFoxSubstrateFile, []byte) (int, error)
	sync  func(acornFoxSubstrateFile) error
	close func(acornFoxSubstrateFile) error
	chmod func(acornFoxSubstrateFile, os.FileMode) error
	chown func(acornFoxSubstrateFile, int, int) error
	stat  func(acornFoxSubstrateFile) (os.FileInfo, error)
}

func (f acornFoxSubstrateTestFile) Read(raw []byte) (int, error) {
	if f.read != nil {
		return f.read(f.acornFoxSubstrateFile, raw)
	}
	return f.acornFoxSubstrateFile.Read(raw)
}
func (f acornFoxSubstrateTestFile) Write(raw []byte) (int, error) {
	if f.write != nil {
		return f.write(f.acornFoxSubstrateFile, raw)
	}
	return f.acornFoxSubstrateFile.Write(raw)
}
func (f acornFoxSubstrateTestFile) Sync() error {
	if f.sync != nil {
		return f.sync(f.acornFoxSubstrateFile)
	}
	return f.acornFoxSubstrateFile.Sync()
}
func (f acornFoxSubstrateTestFile) Close() error {
	if f.close != nil {
		return f.close(f.acornFoxSubstrateFile)
	}
	return f.acornFoxSubstrateFile.Close()
}
func (f acornFoxSubstrateTestFile) Chmod(mode os.FileMode) error {
	if f.chmod != nil {
		return f.chmod(f.acornFoxSubstrateFile, mode)
	}
	return f.acornFoxSubstrateFile.Chmod(mode)
}
func (f acornFoxSubstrateTestFile) Chown(uid, gid int) error {
	if f.chown != nil {
		return f.chown(f.acornFoxSubstrateFile, uid, gid)
	}
	return f.acornFoxSubstrateFile.Chown(uid, gid)
}
func (f acornFoxSubstrateTestFile) Stat() (os.FileInfo, error) {
	if f.stat != nil {
		return f.stat(f.acornFoxSubstrateFile)
	}
	return f.acornFoxSubstrateFile.Stat()
}

func newAcornFoxSubstrateTestPublisher(t *testing.T) (string, *TaskAcornFoxSubstratePublisher, *StagedAcornFoxCandidateV1, AcornFoxStageReceiptV1) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publisher.Close() })
	return root, publisher, &stage, receipt
}

func TestTaskAcornFoxSubstratePublisherFilesystemFaultEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		apply   func(*TaskAcornFoxSubstratePublisher)
		outcome AcornFoxReconciliationOutcome
		fails   bool
	}{
		{"ordinary_partial_write_then_complete", func(p *TaskAcornFoxSubstratePublisher) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, acornFoxSubstrateRootfs+"/") || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				first := true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, write: func(file acornFoxSubstrateFile, raw []byte) (int, error) {
					if !first {
						return file.Write(raw)
					}
					first = false
					return file.Write(raw[:1])
				}}, nil
			}
		}, AcornFoxReconcileCompleted, false},
		{"mkdir_after_create", func(p *TaskAcornFoxSubstratePublisher) {
			base, once := p.fs, false
			p.fs.mkdir = func(root *os.Root, path string, mode os.FileMode) error {
				err := base.mkdir(root, path, mode)
				if !once && err == nil {
					once = true
					return errAcornFoxSubstrateInjected
				}
				return err
			}
		}, AcornFoxReconcileAbsent, true},
		{"ordinary_partial_write_error", func(p *TaskAcornFoxSubstratePublisher) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, acornFoxSubstrateRootfs+"/") || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, write: func(file acornFoxSubstrateFile, raw []byte) (int, error) {
					n, writeErr := file.Write(raw[:1])
					if writeErr != nil {
						return n, writeErr
					}
					return n, errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume, true},
		{"ordinary_chmod_after_write", func(p *TaskAcornFoxSubstratePublisher) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, acornFoxSubstrateRootfs+"/") || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, chmod: func(file acornFoxSubstrateFile, mode os.FileMode) error {
					if err := file.Chmod(mode); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume, true},
		{"ordinary_stat_after_metadata", func(p *TaskAcornFoxSubstratePublisher) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, acornFoxSubstrateRootfs+"/") || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, stat: func(file acornFoxSubstrateFile) (os.FileInfo, error) {
					info, statErr := file.Stat()
					if statErr != nil {
						return info, statErr
					}
					return info, errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			test.apply(publisher)
			_, publishErr := publisher.Publish(context.Background(), stage, receipt.BindingSHA256)
			if test.fails && publishErr == nil {
				t.Fatal("faulted publish succeeded")
			}
			if !test.fails && publishErr != nil {
				t.Fatalf("partial completion publish=%v", publishErr)
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			inspection, err := fresh.Inspect(receipt.BindingSHA256)
			if err != nil || inspection.Outcome != test.outcome {
				t.Fatalf("inspection=%#v err=%v", inspection, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherReleaseControlFaultsResumeFromFreshState(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*TaskAcornFoxSubstratePublisher, string)
	}{
		{"zero_byte_before_write", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, write: func(acornFoxSubstrateFile, []byte) (int, error) {
					return 0, errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"partial_write_error", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, write: func(file acornFoxSubstrateFile, raw []byte) (int, error) {
					n, writeErr := file.Write(raw[:1])
					if writeErr != nil {
						return n, writeErr
					}
					return n, errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"chown_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, chown: func(file acornFoxSubstrateFile, uid, gid int) error {
					if err := file.Chown(uid, gid); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"sync_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, sync: func(file acornFoxSubstrateFile) error {
					if err := file.Sync(); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"close_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, once := p.fs, false
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || once || !strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				once = true
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, close: func(file acornFoxSubstrateFile) error {
					if err := file.Close(); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"link_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base := p.fs
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err == nil && newName == release {
					return errAcornFoxSubstrateInjected
				}
				return err
			}
		}},
		{"parent_sync_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, armed := p.fs, false
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err == nil && newName == release {
					armed = true
				}
				return err
			}
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || !armed || path != parentDirectory(release) || flags&os.O_WRONLY != 0 {
					return file, err
				}
				armed = false
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, sync: func(file acornFoxSubstrateFile) error {
					if err := file.Sync(); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}},
		{"temp_remove_after_effect", func(p *TaskAcornFoxSubstratePublisher, release string) {
			base, armed := p.fs, false
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err == nil && newName == release {
					armed = true
				}
				return err
			}
			p.fs.remove = func(root *os.Root, path string) error {
				err := base.remove(root, path)
				if err == nil && armed && strings.HasPrefix(path, parentDirectory(release)+"/"+acornFoxSubstrateTempPrefix) {
					return errAcornFoxSubstrateInjected
				}
				return err
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			release := acornFoxSubstrateReleaseControlPath(receipt.ReleaseID)
			test.apply(publisher, release)
			if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err == nil {
				t.Fatal("faulted release control publish succeeded")
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileResume {
				t.Fatalf("inspection=%#v err=%v", inspection, err)
			}
			result, err := fresh.Resume(context.Background(), receipt.BindingSHA256)
			if err != nil || result.Outcome != AcornFoxReconcileCompleted {
				t.Fatalf("resume=%#v err=%v", result, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherRecoversManifestModeTempAfterChmodFault(t *testing.T) {
	for _, wantMode := range []os.FileMode{0o644, 0o755} {
		t.Run(wantMode.String(), func(t *testing.T) {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			base, injected := publisher.fs, false
			publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(handle, path, flags, mode)
				if err != nil || injected || !strings.HasPrefix(path, acornFoxSubstrateRootfs+"/") || flags&os.O_CREATE == 0 {
					return file, err
				}
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, chmod: func(file acornFoxSubstrateFile, mode os.FileMode) error {
					if err := file.Chmod(mode); err != nil {
						return err
					}
					if mode == wantMode {
						injected = true
						return errAcornFoxSubstrateInjected
					}
					return nil
				}}, nil
			}
			if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
				t.Fatalf("publish=%v", err)
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if result, err := fresh.Resume(context.Background(), receipt.BindingSHA256); err != nil || result.Outcome != AcornFoxReconcileCompleted {
				t.Fatalf("resume=%#v err=%v", result, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherRejectsForeignReleaseControlHardlinks(t *testing.T) {
	root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
	release := acornFoxSubstrateReleaseControlPath(receipt.ReleaseID)
	base := publisher.fs
	publisher.fs.link = func(root *os.Root, oldName, newName string) error {
		err := base.link(root, oldName, newName)
		if err == nil && newName == release {
			return errAcornFoxSubstrateInjected
		}
		return err
	}
	if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
		t.Fatalf("publish=%v", err)
	}
	releasePath := filepath.Join(root, filepath.FromSlash(release))
	foreign := filepath.Join(filepath.Dir(releasePath), "foreign-release-control-link")
	if err := os.Link(releasePath, foreign); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileResume {
		t.Fatalf("inspection=%#v err=%v", inspection, err)
	}
	if _, err := fresh.Resume(context.Background(), receipt.BindingSHA256); !errors.Is(err, ErrAcornFoxSubstrateConflict) {
		t.Fatalf("foreign hardlink resume=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, acornFoxSubstrateReceipt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign hardlink wrote terminal receipt: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, stage.state.stageName)); err != nil {
		t.Fatalf("foreign hardlink consumed stage: %v", err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign hardlink was removed: %v", err)
	}
}

func TestTaskAcornFoxSubstrateReleaseControlExistingFinalEvidence(t *testing.T) {
	t.Run("canonical final is idempotent", func(t *testing.T) {
		_, publisher, stage, candidate := newAcornFoxSubstrateTestPublisher(t)
		result, err := publisher.Publish(context.Background(), stage, candidate.BindingSHA256)
		if err != nil {
			t.Fatal(err)
		}
		root, err := publisher.openRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := acornFoxSubstrateWriteReleaseControl(publisher.fs, root, result.Receipt, publisher.uid, publisher.gid); err != nil {
			t.Fatalf("canonical replay=%v", err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(string, *TaskAcornFoxSubstratePublisher)
	}{
		{"foreign partial", func(path string, _ *TaskAcornFoxSubstratePublisher) {
			if err := os.WriteFile(path, []byte("foreign partial"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong mode", func(path string, _ *TaskAcornFoxSubstratePublisher) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong owner evidence", func(_ string, publisher *TaskAcornFoxSubstratePublisher) {
			base := publisher.fs
			publisher.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || !strings.HasSuffix(path, ".json") || flags&os.O_WRONLY != 0 {
					return file, err
				}
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, stat: func(file acornFoxSubstrateFile) (os.FileInfo, error) {
					info, statErr := file.Stat()
					if statErr != nil {
						return info, statErr
					}
					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok {
						return nil, errors.New("test cannot alter owner evidence")
					}
					copyStat := *stat
					copyStat.Uid++
					return ownerMismatchFileInfo{FileInfo: info, stat: copyStat}, nil
				}}, nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath, publisher, stage, candidate := newAcornFoxSubstrateTestPublisher(t)
			result, err := publisher.Publish(context.Background(), stage, candidate.BindingSHA256)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(rootPath, filepath.FromSlash(acornFoxSubstrateReleaseControlPath(result.Receipt.CandidateReceipt.ReleaseID)))
			if test.name == "foreign partial" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			test.mutate(path, publisher)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			root, err := publisher.openRoot()
			if err != nil {
				t.Fatal(err)
			}
			err = acornFoxSubstrateWriteReleaseControl(publisher.fs, root, result.Receipt, publisher.uid, publisher.gid)
			closeErr := root.Close()
			if err == nil || !errors.Is(err, ErrAcornFoxSubstrateConflict) {
				t.Fatalf("foreign final error=%v", err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(before) {
				t.Fatalf("foreign final overwritten: before=%q after=%q err=%v", before, after, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherTerminalReceiptAndCleanupFaultEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		apply   func(*TaskAcornFoxSubstratePublisher)
		outcome AcornFoxReconciliationOutcome
	}{
		{"receipt_partial_write_error", func(p *TaskAcornFoxSubstratePublisher) {
			base, controlTemps := p.fs, 0
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || path == acornFoxSubstrateIntent || !strings.HasPrefix(path, acornFoxSubstrateDir+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				controlTemps++
				if controlTemps != 2 {
					return file, nil
				}
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, write: func(file acornFoxSubstrateFile, raw []byte) (int, error) {
					n, writeErr := file.Write(raw[:1])
					if writeErr != nil {
						return n, writeErr
					}
					return n, errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume},
		{"receipt_readback_error", func(p *TaskAcornFoxSubstratePublisher) {
			base, controlTemps := p.fs, 0
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || !strings.HasPrefix(path, acornFoxSubstrateDir+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				controlTemps++
				if controlTemps != 2 {
					return file, nil
				}
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, read: func(file acornFoxSubstrateFile, raw []byte) (int, error) {
					n, readErr := file.Read(raw)
					if readErr != nil {
						return n, readErr
					}
					return n, errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume},
		{"receipt_close_after_write", func(p *TaskAcornFoxSubstratePublisher) {
			base, controlTemps := p.fs, 0
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || !strings.HasPrefix(path, acornFoxSubstrateDir+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
					return file, err
				}
				controlTemps++
				if controlTemps != 2 {
					return file, nil
				}
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, close: func(file acornFoxSubstrateFile) error {
					if err := file.Close(); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileResume},
		{"receipt_link_after_commit", func(p *TaskAcornFoxSubstratePublisher) {
			base := p.fs
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err != nil {
					return err
				}
				if newName == acornFoxSubstrateReceipt {
					return errAcornFoxSubstrateInjected
				}
				return nil
			}
		}, AcornFoxReconcileCleanupUnknown},
		{"receipt_parent_sync_after_commit", func(p *TaskAcornFoxSubstratePublisher) {
			base, armed := p.fs, false
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err == nil && newName == acornFoxSubstrateReceipt {
					armed = true
				}
				return err
			}
			p.fs.openFile = func(root *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
				file, err := base.openFile(root, path, flags, mode)
				if err != nil || !armed || path != acornFoxSubstrateDir || flags&os.O_WRONLY != 0 {
					return file, err
				}
				armed = false
				return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, sync: func(file acornFoxSubstrateFile) error {
					if err := file.Sync(); err != nil {
						return err
					}
					return errAcornFoxSubstrateInjected
				}}, nil
			}
		}, AcornFoxReconcileCleanupUnknown},
		{"receipt_temp_remove_after_commit", func(p *TaskAcornFoxSubstratePublisher) {
			base, armed := p.fs, false
			p.fs.link = func(root *os.Root, oldName, newName string) error {
				err := base.link(root, oldName, newName)
				if err == nil && newName == acornFoxSubstrateReceipt {
					armed = true
				}
				return err
			}
			p.fs.remove = func(root *os.Root, path string) error {
				err := base.remove(root, path)
				if err != nil {
					return err
				}
				if armed && strings.HasPrefix(path, acornFoxSubstrateDir+"/"+acornFoxSubstrateTempPrefix) {
					return errAcornFoxSubstrateInjected
				}
				return nil
			}
		}, AcornFoxReconcileCleanupUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			test.apply(publisher)
			if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err == nil {
				t.Fatal("faulted publish succeeded")
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			inspection, err := fresh.Inspect(receipt.BindingSHA256)
			if err != nil || inspection.Outcome != test.outcome {
				t.Fatalf("inspection=%#v err=%v", inspection, err)
			}
		})
	}
}

func TestTaskAcornFoxSubstratePublisherRejectsBadTerminalTemporaryMetadata(t *testing.T) {
	root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
	if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	temporary := root + "/" + acornFoxSubstrateDir + "/" + acornFoxSubstrateTempPrefix + "foreign"
	if err := os.WriteFile(temporary, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	inspection, err := fresh.Inspect(receipt.BindingSHA256)
	if err != nil || inspection.Outcome != AcornFoxReconcileConflict {
		t.Fatalf("inspection=%#v err=%v", inspection, err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	retry, retryReceipt, err := stager.Stage(newAcornFoxFixture(t, receipt.Version, nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Close()
	if _, err := fresh.Publish(context.Background(), &retry, retryReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxSubstrateConflict) {
		t.Fatalf("publish with foreign terminal temp=%v", err)
	}
	if _, err := os.Lstat(temporary); err != nil {
		t.Fatalf("publish removed unproven terminal temp: %v", err)
	}
}

func TestTaskAcornFoxSubstratePublisherTerminalLinkedReceiptStaysReadOnlyUntilPublish(t *testing.T) {
	root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
	base := publisher.fs
	publisher.fs.link = func(root *os.Root, oldName, newName string) error {
		err := base.link(root, oldName, newName)
		if err == nil && newName == acornFoxSubstrateReceipt {
			return errAcornFoxSubstrateInjected
		}
		return err
	}
	if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
		t.Fatalf("publish=%v", err)
	}
	temps, err := filepath.Glob(root + "/" + acornFoxSubstrateDir + "/" + acornFoxSubstrateTempPrefix + "*")
	if err != nil || len(temps) != 1 {
		t.Fatalf("terminal temporary entries=%v err=%v", temps, err)
	}
	receiptInfo, err := os.Lstat(root + "/" + acornFoxSubstrateReceipt)
	if err != nil {
		t.Fatal(err)
	}
	tempInfo, err := os.Lstat(temps[0])
	if err != nil || !acornFoxSubstrateTerminalTemp(tempInfo, receiptInfo, os.Getuid(), os.Getgid()) {
		t.Fatalf("terminal temporary metadata=%v err=%v", tempInfo, err)
	}
	fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileCleanupUnknown {
		t.Fatalf("inspect=%#v err=%v", inspection, err)
	}
	if _, err := os.Lstat(temps[0]); err != nil {
		t.Fatalf("inspect mutated terminal temp: %v", err)
	}
	published, err := fresh.Reopen(receipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := published.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temps[0]); err != nil {
		t.Fatalf("reopen mutated terminal temp: %v", err)
	}
	result, err := fresh.Publish(context.Background(), stage, receipt.BindingSHA256)
	if !errors.Is(err, ErrAcornFoxStageCleanupUnknown) || result.Outcome != AcornFoxReconcileCleanupUnknown {
		t.Fatalf("reconcile publish=%#v err=%v", result, err)
	}
	if temps, err := filepath.Glob(root + "/" + acornFoxSubstrateDir + "/" + acornFoxSubstrateTempPrefix + "*"); err != nil || len(temps) != 0 {
		t.Fatalf("publish did not reconcile owned terminal temp: %v err=%v", temps, err)
	}
}

func TestTaskAcornFoxSubstratePublisherLockSyscallBoundaries(t *testing.T) {
	t.Run("root_lstat_and_open_root_fail_closed", func(t *testing.T) {
		for _, apply := range []func(*TaskAcornFoxSubstratePublisher){
			func(p *TaskAcornFoxSubstratePublisher) {
				p.fs.lstatPath = func(string) (os.FileInfo, error) { return nil, errAcornFoxSubstrateInjected }
			},
			func(p *TaskAcornFoxSubstratePublisher) {
				p.fs.openRoot = func(*os.Root, string) (*os.Root, error) { return nil, errAcornFoxSubstrateInjected }
			},
		} {
			root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
			apply(publisher)
			if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err == nil {
				t.Fatal("root operation failure was accepted")
			}
			fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileAbsent {
				t.Fatalf("inspection=%#v err=%v", inspection, err)
			}
			_ = fresh.Close()
		}
	})

	t.Run("open_file_and_flock_fail_closed", func(t *testing.T) {
		root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
		base := publisher.fs
		publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
			if path == acornFoxSubstrateLock {
				return nil, errAcornFoxSubstrateInjected
			}
			return base.openFile(handle, path, flags, mode)
		}
		if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
			t.Fatalf("open error=%v", err)
		}
		publisher.fs = base
		flocked := false
		publisher.fs.flock = func(file acornFoxSubstrateFile, operation int) error {
			err := base.flock(file, operation)
			if operation == syscall.LOCK_EX && !flocked && err == nil {
				flocked = true
				return errAcornFoxSubstrateInjected
			}
			return err
		}
		if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
			t.Fatalf("flock error=%v", err)
		}
		fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileAbsent {
			t.Fatalf("inspection=%#v err=%v", inspection, err)
		}
	})

	t.Run("existing_lock_must_be_same_file", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, acornFoxStageDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root+"/"+acornFoxSubstrateLock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer publisher.Close()
		base, swapped := publisher.fs, false
		publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
			if path == acornFoxSubstrateLock && !swapped {
				swapped = true
				if err := os.Remove(root + "/" + acornFoxSubstrateLock); err != nil {
					return nil, err
				}
				if err := os.WriteFile(root+"/"+acornFoxSubstrateLock, []byte("replacement"), 0o600); err != nil {
					return nil, err
				}
			}
			return base.openFile(handle, path, flags, mode)
		}
		if _, err := publisher.Inspect(strings.Repeat("a", 64)); err == nil {
			t.Fatal("replaced existing lock was accepted")
		}
	})

}

func TestTaskAcornFoxSubstratePublisherChownAndConsumeBoundaries(t *testing.T) {
	t.Run("receipt_atomic_temp_chown_after_effect_recovers_from_fresh_publisher", func(t *testing.T) {
		root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
		base, controlTemps := publisher.fs, 0
		publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
			file, err := base.openFile(handle, path, flags, mode)
			if err != nil || !strings.HasPrefix(path, acornFoxSubstrateDir+"/"+acornFoxSubstrateTempPrefix) || flags&os.O_CREATE == 0 {
				return file, err
			}
			controlTemps++
			if controlTemps != 2 {
				return file, nil
			}
			return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, chown: func(file acornFoxSubstrateFile, uid, gid int) error {
				if err := file.Chown(uid, gid); err != nil {
					return err
				}
				return errAcornFoxSubstrateInjected
			}}, nil
		}
		if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); !errors.Is(err, errAcornFoxSubstrateInjected) {
			t.Fatalf("publish=%v", err)
		}
		if controlTemps != 2 {
			t.Fatalf("control atomic temp Chown calls=%d, want 2", controlTemps)
		}
		matches, err := filepath.Glob(root + "/" + acornFoxSubstrateDir + "/" + acornFoxSubstrateTempPrefix + "*")
		if err != nil || len(matches) != 1 {
			t.Fatalf("owned control temps=%v err=%v", matches, err)
		}
		info, err := os.Lstat(matches[0])
		if err != nil || !acornFoxSubstrateUnlinkedTemp(info, acornFoxHelperReceiptMaxBytes, map[os.FileMode]struct{}{0o600: {}}, os.Getuid(), os.Getgid()) {
			t.Fatalf("temp metadata=%v err=%v", info, err)
		}
		fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		inspection, err := fresh.Inspect(receipt.BindingSHA256)
		if err != nil || inspection.Outcome != AcornFoxReconcileResume {
			t.Fatalf("fresh inspection=%#v err=%v", inspection, err)
		}
		result, err := fresh.Resume(context.Background(), receipt.BindingSHA256)
		if err != nil || result.Outcome != AcornFoxReconcileCompleted {
			t.Fatalf("resume=%#v err=%v", result, err)
		}
		if matches, err := filepath.Glob(root + "/" + acornFoxSubstrateDir + "/" + acornFoxSubstrateTempPrefix + "*"); err != nil || len(matches) != 0 {
			t.Fatalf("recovered control temps=%v err=%v", matches, err)
		}
	})

	t.Run("directory_chown_after_create", func(t *testing.T) {
		root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
		base, once := publisher.fs, false
		publisher.fs.openFile = func(handle *os.Root, path string, flags int, mode os.FileMode) (acornFoxSubstrateFile, error) {
			file, err := base.openFile(handle, path, flags, mode)
			if err != nil || once || path != acornFoxSubstrateDir {
				return file, err
			}
			once = true
			return acornFoxSubstrateTestFile{acornFoxSubstrateFile: file, chown: func(file acornFoxSubstrateFile, uid, gid int) error {
				if err := file.Chown(uid, gid); err != nil {
					return err
				}
				return errAcornFoxSubstrateInjected
			}}, nil
		}
		if _, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256); err == nil {
			t.Fatal("faulted publish succeeded")
		}
		fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileAbsent {
			t.Fatalf("inspection=%#v err=%v", inspection, err)
		}
	})

	t.Run("stage_consume_failure_after_terminal_receipt", func(t *testing.T) {
		root, publisher, stage, receipt := newAcornFoxSubstrateTestPublisher(t)
		stage.state.fault = func(step acornFoxStageFaultStep) error {
			if step == acornFoxStageFaultHandleRemove {
				return errAcornFoxSubstrateInjected
			}
			return nil
		}
		result, err := publisher.Publish(context.Background(), stage, receipt.BindingSHA256)
		if !errors.Is(err, ErrAcornFoxStageCleanupUnknown) || result.Outcome != AcornFoxReconcileCleanupUnknown {
			t.Fatalf("publish=%#v err=%v", result, err)
		}
		fresh, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		if inspection, err := fresh.Inspect(receipt.BindingSHA256); err != nil || inspection.Outcome != AcornFoxReconcileCleanupUnknown {
			t.Fatalf("inspection=%#v err=%v", inspection, err)
		}
	})
}
