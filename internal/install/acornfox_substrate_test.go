package install

import (
	"context"
	"os"
	"testing"
)

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

func TestPublishedAcornFoxSubstrateVerifyAndDiscardAreTaskOnly(t *testing.T) {
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
	if err := published.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root + "/substrate"); !os.IsNotExist(err) {
		t.Fatalf("discard retained task substrate: %v", err)
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
	if err := acornFoxSubstrateWriteIntent(taskRoot, AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: candidate, ExpectedEntryEnvelopeSHA256: digest}, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	taskRoot.Close()
	lease.releaseFailure()
	result, err := publisher.Resume(context.Background(), staged.BindingSHA256)
	if err != nil || result.Outcome != AcornFoxReconcileCompleted {
		t.Fatalf("resume=%#v err=%v", result, err)
	}
}
