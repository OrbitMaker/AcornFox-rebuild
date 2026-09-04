package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func acornFoxRepoBootstrapFixture(t *testing.T) (string, *TaskAcornFoxRepoStore, *PublishedAcornFoxSubstrateV1, InactiveSubstrateReceiptV1) {
	t.Helper()
	root, _, published, receipt := newAcornFox03CPublished(t)
	store := newAcornFoxLiveStore(t, root, published, receipt)
	if _, err := materializeAcornFoxLive(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	return root, store, published, receipt
}
func TestAcornFoxRepoBootstrapTaskModelPointers(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		j, _ := store.Resume(context.Background())
		t.Fatalf("bootstrap=%v journal=%#v", err, j)
	}
	j, err := store.Resume(context.Background())
	if err != nil || j.Phase != AcornFoxRepoPreparedFinal || j.NeedsRecovery {
		t.Fatalf("journal=%#v err=%v", j, err)
	}
	id, _ := AcornFoxRepoActivationID(receipt.CandidateReceipt.BindingSHA256)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acornFoxRepoActivationPath(id))))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAcornFoxRepoActivationV1(raw)
	if err != nil || a.Mode != "task_model" || a.ReleaseID != receipt.CandidateReceipt.ReleaseID {
		t.Fatalf("activation=%#v err=%v", a, err)
	}
	for _, v := range []struct{ p, want string }{{acornFoxRepoReleasePath(id), "../../releases/" + receipt.CandidateReceipt.ReleaseID}, {acornFoxRepoActivePath(), "activations/" + id}, {acornFoxRepoCurrentPath(), "active/release"}} {
		got, e := os.Readlink(filepath.Join(root, filepath.FromSlash(v.p)))
		if e != nil || got != v.want {
			t.Fatalf("%s=%q %v", v.p, got, e)
		}
	}
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatalf("replay=%v", err)
	}
}
func TestAcornFoxRepoBootstrapFreshRecoveryExactActivationPrefix(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	old := acornFoxRepoBootstrapFaultStep
	acornFoxRepoBootstrapFaultStep = func(s string) error {
		if s == "journal-activation" {
			return errors.New("fault")
		}
		return nil
	}
	err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
	acornFoxRepoBootstrapFaultStep = old
	if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
		t.Fatalf("fault=%v", err)
	}
	j, e := store.Resume(context.Background())
	if e != nil || !j.NeedsRecovery || j.Phase != AcornFoxRepoStaticVerified {
		t.Fatalf("journal=%#v %v", j, e)
	}
	fresh, e := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	if e = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); e != nil {
		t.Fatalf("resume=%v", e)
	}
}
func TestAcornFoxRepoBootstrapPreservesForeignPointer(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	p := filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "active")
	if e := os.Symlink("foreign", p); e != nil {
		t.Fatal(e)
	}
	if e := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); !errors.Is(e, ErrAcornFoxRepoBootstrapConflict) && !errors.Is(e, ErrAcornFoxRepoConflict) {
		t.Fatalf("err=%v", e)
	}
	got, e := os.Readlink(p)
	if e != nil || got != "foreign" {
		t.Fatalf("got=%q err=%v", got, e)
	}
}
