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

func TestAcornFoxRepoBootstrapRecoversLinkedPointerTemporary(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	old := acornFoxRepoBootstrapFaultStep
	acornFoxRepoBootstrapFaultStep = func(step string) error {
		if step == "pointer-post-link" {
			return errors.New("fault")
		}
		return nil
	}
	err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
	acornFoxRepoBootstrapFaultStep = old
	if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
		t.Fatalf("fault=%v", err)
	}
	fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatalf("recover=%v", err)
	}
}

func TestAcornFoxRepoBootstrapRejectsExtraFinalActivation(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "activations", "foreign")
	if err := os.Mkdir(extra, durableDirMode); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("extra=%v", err)
	}
	if _, err := os.Lstat(extra); err != nil {
		t.Fatalf("extra overwritten=%v", err)
	}
}

func TestAcornFoxRepoBootstrapReportsUnknownWhenFailureJournalIsNotPersisted(t *testing.T) {
	_, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	oldStep, oldRename := acornFoxRepoBootstrapFaultStep, store.fs.rename
	acornFoxRepoBootstrapFaultStep = func(step string) error {
		if step == "journal-activation" {
			return errors.New("fault")
		}
		return nil
	}
	store.fs.rename = func(*os.Root, string, string) error { return errors.New("journal rename unavailable") }
	err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
	acornFoxRepoBootstrapFaultStep, store.fs.rename = oldStep, oldRename
	if !errors.Is(err, ErrAcornFoxRepoRecoveryUnknown) {
		t.Fatalf("err=%v", err)
	}
}

func TestAcornFoxRepoBootstrapPointerFaultPrefixesRecoverFresh(t *testing.T) {
	steps := []string{"pointer-temp", "pointer-link", "pointer-post-link", "pointer-parent-sync", "pointer-readback", "pointer-temp-remove", "pointer-post-remove-sync"}
	for pointer := 1; pointer <= 3; pointer++ {
		for _, step := range steps {
			t.Run(step+"-pointer-"+string(rune('0'+pointer)), func(t *testing.T) {
				root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
				old := acornFoxRepoBootstrapFaultStep
				seen := 0
				acornFoxRepoBootstrapFaultStep = func(got string) error {
					if got == step {
						seen++
						if seen == pointer {
							return errors.New("fault")
						}
					}
					return nil
				}
				err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
				acornFoxRepoBootstrapFaultStep = old
				if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
					t.Fatalf("step=%s pointer=%d err=%v", step, pointer, err)
				}
				fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
				if err != nil {
					t.Fatal(err)
				}
				defer fresh.Close()
				if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
					t.Fatalf("step=%s pointer=%d recover=%v", step, pointer, err)
				}
			})
		}
	}
}

func TestAcornFoxRepoBootstrapRejectsPhaseExtraWithoutMutation(t *testing.T) {
	for _, tc := range []struct{ name, fault, extra string }{
		{"activation", "journal-active", "extra-after-activation"},
		{"active", "journal-current", "extra-after-active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
			old := acornFoxRepoBootstrapFaultStep
			acornFoxRepoBootstrapFaultStep = func(step string) error {
				if step == tc.fault {
					return errors.New("fault")
				}
				return nil
			}
			err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
			acornFoxRepoBootstrapFaultStep = old
			if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
				t.Fatalf("fault=%v", err)
			}
			extra := filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "activations", tc.extra)
			if err = os.Mkdir(extra, durableDirMode); err != nil {
				t.Fatal(err)
			}
			fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err == nil {
				t.Fatal("extra activation was accepted")
			}
			if _, err = os.Lstat(extra); err != nil {
				t.Fatalf("extra was mutated: %v", err)
			}
		})
	}
}

func TestAcornFoxRepoBootstrapRejectsSymlinkReplacementInExactInventory(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(string, string) string
	}{
		{"activations", func(root, _ string) string {
			return filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "activations")
		}},
		{"activation-directory", func(root, id string) string {
			return filepath.Join(root, filepath.FromSlash(acornFoxRepoActivationDir(id)))
		}},
		{"base-directory", func(root, _ string) string { return filepath.Join(root, acornFoxLiveDir, "opt", "acornfox") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
			if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
				t.Fatal(err)
			}
			id, _ := AcornFoxRepoActivationID(receipt.CandidateReceipt.BindingSHA256)
			path := tc.path(root, id)
			moved := path + ".moved"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("foreign", path); err != nil {
				t.Fatal(err)
			}
			if lease, err := store.mintLiveVerifiedLease(context.Background(), published, receipt.CandidateReceipt.BindingSHA256); err == nil {
				_ = lease.Release()
				t.Fatal("mint accepted symlink replacement")
			}
			fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err == nil {
				t.Fatal("prepare accepted symlink replacement")
			}
			got, err := os.Readlink(path)
			if err != nil || got != "foreign" {
				t.Fatalf("foreign changed=%q %v", got, err)
			}
		})
	}
}

func TestAcornFoxRepoBootstrapRejectsWrongFinalPointerTarget(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(acornFoxRepoActivePath()))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign", path); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err == nil {
		t.Fatal("wrong pointer target accepted")
	}
	got, err := os.Readlink(path)
	if err != nil || got != "foreign" {
		t.Fatalf("foreign pointer changed=%q %v", got, err)
	}
}

func TestAcornFoxRepoBootstrapRejectsFinalPointerHardlink(t *testing.T) {
	root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(acornFoxRepoActivePath()))
	foreign := acornFoxRepoActivePath() + ".foreign-link"
	rootHandle, err := store.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	err = rootHandle.Link(acornFoxRepoActivePath(), foreign)
	closeErr := rootHandle.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("link=%v close=%v", err, closeErr)
	}
	fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err == nil {
		t.Fatal("hardlinked final pointer accepted")
	}
	info, err := os.Lstat(path)
	if err != nil || acornFoxRepoNlink(info) != 2 {
		t.Fatalf("hardlink changed: %#v %v", info, err)
	}
}

func TestAcornFoxRepoBootstrapCleanJournalAcceptsExactNextPrefixes(t *testing.T) {
	for _, state := range []acornFoxRepoPrefixState{acornFoxRepoPrefixActivations, acornFoxRepoPrefixActivationDir, acornFoxRepoPrefixActivationJSON, acornFoxRepoPrefixRelease} {
		t.Run("prefix-"+string(rune('0'+state)), func(t *testing.T) {
			root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
			journal, err := store.Resume(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a, raw, err := acornFoxRepoActivation(journal, mustAcornFoxLiveReceipt(t, root), published)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := store.openRoot()
			if err != nil {
				t.Fatal(err)
			}
			mark := func() {}
			if state >= acornFoxRepoPrefixActivations {
				if err = acornFoxRepoDir(handle, store, acornFoxLiveDir+"/opt/acornfox/activations", mark); err != nil {
					t.Fatal(err)
				}
			}
			if state >= acornFoxRepoPrefixActivationDir {
				if err = acornFoxRepoDir(handle, store, acornFoxRepoActivationDir(a.ActivationID), mark); err != nil {
					t.Fatal(err)
				}
			}
			if state >= acornFoxRepoPrefixActivationJSON {
				if err = acornFoxLiveWriteFile(handle, store, journal.TransactionID, acornFoxRepoActivationPath(a.ActivationID), raw, durableFileMode, mark); err != nil {
					t.Fatal(err)
				}
			}
			if state >= acornFoxRepoPrefixRelease {
				if err = acornFoxRepoEnsurePointer(handle, store, journal.TransactionID, acornFoxRepoReleasePath(a.ActivationID), "../../releases/"+a.ReleaseID, mark); err != nil {
					t.Fatal(err)
				}
			}
			if err = handle.Close(); err != nil {
				t.Fatal(err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
				t.Fatalf("state=%d err=%v", state, err)
			}
		})
	}
}

func mustAcornFoxLiveReceipt(t *testing.T, root string) AcornFoxLiveReceiptV1 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, acornFoxLiveReceipt))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ParseAcornFoxLiveReceiptV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
