package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTaskAcornFoxLayoutKeepsExistingTaskTopology(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTaskAcornFoxLayout(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if layout.mode != acornFoxInstallLayoutTask || layout.stateRootPath != root || layout.hostRootPath != root || layout.livePrefix != "live" || layout.receiptPath() != "live/receipt.json" || layout.evidenceSHA256 != "" || !layout.hostRootPinned() {
		t.Fatalf("task layout=%#v", layout)
	}
	if layout.livePath("opt/acornfox/current") != "live/opt/acornfox/current" || layout.activationPath("acornfox-repo-abc") != "live/opt/acornfox/activations/acornfox-repo-abc" || layout.activePath() != "live/opt/acornfox/active" || layout.currentPath() != "live/opt/acornfox/current" || layout.livePath("../escape") != "" || layout.activationPath("../escape") != "" {
		t.Fatal("task layout paths changed")
	}
	for _, role := range acornFoxInstallLayoutRoles {
		principal, ok := layout.owner(role)
		if !ok || principal.uid != os.Getuid() || principal.gid != os.Getgid() {
			t.Fatalf("task role %q principal=%#v ok=%t", role, principal, ok)
		}
	}
}

func TestTestProductionAcornFoxLayoutRejectsHostileRootsAndPrincipals(t *testing.T) {
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	principals := acornFoxTestLayoutPrincipals()
	first, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), principals)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), principals)
	if err != nil || first.evidenceSHA256 == "" || first.evidenceSHA256 != second.evidenceSHA256 || !first.equivalent(second) || first.livePath("opt/acornfox/current") != "opt/acornfox/current" || first.receiptPath() != "var/lib/acornfox/install/live-receipt.json" || first.activationPath("acornfox-repo-abc") != "opt/acornfox/activations/acornfox-repo-abc" {
		t.Fatalf("production layouts first=%#v second=%#v err=%v", first, second, err)
	}
	for name, mutate := range map[string]func(map[AcornFoxLiveRole]acornFoxInstallPrincipal){
		"missing-role": func(values map[AcornFoxLiveRole]acornFoxInstallPrincipal) { delete(values, AcornFoxLiveEdgeRole) },
		"root-not-zero": func(values map[AcornFoxLiveRole]acornFoxInstallPrincipal) {
			values[AcornFoxLiveRootRole] = acornFoxInstallPrincipal{uid: 1, gid: 1}
		},
		"duplicate-nonroot": func(values map[AcornFoxLiveRole]acornFoxInstallPrincipal) {
			values[AcornFoxLiveAgentRole] = values[AcornFoxLiveServerRole]
		},
		"zero-nonroot": func(values map[AcornFoxLiveRole]acornFoxInstallPrincipal) {
			values[AcornFoxLiveAgentRole] = acornFoxInstallPrincipal{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := acornFoxTestLayoutPrincipals()
			mutate(values)
			if _, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), values); err == nil {
				t.Fatal("hostile production layout was accepted")
			}
		})
	}
	if _, err := newTestProductionAcornFoxLayout(filepath.Join(host, "wrong"), host, os.Getuid(), os.Getgid(), principals); err == nil {
		t.Fatal("noncanonical production state root was accepted")
	}
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), principals); err == nil {
		t.Fatal("non-0700 state root was accepted")
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(host, host+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if first.hostRootPinned() {
		t.Fatal("replaced host root retained pin")
	}
}

func TestTaskAcornFoxLayoutDoesNotChangeCanonicalTaskBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	stager, err := NewTaskAcornFoxStager(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, stageReceipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	stageRaw := readAcornFoxLayoutRootFile(t, stage.state.root, ".acornfox-stage-complete.json")
	if want := mustMarshalAcornFoxReceipt(t, stageReceipt); !bytes.Equal(stageRaw, want) {
		t.Fatalf("stage receipt bytes changed\ngot:  %s\nwant: %s", stageRaw, want)
	}
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if !stager.layout.equivalent(publisher.layout) {
		t.Fatal("task stager and substrate publisher diverged")
	}
	publishedResult, err := publisher.Publish(context.Background(), &stage, stageReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	published, err := publisher.Reopen(stageReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer published.Close()
	if !publisher.layout.equivalent(published.layout) {
		t.Fatal("published substrate layout diverged")
	}
	substrateRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acornFoxSubstrateReceipt)))
	if err != nil {
		t.Fatal(err)
	}
	if want, err := MarshalInactiveSubstrateReceiptV1(publishedResult.Receipt); err != nil || !bytes.Equal(substrateRaw, want) {
		t.Fatalf("substrate receipt bytes changed err=%v", err)
	}
	store := newAcornFoxLiveStore(t, root, published, publishedResult.Receipt)
	if !store.layout.equivalent(published.layout) {
		t.Fatal("repo store and published substrate layout diverged")
	}
	if _, err := materializeAcornFoxLive(context.Background(), store, published, stageReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	liveRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acornFoxLiveReceipt)))
	if err != nil {
		t.Fatal(err)
	}
	live, err := ParseAcornFoxLiveReceiptV1(liveRaw)
	if err != nil {
		t.Fatal(err)
	}
	if want, err := MarshalAcornFoxLiveReceiptV1(live); err != nil || !bytes.Equal(liveRaw, want) {
		t.Fatalf("live receipt bytes changed err=%v", err)
	}
	if err := prepareAcornFoxRepository(context.Background(), store, published, stageReceipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	journal, err := store.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	journalRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acornFoxRepoInstallJournal)))
	if err != nil {
		t.Fatal(err)
	}
	if want, err := MarshalAcornFoxRepoJournalV1(journal); err != nil || !bytes.Equal(journalRaw, want) {
		t.Fatalf("journal bytes changed err=%v", err)
	}
	id, err := AcornFoxRepoActivationID(stageReceipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	activationRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acornFoxRepoActivationPath(id))))
	if err != nil {
		t.Fatal(err)
	}
	activation, err := ParseAcornFoxRepoActivationV1(activationRaw)
	if err != nil {
		t.Fatal(err)
	}
	if want, err := MarshalAcornFoxRepoActivationV1(activation); err != nil || !bytes.Equal(activationRaw, want) {
		t.Fatalf("activation bytes changed err=%v", err)
	}
}

func TestProductionTestLayoutSeparatesStateAndPinnedHostBeforeL3(t *testing.T) {
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	if layout.livePath("opt/acornfox/current") != "opt/acornfox/current" || layout.receiptPath() != "var/lib/acornfox/install/live-receipt.json" || layout.activationReceiptPath("acornfox-repo-abc") != "opt/acornfox/activations/acornfox-repo-abc/repo-activation.json" {
		t.Fatalf("production path helpers=%#v", layout)
	}
	stager, err := newAcornFoxStagerForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := newAcornFoxSubstratePublisherForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if _, err = publisher.Publish(context.Background(), &stage, receipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	published, err := publisher.Reopen(receipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer published.Close()
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	acornFoxLayoutCreatePreparedJournal(t, store, published.receipt)
	if _, err := os.Lstat(filepath.Join(host, acornFoxRepoInstallDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host received state journal err=%v", err)
	}
	if files, err := os.ReadDir(state); err != nil || len(files) == 0 {
		t.Fatalf("state lacks stage/substrate/journal files=%v err=%v", files, err)
	}
	hostHandle, err := store.openHostRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := hostHandle.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := acornFoxLiveExpectedEntriesForLayout(layout, published)
	if err != nil {
		t.Fatal(err)
	}
	owners := acornFoxTestOwnershipRecorder(t)
	for _, entry := range entries {
		path := filepath.Join(host, filepath.FromSlash(entry.Path))
		if info, statErr := os.Lstat(path); statErr == nil {
			if entry.Kind == SubstrateEntryDirectory {
				if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
					t.Fatal(err)
				}
			}
			owners.set(info, acornFoxLivePrincipalForEntry(layout, entry))
		}
	}
	store.ownership = owners.edge()
	varInfo, varErr := os.Lstat(filepath.Join(host, "var"))
	if varErr != nil || !acornFoxLiveObservedOwner(store, varInfo, acornFoxInstallPrincipal{}) {
		t.Fatalf("seed var owner err=%v observed=%t", varErr, varErr == nil && acornFoxLiveObservedOwner(store, varInfo, acornFoxInstallPrincipal{}))
	}
	live, err := materializeAcornFoxLive(context.Background(), store, published, receipt.BindingSHA256)
	if err != nil || live.Validate() != nil || live.State != "host_live_materialized" || live.LayoutSHA256 != layout.evidence() {
		t.Fatalf("L3 production materialize receipt=%#v err=%v", live, err)
	}
	if _, err := os.Lstat(filepath.Join(host, "opt", "acornfox")); err != nil {
		t.Fatalf("production live missing: %v", err)
	}
	if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.BindingSHA256); err != nil {
		t.Fatalf("production repository prepare=%v", err)
	}
	current := filepath.Join(host, "opt", "acornfox", "current")
	if target, err := os.Readlink(current); err != nil || target != "active/release" {
		t.Fatalf("production current target=%q err=%v", target, err)
	}
	if journal, err := store.Resume(context.Background()); err != nil || journal.Phase != AcornFoxRepoPreparedFinal || journal.LayoutSHA256 != layout.evidence() {
		t.Fatalf("production journal=%#v err=%v", journal, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	fresh.ownership = owners.edge()
	if err := prepareAcornFoxRepository(context.Background(), fresh, published, receipt.BindingSHA256); err != nil {
		t.Fatalf("fresh production repository resume=%v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(host, host+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openHostRoot(); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("replaced host root open=%v", err)
	}
	if _, err := materializeAcornFoxLive(context.Background(), store, published, receipt.BindingSHA256); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("replaced host root materialize=%v", err)
	}
	if files, err := os.ReadDir(host); err != nil || len(files) != 0 {
		t.Fatalf("replaced host root received effects files=%v err=%v", files, err)
	}
	if got := acornFoxProductionManagedRoots(); !sameAcornFoxStringSlice(got, []string{"opt/acornfox", "etc/acornfox", "var/lib/acornfox", "var/log/acornfox"}) {
		t.Fatalf("production scope=%q", got)
	}
}

func TestProductionLayoutEvidenceBindsDTOsWithoutHostEffects(t *testing.T) {
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	binding, substrate := strings.Repeat("a", 64), strings.Repeat("b", 64)
	journal, err := newAcornFoxRepoJournalForLayout(layout, binding, substrate)
	if err != nil || journal.LayoutSHA256 != layout.evidence() || journal.History[0].EvidenceSHA256 == "" {
		t.Fatalf("production journal=%#v err=%v", journal, err)
	}
	taskPrepared, _ := AcornFoxRepoPreparedEvidence(binding, substrate)
	if journal.History[0].EvidenceSHA256 == taskPrepared {
		t.Fatal("production prepared evidence reused task domain")
	}
	if _, err := MarshalAcornFoxRepoJournalV1(journal); err != nil {
		t.Fatal(err)
	}
	taskJournal := journal
	taskJournal.History = append([]AcornFoxRepoHistoryV1(nil), journal.History...)
	taskJournal.LayoutSHA256 = ""
	taskJournal.History[0].EvidenceSHA256 = taskPrepared
	if err := taskJournal.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lock, err := store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), taskJournal); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("production accepted task journal=%v", err)
	}
	if err := journal.Validate(); err != nil {
		t.Fatalf("production journal validate=%v journal=%#v", err, journal)
	}
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(host, "opt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DTO-only test changed host tree err=%v", err)
	}
}

func TestProductionLayoutPureReceiptAndFakeOwnershipEdge(t *testing.T) {
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	_, _, published, substrate := newAcornFox03CPublished(t)
	entries, err := acornFoxLiveExpectedEntriesForLayout(layout, published)
	if err != nil {
		t.Fatal(err)
	}
	install := substrateEntryAt(entries, "var/lib/acornfox/install")
	if install == nil || install.Kind != SubstrateEntryDirectory || install.Mode != 0o700 || install.Role != OwnerRoleRoot || install.Group != GroupRoleRoot {
		t.Fatalf("production install entry=%#v", install)
	}
	journal, err := newAcornFoxRepoJournalForLayout(layout, substrate.CandidateReceipt.BindingSHA256, sha256Hex(mustMarshalInactiveSubstrateReceipt(t, substrate)))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := acornFoxLiveMakeReceiptForLayout(layout, journal, published, entries)
	if err != nil || receipt.Validate() != nil || receipt.State != "host_live_materialized" || receipt.OwnershipEvidence != "host_uid_gid_verified" || receipt.LayoutSHA256 != layout.evidence() || receipt.LayoutSHA256 == "" {
		t.Fatalf("production receipt=%#v err=%v", receipt, err)
	}
	for _, entry := range receipt.Entries {
		if entry.PhysicalOwnerObservation != "role_uid_gid_verified" {
			t.Fatalf("entry observation=%#v", entry)
		}
	}
	filePath := filepath.Join(parent, "edge")
	if err := os.WriteFile(filePath, []byte("x"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records := map[uint64]acornFoxInstallPrincipal{}
	key := func(info os.FileInfo) uint64 { return acornFoxRepoNlink(info)<<32 | uint64(info.ModTime().UnixNano()) }
	edge := acornFoxOwnershipEdge{
		chown: func(target acornFoxRepoFile, uid, gid int) error {
			info, err := target.Stat()
			if err != nil {
				return err
			}
			records[key(info)] = acornFoxInstallPrincipal{uid: uid, gid: gid}
			return nil
		},
		observe: func(info os.FileInfo) (acornFoxInstallPrincipal, bool) {
			value, ok := records[key(info)]
			return value, ok
		},
	}
	want, _ := layout.owner(AcornFoxLiveEdgeRole)
	if err := edge.chown(file, want.uid, want.gid); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if got, ok := edge.observe(info); err != nil || !ok || got != want {
		t.Fatalf("fake ownership got=%#v ok=%t err=%v", got, ok, err)
	}
}

// TestProductionLayoutFreshCrashPrefixesRecover keeps the production bridge
// honest: every repository preparation fault is recovered by freshly opened
// layout/store/publisher objects, never by the objects that observed the
// fault. The test host remains a temporary, fake-ownership model.
func TestProductionLayoutFreshCrashPrefixesRecover(t *testing.T) {
	steps := []struct {
		name  string
		step  string
		count int
	}{
		{"journal-activation", "journal-activation", 1},
		{"journal-active", "journal-active", 1},
		{"journal-current", "journal-current", 1},
	}
	for _, pointerStep := range []string{"pointer-temp", "pointer-link", "pointer-post-link", "pointer-parent-sync", "pointer-readback", "pointer-temp-remove", "pointer-post-remove-sync"} {
		for count := 1; count <= 3; count++ {
			steps = append(steps, struct {
				name  string
				step  string
				count int
			}{pointerStep + "-" + string(rune('0'+count)), pointerStep, count})
		}
	}
	for _, test := range steps {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionPreparedFixture(t)
			old := acornFoxRepoBootstrapFaultStep
			t.Cleanup(func() { acornFoxRepoBootstrapFaultStep = old })
			seen := 0
			acornFoxRepoBootstrapFaultStep = func(step string) error {
				if step == test.step {
					seen++
					if seen == test.count {
						return errors.New("fault")
					}
				}
				return nil
			}
			err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding)
			acornFoxRepoBootstrapFaultStep = old
			if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
				t.Fatalf("fault=%v", err)
			}
			if journal, resumeErr := f.store.Resume(context.Background()); resumeErr != nil || !journal.NeedsRecovery {
				t.Fatalf("fault journal=%#v err=%v", journal, resumeErr)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			freshLayout, err := newTestProductionAcornFoxLayout(f.state, f.host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := newAcornFoxSubstratePublisherForLayout(freshLayout)
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			published, err := publisher.Reopen(f.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer published.Close()
			store, err := newAcornFoxRepoStoreForLayout(freshLayout)
			if err != nil {
				t.Fatal(err)
			}
			store.ownership = f.owners.edge()
			defer store.Close()
			if err := prepareAcornFoxRepository(context.Background(), store, published, f.binding); err != nil {
				t.Fatalf("fresh recover=%v", err)
			}
			if journal, err := store.Resume(context.Background()); err != nil || journal.Phase != AcornFoxRepoPreparedFinal || journal.NeedsRecovery {
				t.Fatalf("final journal=%#v err=%v", journal, err)
			}
			f.assertExternalSentinel(t)
		})
	}
}

func TestProductionLayoutRejectsPostActivationScopeAndOwnershipDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, acornFoxProductionPreparedFixture)
	}{
		{"foreign-managed-entry", func(t *testing.T, f acornFoxProductionPreparedFixture) {
			if err := os.WriteFile(filepath.Join(f.host, "opt", "acornfox", "foreign"), []byte("foreign"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"ownership-record", func(t *testing.T, f acornFoxProductionPreparedFixture) {
			delete(f.owners.values, acornFoxTestInodeKey(t, filepath.Join(f.host, "opt", "acornfox", "current")))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionPreparedFixture(t)
			if err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, f)
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			fresh, err := newAcornFoxRepoStoreForLayout(f.layout)
			if err != nil {
				t.Fatal(err)
			}
			fresh.ownership = f.owners.edge()
			defer fresh.Close()
			if err := prepareAcornFoxRepository(context.Background(), fresh, f.published, f.binding); !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) && !errors.Is(err, ErrAcornFoxRepoConflict) {
				t.Fatalf("drift accepted=%v", err)
			}
			f.assertExternalSentinel(t)
		})
	}
}

func TestProductionLayoutRejectsPinnedRootAndLayoutDrift(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*testing.T, acornFoxProductionPreparedFixture)
	}{
		{"state-root-replaced", func(t *testing.T, f acornFoxProductionPreparedFixture) {
			if err := os.Rename(f.state, f.state+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.state, durableDirMode); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Resume(context.Background()); !errors.Is(err, ErrAcornFoxRepoConflict) {
				t.Fatalf("replaced state resume=%v", err)
			}
		}},
		{"host-root-replaced", func(t *testing.T, f acornFoxProductionPreparedFixture) {
			if err := os.Rename(f.host, f.host+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.host, durableDirMode); err != nil {
				t.Fatal(err)
			}
			if err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding); !errors.Is(err, ErrAcornFoxRepoConflict) {
				t.Fatalf("replaced host prepare=%v", err)
			}
			if files, err := os.ReadDir(f.host); err != nil || len(files) != 0 {
				t.Fatalf("replaced host effects files=%v err=%v", files, err)
			}
		}},
		{"principal-map-layout-digest", func(t *testing.T, f acornFoxProductionPreparedFixture) {
			mutated := f.layout
			mutated.principals = make(map[AcornFoxLiveRole]acornFoxInstallPrincipal, len(f.layout.principals))
			for role, principal := range f.layout.principals {
				mutated.principals[role] = principal
			}
			mutated.principals[AcornFoxLiveAgentRole] = acornFoxInstallPrincipal{uid: 2002, gid: 2002}
			if _, err := newAcornFoxRepoStoreForLayout(mutated); err == nil {
				t.Fatal("layout digest drift accepted")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionPreparedFixture(t)
			if err := prepareAcornFoxRepository(context.Background(), f.store, f.published, f.binding); err != nil {
				t.Fatal(err)
			}
			test.run(t, f)
			f.assertExternalSentinel(t)
		})
	}
}

type acornFoxProductionPreparedFixture struct {
	parent    string
	host      string
	state     string
	layout    acornFoxInstallLayout
	store     *TaskAcornFoxRepoStore
	published *PublishedAcornFoxSubstrateV1
	binding   string
	owners    *acornFoxTestOwnerRecorder
	sentinel  string
	raw       []byte
}

func newAcornFoxProductionPreparedFixture(t *testing.T) acornFoxProductionPreparedFixture {
	t.Helper()
	parent := t.TempDir()
	host := filepath.Join(parent, "host")
	state := filepath.Join(host, "var", "lib", "acornfox", "install")
	if err := os.Mkdir(host, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	layout, err := newTestProductionAcornFoxLayout(state, host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	stager, err := newAcornFoxStagerForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	stage, receipt, err := stager.Stage(newAcornFoxFixture(t, "1.2.3-test.1", nil).input(nil))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := newAcornFoxSubstratePublisherForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if _, err := publisher.Publish(context.Background(), &stage, receipt.BindingSHA256); err != nil {
		t.Fatal(err)
	}
	published, err := publisher.Reopen(receipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = published.Close() })
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acornFoxLayoutCreatePreparedJournal(t, store, published.receipt)
	entries, err := acornFoxLiveExpectedEntriesForLayout(layout, published)
	if err != nil {
		t.Fatal(err)
	}
	owners := acornFoxTestOwnershipRecorder(t)
	for _, entry := range entries {
		path := filepath.Join(host, filepath.FromSlash(entry.Path))
		if info, statErr := os.Lstat(path); statErr == nil {
			if entry.Kind == SubstrateEntryDirectory {
				if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
					t.Fatal(err)
				}
				info, statErr = os.Lstat(path)
				if statErr != nil {
					t.Fatal(statErr)
				}
			}
			owners.set(info, acornFoxLivePrincipalForEntry(layout, entry))
		}
	}
	store.ownership = owners.edge()
	if _, err := materializeAcornFoxLive(context.Background(), store, published, receipt.BindingSHA256); err != nil {
		t.Fatalf("materialize=%v", err)
	}
	sentinel := filepath.Join(parent, "outside-managed-sentinel")
	raw := []byte("stable")
	if err := os.WriteFile(sentinel, raw, durableFileMode); err != nil {
		t.Fatal(err)
	}
	return acornFoxProductionPreparedFixture{parent: parent, host: host, state: state, layout: layout, store: store, published: published, binding: receipt.BindingSHA256, owners: owners, sentinel: sentinel, raw: raw}
}

func (f acornFoxProductionPreparedFixture) assertExternalSentinel(t *testing.T) {
	t.Helper()
	info, err := os.Lstat(f.sentinel)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("sentinel info=%#v err=%v", info, err)
	}
	raw, err := os.ReadFile(f.sentinel)
	if err != nil || !bytes.Equal(raw, f.raw) {
		t.Fatalf("sentinel raw=%q err=%v", raw, err)
	}
}

func mustMarshalInactiveSubstrateReceipt(t *testing.T, receipt InactiveSubstrateReceiptV1) []byte {
	t.Helper()
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func acornFoxTestLayoutPrincipals() map[AcornFoxLiveRole]acornFoxInstallPrincipal {
	return map[AcornFoxLiveRole]acornFoxInstallPrincipal{
		AcornFoxLiveRootRole:     {},
		AcornFoxLiveServerRole:   {uid: 1001, gid: 1001},
		AcornFoxLiveAgentRole:    {uid: 1002, gid: 1002},
		AcornFoxLiveBuildKitRole: {uid: 1003, gid: 1003},
		AcornFoxLiveCaddyRole:    {uid: 1004, gid: 1004},
		AcornFoxLiveEdgeRole:     {uid: 1005, gid: 1005},
	}
}

type acornFoxTestOwnerRecorder struct {
	values map[[2]uint64]acornFoxInstallPrincipal
}

func acornFoxTestOwnershipRecorder(t *testing.T) *acornFoxTestOwnerRecorder {
	t.Helper()
	return &acornFoxTestOwnerRecorder{values: map[[2]uint64]acornFoxInstallPrincipal{}}
}
func (r *acornFoxTestOwnerRecorder) set(info os.FileInfo, principal acornFoxInstallPrincipal) {
	r.values[acornFoxTestOwnerInfoKey(info)] = principal
}
func (r *acornFoxTestOwnerRecorder) edge() acornFoxOwnershipEdge {
	return acornFoxOwnershipEdge{
		chown: func(file acornFoxRepoFile, uid, gid int) error {
			info, err := file.Stat()
			if err == nil {
				r.set(info, acornFoxInstallPrincipal{uid: uid, gid: gid})
			}
			return err
		},
		lchown: func(root *os.Root, path string, uid, gid int) error {
			info, err := root.Lstat(path)
			if err == nil {
				r.set(info, acornFoxInstallPrincipal{uid: uid, gid: gid})
			}
			return err
		},
		observe: func(info os.FileInfo) (acornFoxInstallPrincipal, bool) {
			value, ok := r.values[acornFoxTestOwnerInfoKey(info)]
			return value, ok
		},
	}
}
func acornFoxTestOwnerInfoKey(info os.FileInfo) [2]uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic("missing stat")
	}
	return [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
}

func readAcornFoxLayoutRootFile(t *testing.T, root *os.Root, name string) []byte {
	t.Helper()
	file, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read %s: %v %v", name, readErr, closeErr)
	}
	return raw
}

func acornFoxLayoutCreatePreparedJournal(t *testing.T, store *TaskAcornFoxRepoStore, receipt InactiveSubstrateReceiptV1) {
	t.Helper()
	lock, err := store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalInactiveSubstrateReceiptV1(receipt)
	if err != nil {
		_ = lock.Release()
		t.Fatal(err)
	}
	journal := newAcornFoxRepoJournal()
	journal.BindingSHA256 = receipt.CandidateReceipt.BindingSHA256
	journal.SubstrateReceiptSHA256 = sha256Hex(raw)
	journal.LayoutSHA256 = store.layout.evidence()
	prepared, err := acornFoxRepoPreparedEvidenceForLayout(journal.LayoutSHA256, journal.BindingSHA256, journal.SubstrateReceiptSHA256)
	if err == nil {
		journal.History[0].EvidenceSHA256 = prepared
		err = journal.Validate()
	}
	if err == nil {
		err = store.Create(context.Background(), journal)
	}
	releaseErr := lock.Release()
	if err != nil || releaseErr != nil {
		t.Fatalf("create production test journal err=%v release=%v", err, releaseErr)
	}
}

func sameAcornFoxStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
