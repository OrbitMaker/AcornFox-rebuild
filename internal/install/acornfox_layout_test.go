package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	state := filepath.Join(parent, "state")
	host := filepath.Join(parent, "host")
	for _, path := range []string{state, host} {
		if err := os.Mkdir(path, durableDirMode); err != nil {
			t.Fatal(err)
		}
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
	if _, err := newTestProductionAcornFoxLayout(state, state, os.Getuid(), os.Getgid(), principals); err == nil {
		t.Fatal("same production roots were accepted")
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
	state, host := filepath.Join(parent, "state"), filepath.Join(parent, "host")
	for _, path := range []string{state, host} {
		if err := os.Mkdir(path, durableDirMode); err != nil {
			t.Fatal(err)
		}
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
	if files, err := os.ReadDir(host); err != nil || len(files) != 0 {
		t.Fatalf("host received state data files=%v err=%v", files, err)
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
	if _, err := materializeAcornFoxLive(context.Background(), store, published, receipt.BindingSHA256); !errors.Is(err, ErrAcornFoxLiveConflict) {
		t.Fatalf("L2 production materialize=%v", err)
	}
	if files, err := os.ReadDir(host); err != nil || len(files) != 0 {
		t.Fatalf("gated L2 materialization changed host files=%v err=%v", files, err)
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
	if err := os.Rename(state, state+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.openRoot(); !errors.Is(err, ErrAcornFoxRepoConflict) {
		t.Fatalf("replaced state root open=%v", err)
	}
	if got := acornFoxProductionManagedRoots(); !sameAcornFoxStringSlice(got, []string{"opt/acornfox", "etc/acornfox", "var/lib/acornfox", "var/log/acornfox"}) {
		t.Fatalf("production scope=%q", got)
	}
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
	prepared, err := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
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
