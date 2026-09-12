package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAcornFoxHostBridgeBootstrapsAndRecoversFixedTestLayout(t *testing.T) {
	prepared := newAcornFoxProductionPreparedFixture(t)
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	candidate, self, selfSHA := writeAcornFoxBridgeCandidate(t, prepared.parent, fixture)
	bridge := newAcornFoxHostBridge(prepared.layout, acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()})
	bridge.ownership = prepared.owners.edge()
	first, err := bridge.bootstrap(context.Background(), AcornFoxCandidateSetRequestV1{Directory: candidate, BindingSHA256: fixture.bindingSHA, SelfSHA256: selfSHA})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err != nil || first.State != "REPO_PREPARED" || first.BindingSHA256 != fixture.bindingSHA || first.LayoutSHA256 != prepared.layout.evidence() {
		t.Fatalf("receipt=%#v err=%v", first, err)
	}
	second, err := bridge.bootstrap(context.Background(), AcornFoxCandidateSetRequestV1{Directory: candidate, BindingSHA256: fixture.bindingSHA, SelfSHA256: selfSHA})
	if err != nil || second != first {
		t.Fatalf("replay=%#v err=%v", second, err)
	}
	recovered, err := bridge.recover(context.Background())
	if err != nil || recovered != first {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	raw, err := MarshalAcornFoxHostBootstrapReceiptV1(first)
	if err != nil || !bytes.Equal(raw, mustMarshalAcornFoxHostReceipt(t, first)) {
		t.Fatalf("canonical receipt err=%v raw=%q", err, raw)
	}
}

func TestAcornFoxHostBridgeRejectsPreparedStateTamper(t *testing.T) {
	mutations := map[string]func(t *testing.T, prepared acornFoxProductionPreparedFixture){
		"release-bytes": func(t *testing.T, prepared acornFoxProductionPreparedFixture) {
			path := filepath.Join(prepared.host, "var", "lib", "acornfox", "install", "releases", prepared.published.receipt.CandidateReceipt.ReleaseID+".json")
			if err := os.WriteFile(path, []byte("tampered"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		},
		"current-target": func(t *testing.T, prepared acornFoxProductionPreparedFixture) {
			path := filepath.Join(prepared.host, "opt", "acornfox", "current")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("wrong-target", path); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-managed-entry": func(t *testing.T, prepared acornFoxProductionPreparedFixture) {
			if err := os.WriteFile(filepath.Join(prepared.host, "opt", "acornfox", "foreign"), []byte("foreign"), durableFileMode); err != nil {
				t.Fatal(err)
			}
		},
		"binding-evidence": func(t *testing.T, prepared acornFoxProductionPreparedFixture) {
			if err := os.Remove(filepath.Join(prepared.state, acornFoxBindingStoreDir, prepared.binding+".json")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			prepared := newAcornFoxProductionPreparedFixture(t)
			fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
			candidate, self, selfSHA := writeAcornFoxBridgeCandidate(t, prepared.parent, fixture)
			bridge := newAcornFoxHostBridge(prepared.layout, acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()})
			bridge.ownership = prepared.owners.edge()
			if _, err := bridge.bootstrap(context.Background(), AcornFoxCandidateSetRequestV1{Directory: candidate, BindingSHA256: fixture.bindingSHA, SelfSHA256: selfSHA}); err != nil {
				t.Fatal(err)
			}
			mutate(t, prepared)
			if receipt, err := bridge.bootstrap(context.Background(), AcornFoxCandidateSetRequestV1{Directory: candidate, BindingSHA256: fixture.bindingSHA, SelfSHA256: selfSHA}); err == nil {
				t.Fatalf("tampered replay accepted: %#v", receipt)
			}
			fresh := newAcornFoxHostBridge(prepared.layout, acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()})
			fresh.ownership = prepared.owners.edge()
			if receipt, err := fresh.recover(context.Background()); err == nil {
				t.Fatalf("tampered recovery accepted: %#v", receipt)
			}
			prepared.assertExternalSentinel(t)
		})
	}
}

func TestAcornFoxHostBridgeVerifyPreparedRequiresFinalAndRechecksScope(t *testing.T) {
	prepared := newAcornFoxProductionPreparedFixture(t)
	bridge := newAcornFoxHostBridge(prepared.layout, acornFoxSelfVerifier{path: filepath.Join(prepared.parent, "self"), uid: os.Getuid(), gid: os.Getgid()})
	bridge.ownership = prepared.owners.edge()
	before, err := prepared.store.Resume(context.Background())
	if err != nil || before.Phase != AcornFoxRepoStaticVerified {
		t.Fatalf("before=%#v err=%v", before, err)
	}
	if _, err := bridge.verifyPrepared(context.Background()); !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
		t.Fatalf("unfinished journal accepted: %v", err)
	}
	after, err := prepared.store.Resume(context.Background())
	if err != nil || !sameAcornFoxRepoJournal(after, before) {
		t.Fatalf("unfinished journal changed: before=%#v after=%#v err=%v", before, after, err)
	}
	if err := prepareAcornFoxRepository(context.Background(), prepared.store, prepared.published, prepared.binding); err != nil {
		t.Fatal(err)
	}
	verified, err := bridge.verifyPrepared(context.Background())
	if err != nil || verified.Validate() != nil {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	if err := os.WriteFile(filepath.Join(prepared.host, "opt", "acornfox", "foreign"), []byte("foreign"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.verifyPrepared(context.Background()); err == nil {
		t.Fatal("tampered managed scope accepted")
	}
	prepared.assertExternalSentinel(t)
}

type acornFoxHostRootInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (i acornFoxHostRootInfo) Name() string       { return "/" }
func (i acornFoxHostRootInfo) Size() int64        { return 0 }
func (i acornFoxHostRootInfo) Mode() os.FileMode  { return i.mode }
func (i acornFoxHostRootInfo) ModTime() time.Time { return time.Time{} }
func (i acornFoxHostRootInfo) IsDir() bool        { return i.mode.IsDir() }
func (i acornFoxHostRootInfo) Sys() any           { return &i.stat }

func TestSafeAcornFoxProductionHostRootRequiresRootOwner(t *testing.T) {
	if !safeAcornFoxProductionHostRoot(acornFoxHostRootInfo{mode: os.ModeDir | 0o755}) {
		t.Fatal("root-owned directory rejected")
	}
	if safeAcornFoxProductionHostRoot(acornFoxHostRootInfo{mode: os.ModeDir | 0o755, stat: syscall.Stat_t{Uid: 1, Gid: 1}}) {
		t.Fatal("nonroot directory accepted")
	}
}

func writeAcornFoxBridgeCandidate(t *testing.T, parent string, fixture acornFoxFixture) (directory, self, selfSHA string) {
	t.Helper()
	directory = filepath.Join(parent, "candidate")
	if err := os.Mkdir(directory, durableDirMode); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(acornFoxCandidateBindingFile, fixture.bindingRaw)
	write(acornFoxCandidateBindingDigestFile, []byte(fixture.bindingSHA+"\n"))
	write(acornFoxCandidateManifestFile, fixture.manifestRaw)
	write(acornFoxCandidateBundleFile, fixture.bundleRaw)
	write(acornFoxCandidateBuildRecordFile, []byte(`{"opaque":true}`))
	write(acornFoxCandidateArchiveName(fixture.binding.Version), fixture.archive)
	var manifest Manifest
	if err := strictCanonicalJSON(fixture.manifestRaw, &manifest, "fixture manifest"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Files {
		if entry.Path == "bin/acornfox-upgrade" {
			selfSHA = entry.SHA256
			break
		}
	}
	if selfSHA == "" {
		t.Fatal("fixture lacks upgrade helper")
	}
	self = filepath.Join(parent, "self")
	if err := os.WriteFile(self, []byte("content: bin/acornfox-upgrade\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return directory, self, selfSHA
}

func mustMarshalAcornFoxHostReceipt(t *testing.T, receipt AcornFoxHostBootstrapReceiptV1) []byte {
	t.Helper()
	raw, err := MarshalAcornFoxHostBootstrapReceiptV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Capture bytes and object identity, excluding access times changed by reads.
// Failure messages name paths only: fixture runtime files may contain secrets.
type acornFoxBridgeObjectSnapshot struct {
	mode     os.FileMode
	size     int64
	modified int64
	device   uint64
	inode    uint64
	links    uint64
	uid, gid uint32
	contents string
}

func acornFoxBridgeTreeSnapshot(t *testing.T, root string) map[string]acornFoxBridgeObjectSnapshot {
	t.Helper()
	out := map[string]acornFoxBridgeObjectSnapshot{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("missing filesystem identity")
		}
		contents := ""
		if info.Mode().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			contents = sha256Hex(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			contents, e = os.Readlink(path)
			if e != nil {
				return e
			}
		}
		relative, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		out[relative] = acornFoxBridgeObjectSnapshot{info.Mode(), info.Size(), info.ModTime().UnixNano(), uint64(stat.Dev), stat.Ino, uint64(stat.Nlink), stat.Uid, stat.Gid, contents}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func assertAcornFoxBridgeTreeUnchanged(t *testing.T, root string, before map[string]acornFoxBridgeObjectSnapshot) {
	t.Helper()
	after := acornFoxBridgeTreeSnapshot(t, root)
	if len(after) != len(before) {
		t.Fatalf("verification changed tree entry count: %d -> %d", len(before), len(after))
	}
	for name, want := range before {
		if got, ok := after[name]; !ok || got != want {
			t.Fatalf("verification changed bytes, metadata or identity at %s", name)
		}
	}
}
func acornFoxFinalBridgeFixture(t *testing.T) (acornFoxProductionPreparedFixture, acornFoxHostBridge) {
	t.Helper()
	p := newAcornFoxProductionPreparedFixture(t)
	if e := prepareAcornFoxRepository(context.Background(), p.store, p.published, p.binding); e != nil {
		t.Fatal(e)
	}
	b := newAcornFoxHostBridge(p.layout, acornFoxSelfVerifier{path: filepath.Join(p.parent, "self"), uid: os.Getuid(), gid: os.Getgid()})
	b.ownership = p.owners.edge()
	return p, b
}
func TestAcornFoxHostBridgeVerifyPreparedIsReadOnlyForCompletedTree(t *testing.T) {
	p, b := acornFoxFinalBridgeFixture(t)
	before := acornFoxBridgeTreeSnapshot(t, p.host)
	receipt, e := b.verifyPrepared(context.Background())
	if e != nil || receipt.Validate() != nil || receipt.BindingSHA256 != p.binding {
		t.Fatalf("verify completed: %v", e)
	}
	assertAcornFoxBridgeTreeUnchanged(t, p.host, before)
	p.assertExternalSentinel(t)
}
func TestAcornFoxHostBridgeVerifyPreparedNeverRepairsMetadata(t *testing.T) {
	for _, kind := range []string{"repository-lock", "substrate-lock", "bindings-directory", "binding-lock", "binding-temporary", "binding-unknown", "lock-mode"} {
		t.Run(kind, func(t *testing.T) {
			p, b := acornFoxFinalBridgeFixture(t)
			switch kind {
			case "repository-lock":
				if e := os.Remove(filepath.Join(p.state, acornFoxRepoInstallLock)); e != nil {
					t.Fatal(e)
				}
			case "substrate-lock":
				if e := os.Remove(filepath.Join(p.state, acornFoxSubstrateLock)); e != nil {
					t.Fatal(e)
				}
			case "bindings-directory":
				if e := os.Rename(filepath.Join(p.state, acornFoxBindingStoreDir), filepath.Join(p.parent, "saved-bindings")); e != nil {
					t.Fatal(e)
				}
			case "binding-lock":
				if e := os.Remove(filepath.Join(p.state, acornFoxBindingStoreLockPath)); e != nil {
					t.Fatal(e)
				}
			case "binding-temporary":
				raw, e := os.ReadFile(filepath.Join(p.state, acornFoxBindingStoreDir, p.binding+".json"))
				if e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(p.state, acornFoxBindingStoreDir, p.binding+".tmp"), raw, durableFileMode); e != nil {
					t.Fatal(e)
				}
			case "binding-unknown":
				if e := os.WriteFile(filepath.Join(p.state, acornFoxBindingStoreDir, "unknown"), []byte("retain"), durableFileMode); e != nil {
					t.Fatal(e)
				}
			case "lock-mode":
				if e := os.Chmod(filepath.Join(p.state, acornFoxRepoInstallLock), 0666); e != nil {
					t.Fatal(e)
				}
			}
			before := acornFoxBridgeTreeSnapshot(t, p.host)
			if _, e := b.verifyPrepared(context.Background()); e == nil {
				t.Fatal("incomplete/unsafe metadata accepted")
			}
			assertAcornFoxBridgeTreeUnchanged(t, p.host, before)
			p.assertExternalSentinel(t)
		})
	}
}
func TestAcornFoxHostBridgeVerifyPreparedRechecksPhaseAfterConcurrentWriter(t *testing.T) {
	for _, recovering := range []bool{false, true} {
		t.Run(fmt.Sprint(recovering), func(t *testing.T) {
			p, b := acornFoxFinalBridgeFixture(t)
			initial, e := p.store.Resume(context.Background())
			if e != nil || initial.Phase != AcornFoxRepoPreparedFinal {
				t.Fatal("initial final phase missing")
			}
			// The first, unlocked facade observation has seen FINAL. Model another
			// coordinator publishing a valid CURRENT_PUBLISHED prefix before lease lock.
			switched := initial
			switched.Phase = AcornFoxRepoCurrentPublished
			switched.Revision--
			switched.History = append([]AcornFoxRepoHistoryV1(nil), initial.History[:len(initial.History)-1]...)
			if recovering {
				switched = acornFoxRepoFailure(switched, switched.ActivationSHA256)
			}
			raw, e := MarshalAcornFoxRepoJournalV1(switched)
			if e != nil {
				t.Fatal(e)
			}
			writer, e := newAcornFoxRepoStoreForLayout(p.layout)
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			writer.ownership = p.owners.edge()
			begin, done := make(chan struct{}), make(chan error, 1)
			go func() {
				<-begin
				lock, e := writer.Acquire(context.Background())
				if e == nil {
					e = os.WriteFile(filepath.Join(p.state, acornFoxRepoInstallJournal), raw, durableFileMode)
					release := lock.Release()
					if e == nil {
						e = release
					}
				}
				done <- e
			}()
			fired := false
			var before map[string]acornFoxBridgeObjectSnapshot
			b.beforeVerifyPreparedLease = func() {
				fired = true
				close(begin)
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				before = acornFoxBridgeTreeSnapshot(t, p.host)
			}
			if _, e := b.verifyPrepared(context.Background()); e == nil {
				t.Fatal("concurrent nonfinal prefix advanced or accepted")
			}
			if !fired {
				t.Fatal("concurrent writer boundary not exercised")
			}
			assertAcornFoxBridgeTreeUnchanged(t, p.host, before)
			got, e := p.store.Resume(context.Background())
			if e != nil || !sameAcornFoxRepoJournal(got, switched) {
				t.Fatal("read-only verification changed the new prefix")
			}
		})
	}
}
func TestAcornFoxHostBridgeVerifyPreparedHoldsLeaseAndDoesNotReleaseCallerLock(t *testing.T) {
	p, b := acornFoxFinalBridgeFixture(t)
	other, e := newAcornFoxRepoStoreForLayout(p.layout)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	before := acornFoxBridgeTreeSnapshot(t, p.host)
	originalOpen := p.store.fs.openFile
	checked := false
	p.store.fs.openFile = func(root *os.Root, name string, flags int, mode os.FileMode) (acornFoxRepoFile, error) {
		if name == acornFoxRepoInstallJournal && !checked {
			checked = true
			lock, e := other.Acquire(context.Background())
			if lock != nil {
				lock.Release()
			}
			if !errors.Is(e, ErrAcornFoxRepoLocked) {
				t.Fatalf("writer entered during read-only lease: %v", e)
			}
		}
		return originalOpen(root, name, flags, mode)
	}
	if _, e := b.verifyPreparedRepository(context.Background(), p.store, p.published, p.binding); e != nil {
		t.Fatal(e)
	}
	if !checked {
		t.Fatal("locked journal read not observed")
	}
	if p.store.ownsLock() {
		t.Fatal("private view leaked lock into caller")
	}
	p.store.fs.openFile = originalOpen
	caller, e := p.store.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := b.verifyPreparedRepository(context.Background(), p.store, p.published, p.binding); e == nil {
		t.Fatal("borrowed a caller-owned lock")
	}
	if !p.store.ownsLock() {
		t.Fatal("caller-owned lock was released")
	}
	if e := caller.Release(); e != nil {
		t.Fatal(e)
	}
	assertAcornFoxBridgeTreeUnchanged(t, p.host, before)
}
func TestAcornFoxHostBridgeVerifyPreparedAfterLegalUpgradeIsReadOnly(t *testing.T) {
	u, p, request, _ := upgradeFixture(t)
	upgraded, e := u.upgrade(context.Background(), request)
	if e != nil || upgraded.State != "UPGRADED" {
		t.Fatalf("fixture upgrade: %v", e)
	}
	b := newAcornFoxHostBridge(p.layout, u.self)
	b.ownership = p.owners.edge()
	before := acornFoxBridgeTreeSnapshot(t, p.host)
	receipt, e := b.verifyPrepared(context.Background())
	if e != nil || receipt.Validate() != nil || receipt.BindingSHA256 != request.BindingSHA256 || receipt.ReleaseID != upgraded.ReleaseID {
		t.Fatalf("verify upgraded current: %v", e)
	}
	assertAcornFoxBridgeTreeUnchanged(t, p.host, before)
	p.assertExternalSentinel(t)
}
