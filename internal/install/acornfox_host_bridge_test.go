package install

import (
	"bytes"
	"context"
	"errors"
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
