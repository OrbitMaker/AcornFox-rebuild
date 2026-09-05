package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
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
