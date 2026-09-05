package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestLoadAcornFoxCandidateSetPinsSixFilesAndSelfTripleDigest(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate")
	if err := os.Mkdir(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), raw, 0o644); err != nil {
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
	var upgrade FileDigest
	for _, entry := range manifest.Files {
		if entry.Path == "bin/acornfox-upgrade" {
			upgrade = entry
			break
		}
	}
	if upgrade.SHA256 == "" {
		t.Fatal("fixture lacks upgrade entry")
	}
	self := filepath.Join(parent, "self")
	if err := os.WriteFile(self, []byte("content: bin/acornfox-upgrade\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	set, err := loadAcornFoxCandidateSet(acornFoxCandidateSetRequest{Directory: root, BindingSHA256: fixture.bindingSHA, SelfSHA256: upgrade.SHA256}, nil, acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if set.bindingSHA256 != fixture.bindingSHA || set.archiveSize != int64(len(fixture.archive)) || !bytes.Equal(set.buildRecordRaw, []byte(`{"opaque":true}`)) {
		t.Fatalf("set=%#v", set)
	}
	if pos, seekErr := set.archive.Seek(0, 1); seekErr != nil || pos != 0 {
		t.Fatalf("archive not rewound pos=%d err=%v", pos, seekErr)
	}
	if err := os.WriteFile(filepath.Join(root, acornFoxCandidateBindingDigestFile), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAcornFoxCandidateSet(acornFoxCandidateSetRequest{Directory: root, BindingSHA256: fixture.bindingSHA, SelfSHA256: upgrade.SHA256}, nil, acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()}); err == nil {
		t.Fatal("sidecar substituted independent binding authority")
	}
}

func TestAcornFoxBindingStoreIsContentAddressedAndRejectsTamper(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	store, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	bindings := newAcornFoxBindingStore(store)
	if err := bindings.Put(fixture.bindingRaw); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Put(fixture.bindingRaw); err != nil {
		t.Fatal(err)
	}
	raw, err := bindings.Read(fixture.bindingSHA)
	if err != nil || !bytes.Equal(raw, fixture.bindingRaw) {
		t.Fatalf("read=%q err=%v", raw, err)
	}
	path := filepath.Join(root, acornFoxBindingStoreDir, fixture.bindingSHA+".json")
	if err := os.WriteFile(path, []byte("tampered"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := bindings.Read(fixture.bindingSHA); err == nil {
		t.Fatal("tampered binding accepted")
	}
}

func TestAcornFoxBindingStoreSerializesConcurrentPutAndReconcilesOrphan(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, durableDirMode); err != nil {
		t.Fatal(err)
	}
	first, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	seed := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	if err := newAcornFoxBindingStore(first).Put(seed.bindingRaw); err != nil {
		t.Fatal(err)
	}
	fixture := newAcornFoxFixture(t, "1.2.4-test.1", nil)
	second, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for _, store := range []*TaskAcornFoxRepoStore{first, second} {
		group.Add(1)
		go func(store *TaskAcornFoxRepoStore) {
			defer group.Done()
			errs <- newAcornFoxBindingStore(store).Put(fixture.bindingRaw)
		}(store)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent put: %v", err)
		}
	}
	orphan := newAcornFoxFixture(t, "1.2.5-test.1", nil)
	tmp := filepath.Join(root, acornFoxBindingStoreDir, orphan.bindingSHA+".tmp")
	if err := os.WriteFile(tmp, orphan.bindingRaw, durableFileMode); err != nil {
		t.Fatal(err)
	}
	raw, err := newAcornFoxBindingStore(first).Read(orphan.bindingSHA)
	if err != nil || !bytes.Equal(raw, orphan.bindingRaw) {
		t.Fatalf("orphan read=%q err=%v", raw, err)
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatalf("orphan tmp remains: %v", err)
	}
}

func TestAcornFoxSelfVerifierRejectsInjectedSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.WriteFile(target, []byte("self"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "self-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("self"))
	digest := hex.EncodeToString(sum[:])
	manifest, err := json.Marshal(Manifest{Files: []FileDigest{{Path: "bin/acornfox-upgrade", SHA256: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := (acornFoxSelfVerifier{path: link, uid: os.Getuid(), gid: os.Getgid()}).verify(digest, manifest); err == nil {
		t.Fatal("injected symlink accepted")
	}
}

func TestAcornFoxProductionSelfVerifierUsesLinuxProcDescriptor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs production path is Linux-only")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	manifest, err := json.Marshal(Manifest{Files: []FileDigest{{Path: "bin/acornfox-upgrade", SHA256: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := newAcornFoxProductionSelfVerifier().verify(digest, manifest); err != nil {
		t.Fatalf("proc self verification: %v", err)
	}
}
