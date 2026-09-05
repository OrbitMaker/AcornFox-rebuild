package acornfoxrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

func TestSealCandidateArtifactsV1ProducesDeterministicPrivateArtifacts(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	tree, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	first, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	left, err := first.Receipt()
	if err != nil || left.Validate() != nil {
		t.Fatalf("receipt=%#v err=%v", left, err)
	}
	right, err := second.Receipt()
	if err != nil || !sameFileEntries(left.Files, right.Files) {
		t.Fatalf("receipts differ %#v %#v %v", left, right, err)
	}
	for _, file := range left.Files {
		a, ea := os.ReadFile(filepath.Join(first.root, file.Path))
		b, eb := os.ReadFile(filepath.Join(second.root, file.Path))
		if ea != nil || eb != nil || !bytes.Equal(a, b) {
			t.Fatalf("artifact differs %s", file.Path)
		}
	}
	manifestRaw, err := os.ReadFile(filepath.Join(first.root, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest install.Manifest
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil || manifest.NMinusOne != nil || len(manifest.Files) != len(tree.receipt.Files) {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	archive := filepath.Join(first.root, "acornfox-"+tree.receipt.Version+"-production.tar.gz")
	checkSyntheticArchive(t, archive, manifestRaw, tree.receipt.Files)
	bundle, err := os.ReadFile(filepath.Join(first.root, "bundle-manifest.sha256"))
	if err != nil || string(bundle) != left.ArchiveSHA256+"  acornfox-"+left.Version+"-production.tar.gz\n"+left.ManifestSHA256+"  release/manifest.json\n" {
		t.Fatalf("bundle=%q err=%v", bundle, err)
	}
	bindingRaw, err := os.ReadFile(filepath.Join(first.root, "candidate-binding.json"))
	if err != nil {
		t.Fatal(err)
	}
	var binding install.AcornFoxCandidateBindingV1
	if err = json.Unmarshal(bindingRaw, &binding); err != nil || binding.NMinusOne != nil || binding.ArchiveSHA256 != left.ArchiveSHA256 {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
}

func checkSyntheticArchive(t *testing.T, path string, manifest []byte, files []install.FileDigest) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !gz.Header.ModTime.IsZero() || gz.Header.OS != 255 {
		t.Fatalf("gzip header %#v", gz.Header)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(time.Unix(0, 0)) || h.Uname != "" || h.Gname != "" {
			t.Fatalf("bad tar header %#v", h)
		}
		body, e := io.ReadAll(tr)
		if e != nil {
			t.Fatal(e)
		}
		names = append(names, h.Name)
		if h.Name == "release/manifest.json" && !bytes.Equal(body, manifest) {
			t.Fatal("manifest bytes drift")
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"release/manifest.json"}
	for _, f := range files {
		want = append(want, "release/"+f.Path)
	}
	sort.Strings(want)
	if len(names) != len(want) {
		t.Fatalf("names=%d want=%d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("name %d=%s want=%s", i, names[i], want[i])
		}
	}
}

func TestCandidateArtifactStageRejectsReplacement(t *testing.T) {
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	tree, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	stage, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	moved := stage.root + "-moved"
	if err = os.Rename(stage.root, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(stage.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = stage.Receipt(); err == nil {
		t.Fatal("replacement accepted")
	}
	if err = stage.Close(); err == nil {
		t.Fatal("replacement close accepted")
	}
}
