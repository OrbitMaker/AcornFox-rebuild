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
	"strings"
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

func TestCandidateArtifactReceiptV1RequiresExactNamedCrossHashes(t *testing.T) {
	stage := candidateArtifactFixture(t)
	defer func() { _ = os.RemoveAll(stage.root) }()
	receipt, err := stage.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source_repository"`) || !strings.Contains(string(raw), `"architecture":"amd64"`) || !strings.Contains(string(raw), `"migration_version":"`+Migration+`"`) {
		t.Fatalf("receipt JSON lost stable schema fields: %s", raw)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*CandidateArtifactReceiptV1)
	}{
		{"missing", func(r *CandidateArtifactReceiptV1) { r.Files = r.Files[:len(r.Files)-1] }},
		{"extra", func(r *CandidateArtifactReceiptV1) {
			r.Files = append(r.Files, FileEntryV1{Path: "z-extra", SHA256: strings.Repeat("a", 64), Mode: 0o644})
		}},
		{"renamed", func(r *CandidateArtifactReceiptV1) { r.Files[0].Path = "renamed" }},
		{"swapped", func(r *CandidateArtifactReceiptV1) {
			r.Files[0].SHA256, r.Files[1].SHA256 = r.Files[1].SHA256, r.Files[0].SHA256
		}},
		{"cross hash", func(r *CandidateArtifactReceiptV1) { r.ManifestSHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			changed := receipt
			changed.Files = append([]FileEntryV1(nil), receipt.Files...)
			mutate.fn(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestCandidateArtifactStageRejectsSemanticAndPayloadTampering(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(t *testing.T, stage *CandidateArtifactStageV1)
	}{
		{"manifest identity", func(t *testing.T, stage *CandidateArtifactStageV1) {
			var manifest install.Manifest
			raw := readArtifactFile(t, stage, "release-manifest.json")
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.ReleaseID = "release-9.9.9-test.9"
			writeArtifactFileAndReceipt(t, stage, "release-manifest.json", mustJSON(t, manifest))
		}},
		{"bundle semantics", func(t *testing.T, stage *CandidateArtifactStageV1) {
			writeArtifactFileAndReceipt(t, stage, "bundle-manifest.sha256", []byte(strings.Repeat("0", 64)+"  not-the-archive\n"))
		}},
		{"binding digest file", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "candidate-binding.sha256"), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			setReceiptFileDigest(t, stage, "candidate-binding.sha256")
		}},
		{"binding identity", func(t *testing.T, stage *CandidateArtifactStageV1) {
			var binding install.AcornFoxCandidateBindingV1
			if err := json.Unmarshal(readArtifactFile(t, stage, "candidate-binding.json"), &binding); err != nil {
				t.Fatal(err)
			}
			binding.NMinusOne = &install.AcornFoxNMinusOneV1{Version: "1.2.2-test.1", MigrationVersion: "0033", SourceCommit: strings.Repeat("a", 40), ReleaseManifestSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("a", 64), BundleManifestSHA256: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("a", 64)}
			writeArtifactFileAndReceipt(t, stage, "candidate-binding.json", mustJSON(t, binding))
			writeArtifactFileAndReceipt(t, stage, "candidate-binding.sha256", []byte(stage.receipt.BindingSHA256+"\n"))
		}},
		{"build state", func(t *testing.T, stage *CandidateArtifactStageV1) {
			var record candidateBuildRecordV1
			if err := json.Unmarshal(readArtifactFile(t, stage, "build-record.json"), &record); err != nil {
				t.Fatal(err)
			}
			record.State = "PUBLISHED"
			writeArtifactFileAndReceipt(t, stage, "build-record.json", mustJSON(t, record))
		}},
		{"payload extra", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "payload", "release", "extra"), []byte("extra"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload missing", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.Remove(filepath.Join(stage.root, "payload", "release", stage.treeReceipt.Files[0].Path)); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload mode", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.Chmod(filepath.Join(stage.root, "payload", "release", stage.treeReceipt.Files[0].Path), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload manifest mode", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.Chmod(filepath.Join(stage.root, "payload", "release", "manifest.json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload manifest content", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "payload", "release", "manifest.json"), []byte(`{"schema_version":0}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload link", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.Symlink("release-manifest.json", filepath.Join(stage.root, "payload", "release", "unexpected-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"archive hash", func(t *testing.T, stage *CandidateArtifactStageV1) {
			archive := "acornfox-" + stage.receipt.Version + "-production.tar.gz"
			if err := os.WriteFile(filepath.Join(stage.root, archive), []byte("not an archive"), 0o644); err != nil {
				t.Fatal(err)
			}
			setReceiptFileDigest(t, stage, archive)
			stage.receipt.ArchiveSHA256 = stage.receipt.Files[indexArtifactFile(t, stage.receipt.Files, archive)].SHA256
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			stage := candidateArtifactFixture(t)
			defer func() { _ = os.RemoveAll(stage.root) }()
			mutate.fn(t, stage)
			if _, err := stage.Receipt(); err == nil {
				t.Fatal("tampered stage was accepted")
			}
		})
	}
}

func candidateArtifactFixture(t *testing.T) *CandidateArtifactStageV1 {
	t.Helper()
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t)
	defer goStage.Close()
	defer webStage.Close()
	tree, err := BuildCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	return stage
}

func readArtifactFile(t *testing.T, stage *CandidateArtifactStageV1, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stage.root, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeArtifactFileAndReceipt(t *testing.T, stage *CandidateArtifactStageV1, name string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stage.root, name), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	setReceiptFileDigest(t, stage, name)
	switch name {
	case "release-manifest.json":
		stage.receipt.ManifestSHA256 = sha256Text(raw)
	case "bundle-manifest.sha256":
		stage.receipt.BundleSHA256 = sha256Text(raw)
	case "candidate-binding.json":
		stage.receipt.BindingSHA256 = sha256Text(raw)
	case "build-record.json":
		stage.receipt.BuildRecordSHA256 = sha256Text(raw)
	}
}

func setReceiptFileDigest(t *testing.T, stage *CandidateArtifactStageV1, name string) {
	t.Helper()
	stage.receipt.Files[indexArtifactFile(t, stage.receipt.Files, name)].SHA256 = sha256Text(readArtifactFile(t, stage, name))
}

func indexArtifactFile(t *testing.T, files []FileEntryV1, name string) int {
	t.Helper()
	for i := range files {
		if files[i].Path == name {
			return i
		}
	}
	t.Fatalf("missing artifact file %s", name)
	return -1
}
