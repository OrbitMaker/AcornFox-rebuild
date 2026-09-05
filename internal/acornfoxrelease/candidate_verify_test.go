package acornfoxrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

func TestVerifySyntheticCandidateV1TransfersSingleCleanupOwnership(t *testing.T) {
	stage := candidateArtifactFixture(t)
	verified, err := VerifySyntheticCandidateV1(stage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Receipt(); err == nil {
		t.Fatal("original stage remained readable after transfer")
	}
	if err := stage.Close(); err == nil {
		t.Fatal("original stage retained cleanup after transfer")
	}
	receipt, err := verified.Receipt()
	if err != nil || receipt.Validate() != nil || receipt.State != syntheticCandidateInternallyVerified || !receipt.Synthetic || !receipt.InstallerVerified || receipt.ProductionAccepted || receipt.PublicReleased {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	bindingRaw := readArtifactFile(t, stage, "candidate-binding.json")
	var binding install.AcornFoxCandidateBindingV1
	if err := json.Unmarshal(bindingRaw, &binding); err != nil || binding.NMinusOne != nil {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
	var manifest install.Manifest
	if err := json.Unmarshal(readArtifactFile(t, stage, "release-manifest.json"), &manifest); err != nil || manifest.NMinusOne != nil {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Receipt(); err == nil {
		t.Fatal("closed verified stage remained readable")
	}
}

func TestVerifySyntheticCandidateV1RejectsOrdinaryTamperingWithoutTransfer(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(t *testing.T, stage *CandidateArtifactStageV1)
	}{
		{"binding", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "candidate-binding.json"), []byte(`{"schema_version":0}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "release-manifest.json"), []byte(`{"schema_version":0}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"bundle", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, "bundle-manifest.sha256"), []byte("bad\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"archive", func(t *testing.T, stage *CandidateArtifactStageV1) {
			if err := os.WriteFile(filepath.Join(stage.root, candidateArchiveName(stage.receipt.Version)), []byte("bad"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			stage := candidateArtifactFixture(t)
			defer func() { _ = os.RemoveAll(stage.root) }()
			mutate.fn(t, stage)
			if verified, err := VerifySyntheticCandidateV1(stage); err == nil || verified != nil || stage.transferred {
				t.Fatalf("verified=%#v err=%v transferred=%t", verified, err, stage.transferred)
			}
		})
	}
}

func TestVerifySyntheticCandidateV1RejectsSelfConsistentMalformedArchive(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(t *testing.T, stage *CandidateArtifactStageV1) []byte
	}{
		{"pax", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{pax: true})
		}},
		{"nonroot", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{uid: 1})
		}},
		{"wrong mode", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{wrongMode: true})
		}},
		{"extra member", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{extra: true})
		}},
		{"missing member", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{missing: true})
		}},
		{"changed member", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return archiveForCandidateTest(t, stage, archiveTestOptions{changed: true})
		}},
		{"trailing bytes", func(t *testing.T, stage *CandidateArtifactStageV1) []byte {
			return append(archiveForCandidateTest(t, stage, archiveTestOptions{}), []byte("trailing")...)
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			stage := candidateArtifactFixture(t)
			defer func() { _ = os.RemoveAll(stage.root) }()
			rewriteArchiveDAG(t, stage, mutate.fn(t, stage))
			if !stage.validOwned() {
				t.Fatal("02B precondition rejected self-consistent archive")
			}
			if verified, err := VerifySyntheticCandidateV1(stage); err == nil || verified != nil || stage.transferred {
				t.Fatalf("verified=%#v err=%v transferred=%t", verified, err, stage.transferred)
			}
			if !stage.validOwned() {
				t.Fatal("failed installer verification consumed caller-owned valid stage")
			}
		})
	}
}

func TestVerifiedCandidateStageV1RejectsPostTransferMutationAndReplacement(t *testing.T) {
	t.Run("byte mutation", func(t *testing.T) {
		stage := candidateArtifactFixture(t)
		defer func() { _ = os.RemoveAll(stage.root) }()
		verified, err := VerifySyntheticCandidateV1(stage)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage.root, candidateArchiveName(stage.receipt.Version)), []byte("changed"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := verified.Receipt(); err == nil {
			t.Fatal("post-transfer mutation accepted")
		}
		if err := verified.Close(); err == nil {
			t.Fatal("post-transfer mutation removed stage")
		}
	})
	t.Run("foreign replacement", func(t *testing.T) {
		stage := candidateArtifactFixture(t)
		defer func() { _ = os.RemoveAll(stage.root) }()
		verified, err := VerifySyntheticCandidateV1(stage)
		if err != nil {
			t.Fatal(err)
		}
		moved := stage.root + "-moved"
		if err := os.Rename(stage.root, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(stage.root, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := verified.Receipt(); err == nil {
			t.Fatal("replacement accepted")
		}
		if err := verified.Close(); err == nil {
			t.Fatal("replacement removed foreign path")
		}
		if _, err := os.Stat(moved); err != nil {
			t.Fatalf("original moved stage was removed: %v", err)
		}
	})
}

type archiveTestOptions struct {
	pax, wrongMode, extra, missing, changed bool
	uid                                     int
}

func archiveForCandidateTest(t *testing.T, stage *CandidateArtifactStageV1, options archiveTestOptions) []byte {
	t.Helper()
	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gz.Header.ModTime, gz.Header.OS = time.Unix(0, 0), 255
	tw := tar.NewWriter(gz)
	members := append([]install.FileDigest(nil), stage.treeReceipt.Files...)
	members = append(members, install.FileDigest{Path: "manifest.json", SHA256: stage.receipt.ManifestSHA256, Mode: 0o644})
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	for index, member := range members {
		if options.missing && index == 0 {
			continue
		}
		body := readArtifactFile(t, stage, filepath.Join("payload", "release", member.Path))
		if options.changed && index == 0 {
			body = append([]byte("x"), body[1:]...)
		}
		mode := int64(member.Mode)
		if options.wrongMode && index == 0 {
			mode = 0o600
		}
		format := tar.FormatUSTAR
		if options.pax && index == 0 {
			format = tar.FormatPAX
		}
		header := &tar.Header{Name: "release/" + member.Path, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: format, ModTime: time.Unix(0, 0), Uid: options.uid, Gid: 0}
		if options.pax && index == 0 {
			header.PAXRecords = map[string]string{"comment": "synthetic"}
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if options.extra {
		body := []byte("extra")
		if err := tw.WriteHeader(&tar.Header{Name: "release/extra", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func rewriteArchiveDAG(t *testing.T, stage *CandidateArtifactStageV1, archive []byte) {
	t.Helper()
	archiveName := candidateArchiveName(stage.receipt.Version)
	if err := os.WriteFile(filepath.Join(stage.root, archiveName), archive, 0o644); err != nil {
		t.Fatal(err)
	}
	stage.receipt.ArchiveSHA256 = sha256Text(archive)
	setReceiptFileDigest(t, stage, archiveName)
	bundle := []byte(stage.receipt.ArchiveSHA256 + "  " + archiveName + "\n" + stage.receipt.ManifestSHA256 + "  release/manifest.json\n")
	writeArtifactFileAndReceipt(t, stage, "bundle-manifest.sha256", bundle)
	var binding install.AcornFoxCandidateBindingV1
	if err := json.Unmarshal(readArtifactFile(t, stage, "candidate-binding.json"), &binding); err != nil {
		t.Fatal(err)
	}
	binding.ArchiveSHA256, binding.BundleManifestSHA256 = stage.receipt.ArchiveSHA256, stage.receipt.BundleSHA256
	writeArtifactFileAndReceipt(t, stage, "candidate-binding.json", mustJSON(t, binding))
	writeArtifactFileAndReceipt(t, stage, "candidate-binding.sha256", []byte(stage.receipt.BindingSHA256+"\n"))
	var record candidateBuildRecordV1
	if err := json.Unmarshal(readArtifactFile(t, stage, "build-record.json"), &record); err != nil {
		t.Fatal(err)
	}
	record.ArchiveSHA256, record.BundleSHA256, record.BindingSHA256 = stage.receipt.ArchiveSHA256, stage.receipt.BundleSHA256, stage.receipt.BindingSHA256
	writeArtifactFileAndReceipt(t, stage, "build-record.json", mustJSON(t, record))
}
