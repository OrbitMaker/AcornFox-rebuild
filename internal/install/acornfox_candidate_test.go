package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

type acornFoxFixture struct {
	binding                                     AcornFoxCandidateBindingV1
	bindingRaw, manifestRaw, bundleRaw, archive []byte
	bindingSHA                                  string
}

func acornFoxFixtureDigest(value string) string { return strings.Repeat(value, 64) }

func newAcornFoxFixture(t *testing.T, version string, predecessor *acornFoxFixture) acornFoxFixture {
	t.Helper()
	binding := AcornFoxCandidateBindingV1{
		SchemaVersion: AcornFoxCandidateBindingV1Schema, Product: AcornFoxV1Product, Version: version,
		ReleaseID: "release-" + version, SourceRepository: "https://github.com/acornfox/acornfox",
		SourceCommit: strings.Repeat("a", 40), Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxV1MigrationVersion,
		ManifestSHA256: acornFoxFixtureDigest("b"), ArchiveSHA256: acornFoxFixtureDigest("c"), BundleManifestSHA256: acornFoxFixtureDigest("d"),
	}
	if predecessor != nil {
		binding.NMinusOne = &AcornFoxNMinusOneV1{
			Version: predecessor.binding.Version, MigrationVersion: predecessor.binding.MigrationVersion, SourceCommit: predecessor.binding.SourceCommit,
			ReleaseManifestSHA256: predecessor.binding.ManifestSHA256, ArchiveSHA256: predecessor.binding.ArchiveSHA256,
			BundleManifestSHA256: predecessor.binding.BundleManifestSHA256, BindingSHA256: predecessor.bindingSHA,
		}
	}
	files := make([]FileDigest, 0, len(AcornFoxV1RequiredFiles())+1)
	contents := map[string][]byte{}
	for _, required := range AcornFoxV1RequiredFiles() {
		contents[required.Path] = []byte("content: " + required.Path + "\n")
		files = append(files, FileDigest{Path: required.Path, SHA256: sha256Hex(contents[required.Path]), Mode: required.Mode})
	}
	contents["web/dist/assets/app-12345678.js"] = []byte("asset\n")
	files = append(files, FileDigest{Path: "web/dist/assets/app-12345678.js", SHA256: sha256Hex(contents["web/dist/assets/app-12345678.js"]), Mode: 0o644})
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, Product: AcornFoxV1Product, Version: binding.Version, ReleaseID: binding.ReleaseID,
		Architecture: AcornFoxV1Architecture, MigrationVersion: AcornFoxV1MigrationVersion, SourceCommit: binding.SourceCommit,
		Protocol: AgentProtocolVersion, ConfigDir: AcornFoxV1ConfigDir, DataDir: AcornFoxV1DataDir,
		Compatibility: Compatibility{MinDataVersion: 33, MaxDataVersion: 33, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion}, Files: files,
	}
	if binding.NMinusOne != nil {
		n := binding.NMinusOne
		manifest.NMinusOne = &NMinusOne{Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit, ReleaseManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256, BundleManifestSHA256: n.BundleManifestSHA256}
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	archive := acornFoxArchive(t, manifestRaw, files, contents, nil)
	binding.ManifestSHA256, binding.ArchiveSHA256 = sha256Hex(manifestRaw), sha256Hex(archive)
	bundleRaw := []byte("" + binding.ArchiveSHA256 + "  acornfox-" + binding.Version + "-production.tar.gz\n" + binding.ManifestSHA256 + "  release/manifest.json\n")
	binding.BundleManifestSHA256 = sha256Hex(bundleRaw)
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return acornFoxFixture{binding: binding, bindingRaw: bindingRaw, manifestRaw: manifestRaw, bundleRaw: bundleRaw, archive: archive, bindingSHA: sha256Hex(bindingRaw)}
}

func acornFoxArchive(t *testing.T, manifest []byte, files []FileDigest, contents map[string][]byte, mutate func(*tar.Writer)) []byte {
	return acornFoxArchiveWithManifestMode(t, manifest, files, contents, 0o644, mutate)
}

func acornFoxArchiveWithManifestMode(t *testing.T, manifest []byte, files []FileDigest, contents map[string][]byte, manifestMode int64, mutate func(*tar.Writer)) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	write := func(name string, mode int64, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("release/manifest.json", manifestMode, manifest)
	for _, file := range files {
		write("release/"+file.Path, int64(file.Mode), contents[file.Path])
	}
	if mutate != nil {
		mutate(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func (f acornFoxFixture) input(predecessor []byte) VerifyAcornFoxCandidateArtifactsV1Input {
	return VerifyAcornFoxCandidateArtifactsV1Input{Binding: f.bindingRaw, BindingSHA256: f.bindingSHA, Manifest: f.manifestRaw, BundleManifest: f.bundleRaw, Archive: bytes.NewReader(f.archive), ArchiveSize: int64(len(f.archive)), PredecessorBinding: predecessor}
}

func TestVerifyAcornFoxCandidateArtifactsV1CleanAndUpgrade(t *testing.T) {
	clean := newAcornFoxFixture(t, "1.2.2-test.1", nil)
	if verified, err := VerifyAcornFoxCandidateArtifactsV1(clean.input(nil)); err != nil || !verified.valid() {
		t.Fatalf("clean=%#v err=%v", verified, err)
	}
	upgrade := newAcornFoxFixture(t, "1.2.3-test.1", &clean)
	if verified, err := VerifyAcornFoxCandidateArtifactsV1(upgrade.input(clean.bindingRaw)); err != nil || !verified.valid() {
		t.Fatalf("upgrade=%#v err=%v", verified, err)
	}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(upgrade.input(nil)); err == nil {
		t.Fatal("upgrade accepted missing predecessor binding")
	}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(clean.input([]byte("unexpected"))); err == nil {
		t.Fatal("bootstrap accepted predecessor input")
	}
	changedBindingSHA := cloneAcornFoxFixture(upgrade)
	changedBindingSHA.binding.NMinusOne.BindingSHA256 = acornFoxFixtureDigest("f")
	refreshAcornFoxBinding(t, &changedBindingSHA)
	if _, err := VerifyAcornFoxCandidateArtifactsV1(changedBindingSHA.input(clean.bindingRaw)); err == nil {
		t.Fatal("successor accepted changed predecessor binding sha")
	}
}

func TestVerifyAcornFoxCandidateArtifactsV1RejectsDigestMismatches(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, candidate := range []struct {
		name   string
		mutate func(*VerifyAcornFoxCandidateArtifactsV1Input)
	}{
		{"binding", func(in *VerifyAcornFoxCandidateArtifactsV1Input) { in.BindingSHA256 = acornFoxFixtureDigest("f") }},
		{"manifest", func(in *VerifyAcornFoxCandidateArtifactsV1Input) { in.Manifest = append([]byte("x"), in.Manifest...) }},
		{"bundle", func(in *VerifyAcornFoxCandidateArtifactsV1Input) {
			in.BundleManifest = append([]byte("x"), in.BundleManifest...)
		}},
		{"archive", func(in *VerifyAcornFoxCandidateArtifactsV1Input) {
			in.Archive = bytes.NewReader(append([]byte("x"), fixture.archive...))
			in.ArchiveSize++
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			in := fixture.input(nil)
			candidate.mutate(&in)
			if _, err := VerifyAcornFoxCandidateArtifactsV1(in); err == nil {
				t.Fatal("digest mismatch accepted")
			}
		})
	}
}

func TestVerifyAcornFoxCandidateArtifactsV1RejectsJSONAndBundleAliases(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, candidate := range []struct {
		name   string
		mutate func(*acornFoxFixture)
	}{
		{"binding_unknown", func(f *acornFoxFixture) {
			f.bindingRaw = append(f.bindingRaw[:len(f.bindingRaw)-1], []byte(`,"unknown":true}`)...)
			f.bindingSHA = sha256Hex(f.bindingRaw)
		}},
		{"binding_trailing", func(f *acornFoxFixture) {
			f.bindingRaw = append(f.bindingRaw, '\n')
			f.bindingSHA = sha256Hex(f.bindingRaw)
		}},
		{"binding_duplicate_nested", func(f *acornFoxFixture) {
			f.bindingRaw = []byte(`{"schema_version":1,"n_minus_one":{"version":"1.0.0","version":"1.0.0"}}`)
			f.bindingSHA = sha256Hex(f.bindingRaw)
		}},
		{"binding_null", func(f *acornFoxFixture) {
			f.bindingRaw = []byte(`{"schema_version":null}`)
			f.bindingSHA = sha256Hex(f.bindingRaw)
		}},
		{"manifest_unknown", func(f *acornFoxFixture) {
			f.manifestRaw = append(f.manifestRaw[:len(f.manifestRaw)-1], []byte(`,"unknown":true}`)...)
			f.binding.ManifestSHA256 = sha256Hex(f.manifestRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"manifest_duplicate", func(f *acornFoxFixture) {
			f.manifestRaw = []byte(`{"schema_version":1,"schema_version":1}`)
			f.binding.ManifestSHA256 = sha256Hex(f.manifestRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"manifest_null", func(f *acornFoxFixture) {
			f.manifestRaw = []byte(`{"schema_version":null}`)
			f.binding.ManifestSHA256 = sha256Hex(f.manifestRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"manifest_trailing", func(f *acornFoxFixture) {
			f.manifestRaw = append(f.manifestRaw, '\n')
			f.binding.ManifestSHA256 = sha256Hex(f.manifestRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"bundle_extra", func(f *acornFoxFixture) {
			f.bundleRaw = append(f.bundleRaw, []byte("x  nope\n")...)
			f.binding.BundleManifestSHA256 = sha256Hex(f.bundleRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"bundle_order", func(f *acornFoxFixture) {
			f.bundleRaw = []byte(strings.Split(string(f.bundleRaw), "\n")[1] + "\n" + strings.Split(string(f.bundleRaw), "\n")[0] + "\n")
			f.binding.BundleManifestSHA256 = sha256Hex(f.bundleRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"bundle_name", func(f *acornFoxFixture) {
			f.bundleRaw = bytes.Replace(f.bundleRaw, []byte("production.tar.gz"), []byte("other.tar.gz"), 1)
			f.binding.BundleManifestSHA256 = sha256Hex(f.bundleRaw)
			refreshAcornFoxBinding(t, f)
		}},
		{"bundle_malformed", func(f *acornFoxFixture) {
			f.bundleRaw = []byte("not a bundle manifest")
			f.binding.BundleManifestSHA256 = sha256Hex(f.bundleRaw)
			refreshAcornFoxBinding(t, f)
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			changed := fixture
			changed.bindingRaw = append([]byte(nil), fixture.bindingRaw...)
			changed.manifestRaw = append([]byte(nil), fixture.manifestRaw...)
			changed.bundleRaw = append([]byte(nil), fixture.bundleRaw...)
			candidate.mutate(&changed)
			if _, err := VerifyAcornFoxCandidateArtifactsV1(changed.input(nil)); err == nil {
				t.Fatal("JSON or bundle alias accepted")
			}
		})
	}
}

func refreshAcornFoxBinding(t *testing.T, fixture *acornFoxFixture) {
	t.Helper()
	raw, err := json.Marshal(fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	fixture.bindingRaw, fixture.bindingSHA = raw, sha256Hex(raw)
}

func TestVerifyAcornFoxCandidateArtifactsV1RejectsArchiveTreeDrift(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, candidate := range []struct {
		name   string
		mutate func(*testing.T, *acornFoxFixture)
	}{
		{"extra", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) { writeAcornFoxTar(t, w, "release/extra", 0o644, []byte("x")) })
		}},
		{"traversal", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) { writeAcornFoxTar(t, w, "release/../escape", 0o644, []byte("x")) })
		}},
		{"missing", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, func(files []FileDigest) []FileDigest { return files[1:] }, nil, nil)
		}},
		{"duplicate", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				writeAcornFoxTar(t, w, "release/bin/acornfox-server", 0o755, []byte("content: bin/acornfox-server\n"))
			})
		}},
		{"directory", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				if err := w.WriteHeader(&tar.Header{Name: "release/dir", Mode: 0o755, Typeflag: tar.TypeDir, Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"symlink", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				if err := w.WriteHeader(&tar.Header{Name: "release/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "target", Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"hardlink", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				if err := w.WriteHeader(&tar.Header{Name: "release/link", Mode: 0o777, Typeflag: tar.TypeLink, Linkname: "target", Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"fifo", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				if err := w.WriteHeader(&tar.Header{Name: "release/fifo", Mode: 0o644, Typeflag: tar.TypeFifo, Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"gnu_regular", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) { writeAcornFoxTarFormat(t, w, "release/gnu", tar.TypeReg, tar.FormatGNU) })
		}},
		{"v7_regular", func(t *testing.T, f *acornFoxFixture) {
			f.archive = acornFoxArchiveV7(t, f.archive)
			refreshAcornFoxArchiveBinding(t, f)
		}},
		{"type_reg_a", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) { writeAcornFoxTarFormat(t, w, "release/reg-a", tar.TypeRegA, tar.FormatUSTAR) })
		}},
		{"pax_regular", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) { writeAcornFoxTarFormat(t, w, "release/pax", tar.TypeReg, tar.FormatPAX) })
		}},
		{"ownership", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				if err := w.WriteHeader(&tar.Header{Name: "release/foreign-owner", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg, Uid: 1, Gid: 2, Uname: "foreign", Gname: "foreign", Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"mode", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, func(files []FileDigest) []FileDigest { files[0].Mode = 0o644; return files }, nil, nil)
		}},
		{"setuid_mode", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, func(files []FileDigest) []FileDigest { files[0].Mode = 0o4755; return files }, nil, nil)
		}},
		{"setgid_mode", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, func(files []FileDigest) []FileDigest { files[0].Mode = 0o2755; return files }, nil, nil)
		}},
		{"sticky_mode", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, func(files []FileDigest) []FileDigest { files[0].Mode = 0o1755; return files }, nil, nil)
		}},
		{"manifest_setuid_mode", func(t *testing.T, f *acornFoxFixture) {
			files, contents := fixtureManifestAndContents(t, *f)
			f.archive = acornFoxArchiveWithManifestMode(t, f.manifestRaw, files, contents, 0o4644, nil)
			refreshAcornFoxArchiveBinding(t, f)
		}},
		{"content", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, func(contents map[string][]byte) { contents["bin/acornfox-server"] = []byte("tampered\n") }, nil)
		}},
		{"trailing", func(t *testing.T, f *acornFoxFixture) {
			f.archive = append(append([]byte(nil), f.archive...), []byte("trailing")...)
			refreshAcornFoxArchiveBinding(t, f)
		}},
		{"count", func(t *testing.T, f *acornFoxFixture) {
			rebuildAcornFoxArchive(t, f, nil, nil, func(w *tar.Writer) {
				for i := 0; i < acornFoxArchiveMaxMembers; i++ {
					writeAcornFoxTar(t, w, fmt.Sprintf("release/assets/%03d", i), 0o644, []byte("x"))
				}
			})
		}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			changed := cloneAcornFoxFixture(fixture)
			candidate.mutate(t, &changed)
			if _, err := VerifyAcornFoxCandidateArtifactsV1(changed.input(nil)); err == nil {
				t.Fatal("archive drift accepted")
			}
		})
	}
}

func TestVerifyAcornFoxCandidateArtifactsV1RejectsArchiveSizeMismatch(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, size := range []int64{int64(len(fixture.archive)) - 1, int64(len(fixture.archive)) + 1} {
		input := fixture.input(nil)
		input.ArchiveSize = size
		if _, err := VerifyAcornFoxCandidateArtifactsV1(input); err == nil {
			t.Fatal("archive size mismatch accepted")
		}
	}
}

type acornFoxChunkReader struct {
	data []byte
	max  int
}

func (r *acornFoxChunkReader) Read(target []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(target) > r.max {
		target = target[:r.max]
	}
	if len(target) > len(r.data) {
		target = target[:len(r.data)]
	}
	n := copy(target, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestVerifyAcornFoxCandidateArtifactsV1StreamsBoundedArchiveInput(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	input := fixture.input(nil)
	input.Archive = &acornFoxChunkReader{data: append([]byte(nil), fixture.archive...), max: 7}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(input); err != nil {
		t.Fatalf("bounded streaming reader rejected: %v", err)
	}

	short := fixture.input(nil)
	short.Archive = &acornFoxChunkReader{data: append([]byte(nil), fixture.archive[:len(fixture.archive)-1]...), max: 3}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(short); err == nil {
		t.Fatal("short streaming input accepted")
	}

	long := fixture.input(nil)
	long.Archive = &acornFoxChunkReader{data: append(append([]byte(nil), fixture.archive...), 'x'), max: 3}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(long); err == nil {
		t.Fatal("long streaming input accepted")
	}

	huge := fixture.input(nil)
	huge.ArchiveSize = acornFoxArchiveMaxBytes
	huge.Archive = &acornFoxChunkReader{data: []byte{0x1f, 0x8b}, max: 1}
	if _, err := VerifyAcornFoxCandidateArtifactsV1(huge); err == nil {
		t.Fatal("declared huge short stream accepted")
	}
}

func cloneAcornFoxFixture(input acornFoxFixture) acornFoxFixture {
	clone := input
	clone.binding = cloneAcornFoxBinding(input.binding)
	clone.bindingRaw, clone.manifestRaw, clone.bundleRaw, clone.archive = append([]byte(nil), input.bindingRaw...), append([]byte(nil), input.manifestRaw...), append([]byte(nil), input.bundleRaw...), append([]byte(nil), input.archive...)
	return clone
}

func fixtureManifestAndContents(t *testing.T, fixture acornFoxFixture) ([]FileDigest, map[string][]byte) {
	t.Helper()
	var manifest Manifest
	if err := json.Unmarshal(fixture.manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	contents := make(map[string][]byte, len(manifest.Files))
	for _, file := range manifest.Files {
		if file.Path == "web/dist/assets/app-12345678.js" {
			contents[file.Path] = []byte("asset\n")
		} else {
			contents[file.Path] = []byte("content: " + file.Path + "\n")
		}
	}
	return manifest.Files, contents
}

func rebuildAcornFoxArchive(t *testing.T, fixture *acornFoxFixture, changeFiles func([]FileDigest) []FileDigest, changeContents func(map[string][]byte), mutate func(*tar.Writer)) {
	t.Helper()
	files, contents := fixtureManifestAndContents(t, *fixture)
	if changeFiles != nil {
		files = changeFiles(files)
	}
	if changeContents != nil {
		changeContents(contents)
	}
	fixture.archive = acornFoxArchive(t, fixture.manifestRaw, files, contents, mutate)
	refreshAcornFoxArchiveBinding(t, fixture)
}

func refreshAcornFoxArchiveBinding(t *testing.T, fixture *acornFoxFixture) {
	t.Helper()
	fixture.binding.ArchiveSHA256 = sha256Hex(fixture.archive)
	fixture.bundleRaw = []byte(fixture.binding.ArchiveSHA256 + "  acornfox-" + fixture.binding.Version + "-production.tar.gz\n" + fixture.binding.ManifestSHA256 + "  release/manifest.json\n")
	fixture.binding.BundleManifestSHA256 = sha256Hex(fixture.bundleRaw)
	refreshAcornFoxBinding(t, fixture)
}

func writeAcornFoxTar(t *testing.T, writer *tar.Writer, name string, mode int64, data []byte) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
}

func writeAcornFoxTarFormat(t *testing.T, writer *tar.Writer, name string, typeflag byte, format tar.Format) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: typeflag, Format: format}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

func acornFoxArchiveV7(t *testing.T, compressed []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if len(raw) < 512 {
		t.Fatal("tar is too short")
	}
	for i := 257; i < 265; i++ {
		raw[i] = 0
	}
	for i := 148; i < 156; i++ {
		raw[i] = ' '
	}
	var sum int
	for _, value := range raw[:512] {
		sum += int(value)
	}
	copy(raw[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestAcornFoxSealedWitnessesRejectZeroValues(t *testing.T) {
	if (VerifiedAcornFoxBindingV1{}).valid() || (VerifiedAcornFoxCandidateV1{}).valid() {
		t.Fatal("zero sealed witness is valid")
	}
	if _, err := ParseAcornFoxCandidateBindingV1(nil, ""); err == nil {
		t.Fatal("empty binding parsed")
	}
}

func TestAcornFoxCandidateBindingRejectsGitHubAliases(t *testing.T) {
	fixture := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	for _, repository := range []string{
		"https://github.com/acornfox/acornfox.git", "https://github.com/acornfox/acornfox/",
		"https://github.com/acornfox%2Facornfox", "https://github.com:443/acornfox/acornfox",
		"https://user@github.com/acornfox/acornfox", "https://github.com/acornfox/acornfox?ref=main",
	} {
		changed := cloneAcornFoxFixture(fixture)
		changed.binding.SourceRepository = repository
		refreshAcornFoxBinding(t, &changed)
		if _, err := VerifyAcornFoxCandidateArtifactsV1(changed.input(nil)); err == nil {
			t.Fatalf("GitHub alias accepted: %s", repository)
		}
	}
}
