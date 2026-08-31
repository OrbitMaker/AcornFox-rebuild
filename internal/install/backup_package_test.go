package install

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"
)

func platformBackupDigest(value string) string { return sha256Bytes([]byte(value)) }

func platformBackupInput(t *testing.T) PlatformBackupPackageInput {
	t.Helper()
	refs, err := MarshalPlatformBackupKeyReferencesV1(PlatformBackupKeyReferencesV1{SchemaVersion: 1, References: []PlatformBackupKeyReferenceV1{{Provider: "cos", KeyID: "backup-key", KeyVersion: "v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	data := map[string][]byte{
		"config/Caddyfile": []byte("example.test { respond \"ok\" }\n"), "config/open-card-edge.Caddyfile": []byte("edge.example.test { respond \"ok\" }\n"),
		"config/runtime.json": []byte(`{"schema_version":1}`), "database/control-plane.dump": []byte("PGDMP\x01opaque dump"), "edge/tls.json": []byte(`{"schema_version":1}`),
		"facts/audit.json": []byte(`{"schema_version":1}`), "facts/key-references.json": refs, "facts/release.json": []byte(`{"schema_version":1}`),
		"facts/routes.json": []byte(`{"schema_version":1}`), "facts/tasks-outbox.json": []byte(`{"schema_version":1}`),
	}
	artifacts := make([]PlatformBackupArtifactSource, 0, len(data))
	for path, body := range data {
		artifacts = append(artifacts, PlatformBackupArtifactSource{Path: path, Source: bytes.NewReader(body), Size: int64(len(body)), Mode: platformBackupV3Mode})
	}
	return PlatformBackupPackageInput{Manifest: PlatformBackupV3{
		Schema: PlatformBackupV3Schema, BackupID: "backup-platform-package", CreatedAt: time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC), Reason: "manual",
		SourceInstallationIDSHA256: platformBackupDigest("installation"), SourceActivationID: "activation-platform", SourceActivationJSONSHA256: platformBackupDigest("activation"),
		SourceRelease:  ReleaseV1{ID: "release-platform", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: platformBackupDigest("release")},
		SourceDatabase: DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: platformBackupDigest("migrations")},
	}, Artifacts: artifacts}
}

type platformBackupBuildSink struct {
	output             bytes.Buffer
	writer             io.Writer
	aborted, committed int
	openErr, commitErr error
}

func (s *platformBackupBuildSink) Open() (io.Writer, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	if s.writer != nil {
		return s.writer, nil
	}
	return &s.output, nil
}
func (s *platformBackupBuildSink) Abort()        { s.aborted++ }
func (s *platformBackupBuildSink) Commit() error { s.committed++; return s.commitErr }

func platformBackupBytes(t *testing.T, input PlatformBackupPackageInput) []byte {
	t.Helper()
	sink := &platformBackupBuildSink{}
	if err := BuildPlatformBackupV3Package(sink, input); err != nil || sink.aborted != 0 || sink.committed != 1 {
		t.Fatalf("err=%v abort=%d commit=%d", err, sink.aborted, sink.committed)
	}
	return sink.output.Bytes()
}

type platformBackupSink struct {
	opened             []PlatformBackupArtifactV1
	content            map[string]*bytes.Buffer
	aborted, committed int
	commitErr          error
}

func (s *platformBackupSink) OpenArtifact(a PlatformBackupArtifactV1) (io.Writer, error) {
	if s.content == nil {
		s.content = map[string]*bytes.Buffer{}
	}
	b := &bytes.Buffer{}
	s.opened = append(s.opened, a)
	s.content[a.Path] = b
	return b, nil
}
func (s *platformBackupSink) Abort()        { s.aborted++; s.content = nil }
func (s *platformBackupSink) Commit() error { s.committed++; return s.commitErr }

func TestPlatformBackupV3StreamingDeterministicRoundTrip(t *testing.T) {
	input := platformBackupInput(t)
	first := platformBackupBytes(t, input)
	input.Artifacts[0], input.Artifacts[len(input.Artifacts)-1] = input.Artifacts[len(input.Artifacts)-1], input.Artifacts[0]
	second := platformBackupBytes(t, input)
	if !bytes.Equal(first, second) {
		t.Fatal("shuffled sources changed package bytes")
	}
	if strings.Contains(string(first), "raw-installation-id") {
		t.Fatal("raw installation identity appeared")
	}
	sink := &platformBackupSink{}
	manifest, err := VerifyPlatformBackupV3Package(bytes.NewReader(first), sink)
	if err != nil || manifest.SourceInstallationIDSHA256 != platformBackupDigest("installation") || sink.committed != 1 || sink.aborted != 0 || len(sink.opened) != len(platformBackupV3Members) {
		t.Fatalf("manifest=%+v sink=%+v err=%v", manifest, sink, err)
	}
	if got := sink.content["database/control-plane.dump"].String(); got != "PGDMP\x01opaque dump" {
		t.Fatalf("dump=%q", got)
	}
	reader := tar.NewReader(bytes.NewReader(first))
	var names []string
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Format != tar.FormatUSTAR || h.Mode != platformBackupV3Mode || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || !h.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("header=%+v", h)
		}
	}
	want := append([]string{PlatformBackupV3Manifest}, platformBackupV3Members...)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names=%v", names)
	}
	if expected, _ := platformBackupHeaderBlock(PlatformBackupV3Manifest, int64(platformTestManifestSize(t, first)), platformBackupV3Mode); !bytes.Equal(first[:512], expected) {
		t.Fatal("manifest header was not canonical")
	}
}

func platformTestManifestSize(t *testing.T, raw []byte) int {
	t.Helper()
	size, ok := platformBackupHeaderSize(raw[:512])
	if !ok {
		t.Fatal("size")
	}
	return int(size)
}

func TestPlatformBackupV3ParserQuarantineAndCanonicalRejections(t *testing.T) {
	raw := platformBackupBytes(t, platformBackupInput(t))
	for name, mutate := range map[string]func([]byte) []byte{
		"trailing":          func(v []byte) []byte { return append(append([]byte(nil), v...), 1) },
		"prefix":            func(v []byte) []byte { v = append([]byte(nil), v...); v[345] = 'x'; return v },
		"alternate-numeric": func(v []byte) []byte { v = append([]byte(nil), v...); v[124] = ' '; return v },
		"hidden-secret-padding": func(v []byte) []byte {
			v = append([]byte(nil), v...)
			size := platformTestManifestSize(t, v)
			v[512+size] = 'X'
			return v
		},
		"hash": func(v []byte) []byte {
			v = append([]byte(nil), v...)
			for i := 512; i < len(v); i++ {
				if v[i] == 'P' {
					v[i] = 'Q'
					break
				}
			}
			return v
		},
	} {
		t.Run(name, func(t *testing.T) {
			sink := &platformBackupSink{}
			manifest, err := VerifyPlatformBackupV3Package(bytes.NewReader(mutate(raw)), sink)
			if !errors.Is(err, ErrPlatformBackupPackage) || manifest.Schema != "" || sink.aborted != 1 || sink.committed != 0 {
				t.Fatalf("manifest=%+v sink=%+v err=%v", manifest, sink, err)
			}
		})
	}
}

func TestPlatformBackupV3RejectsBuilderSecretsMalformedAndOversize(t *testing.T) {
	for name, mutate := range map[string]func(*PlatformBackupPackageInput){
		"raw-installation": func(in *PlatformBackupPackageInput) { in.Manifest.SourceInstallationIDSHA256 = "raw-installation-id" }, "bad-schema": func(in *PlatformBackupPackageInput) { in.Manifest.Schema = "v4" },
		"wrong-mode": func(in *PlatformBackupPackageInput) { in.Artifacts[0].Mode = 0o644 }, "path-traversal": func(in *PlatformBackupPackageInput) { in.Artifacts[0].Path = "../escape" },
		"aws-secret": func(in *PlatformBackupPackageInput) {
			platformTestReplace(in, "config/Caddyfile", []byte("AWS_SECRET_ACCESS_KEY=not-accepted"))
		},
		"malformed-json": func(in *PlatformBackupPackageInput) {
			platformTestReplace(in, "config/runtime.json", []byte(`{"broken":`))
		},
		"oversized-text": func(in *PlatformBackupPackageInput) {
			platformTestReplace(in, "config/Caddyfile", make([]byte, PlatformBackupV3MaxTextMemberSize+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := platformBackupInput(t)
			mutate(&input)
			sink := &platformBackupBuildSink{}
			if err := BuildPlatformBackupV3Package(sink, input); !errors.Is(err, ErrPlatformBackupPackage) || sink.aborted != 1 || sink.committed != 0 {
				t.Fatalf("err=%v", err)
			}
		})
	}
	// Exercise the package cap arithmetically without allocating a one-tebibyte
	// fixture. The writer/parser stream production-sized dumps.
	if platformBackupArchiveSizeOK(PlatformBackupV3MaxTextMemberSize+1, nil) {
		t.Fatal("oversized package arithmetic accepted")
	}
	oversized := bytes.Repeat([]byte{0}, 512)
	sink := &platformBackupSink{}
	if manifest, err := VerifyPlatformBackupV3Package(bytes.NewReader(oversized), sink); !errors.Is(err, ErrPlatformBackupPackage) || manifest.Schema != "" || sink.aborted != 1 {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
}

func TestPlatformBackupV3LargeDumpUsesFixedPAXPreamble(t *testing.T) {
	header, err := platformBackupHeaderBlock("database/control-plane.dump", PlatformBackupV3MaxDumpSize, platformBackupV3Mode)
	if err != nil || len(header) <= 512 || len(header)%512 != 0 {
		t.Fatalf("header=%d err=%v", len(header), err)
	}
	// Checked-in wire vector: the deterministic PAX `size` record for 1 TiB.
	if got := hex.EncodeToString(header[512:534]); got != "32322073697a653d313039393531313632373737360a" {
		t.Fatalf("PAX size vector=%s", got)
	}
}

func TestPlatformBackupV3BuildSinkAbortsPartialOutput(t *testing.T) {
	t.Run("mutable-between-passes", func(t *testing.T) {
		input := platformBackupInput(t)
		for i := range input.Artifacts {
			if input.Artifacts[i].Path == "config/Caddyfile" {
				input.Artifacts[i].Source = &platformBackupFlippingSource{first: []byte("example.test { respond \"ok\" }\n"), second: []byte("example.test { respond \"no\" }\n")}
			}
		}
		sink := &platformBackupBuildSink{}
		if err := BuildPlatformBackupV3Package(sink, input); !errors.Is(err, ErrPlatformBackupPackage) || sink.aborted != 1 || sink.committed != 0 || sink.output.Len() == 0 {
			t.Fatalf("err=%v abort=%d commit=%d bytes=%d", err, sink.aborted, sink.committed, sink.output.Len())
		}
	})
	t.Run("short-writer", func(t *testing.T) {
		short := platformBackupShortWriter{}
		sink := &platformBackupBuildSink{writer: short}
		if err := BuildPlatformBackupV3Package(sink, platformBackupInput(t)); !errors.Is(err, ErrPlatformBackupPackage) || sink.aborted != 1 || sink.committed != 0 {
			t.Fatalf("err=%v abort=%d commit=%d", err, sink.aborted, sink.committed)
		}
	})
	t.Run("commit", func(t *testing.T) {
		sink := &platformBackupBuildSink{commitErr: errors.New("commit")}
		if err := BuildPlatformBackupV3Package(sink, platformBackupInput(t)); !errors.Is(err, ErrPlatformBackupPackage) || sink.aborted != 1 || sink.committed != 1 {
			t.Fatalf("err=%v abort=%d commit=%d", err, sink.aborted, sink.committed)
		}
	})
}

type platformBackupFlippingSource struct {
	first, second []byte
	reader        *bytes.Reader
	seeks         int
}

func (s *platformBackupFlippingSource) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *platformBackupFlippingSource) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekStart && offset == 0 {
		s.seeks++
		body := s.first
		if s.seeks >= 2 {
			body = s.second
		}
		s.reader = bytes.NewReader(body)
	}
	return s.reader.Seek(offset, whence)
}

type platformBackupShortWriter struct{}

func (platformBackupShortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}
func platformTestReplace(in *PlatformBackupPackageInput, path string, data []byte) {
	for i := range in.Artifacts {
		if in.Artifacts[i].Path == path {
			in.Artifacts[i].Source = bytes.NewReader(data)
			in.Artifacts[i].Size = int64(len(data))
		}
	}
}

func TestPlatformBackupV3KeyReferencesAreCanonical(t *testing.T) {
	valid := PlatformBackupKeyReferencesV1{SchemaVersion: 1, References: []PlatformBackupKeyReferenceV1{{Provider: "cos", KeyID: "a", KeyVersion: "v1"}, {Provider: "cos", KeyID: "b", KeyVersion: "v1"}}}
	if _, err := MarshalPlatformBackupKeyReferencesV1(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []PlatformBackupKeyReferencesV1{{SchemaVersion: 1, References: []PlatformBackupKeyReferenceV1{{Provider: "cos", KeyID: "b", KeyVersion: "v1"}, {Provider: "cos", KeyID: "a", KeyVersion: "v1"}}}, {SchemaVersion: 1, References: []PlatformBackupKeyReferenceV1{{Provider: "cos", KeyID: "a", KeyVersion: "v1"}, {Provider: "cos", KeyID: "a", KeyVersion: "v1"}}}} {
		if bad.Validate() == nil {
			t.Fatal("noncanonical key references accepted")
		}
	}
	if _, err := ParsePlatformBackupKeyReferencesV1([]byte(`{"schema_version":1,"references":[{"provider":"cos","key_id":"b","key_version":"v1"},{"provider":"cos","key_id":"a","key_version":"v1"}]}`)); !errors.Is(err, ErrPlatformBackupPackage) {
		t.Fatalf("err=%v", err)
	}
}

func TestPlatformBackupV3DuplicateMissingExtraRejectAndNoCommit(t *testing.T) {
	raw := platformBackupBytes(t, platformBackupInput(t))
	entries := platformTestEntries(t, raw)
	for name, mutate := range map[string]func([]platformTestEntry) []platformTestEntry{
		"duplicate": func(e []platformTestEntry) []platformTestEntry { return append(e, e[1]) }, "missing": func(e []platformTestEntry) []platformTestEntry { return append(e[:2], e[3:]...) },
		"extra": func(e []platformTestEntry) []platformTestEntry {
			return append(e, platformTestEntry{name: "z-extra", data: []byte(`{}`)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			sink := &platformBackupSink{}
			manifest, err := VerifyPlatformBackupV3Package(bytes.NewReader(platformTestArchive(t, mutate(entries))), sink)
			if !errors.Is(err, ErrPlatformBackupPackage) || manifest.Schema != "" || sink.aborted != 1 || sink.committed != 0 {
				t.Fatalf("manifest=%+v sink=%+v err=%v", manifest, sink, err)
			}
		})
	}
}

type platformTestEntry struct {
	name string
	data []byte
}

func platformTestEntries(t *testing.T, raw []byte) []platformTestEntry {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(raw))
	var entries []platformTestEntry
	for {
		h, err := reader.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, platformTestEntry{h.Name, data})
	}
}
func platformTestArchive(t *testing.T, entries []platformTestEntry) []byte {
	t.Helper()
	entries = append([]platformTestEntry(nil), entries...)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].name == PlatformBackupV3Manifest {
			return true
		}
		if entries[j].name == PlatformBackupV3Manifest {
			return false
		}
		return entries[i].name < entries[j].name
	})
	var output bytes.Buffer
	for _, entry := range entries {
		if err := platformBackupWriteBytesMember(&output, entry.name, entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := platformBackupWriteAll(&output, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
