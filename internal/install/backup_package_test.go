package install

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
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
	manifest := PlatformBackupV3{
		Schema: PlatformBackupV3Schema, BackupID: "backup-platform-package", CreatedAt: time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC), Reason: "manual",
		SourceInstallationIDSHA256: platformBackupDigest("installation"), SourceActivationID: "activation-platform", SourceActivationJSONSHA256: platformBackupDigest("activation"),
		DatabaseSnapshotSHA256: platformBackupDigest("snapshot"),
		SourceRelease:          ReleaseV1{ID: "release-platform", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: platformBackupDigest("release")},
		SourceDatabase:         DatabaseV1{Name: "open_card", Migration: "0024", SchemaMigrationsSHA256: platformBackupDigest("migrations")},
	}
	data := platformBackupTypedFixture(t, manifest)
	data["config/Caddyfile"] = []byte("example.test { respond \"ok\" }\n")
	data["config/open-card-edge.Caddyfile"] = []byte("edge.example.test { respond \"ok\" }\n")
	data["database/control-plane.dump"] = []byte("PGDMP\x01opaque dump")
	for path, raw := range data {
		if path != "database/control-plane.dump" && !validPlatformBackupText(path, raw) {
			t.Fatalf("invalid fixture %s: %s", path, raw)
		}
	}
	artifacts := make([]PlatformBackupArtifactSource, 0, len(data))
	for path, body := range data {
		artifacts = append(artifacts, PlatformBackupArtifactSource{Path: path, Source: bytes.NewReader(body), Size: int64(len(body)), Mode: platformBackupV3Mode})
	}
	return PlatformBackupPackageInput{Manifest: manifest, Artifacts: artifacts}
}

func platformBackupTypedFixture(t *testing.T, manifest PlatformBackupV3) map[string][]byte {
	t.Helper()
	snapshot := platformBackupDigest("snapshot")
	serverKeys := []string{"OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_RUNTIME_TASK_PREFIX"}
	server := []PlatformBackupRuntimeSettingV1{}
	for _, key := range serverKeys {
		server = append(server, PlatformBackupRuntimeSettingV1{Key: key, Value: platformRuntimeValue(key, true)})
	}
	agentKeys := []string{"OPEN_CARD_INSTANCE_ID", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_NODE_ID", "OPEN_CARD_RUNTIME_TASK_PREFIX"}
	agent := []PlatformBackupRuntimeSettingV1{}
	for _, key := range agentKeys {
		agent = append(agent, PlatformBackupRuntimeSettingV1{Key: key, Value: platformRuntimeValue(key, false)})
	}
	routeTables := make([]TableDigest, len(platformBackupRouteTables))
	for i, e := range platformBackupRouteTables {
		routeTables[i] = TableDigest{Name: e.name, RowCount: 0, RowsSHA256: platformBackupDigest(e.name), OrderBy: e.order}
	}
	taskTables := []TableDigest{{Name: "outbox_events", RowCount: 0, RowsSHA256: platformBackupDigest("outbox"), OrderBy: []string{"stream_sequence"}}, {Name: "task_agent_events", RowCount: 0, RowsSHA256: platformBackupDigest("agent"), OrderBy: []string{"task_id", "sequence"}}, {Name: "task_leases", RowCount: 0, RowsSHA256: platformBackupDigest("leases"), OrderBy: []string{"created_at", "task_id"}}}
	values := []any{
		PlatformBackupRuntimeConfigV1{SchemaVersion: 1, Server: server, Agent: agent},
		PlatformBackupTLSV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, MaterialIncluded: false, RestorePolicy: "resolve-or-reissue", References: []PlatformBackupTLSReferenceV1{}},
		PlatformBackupAuditV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, Canonicalization: PlatformBackupFactCanonicalization, Table: TableDigest{Name: "audit_evidence", RowCount: 0, RowsSHA256: platformBackupDigest("audit"), OrderBy: []string{"sequence"}}, Sequence: PlatformBackupSequenceV1{Relation: "public.audit_evidence_sequence_seq", LastValue: 0, IsCalled: false}, LinkContinuity: true},
		PlatformBackupKeyReferencesV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, References: []PlatformBackupKeyReferenceV1{{Provider: "control-plane-secret", KeyID: "control-secret", KeyVersion: "v1", Revoked: false}, {Provider: "local-backup-key", KeyID: "backup-key", KeyVersion: "v1", Revoked: false}}},
		PlatformBackupReleaseV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, Activation: PlatformBackupReleaseActivationV1{ActivationID: manifest.SourceActivationID, ActivationJSONSHA256: manifest.SourceActivationJSONSHA256, Origin: "manual", CreatedAt: manifest.CreatedAt, CreatedByTransactionID: "tx-platform", DatabaseEnvSHA256: platformBackupDigest("db-env")}, Release: manifest.SourceRelease, Database: PlatformBackupReleaseDatabaseV1{DatabaseV1: manifest.SourceDatabase, CurrentDatabase: manifest.SourceDatabase.Name, SchemaMigrationsCount: 24, SchemaMigrationsRowsSHA256: manifest.SourceDatabase.SchemaMigrationsSHA256}, Pointers: PlatformBackupReleasePointersV1{ActiveTarget: "activations/" + manifest.SourceActivationID, CurrentTarget: "active/release", ActivationReleaseTarget: "../../releases/" + manifest.SourceRelease.ID}},
		PlatformBackupRoutesV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, Canonicalization: PlatformBackupFactCanonicalization, Tables: routeTables},
		PlatformBackupTasksOutboxV1{SchemaVersion: 1, DatabaseSnapshotSHA256: snapshot, Canonicalization: PlatformBackupFactCanonicalization, Tables: taskTables, OutboxSequence: PlatformBackupSequenceV1{Relation: "public.outbox_events_stream_sequence", LastValue: 0, IsCalled: false}, PendingOutbox: PlatformBackupPendingOutboxV1{PlatformBackupRowsDigestV1: PlatformBackupRowsDigestV1{RowCount: 0, RowsSHA256: platformBackupDigest("pending"), OrderBy: []string{"stream_sequence"}}}, RecoverableTasks: PlatformBackupRecoverableTasksV1{PlatformBackupRowsDigestV1: PlatformBackupRowsDigestV1{RowCount: 0, RowsSHA256: platformBackupDigest("recoverable"), OrderBy: []string{"created_at", "task_id"}}}},
	}
	paths := []string{"config/runtime.json", "edge/tls.json", "facts/audit.json", "facts/key-references.json", "facts/release.json", "facts/routes.json", "facts/tasks-outbox.json"}
	out := make(map[string][]byte, len(paths))
	for i, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		out[paths[i]] = raw
	}
	return out
}
func platformRuntimeValue(key string, server bool) string {
	if key == "OPEN_CARD_M2_ENABLED" || key == "OPEN_CARD_M4_ENABLED" {
		return "false"
	}
	if strings.HasSuffix(key, "_ENABLED") || key == "OPEN_CARD_RUNTIME_ENABLED" || key == "OPEN_CARD_WORKER_NETWORK_ISOLATED" {
		return "true"
	}
	switch key {
	case "OPEN_CARD_SERVER_ADDR", "OPEN_CARD_AGENT_GATEWAY_ADDR", "OPEN_CARD_CADDY_LISTEN", "OPEN_CARD_BUILDKIT_ADDRESS":
		return "127.0.0.1:8080"
	case "OPEN_CARD_CADDY_ADMIN_URL":
		return "http://127.0.0.1:2019"
	case "OPEN_CARD_AUTH_ORIGIN":
		return "https://console.example.test"
	case "OPEN_CARD_CONTROL_PLANE_URL":
		return "https://127.0.0.1:8443"
	case "OPEN_CARD_CONTROL_PLANE_SERVER_NAME":
		return "console.example.test"
	case "OPEN_CARD_AGENT_IDENTITIES_JSON":
		return `[{"certificate_id":"cert-a","instance_id":"instance-platform","node_id":"node-platform"}]`
	case "OPEN_CARD_M3_COMPOSITION":
		return "production"
	case "OPEN_CARD_M4_ROLLOUT_INTERVAL":
		return "1s"
	case "OPEN_CARD_M4_LOG_COLLECTION_INTERVAL":
		return "1m0s"
	case "OPEN_CARD_LOG_MAX_FILE_BYTES", "OPEN_CARD_LOG_MAX_TOTAL_BYTES", "OPEN_CARD_M5_STORAGE_CAPACITY_BYTES", "OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES", "OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES":
		return "1"
	case "OPEN_CARD_STATIC_RUNTIME_DIGEST":
		return "sha256:" + platformBackupDigest("runtime")
	case "OPEN_CARD_M2_REGISTRY_BASE_URL":
		return "http://127.0.0.1:5000"
	case "OPEN_CARD_SOURCE_GIT_RESOLVERS":
		return "1.1.1.1:53,8.8.8.8:53"
	case "OPEN_CARD_BUILDKIT_WORKER":
		return "rootless-worker"
	case "OPEN_CARD_BUILDKIT_COMMAND", "OPEN_CARD_STATIC_SERVER_BINARY":
		return "/opt/open-card/bin/tool"
	case "OPEN_CARD_BUILD_WORK_ROOT", "OPEN_CARD_LOG_ROOT", "OPEN_CARD_OCI_STORE_ROOT", "OPEN_CARD_SOURCE_UPLOAD_ROOT", "OPEN_CARD_SOURCE_WORKSPACE_ROOT", "OPEN_CARD_M6_WORKSPACE_ROOT", "OPEN_CARD_RUNTIME_WORK_ROOT":
		return "/var/lib/open-card/data"
	case "OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_INSTANCE_ID":
		return "instance-platform"
	case "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_NODE_ID":
		return "node-platform"
	default:
		return "runtime-value"
	}
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
	valid := PlatformBackupKeyReferencesV1{SchemaVersion: 1, DatabaseSnapshotSHA256: platformBackupDigest("snapshot"), References: []PlatformBackupKeyReferenceV1{{Provider: "control-plane-secret", KeyID: "a", KeyVersion: "v1", Revoked: false}, {Provider: "local-backup-key", KeyID: "b", KeyVersion: "v1", Revoked: false}}}
	if _, err := MarshalPlatformBackupKeyReferencesV1(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []PlatformBackupKeyReferencesV1{{SchemaVersion: 1, DatabaseSnapshotSHA256: platformBackupDigest("snapshot"), References: []PlatformBackupKeyReferenceV1{{Provider: "local-backup-key", KeyID: "b", KeyVersion: "v1", Revoked: false}, {Provider: "control-plane-secret", KeyID: "a", KeyVersion: "v1", Revoked: false}}}, {SchemaVersion: 1, DatabaseSnapshotSHA256: platformBackupDigest("snapshot"), References: []PlatformBackupKeyReferenceV1{{Provider: "control-plane-secret", KeyID: "a", KeyVersion: "v1", Revoked: false}, {Provider: "control-plane-secret", KeyID: "a", KeyVersion: "v1", Revoked: false}}}} {
		if bad.Validate() == nil {
			t.Fatal("noncanonical key references accepted")
		}
	}
	if _, err := ParsePlatformBackupKeyReferencesV1([]byte(`{"schema_version":1,"database_snapshot_sha256":"16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112","references":[{"provider":"local-backup-key","key_id":"b","key_version":"v1","revoked":false},{"provider":"control-plane-secret","key_id":"a","key_version":"v1","revoked":false}]}`)); !errors.Is(err, ErrPlatformBackupPackage) {
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

func TestPlatformBackupV3EachTypedMemberAbortsBeforeCommit(t *testing.T) {
	typed := []string{"config/runtime.json", "edge/tls.json", "facts/audit.json", "facts/key-references.json", "facts/release.json", "facts/routes.json", "facts/tasks-outbox.json"}
	for _, path := range typed {
		t.Run(path, func(t *testing.T) {
			input := platformBackupInput(t)
			for i := range input.Artifacts {
				if input.Artifacts[i].Path == path {
					raw, err := platformBackupArtifactText(input.Artifacts[i].Source, input.Artifacts[i].Size, path)
					if err != nil {
						t.Fatal(err)
					}
					raw = append(raw, ' ')
					input.Artifacts[i].Source = bytes.NewReader(raw)
					input.Artifacts[i].Size = int64(len(raw))
				}
			}
			build := &platformBackupBuildSink{}
			if err := BuildPlatformBackupV3Package(build, input); !errors.Is(err, ErrPlatformBackupPackage) || build.aborted != 1 || build.committed != 0 {
				t.Fatalf("build err=%v abort=%d commit=%d", err, build.aborted, build.committed)
			}
			raw := platformBackupBytes(t, platformBackupInput(t))
			entries := platformTestEntries(t, raw)
			for i := range entries {
				if entries[i].name == path {
					entries[i].data = append(entries[i].data, ' ')
				}
			}
			parse := &platformBackupSink{}
			if _, err := VerifyPlatformBackupV3Package(bytes.NewReader(platformTestArchive(t, entries)), parse); !errors.Is(err, ErrPlatformBackupPackage) || parse.aborted != 1 || parse.committed != 0 {
				t.Fatalf("parse err=%v abort=%d commit=%d", err, parse.aborted, parse.committed)
			}
		})
	}
}

func TestPlatformBackupV3SnapshotMismatchAbortsBuildAndVerify(t *testing.T) {
	input := platformBackupInput(t)
	for i := range input.Artifacts {
		if input.Artifacts[i].Path == "facts/routes.json" {
			raw, err := platformBackupArtifactText(input.Artifacts[i].Source, input.Artifacts[i].Size, input.Artifacts[i].Path)
			if err != nil {
				t.Fatal(err)
			}
			fact, err := ParsePlatformBackupRoutesV1(raw)
			if err != nil {
				t.Fatal(err)
			}
			fact.DatabaseSnapshotSHA256 = platformBackupDigest("other")
			raw, err = MarshalPlatformBackupRoutesV1(fact)
			if err != nil {
				t.Fatal(err)
			}
			input.Artifacts[i].Source, input.Artifacts[i].Size = bytes.NewReader(raw), int64(len(raw))
		}
	}
	build := &platformBackupBuildSink{}
	if err := BuildPlatformBackupV3Package(build, input); !errors.Is(err, ErrPlatformBackupPackage) || build.aborted != 1 || build.committed != 0 {
		t.Fatalf("build err=%v abort=%d commit=%d", err, build.aborted, build.committed)
	}
	raw := platformBackupBytes(t, platformBackupInput(t))
	entries := platformTestEntries(t, raw)
	for i := range entries {
		if entries[i].name == "facts/routes.json" {
			fact, err := ParsePlatformBackupRoutesV1(entries[i].data)
			if err != nil {
				t.Fatal(err)
			}
			fact.DatabaseSnapshotSHA256 = platformBackupDigest("other")
			entries[i].data, err = MarshalPlatformBackupRoutesV1(fact)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	parse := &platformBackupSink{}
	if _, err := VerifyPlatformBackupV3Package(bytes.NewReader(platformTestArchive(t, entries)), parse); !errors.Is(err, ErrPlatformBackupPackage) || parse.aborted != 1 || parse.committed != 0 {
		t.Fatalf("parse err=%v abort=%d commit=%d", err, parse.aborted, parse.committed)
	}
}

func TestPlatformBackupV3VerifierRejectsOmittedOrReorderedPublicRouteFacts(t *testing.T) {
	for name, mutate := range map[string]func(*PlatformBackupRoutesV1){
		"omitted-public-command-ledger": func(routes *PlatformBackupRoutesV1) {
			routes.Tables = append([]TableDigest(nil), routes.Tables[1:]...)
		},
		"reordered-dns-execution-ledger": func(routes *PlatformBackupRoutesV1) {
			routes.Tables[0], routes.Tables[1] = routes.Tables[1], routes.Tables[0]
		},
		"omitted-occupied-dns-execution-scope": func(routes *PlatformBackupRoutesV1) {
			routes.Tables = append(routes.Tables[:2:2], routes.Tables[3:]...)
		},
		"reordered-occupied-dns-execution-scope": func(routes *PlatformBackupRoutesV1) {
			routes.Tables[1], routes.Tables[2] = routes.Tables[2], routes.Tables[1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			entries := platformTestEntries(t, platformBackupBytes(t, platformBackupInput(t)))
			manifest := platformRewriteRouteFactForVerifier(t, entries, mutate)
			if manifest.Validate() != nil {
				t.Fatal("the package manifest must still bind the altered typed fact")
			}
			sink := &platformBackupSink{}
			if _, err := VerifyPlatformBackupV3Package(bytes.NewReader(platformTestArchive(t, entries)), sink); !errors.Is(err, ErrPlatformBackupPackage) || sink.aborted != 1 || sink.committed != 0 {
				t.Fatalf("restore-gate verifier err=%v sink=%+v", err, sink)
			}
		})
	}
}

// platformRewriteRouteFactForVerifier keeps the archive manifest's artifact
// digest valid so this test reaches typed fact verification, which is the
// required pre-restore integrity gate for the full PostgreSQL snapshot.
func platformRewriteRouteFactForVerifier(t *testing.T, entries []platformTestEntry, mutate func(*PlatformBackupRoutesV1)) PlatformBackupV3 {
	t.Helper()
	var manifest PlatformBackupV3
	var routeIndex, manifestIndex = -1, -1
	for i := range entries {
		switch entries[i].name {
		case PlatformBackupV3Manifest:
			parsed, err := ParsePlatformBackupV3(entries[i].data)
			if err != nil {
				t.Fatal(err)
			}
			manifest, manifestIndex = parsed, i
		case "facts/routes.json":
			routeIndex = i
		}
	}
	if routeIndex < 0 || manifestIndex < 0 {
		t.Fatal("required route fact or manifest missing")
	}
	routes, err := ParsePlatformBackupRoutesV1(entries[routeIndex].data)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&routes)
	entries[routeIndex].data, err = json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Path == "facts/routes.json" {
			manifest.Artifacts[i].SHA256 = sha256Bytes(entries[routeIndex].data)
			manifest.Artifacts[i].Size = int64(len(entries[routeIndex].data))
		}
	}
	entries[manifestIndex].data, err = MarshalPlatformBackupV3(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
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
