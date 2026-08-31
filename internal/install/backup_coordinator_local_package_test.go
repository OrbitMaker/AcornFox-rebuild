package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func localPackageFixture(t *testing.T) (*platformBackupLocalStore, platformBackupCaptureFilesInput) {
	t.Helper()
	order := []string{}
	database, snapshotter, _, request := compositeFixture(t, &order, nil, nil)
	result, err := CapturePlatformBackupDatabase(context.Background(), database, snapshotter, request)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newPlatformBackupLocalStore(request.Writer)
	if err != nil {
		t.Fatal(err)
	}
	databaseFact, err := result.Facts.ReleaseDatabase()
	if err != nil {
		t.Fatal(err)
	}
	identity := platformBackupInput(t).Manifest
	identity.Artifacts = nil
	identity.DatabaseSnapshotSHA256 = result.DatabaseSnapshotSHA256
	identity.SourceDatabase = databaseFact.DatabaseV1
	runtimeMembers := platformBackupTypedFixture(t, identity)
	runtime, err := ParsePlatformBackupRuntimeConfigV1(runtimeMembers["config/runtime.json"])
	if err != nil {
		t.Fatal(err)
	}
	release := PlatformBackupReleaseV1{
		SchemaVersion:          1,
		DatabaseSnapshotSHA256: result.DatabaseSnapshotSHA256,
		Activation: PlatformBackupReleaseActivationV1{
			ActivationID: identity.SourceActivationID, ActivationJSONSHA256: identity.SourceActivationJSONSHA256, Origin: "manual", CreatedAt: identity.CreatedAt,
			CreatedByTransactionID: "transaction-1", DatabaseEnvSHA256: platformBackupDigest("database-env"),
		},
		Release:  identity.SourceRelease,
		Database: databaseFact,
		Pointers: PlatformBackupReleasePointersV1{ActiveTarget: "activations/" + identity.SourceActivationID, CurrentTarget: "active/release", ActivationReleaseTarget: "../../releases/" + identity.SourceRelease.ID},
	}
	return store, platformBackupCaptureFilesInput{
		ManifestIdentity: identity, KeyVersion: "key-v1", DumpEvidence: result.DumpEvidence, DatabaseFacts: result.Facts,
		Caddyfile: []byte("example.test { respond \"ok\" }\n"), EdgeCaddyfile: []byte("edge.example.test { respond \"ok\" }\n"), Runtime: runtime, Release: release,
	}
}

func TestPlatformBackupLocalCollectCaptureAndBuildFixedPackage(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil || capture.Manifest.Validate() != nil || len(capture.Manifest.Artifacts) != len(platformBackupLocalMembers) {
		t.Fatalf("capture=%+v err=%v", capture, err)
	}
	for i, member := range platformBackupLocalMembers {
		if capture.Manifest.Artifacts[i].Path != member.path || capture.Manifest.Artifacts[i].Mode != platformBackupV3Mode {
			t.Fatalf("artifact[%d]=%+v", i, capture.Manifest.Artifacts[i])
		}
	}
	evidence, err := store.buildPackage(capture)
	if err != nil || evidence.PackageSize <= 0 || !validSHA(evidence.PackageSHA256) {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	reader, err := store.openPackage(capture, evidence)
	if err != nil {
		t.Fatal(err)
	}
	manifest, verifyErr := VerifyPlatformBackupV3Package(reader, PlatformBackupDiscardSink{})
	closeErr := reader.Close()
	if verifyErr != nil || closeErr != nil || !platformBackupManifestEqual(manifest, capture.Manifest) {
		t.Fatalf("manifest=%+v verify=%v close=%v", manifest, verifyErr, closeErr)
	}
	replay, err := store.buildPackage(capture)
	if err != nil || replay != evidence {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}

func TestPlatformBackupLocalCollectTextConvergenceAndConflict(t *testing.T) {
	store, input := localPackageFixture(t)
	if _, err := store.collectCapture(input); err != nil {
		t.Fatal(err)
	}
	if _, err := store.collectCapture(input); err != nil {
		t.Fatalf("exact convergence=%v", err)
	}
	input.Caddyfile = []byte("other.example.test { respond \"ok\" }\n")
	if _, err := store.collectCapture(input); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("text conflict=%v", err)
	}
}

func TestPlatformBackupLocalCollectRejectsDumpAndBindingBeforeText(t *testing.T) {
	for name, mutate := range map[string]func(*platformBackupCaptureFilesInput){
		"dump": func(v *platformBackupCaptureFilesInput) { v.DumpEvidence.SHA256 = strings.Repeat("0", 64) },
		"snapshot": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
		"release": func(v *platformBackupCaptureFilesInput) { v.Release.Database.CurrentDatabase = "other" },
		"key":     func(v *platformBackupCaptureFilesInput) { v.KeyVersion = "key-other" },
		"secret":  func(v *platformBackupCaptureFilesInput) { v.Caddyfile = []byte("password=secret") },
		"oversized": func(v *platformBackupCaptureFilesInput) {
			v.EdgeCaddyfile = bytes.Repeat([]byte("x"), int(PlatformBackupV3MaxTextMemberSize)+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, input := localPackageFixture(t)
			mutate(&input)
			if _, err := store.collectCapture(input); !errors.Is(err, ErrPlatformBackupLocal) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("collect=%v", err)
			}
			if _, err := store.transaction.ops.Lstat("config-caddyfile"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected input published text: %v", err)
			}
		})
	}
}

func TestPlatformBackupLocalCollectCrossFactMismatchesPublishNoTextLeaves(t *testing.T) {
	for name, mutate := range map[string]func(*platformBackupCaptureFilesInput){
		"routes": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.Routes.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
		"audit": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.Audit.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
		"keys": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.KeyReferences.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
		"tasks": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.TasksOutbox.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
		"tls": func(v *platformBackupCaptureFilesInput) {
			v.DatabaseFacts.TLS.DatabaseSnapshotSHA256 = strings.Repeat("1", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, input := localPackageFixture(t)
			mutate(&input)
			if _, err := store.collectCapture(input); !errors.Is(err, ErrPlatformBackupLocal) {
				t.Fatalf("collect=%v", err)
			}
			for _, member := range platformBackupLocalMembers {
				if member.leaf == platformBackupLocalControlPlaneDump {
					continue
				}
				spec, _ := platformBackupLocalSpec(member.leaf)
				if _, err := store.transaction.ops.Lstat(spec.name); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s published %q: %v", name, spec.name, err)
				}
			}
		})
	}
}

func TestPlatformBackupCaptureTextClonesCaddyInputsBeforeDurablePublication(t *testing.T) {
	store, input := localPackageFixture(t)
	text, err := platformBackupCaptureText(input)
	if err != nil {
		t.Fatal(err)
	}
	wantCaddy, wantEdge := append([]byte(nil), text["config/Caddyfile"]...), append([]byte(nil), text["config/open-card-edge.Caddyfile"]...)
	input.Caddyfile[0], input.EdgeCaddyfile[0] = 'X', 'Y'
	if !bytes.Equal(text["config/Caddyfile"], wantCaddy) || !bytes.Equal(text["config/open-card-edge.Caddyfile"], wantEdge) {
		t.Fatal("captured text aliased mutable caller input")
	}
	if err := store.publishCaptureText(platformBackupLocalConfigCaddyfile, text["config/Caddyfile"]); err != nil {
		t.Fatal(err)
	}
	if got, err := store.transaction.ReadMetadata("config-caddyfile"); err != nil || !bytes.Equal(got, wantCaddy) {
		t.Fatalf("durable caddy=%q err=%v", got, err)
	}
}

func TestPlatformBackupLocalPackageConflictAndLargeDump(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.transaction.WriteMetadata("package.tar", []byte("conflict")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.buildPackage(capture); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("conflicting final=%v", err)
	}
	if raw, err := store.transaction.ReadMetadata("package.tar"); err != nil || string(raw) != "conflict" {
		t.Fatalf("conflict replaced: %q %v", raw, err)
	}

	store, input = localPackageFixture(t)
	large := bytes.Repeat([]byte("dump"), backupEncryptionChunkSize/4+1)
	if err := store.transaction.RemoveMetadata("control-plane.dump"); err != nil {
		t.Fatal(err)
	}
	if err := store.transaction.WriteMetadata("control-plane.dump", large); err != nil {
		t.Fatal(err)
	}
	input.DumpEvidence = SnapshotEvidence{SHA256: scratchDigest(large), Size: int64(len(large))}
	capture, err = store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.buildPackage(capture); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformBackupLocalPackageSourceMutationAborts(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	// A changed accepted source cannot match its journal evidence and must fail
	// before it reaches the archive's second streaming pass.
	if err := store.transaction.RemoveMetadata("config-caddyfile"); err != nil {
		t.Fatal(err)
	}
	if err := store.transaction.WriteMetadata("config-caddyfile", []byte("changed.example.test { respond \"ok\" }\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.buildPackage(capture); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("source drift=%v", err)
	}
	if _, err := store.transaction.ops.Lstat("package.tar"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed build published package: %v", err)
	}
}

func TestPlatformBackupLocalPackageRejectsJournalKeyVersionMismatchOnReplayAndOpen(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := store.buildPackage(capture)
	if err != nil {
		t.Fatal(err)
	}
	tampered := capture
	tampered.KeyVersion = "key-other"
	if _, err := store.buildPackage(tampered); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("replay key mismatch=%v", err)
	}
	if reader, err := store.openPackage(tampered, evidence); !errors.Is(err, ErrPlatformBackupLocal) || reader != nil {
		t.Fatalf("open key mismatch reader=%v err=%v", reader, err)
	}
}

type localPackageMutatingReader struct{ *platformBackupMutatingReader }

func (localPackageMutatingReader) Close() error { return nil }

func TestPlatformBackupLocalBuildFromSourcesMutationAbortsWithoutFinalPackage(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := store.openCaptureMembers(capture)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(sources[0])
	if closeErr := sources[0].Close(); err != nil || closeErr != nil {
		t.Fatalf("source err=%v close=%v", err, closeErr)
	}
	mutated := append([]byte(nil), raw...)
	mutated[0] ^= 1
	sources[0] = localPackageMutatingReader{&platformBackupMutatingReader{current: bytes.NewReader(raw), replacement: mutated, mutateAtStartSeek: 4}}
	if _, err := store.buildPackageFromSources(capture, sources); !errors.Is(err, ErrPlatformBackupLocal) {
		t.Fatalf("mutation build=%v", err)
	}
	if _, err := store.transaction.ops.Lstat("package.tar"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mutation published final package: %v", err)
	}
}

func TestPlatformBackupLocalPackageReaderIsStreaming(t *testing.T) {
	store, input := localPackageFixture(t)
	capture, err := store.collectCapture(input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := store.buildPackage(capture)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.openPackage(capture, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if copied, err := io.Copy(io.Discard, reader); err != nil || copied != evidence.PackageSize {
		t.Fatalf("copied=%d err=%v", copied, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}
