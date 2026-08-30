package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type bootstrapNthSyncFaultOps struct {
	durableOps
	failAt int
	calls  int
}

func (o *bootstrapNthSyncFaultOps) Sync(file *os.File) error {
	o.calls++
	if o.calls == o.failAt {
		return errors.New("injected bootstrap pointer sync failure")
	}
	return o.durableOps.Sync(file)
}

func bootstrapTaskStore(t *testing.T) (*BootstrapStore, UpgradeLock) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card", "var/lib/open-card/bootstrap-transactions", "opt/open-card", "etc/open-card", "etc/systemd/system"} {
		if e := os.MkdirAll(filepath.Join(root, p), 0o700); e != nil {
			t.Fatal(e)
		}
	}
	prepareTaskLock(t, root)
	s, e := TaskBootstrapStore(root, os.Getuid(), os.Getgid())
	if e != nil {
		t.Fatal(e)
	}
	l, e := s.Acquire(context.Background(), "bootstrap-txn-1")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Release(); _ = s.upgrade.Close() })
	return s, l
}
func TestBootstrapStoreJournalCASAndMarker(t *testing.T) {
	s, _ := bootstrapTaskStore(t)
	j := bootstrapJournalAt(t, BootstrapPrepared)
	if e := s.Create(context.Background(), j); e != nil {
		t.Fatal(e)
	}
	if e := s.Create(context.Background(), j); !errors.Is(e, ErrUpgradeJournalConflict) {
		t.Fatalf("create=%v", e)
	}
	if e := s.EnsureMarker(context.Background(), j.TransactionID); e != nil {
		t.Fatal(e)
	}
	if e := s.Marker(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	next := bootstrapJournalAt(t, BootstrapCandidateDBCreated)
	if e := s.Save(context.Background(), next); e != nil {
		t.Fatal(e)
	}
	bad := next
	bad.History[0].EvidenceSHA256 = "0" + bad.History[0].EvidenceSHA256[1:]
	bad.Revision++
	bad.History = append(bad.History, BootstrapHistoryV1{Revision: bad.Revision, From: bad.State, To: BootstrapMigrated0024, At: bad.UpdatedAt.AddDate(0, 0, 1), EvidenceSHA256: "1" + bad.History[0].EvidenceSHA256[1:]})
	bad.State = BootstrapMigrated0024
	if e := s.Save(context.Background(), bad); !errors.Is(e, ErrUpgradeJournalConflict) {
		t.Fatalf("cas=%v", e)
	}
	migrated := bootstrapJournalAt(t, BootstrapMigrated0024)
	if e := s.Save(context.Background(), migrated); e != nil {
		t.Fatal(e)
	}
	tampered := bootstrapJournalAt(t, BootstrapActivationWritten)
	tampered.CandidateDatabaseSchemaSHA256 = strings.Repeat("0", 64)
	if e := s.Save(context.Background(), tampered); !errors.Is(e, ErrUpgradeJournalConflict) {
		t.Fatalf("progressive evidence drift=%v", e)
	}
}
func TestBootstrapStoreRejectsUnownedMarkerAndFixedPath(t *testing.T) {
	s, _ := bootstrapTaskStore(t)
	if s.path("x") != "bootstrap-transactions/x.json" {
		t.Fatal("path drift")
	}
	if e := s.EnsureMarker(context.Background(), "other"); !errors.Is(e, ErrUpgradeJournalConflict) {
		t.Fatalf("marker=%v", e)
	}
}

func TestBootstrapStoreCreateAcceptsOnlyCanonicalPreparedJournal(t *testing.T) {
	store, _ := bootstrapTaskStore(t)
	for _, state := range []BootstrapState{BootstrapCandidateDBCreated, BootstrapMigrated0024, BootstrapActivationWritten, BootstrapPointersPublished, BootstrapInternalHealthy, BootstrapEdgeHealthy, BootstrapCommitted} {
		if err := store.Create(context.Background(), bootstrapJournalAt(t, state)); !errors.Is(err, ErrUpgradeJournalConflict) {
			t.Fatalf("direct create state=%s err=%v", state, err)
		}
	}
	recovery := bootstrapJournalAt(t, BootstrapActivationWritten)
	at := recovery.UpdatedAt.Add(time.Second)
	recovery.Revision++
	recovery.State, recovery.UpdatedAt = BootstrapRecoveryRequired, at
	recovery.Failure = &BootstrapFailureV1{Code: "activation_unknown", Digest: strings.Repeat("7", 64)}
	recovery.History = append(recovery.History, BootstrapHistoryV1{Revision: recovery.Revision, From: BootstrapActivationWritten, To: BootstrapRecoveryRequired, At: at, EvidenceSHA256: strings.Repeat("6", 64)})
	if err := store.Create(context.Background(), recovery); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("direct recovery create err=%v", err)
	}
	if _, err := store.Load(context.Background(), recovery.TransactionID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected direct create persisted a journal: %v", err)
	}
}

func bootstrapRC2Store(t *testing.T) (*BootstrapStore, BootstrapJournalV1, ActivationV1, []byte, string, func()) {
	t.Helper()
	upgrade, _, manifest, manifestPath, upgradeCleanup := productionCandidateUnitFixture(t)
	root := upgrade.root
	if err := os.Mkdir(filepath.Join(root, "var/lib/open-card/bootstrap-transactions"), 0o700); err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	lineage, err := RC1LineageForArchitecture("amd64")
	if err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	manifest.Version = Gate6CandidateVersion
	manifest.NMinusOne = &NMinusOne{Version: Gate6NMinusOneVersion, MigrationVersion: CurrentMigrationVersion, SourceCommit: lineage.SourceCommit, ReleaseManifestSHA256: lineage.ReleaseManifestSHA256, ArchiveSHA256: lineage.ArchiveSHA256, BundleManifestSHA256: lineage.BundleManifestSHA256}
	releaseDirectory := filepath.Dir(manifestPath)
	for path, mode := range map[string]os.FileMode{
		"scripts/mvp/host-preflight.sh":               0o755,
		"scripts/mvp/buildkit-production-capacity.sh": 0o755,
		"scripts/mvp/g6-staging-evidence.sh":          0o755,
		"tools/evidence/g6_validate.py":               0o644,
		"tools/evidence/g6_target_receipt.py":         0o644,
	} {
		full := filepath.Join(releaseDirectory, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			upgradeCleanup()
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(path+"\n"), mode); err != nil {
			upgradeCleanup()
			t.Fatal(err)
		}
		digest, err := SHA256File(full)
		if err != nil {
			upgradeCleanup()
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, FileDigest{Path: path, SHA256: digest, Mode: uint32(mode)})
	}
	if err := SaveManifest(manifestPath, manifest); err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	manifestDigest, err := SHA256File(manifestPath)
	if err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	release := ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: manifestDigest}
	databaseName := "open_card_act_0123456789abcdef"
	databaseEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:secret@127.0.0.1:5432/" + databaseName + "?sslmode=disable\n")
	envSum := sha256.Sum256(databaseEnv)
	journal := bootstrapJournalAt(t, BootstrapActivationWritten)
	journal.Release = release
	journal.CandidateActivationID = "bootstrap-activation-1"
	journal.CandidateDatabaseName = databaseName
	activation := ActivationV1{
		SchemaVersion: ActivationSchemaVersion, ActivationID: journal.CandidateActivationID, Origin: "native", Release: release,
		Database:          DatabaseV1{Name: databaseName, Migration: CurrentMigrationVersion, SchemaMigrationsSHA256: journal.CandidateDatabaseSchemaSHA256},
		DatabaseEnvSHA256: hex.EncodeToString(envSum[:]), CreatedAt: time.Unix(20, 0).UTC(), CreatedByTransactionID: journal.TransactionID,
	}
	activationDigest, err := CanonicalActivationJSONSHA256(activation)
	if err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	journal.ActivationJSONSHA256 = activationDigest
	if err := journal.Validate(); err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	store := &BootstrapStore{upgrade: upgrade}
	lock, err := store.Acquire(context.Background(), journal.TransactionID)
	if err != nil {
		upgradeCleanup()
		t.Fatal(err)
	}
	cleanup := func() {
		_ = lock.Release()
		upgradeCleanup()
	}
	return store, journal, activation, databaseEnv, root, cleanup
}

func bootstrapJournalRevision(t *testing.T, journal BootstrapJournalV1, revision int64) BootstrapJournalV1 {
	t.Helper()
	if revision < 1 || revision > int64(len(journal.History)) {
		t.Fatal("invalid bootstrap journal fixture revision")
	}
	next := journal
	next.Revision = revision
	next.History = append([]BootstrapHistoryV1(nil), journal.History[:revision]...)
	last := next.History[len(next.History)-1]
	next.State, next.UpdatedAt = last.To, last.At
	rank := bootstrapRank(next.State)
	if rank < 2 {
		next.CandidateDatabaseSchemaSHA256 = ""
	}
	if rank < 3 {
		next.ActivationJSONSHA256 = ""
	}
	if rank < 4 {
		next.PointerStateSHA256 = ""
	}
	if rank < 5 {
		next.InternalHealthSHA256, next.ServiceSnapshot = "", nil
	}
	if rank < 6 {
		next.EdgeHealthSHA256 = ""
	}
	next.Failure = nil
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	return next
}

func persistBootstrapJournal(t *testing.T, store *BootstrapStore, journal BootstrapJournalV1, marker bool) {
	t.Helper()
	if err := store.Create(context.Background(), bootstrapJournalRevision(t, journal, 1)); err != nil {
		t.Fatal(err)
	}
	for revision := int64(2); revision <= journal.Revision; revision++ {
		if err := store.Save(context.Background(), bootstrapJournalRevision(t, journal, revision)); err != nil {
			t.Fatal(err)
		}
	}
	if marker {
		if err := store.EnsureMarker(context.Background(), journal.TransactionID); err != nil {
			t.Fatal(err)
		}
	}
}

func persistBootstrapActivationWritten(t *testing.T, store *BootstrapStore, journal BootstrapJournalV1, activation ActivationV1, databaseEnv []byte) {
	t.Helper()
	migrated := bootstrapJournalRevision(t, journal, 3)
	persistBootstrapJournal(t, store, migrated, true)
	digest, err := store.WriteInitialActivation(context.Background(), migrated, activation, databaseEnv)
	if err != nil || digest != journal.ActivationJSONSHA256 {
		t.Fatalf("write activation digest=%q err=%v", digest, err)
	}
	if err := store.Save(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapInitialActivationPublishesExactPointersAndReplays(t *testing.T) {
	store, journal, activation, databaseEnv, _, cleanup := bootstrapRC2Store(t)
	defer cleanup()
	persistBootstrapActivationWritten(t, store, journal, activation, databaseEnv)
	first, err := store.PublishInitialPointers(context.Background(), journal, activation)
	if err != nil || !validSHA(first) {
		t.Fatalf("publish digest=%q err=%v", first, err)
	}
	second, err := store.PublishInitialPointers(context.Background(), journal, activation)
	if err != nil || second != first {
		t.Fatalf("replay digest=%q want=%q err=%v", second, first, err)
	}
	state, err := store.upgrade.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != activation.ActivationID || state.ActiveActivationJSONSHA256 != journal.ActivationJSONSHA256 || state.PreviousID != "" || !state.Marker {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if first == journal.ActivationJSONSHA256 || strings.Contains(first, activation.ActivationID) {
		t.Fatal("pointer evidence is not an independent digest")
	}
}

func TestBootstrapInitialActivationConvergesExactActiveOnlyCrash(t *testing.T) {
	store, journal, activation, databaseEnv, _, cleanup := bootstrapRC2Store(t)
	defer cleanup()
	persistBootstrapActivationWritten(t, store, journal, activation, databaseEnv)
	if err := store.upgrade.activationWriter.SwapActivationLink(ActivationLinkActive, activation.ActivationID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishInitialPointers(context.Background(), journal, activation); err != nil {
		t.Fatal(err)
	}
	if !store.exactCurrent() {
		t.Fatal("exact active-only crash did not converge current")
	}
}

func TestBootstrapInitialActivationRejectsForeignAndUnsafePointerStates(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, *BootstrapStore, ActivationV1, string){
		"foreign-active": func(t *testing.T, store *BootstrapStore, _ ActivationV1, _ string) {
			t.Helper()
			if err := store.upgrade.activationWriter.SwapActivationLink(ActivationLinkActive, "foreign", ""); err != nil {
				t.Fatal(err)
			}
		},
		"current-without-active": func(t *testing.T, store *BootstrapStore, _ ActivationV1, _ string) {
			t.Helper()
			if err := store.upgrade.activationWriter.SwapActivationLink(ActivationLinkCurrent, "", ""); err != nil {
				t.Fatal(err)
			}
		},
		"previous-present": func(t *testing.T, store *BootstrapStore, _ ActivationV1, _ string) {
			t.Helper()
			if err := store.upgrade.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, "foreign", ""); err != nil {
				t.Fatal(err)
			}
		},
		"unsafe-current": func(t *testing.T, store *BootstrapStore, _ ActivationV1, root string) {
			t.Helper()
			if err := os.Symlink("foreign", filepath.Join(root, "opt/open-card/current")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, journal, activation, databaseEnv, root, cleanup := bootstrapRC2Store(t)
			defer cleanup()
			persistBootstrapActivationWritten(t, store, journal, activation, databaseEnv)
			arrange(t, store, activation, root)
			if _, err := store.PublishInitialPointers(context.Background(), journal, activation); !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("unsafe pointer state err=%v", err)
			}
		})
	}
}

func TestBootstrapWriteInitialActivationRequiresPointerAbsence(t *testing.T) {
	store, journal, activation, databaseEnv, _, cleanup := bootstrapRC2Store(t)
	defer cleanup()
	migrated := bootstrapJournalRevision(t, journal, 3)
	persistBootstrapJournal(t, store, migrated, true)
	if err := store.upgrade.activationWriter.SwapActivationLink(ActivationLinkActive, activation.ActivationID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteInitialActivation(context.Background(), migrated, activation, databaseEnv); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("preexisting pointer accepted before activation write: %v", err)
	}
}

func TestBootstrapInitialActivationRequiresDurableBoundJournalAndMarker(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*BootstrapJournalV1, *ActivationV1)
		keepMarker bool
	}{
		"wrong-state":      {func(j *BootstrapJournalV1, _ *ActivationV1) { j.State = BootstrapMigrated0024 }, true},
		"wrong-activation": {func(_ *BootstrapJournalV1, a *ActivationV1) { a.ActivationID = "other-activation" }, true},
		"wrong-database":   {func(_ *BootstrapJournalV1, a *ActivationV1) { a.Database.Name = "open_card_act_ffffffffffffffff" }, true},
		"wrong-release":    {func(_ *BootstrapJournalV1, a *ActivationV1) { a.Release.SourceCommit = strings.Repeat("f", 40) }, true},
		"no-marker":        {func(*BootstrapJournalV1, *ActivationV1) {}, false},
	} {
		t.Run(name, func(t *testing.T) {
			store, journal, activation, databaseEnv, _, cleanup := bootstrapRC2Store(t)
			defer cleanup()
			if tc.keepMarker {
				persistBootstrapActivationWritten(t, store, journal, activation, databaseEnv)
			} else {
				migrated := bootstrapJournalRevision(t, journal, 3)
				persistBootstrapJournal(t, store, migrated, false)
				if _, err := store.upgrade.WriteCandidateActivation(context.Background(), activation, databaseEnv); err != nil {
					t.Fatal(err)
				}
				if err := store.Save(context.Background(), journal); err != nil {
					t.Fatal(err)
				}
			}
			tc.mutate(&journal, &activation)
			if _, err := store.PublishInitialPointers(context.Background(), journal, activation); !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("unbound request err=%v", err)
			}
		})
	}
}

func TestBootstrapInitialActivationReconcilesPostRenameUnknown(t *testing.T) {
	store, journal, activation, databaseEnv, _, cleanup := bootstrapRC2Store(t)
	defer cleanup()
	persistBootstrapActivationWritten(t, store, journal, activation, databaseEnv)
	original := store.upgrade.activationWriter.ops
	store.upgrade.activationWriter.ops = &bootstrapNthSyncFaultOps{durableOps: original, failAt: 3}
	digest, err := store.PublishInitialPointers(context.Background(), journal, activation)
	if err != nil || !validSHA(digest) {
		t.Fatalf("post-rename reconciliation digest=%q err=%v", digest, err)
	}
}

func TestBootstrapStoreHasNoDestructiveOrLegacyFallbackSurface(t *testing.T) {
	raw, err := os.ReadFile("bootstrap_store.go")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"drop database", "removeactivationlink", "projectlegacy", "server.env", "open_card_database_url"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("bootstrap store contains forbidden surface %q", forbidden)
		}
	}
}
