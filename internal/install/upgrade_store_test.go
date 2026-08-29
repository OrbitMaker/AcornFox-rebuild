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

func TestUpgradeStoreLockMarkerAndStubs(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var", "var/lib", "var/lib/open-card", "var/lib/open-card/upgrade-transactions", "opt", "opt/open-card"} {
		if err := os.Mkdir(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	a, err := s.Acquire(ctx, "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Acquire(ctx, "txn-1"); err == nil {
		t.Fatal("second lock acquired")
	}
	if err = a.Release(); err != nil {
		t.Fatal(err)
	}
	if err = s.EnsureMarker(ctx, "txn-1"); err != nil {
		t.Fatal(err)
	}
	if err = s.EnsureMarker(ctx, "txn-2"); err == nil {
		t.Fatal("foreign marker")
	}
	if _, err = s.ProjectLegacy(ctx, "txn-1", ActivationV1{}); !errors.Is(err, ErrUpgradeStoreNotImplemented) {
		t.Fatal(err)
	}
}

func TestUpgradeStoreMarkerRequiresOwnedLock(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var", "var/lib", "var/lib/open-card", "var/lib/open-card/upgrade-transactions", "opt", "opt/open-card"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Marker(context.Background(), false); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("without lock err=%v", err)
	}
	lock, err := s.Acquire(context.Background(), "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Marker(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureMarker(context.Background(), "txn-2"); err == nil {
		t.Fatal("foreign marker accepted")
	}
	if err := s.Marker(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = lock.Release()
}

func TestUpgradeStoreJournalMutationRequiresMatchingLock(t *testing.T) {
	store, _, _, _, cleanup := candidateStore(t)
	defer cleanup()
	journal := journalAt(JournalPreflighted, false)
	if err := store.CreateJournal(context.Background(), journal); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("create without lock: %v", err)
	}
	wrong, err := store.Acquire(context.Background(), "txn-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateJournal(context.Background(), journal); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("create with foreign lock: %v", err)
	}
	if err := wrong.Release(); err != nil {
		t.Fatal(err)
	}
	lock := acquireCandidate(t, store)
	defer lock.Release()
	if err := store.CreateJournal(context.Background(), journal); err != nil {
		t.Fatal(err)
	}
	next := journal
	next.Revision = 2
	next.State = JournalQuiesced
	next.UpdatedAt = journal.UpdatedAt.Add(time.Second)
	next.History = []JournalTransitionV1{{Revision: 2, From: JournalPreflighted, To: JournalQuiesced, At: next.UpdatedAt, EvidenceSHA256: strings.Repeat("a", 64)}}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	wrong, err = store.Acquire(context.Background(), "txn-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(context.Background(), next); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("save with foreign lock: %v", err)
	}
	if err := wrong.Release(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(context.Background(), next); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("save without lock: %v", err)
	}
	lock = acquireCandidate(t, store)
	defer lock.Release()
	if err := store.SaveJournal(context.Background(), next); err != nil {
		t.Fatal(err)
	}
}

func candidateStore(t *testing.T) (*UpgradeStore, string, ActivationV1, []byte, func()) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card/upgrade-transactions", "run/lock"} {
		if err := os.MkdirAll(filepath.Join(root, p), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "opt/open-card"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"opt", "opt/open-card"} {
		if err := os.Chmod(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{"opt/open-card/activations", activationSlotDirMode}, {"opt/open-card/releases", 0o755}} {
		if err := os.Mkdir(filepath.Join(root, directory.path), directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	releaseID := "release-1"
	releaseDir := filepath.Join(root, "opt/open-card/releases", releaseID)
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(releaseDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(releaseDir, "bin/open-card-server")
	if err := os.WriteFile(binary, []byte("candidate-server\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binaryDigest, err := SHA256File(binary)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: "0.8.0-rc.0", ReleaseID: releaseID,
		Architecture: "amd64", MigrationVersion: "0023", SourceCommit: RC0SourceCommit, Protocol: AgentProtocolVersion,
		ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir,
		Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion},
		Files:         []FileDigest{{Path: "bin/open-card-server", SHA256: binaryDigest, Mode: 0o755}},
	}
	manifestPath := filepath.Join(releaseDir, "manifest.json")
	if err := SaveManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := SHA256File(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	env := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card_act_0123456789abcdef?sslmode=disable\n")
	envDigest := sha256.Sum256(env)
	activation := ActivationV1{
		SchemaVersion: ActivationSchemaVersion, ActivationID: "activation-1", Origin: "native",
		Release:           ReleaseV1{ID: releaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: manifestDigest},
		Database:          DatabaseV1{Name: "open_card_act_0123456789abcdef", Migration: manifest.MigrationVersion, SchemaMigrationsSHA256: strings.Repeat("a", 64)},
		DatabaseEnvSHA256: hex.EncodeToString(envDigest[:]), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "txn-1",
	}
	store, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() { _ = store.Close() }
	return store, root, activation, env, cleanup
}

func acquireCandidate(t *testing.T, store *UpgradeStore) UpgradeLock {
	t.Helper()
	lock, err := store.Acquire(context.Background(), "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	return lock
}

func seededPointerStore(t *testing.T) (*UpgradeStore, string, ActivationV1, ActivationV1, []byte, UpgradeLock, func()) {
	t.Helper()
	store, root, old, env, cleanup := candidateStore(t)
	lock := acquireCandidate(t, store)
	if _, err := store.WriteCandidateActivation(context.Background(), old, env); err != nil {
		lock.Release()
		cleanup()
		t.Fatal(err)
	}
	candidate := old
	candidate.ActivationID = "activation-2"
	if _, err := store.WriteCandidateActivation(context.Background(), candidate, env); err != nil {
		lock.Release()
		cleanup()
		t.Fatal(err)
	}
	if err := store.activationWriter.SwapActivationLink(ActivationLinkActive, old.ActivationID, ""); err != nil {
		lock.Release()
		cleanup()
		t.Fatal(err)
	}
	if err := store.activationWriter.SwapActivationLink(ActivationLinkCurrent, "", ""); err != nil {
		lock.Release()
		cleanup()
		t.Fatal(err)
	}
	return store, root, old, candidate, env, lock, cleanup
}

func TestUpgradeStoreWriteCandidateActivationSuccessAndIdempotence(t *testing.T) {
	store, root, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()

	got, err := store.WriteCandidateActivation(context.Background(), activation, env)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalActivationV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(raw)
	if got != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("digest=%q", got)
	}
	base := filepath.Join(root, "opt/open-card/activations", activation.ActivationID)
	for path, mode := range map[string]os.FileMode{
		filepath.Join(root, "opt/open-card"):             0o755,
		filepath.Join(root, "opt/open-card/activations"): activationSlotDirMode,
		base: activationSlotDirMode,
		filepath.Join(root, "opt/open-card/releases"):                                                   0o755,
		filepath.Join(root, "opt/open-card/releases", activation.Release.ID):                            0o755,
		filepath.Join(root, "opt/open-card/releases", activation.Release.ID, "manifest.json"):           0o644,
		filepath.Join(root, "opt/open-card/releases", activation.Release.ID, "bin", "open-card-server"): 0o755,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("runtime traversal mode path=%s got=%#o err=%v", path, info.Mode().Perm(), err)
		}
	}
	for _, name := range []string{"database.env", "activation.json"} {
		info, err := os.Lstat(filepath.Join(base, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != durableFileMode {
			t.Fatalf("%s is not durable metadata: %v %#o", name, err, info.Mode())
		}
	}
	if target, err := os.Readlink(filepath.Join(base, "release")); err != nil || target != "../../releases/release-1" {
		t.Fatalf("release link=%q err=%v", target, err)
	}
	if repeat, err := store.WriteCandidateActivation(context.Background(), activation, env); err != nil || repeat != got {
		t.Fatalf("idempotence digest=%q err=%v", repeat, err)
	}
}

func TestUpgradeStoreRejectsWritableSlotsAndReadableSecrets(t *testing.T) {
	store, root, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "opt/open-card/activations", activation.ActivationID)
	if err := os.Chmod(base, 0o731); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.readActivation(activation.ActivationID); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("writable slot accepted: %v", err)
	}
	if err := os.Chmod(base, activationSlotDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "database.env"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.readActivation(activation.ActivationID); err == nil {
		t.Fatal("readable database secret accepted")
	}
}

func TestUpgradeStorePreflightAndPointersCAS(t *testing.T) {
	store, _, old, candidate, _, lock, cleanup := seededPointerStore(t)
	defer cleanup()
	defer lock.Release()

	got, oldDigest, legacy, err := store.Preflight(context.Background(), "txn-1")
	if err != nil || legacy || got.ActivationID != old.ActivationID || !validSHA(oldDigest) {
		t.Fatalf("preflight activation=%#v digest=%q legacy=%v err=%v", got, oldDigest, legacy, err)
	}
	if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
		t.Fatal(err)
	}
	if err := store.SwapActive(context.Background(), candidate.ActivationID); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != candidate.ActivationID || state.PreviousID != old.ActivationID || state.Marker {
		t.Fatalf("after switch state=%#v err=%v", state, err)
	}
	if err := store.RestoreActive(context.Background(), old.ActivationID, candidate.ActivationID); err != nil {
		t.Fatal(err)
	}
	state, err = store.ReadActivationState(context.Background())
	if err != nil || state.ActiveID != old.ActivationID || state.PreviousID != candidate.ActivationID {
		t.Fatalf("after restore state=%#v err=%v", state, err)
	}
}

func TestUpgradeStoreRestorePreviousAndActualState(t *testing.T) {
	store, _, old, candidate, _, lock, cleanup := seededPointerStore(t)
	defer cleanup()
	defer lock.Release()
	if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
		t.Fatal(err)
	}
	if err := store.RestorePrevious(context.Background(), old.ActivationID, "", ""); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadActivationState(context.Background())
	if err != nil || state.PreviousID != "" {
		t.Fatalf("previous was not removed: %#v %v", state, err)
	}
	if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
		t.Fatal(err)
	}
	_, oldDigest, err := store.readActivation(old.ActivationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RestorePrevious(context.Background(), old.ActivationID, old.ActivationID, oldDigest); err != nil {
		t.Fatalf("same-pointer restore must be a CAS no-op: %v", err)
	}
	_, candidateDigest, err := store.readActivation(candidate.ActivationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RestorePrevious(context.Background(), old.ActivationID, candidate.ActivationID, candidateDigest); err != nil {
		t.Fatal(err)
	}
	if err := store.Marker(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	actual, err := store.ReadActualState(context.Background(), old.ActivationID, candidate.ActivationID)
	if err != nil || actual.ActiveID != old.ActivationID || actual.PreviousID != candidate.ActivationID || actual.MarkerTransactionID != "txn-1" || !actual.OldActivationExists || !actual.CandidateActivationExists || !validSHA(actual.OldActivationJSONSHA256) || !validSHA(actual.CandidateActivationJSONSHA256) {
		t.Fatalf("actual=%#v err=%v", actual, err)
	}
	if err := store.RestorePrevious(context.Background(), old.ActivationID, old.ActivationID, actual.OldActivationJSONSHA256); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("restore previous CAS mismatch: %v", err)
	}
}

func TestUpgradeStoreReadActivationStateFailsClosedOnCurrentDrift(t *testing.T) {
	store, root, _, _, _, lock, cleanup := seededPointerStore(t)
	defer cleanup()
	defer lock.Release()
	if err := os.Remove(filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/release-1", filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadActivationState(context.Background()); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("current drift accepted: %v", err)
	}
}

func TestUpgradeStorePreflightRefusesLegacyAndPointerDrift(t *testing.T) {
	store, root, old, _, _, lock, cleanup := seededPointerStore(t)
	defer cleanup()
	defer lock.Release()
	if err := os.Remove(filepath.Join(root, "opt/open-card/active")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+old.Release.ID, filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/open-card"), durableDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/open-card/server.env"), []byte("legacy"), durableFileMode); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Preflight(context.Background(), "txn-1"); !errors.Is(err, ErrLegacyProjectionRequired) {
		t.Fatalf("legacy preflight err=%v", err)
	}
	if err := os.Remove(filepath.Join(root, "etc/open-card/server.env")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Preflight(context.Background(), "txn-1"); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("missing active preflight err=%v", err)
	}
}

func TestUpgradeStoreWriteCandidateActivationRequiresOwnedTransactionAndDatabaseDigest(t *testing.T) {
	store, _, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("without lock: %v", err)
	}
	lock := acquireCandidate(t, store)
	defer lock.Release()
	wrongTransaction := activation
	wrongTransaction.CreatedByTransactionID = "txn-2"
	if _, err := store.WriteCandidateActivation(context.Background(), wrongTransaction, env); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("wrong transaction: %v", err)
	}
	badEnv := append([]byte(nil), env...)
	badEnv[len(badEnv)-2] = 'x'
	if _, err := store.WriteCandidateActivation(context.Background(), activation, badEnv); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("wrong database digest: %v", err)
	}
}

func TestUpgradeStoreWriteCandidateActivationRejectsReleaseDrift(t *testing.T) {
	store, root, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	manifest := filepath.Join(root, "opt/open-card/releases", activation.Release.ID, "manifest.json")
	if err := os.WriteFile(manifest, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("manifest hash drift: %v", err)
	}
	releaseDir := filepath.Join(root, "opt/open-card/releases", activation.Release.ID)
	if err := os.Chmod(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err == nil {
		t.Fatal("insecure release directory accepted")
	}
	if err := os.Chmod(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err == nil {
		t.Fatal("release manifest symlink accepted")
	}
}

func TestUpgradeStoreWriteCandidateActivationRejectsManifestIdentityMismatchWithoutOutsideWrite(t *testing.T) {
	store, root, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongMigration := activation
	wrongMigration.Database.Migration = "0024"
	if _, err := store.WriteCandidateActivation(context.Background(), wrongMigration, env); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("manifest migration mismatch: %v", err)
	}
	unsafeID := activation
	unsafeID.ActivationID = "../outside"
	if _, err := store.WriteCandidateActivation(context.Background(), unsafeID, env); err == nil {
		t.Fatal("unsafe activation id accepted")
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "unchanged" {
		t.Fatalf("outside path changed: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "opt/open-card/activations", activation.ActivationID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation created despite rejected inputs: %v", err)
	}
}

func TestUpgradeStoreWriteCandidateActivationRejectsPartialAndConflictingExistingActivation(t *testing.T) {
	for _, partial := range []string{"directory", "release", "database.env", "activation.json"} {
		t.Run(partial, func(t *testing.T) {
			store, root, activation, env, cleanup := candidateStore(t)
			defer cleanup()
			lock := acquireCandidate(t, store)
			defer lock.Release()
			base := filepath.Join(root, "opt/open-card/activations", activation.ActivationID)
			if err := os.Mkdir(base, activationSlotDirMode); err != nil {
				t.Fatal(err)
			}
			if partial == "release" {
				if err := os.Symlink("../../releases/"+activation.Release.ID, filepath.Join(base, "release")); err != nil {
					t.Fatal(err)
				}
			}
			if partial == "database.env" {
				if err := os.WriteFile(filepath.Join(base, "database.env"), env, durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if partial == "activation.json" {
				raw, err := MarshalActivationV1(activation)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(base, "activation.json"), raw, durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.WriteCandidateActivation(context.Background(), activation, env); !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("partial %s err=%v", partial, err)
			}
		})
	}

	store, root, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), env...)
	changed[len(changed)-2] = 'x'
	changedActivation := activation
	changedDigest := sha256.Sum256(changed)
	changedActivation.DatabaseEnvSHA256 = hex.EncodeToString(changedDigest[:])
	if _, err := store.WriteCandidateActivation(context.Background(), changedActivation, changed); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("conflicting re-entry err=%v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "opt/open-card/activations", activation.ActivationID, "database.env")); err != nil || string(raw) != string(env) {
		t.Fatalf("candidate env overwritten: %q %v", raw, err)
	}
}
