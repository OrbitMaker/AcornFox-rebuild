package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type legacyVerifierFake struct {
	release           ReleaseV1
	rows              []MigrationRow
	unit              []byte
	sourceTemplate    []byte
	candidateTemplate []byte
	caddy             []byte
	err               error
}

func prepareTaskLock(t *testing.T, root string) {
	t.Helper()
	if err := PrepareTaskUpgradeLock(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
}

func (v legacyVerifierFake) VerifyRC0(string) (ReleaseV1, []MigrationRow, error) {
	return v.release, v.rows, v.err
}
func (v legacyVerifierFake) CandidateServerUnit(ReleaseV1) ([]byte, error) { return v.unit, v.err }
func (v legacyVerifierFake) RC0EdgeTemplate(ReleaseV1) ([]byte, error) {
	if len(v.sourceTemplate) == 0 {
		return edgeSourceTemplateFixture(), v.err
	}
	return v.sourceTemplate, v.err
}
func (v legacyVerifierFake) CandidateEdgeConfig(ReleaseV1) ([]byte, []byte, error) {
	template, caddy := v.candidateTemplate, v.caddy
	if len(template) == 0 {
		template = edgeCandidateTemplateFixture()
	}
	if len(caddy) == 0 {
		caddy = []byte("caddy\n")
	}
	return template, caddy, v.err
}

func edgeSourceTemplateFixture() []byte {
	return []byte("console.example.invalid {\n\trespond 200\n}\n")
}
func edgeCandidateTemplateFixture() []byte {
	return []byte("http://127.0.0.1:18482 {\n\t@edge_health path /healthz\n\trespond @edge_health 200\n\trespond 404\n}\n\nconsole.example.invalid {\n\trespond 200\n}\n")
}

func TestLegacyMigrationRowsRequireFrozenRC0BundleMode(t *testing.T) {
	names := []string{
		"0001_foundation", "0002_invariants", "0003_audit_chain_serialization",
		"0004_repository_runtime", "0005_observability", "0006_controller_worker",
		"0007_compatibility_contract", "0008_m1_delivery", "0009_m1_runtime_observation",
		"0010_m1_publish_idempotency", "0011_m1_source_reupload", "0012_m2_service_groups",
		"0013_m3_access_routes", "0014_m4_operations_notifications", "0015_m4_rollout_coordinator",
		"0016_m4_staged_route_sets", "0017_m4_independent_runtime_facts", "0018_m4_atomic_rollout_plan",
		"0019_m4_durable_candidate_cleanup", "0020_m5_usage", "0021_m6_controlled_ai",
		"0022_admin_auth", "0023_source_uploads",
	}
	manifest := Manifest{}
	for _, name := range names {
		manifest.Files = append(manifest.Files, FileDigest{
			Path:   "migrations/control-plane/" + name + ".sql",
			SHA256: strings.Repeat("a", 64),
			Mode:   0o640,
		})
	}
	rows, err := legacyMigrationRows(manifest)
	if err != nil || len(rows) != len(names) || rows[0].Version != names[0] || rows[22].Version != names[22] {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	evidence, err := migrationEvidence(rows)
	if err != nil || evidence.RowsSHA256 != "94861d794456e6be9672ea26f3ec4ef503ddd6fea48c3487c278552b2c9d0b05" {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	manifest.Files[0].Mode = 0o644
	if _, err := legacyMigrationRows(manifest); err == nil {
		t.Fatal("source-tree migration mode accepted as frozen RC0 bundle evidence")
	}
}

func TestPreflightPlanLegacyWithInjectedVerifierIsPureAndRedacted(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card/upgrade-transactions", "run/lock", "etc/open-card", "etc/systemd/system", "opt/open-card/releases/rc0"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"opt", "opt/open-card", "opt/open-card/releases", "opt/open-card/releases/rc0"} {
		_ = os.Chmod(filepath.Join(root, p), 0755)
	}
	if err := os.Symlink("releases/rc0", filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/open-card/server.env"), []byte("# keep\nOPEN_CARD_DATABASE_URL=postgresql://u:p@127.0.0.1:5432/open_card\n"), 0600); err != nil {
		t.Fatal(err)
	}
	installed, err := renderEdgeConfigTemplate(edgeSourceTemplateFixture(), "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/open-card/open-card-edge.Caddyfile"), installed, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/open-card-server.service"), []byte("[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rows := migrationRows(23)
	release := ReleaseV1{ID: "rc0", Version: ProductionNMinusOneVersion, SourceCommit: RC0SourceCommit, Architecture: "amd64", ManifestSHA256: RC0ReleaseManifestSHA256}
	candidate := ReleaseV1{ID: "rc1", Version: ProductionCandidateVersion, SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("b", 64)}
	unit := []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\n")
	prepareTaskLock(t, root)
	store, err := TaskUpgradeStoreWithLegacyVerifier(root, os.Getuid(), os.Getgid(), legacyVerifierFake{release: release, rows: rows, unit: unit})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.Acquire(context.Background(), "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	plan, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: candidate})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Legacy == nil || len(plan.Legacy.DatabaseEnv) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.Legacy.ServerEnvBeforeSHA256 == plan.Legacy.ServerEnvAfterSHA256 {
		t.Fatal("legacy plan did not record distinct server.env before/after hashes")
	}
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "u:p") {
		t.Fatal("DSN leaked")
	}
}

func TestLegacyDatabaseEnvRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	valid := []byte("# keep\nOPEN_CARD_DATABASE_URL=postgresql://u:p@127.0.0.1:5432/open_card\n")
	got, _, err := splitLegacyServerEnv(valid)
	if err != nil || !bytes.Contains(got, []byte("OPEN_CARD_DATABASE_URL=postgresql://u:p@127.0.0.1:5432/open_card")) {
		t.Fatalf("valid env got=%q err=%v", got, err)
	}
	for _, raw := range [][]byte{
		[]byte("OPEN_CARD_DATABASE_URL=x\nOPEN_CARD_DATABASE_URL=y\n"),
		[]byte("export OPEN_CARD_DATABASE_URL=x\n"), []byte(" OPEN_CARD_DATABASE_URL=x\n"),
		[]byte("OPEN_CARD_DATABASE_URL=x\r\n"), []byte("OPEN_CARD_DATABASE_URL=x\x00\n"), []byte("OTHER=x\n"),
	} {
		if _, _, err := splitLegacyServerEnv(raw); err == nil {
			t.Fatalf("unsafe env accepted: %q", raw)
		}
	}
}

func TestUpgradeStoreLockMarkerAndStubs(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var", "var/lib", "var/lib/open-card", "var/lib/open-card/upgrade-transactions", "opt", "opt/open-card", "etc", "etc/open-card", "etc/systemd", "etc/systemd/system"} {
		if err := os.Mkdir(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	prepareTaskLock(t, root)
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
}

func TestUpgradeStoreAcceptsInstallerRecoverySubstrateModes(t *testing.T) {
	root := t.TempDir()
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{"var", 0o711}, {"var/lib", 0o711}, {"var/lib/open-card", 0o711},
		{"var/lib/open-card/upgrade-transactions", 0o700}, {"var/lib/open-card/upgrade-artifacts", 0o700},
		{"opt", 0o711}, {"opt/open-card", 0o711}, {"opt/open-card/activations", 0o711},
		{"etc", 0o711}, {"etc/open-card", 0o700}, {"etc/systemd", 0o711}, {"etc/systemd/system", 0o755},
	} {
		if err := os.Mkdir(filepath.Join(root, item.path), item.mode); err != nil {
			t.Fatalf("mkdir %s: %v", item.path, err)
		}
	}
	prepareTaskLock(t, root)
	store, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("installer substrate modes rejected: %v", err)
	}
	defer store.Close()
}

func TestUpgradeStoreCloseReleasesLockAndAttemptsWritersInReverseOrder(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var", "var/lib", "var/lib/open-card", "var/lib/open-card/upgrade-transactions", "opt", "opt/open-card", "etc", "etc/open-card", "etc/systemd", "etc/systemd/system"} {
		if err := os.Mkdir(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	prepareTaskLock(t, root)
	store, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), "txn-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if lock, err := second.Acquire(context.Background(), "txn-2"); err != nil {
		t.Fatalf("lock was not released: %v", err)
	} else {
		defer lock.Release()
	}

	order := []string{}
	first := errors.New("first close")
	writers := []*DurableWriter{
		{ops: &storeCloseOps{name: "data", order: &order}},
		{ops: &storeCloseOps{name: "activation", order: &order}},
		{ops: &storeCloseOps{name: "config", order: &order, err: first}},
		{ops: &storeCloseOps{name: "unit", order: &order}},
	}
	manual := &UpgradeStore{dataWriter: writers[0], activationWriter: writers[1], configDurable: writers[2], unitDurable: writers[3]}
	if err := manual.Close(); !errors.Is(err, first) {
		t.Fatalf("close error = %v", err)
	}
	want := []string{"unit", "config", "activation", "data"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("close order = %v, want %v", order, want)
	}
	if err := manual.Close(); err != nil || !reflect.DeepEqual(order, want) {
		t.Fatalf("second close=%v order=%v", err, order)
	}
}

type storeCloseOps struct {
	durableOps
	name  string
	order *[]string
	err   error
}

func (o *storeCloseOps) Close() error {
	*o.order = append(*o.order, o.name)
	return o.err
}

func TestUpgradeStoreLockIsPreprovisionedAndValidated(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card/upgrade-transactions", "opt/open-card/activations", "etc/open-card", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, p), durableDirMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "opt/open-card/activations"), activationSlotDirMode); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "run/lock/open-card-upgrade.lock")
	if _, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("missing task lock constructor was accepted")
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor created task lock: %v", err)
	}
	if err := PrepareTaskUpgradeLock(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	store, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), "txn-1"); err == nil {
		t.Fatal("missing lock was accepted")
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Acquire recreated missing task lock: %v", err)
	}
	if err := PrepareTaskUpgradeLock(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := verifyLockFile(lockPath, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("wrong-owner lock was accepted")
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), "txn-1"); err == nil {
		t.Fatal("wrong-mode lock was accepted")
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), "txn-1"); err == nil {
		t.Fatal("symlink lock was accepted")
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := PrepareTaskUpgradeLock(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	first, err := store.Acquire(context.Background(), "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	secondStore, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	if _, err := secondStore.Acquire(context.Background(), "txn-2"); !errors.Is(err, ErrUpgradeLocked) {
		t.Fatalf("busy lock err=%v", err)
	}
}

func TestUpgradeStoreMarkerRequiresOwnedLock(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var", "var/lib", "var/lib/open-card", "var/lib/open-card/upgrade-transactions", "opt", "opt/open-card", "etc", "etc/open-card", "etc/systemd", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	prepareTaskLock(t, root)
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

func TestAcquirePendingBootAtomicallyBindsMarkerAndFlock(t *testing.T) {
	store, root, _, _, cleanup := candidateStore(t)
	defer cleanup()
	other, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	lock, pending, err := store.AcquirePendingBoot(context.Background())
	if err != nil || pending.Marker != UpgradeMarkerAbsent || store.lock == nil || store.lock.tx != pendingBootLockIdentity {
		t.Fatalf("absent boot acquire pending=%+v lock=%#v err=%v", pending, store.lock, err)
	}
	// This is the marker-absent TOCTOU proof: an ordinary upgrade cannot acquire
	// the global lock before the boot barrier releases its no-op decision.
	if _, err := other.Acquire(context.Background(), "txn-race"); !errors.Is(err, ErrUpgradeLocked) {
		t.Fatalf("ordinary upgrade acquired during boot decision: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	if err := store.dataWriter.CreateMetadata(storeUpgradeInProgressPath, []byte("txn-marker\n")); err != nil {
		t.Fatal(err)
	}
	lock, pending, err = store.AcquirePendingBoot(context.Background())
	if err != nil || pending.Marker != UpgradeMarkerSame || pending.TransactionID != "txn-marker" || store.lock == nil || store.lock.tx != "txn-marker" {
		t.Fatalf("same-marker boot acquire pending=%+v lock=%#v err=%v", pending, store.lock, err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	if err := store.dataWriter.WriteMetadata(storeUpgradeInProgressPath, []byte("bad\nmarker\n")); err != nil {
		t.Fatal(err)
	}
	if lock, pending, err := store.AcquirePendingBoot(context.Background()); err == nil || lock != nil || pending.Marker != "" {
		t.Fatalf("malformed marker accepted: lock=%v pending=%+v err=%v", lock, pending, err)
	}
	if lock, err := other.Acquire(context.Background(), "txn-after-malformed"); err != nil {
		t.Fatalf("malformed marker leaked flock: %v", err)
	} else if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreReturnsUnknownWhenMarkerOrPointerPublishesIntoReplacedRoot(t *testing.T) {
	t.Run("marker", func(t *testing.T) {
		store, root, _, _, cleanup := candidateStore(t)
		defer cleanup()
		lock := acquireCandidate(t, store)
		defer lock.Release()
		live := filepath.Join(root, "var", "lib", "open-card")
		writer, fault := renameHookWriter(t, live)
		store.dataWriter = writer
		fault.afterRename = func() error {
			if err := os.Rename(live, live+"-detached"); err != nil {
				return err
			}
			return os.Mkdir(live, durableDirMode)
		}
		if err := store.Marker(context.Background(), true); !errors.Is(err, ErrDurableCommitUnknown) {
			t.Fatalf("marker err=%v", err)
		}
	})
	t.Run("pointer", func(t *testing.T) {
		store, root, old, _, _, lock, cleanup := seededPointerStore(t)
		defer cleanup()
		defer lock.Release()
		live := filepath.Join(root, "opt", "open-card")
		writer, fault := renameHookWriter(t, live)
		store.activationWriter = writer
		fault.afterRename = func() error {
			if err := os.Rename(live, live+"-detached"); err != nil {
				return err
			}
			return os.Mkdir(live, durableDirMode)
		}
		if err := store.SetPrevious(context.Background(), old.ActivationID); !errors.Is(err, ErrDurableCommitUnknown) {
			t.Fatalf("pointer err=%v", err)
		}
	})
}

func TestUpgradeStoreRejectsReplacedPinnedRoots(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card/upgrade-transactions", "opt/open-card/activations", "etc/open-card", "etc/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "opt/open-card/activations"), activationSlotDirMode); err != nil {
		t.Fatal(err)
	}
	prepareTaskLock(t, root)
	s, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lock, err := s.Acquire(context.Background(), "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	for _, relative := range []string{"opt/open-card", "etc/open-card", "etc/systemd/system", "var/lib/open-card"} {
		sub := filepath.Join(root, relative)
		moved := sub + "-old"
		if err := os.Rename(sub, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
		if err := s.verifyLiveRoots(); !errors.Is(err, ErrUpgradeJournalConflict) {
			t.Fatalf("root %s replacement err=%v", relative, err)
		}
		if relative == "opt/open-card" {
			if _, err := s.createActivationDirectory("act-replaced"); err == nil {
				t.Fatal("activation slot was created in replacement root")
			}
			if _, err := os.Lstat(filepath.Join(sub, "activations", "act-replaced")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("replacement activation root was mutated: %v", err)
			}
		}
		// Recreate the store each loop so each root is independently pinned.
		_ = lock.Release()
		s.Close()
		prepareTaskLock(t, root)
		s, err = TaskUpgradeStore(root, os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		lock, err = s.Acquire(context.Background(), "txn-1")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecureReleaseFileRejectsLinksModesAndParentEscape(t *testing.T) {
	root := t.TempDir()
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, path := range []string{"releases", "releases/release-1", "releases/release-1/systemd"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(root, "releases/release-1/manifest.json")
	unit := filepath.Join(root, "releases/release-1/systemd/open-card-server.service")
	if err := os.WriteFile(manifest, []byte("manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := secureReleaseFile(writer, "release-1", "manifest.json", 0o644); err != nil || string(got) != "manifest" {
		t.Fatalf("read=%q err=%v", got, err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReleaseFile(writer, "release-1", "manifest.json", 0o644); err == nil {
		t.Fatal("manifest symlink accepted")
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReleaseFile(writer, "release-1", "manifest.json", 0o644); err == nil {
		t.Fatal("wrong manifest mode accepted")
	}
	if err := os.Chmod(manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", unit); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReleaseFile(writer, "release-1", "systemd/open-card-server.service", 0o644); err == nil {
		t.Fatal("unit symlink accepted")
	}
	if err := os.RemoveAll(filepath.Join(root, "releases/release-1/systemd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", filepath.Join(root, "releases/release-1/systemd")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReleaseFile(writer, "release-1", "systemd/open-card-server.service", 0o644); err == nil {
		t.Fatal("parent symlink accepted")
	}
}

func TestSecureReleaseFileRejectsOwnerMismatchForLeafAndParent(t *testing.T) {
	root := t.TempDir()
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, path := range []string{"releases/release-1/systemd"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(root, "releases/release-1/manifest.json")
	unit := filepath.Join(root, "releases/release-1/systemd/open-card-server.service")
	if err := os.WriteFile(manifest, []byte("manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	ownerMismatch := func(name string) func(os.FileInfo, int, int) error {
		return func(info os.FileInfo, uid, gid int) error {
			if info.Name() == name {
				return errors.New("synthetic owner mismatch")
			}
			return verifyOwner(info, uid, gid)
		}
	}
	if _, err := secureReleaseFileWithOwnerCheck(writer, "release-1", "manifest.json", 0o644, ownerMismatch("manifest.json")); err == nil {
		t.Fatal("wrong leaf owner accepted")
	}
	if _, err := secureReleaseFileWithOwnerCheck(writer, "release-1", "systemd/open-card-server.service", 0o644, ownerMismatch("systemd")); err == nil {
		t.Fatal("wrong nested parent owner accepted")
	}
}

func TestSecureReleaseFileBindsDescriptorAcrossReplacement(t *testing.T) {
	root := t.TempDir()
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := os.MkdirAll(filepath.Join(root, "releases/release-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "releases/release-1/manifest.json")
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	replaced := false
	check := func(info os.FileInfo, uid, gid int) error {
		if info.Name() == "manifest.json" && !replaced {
			replaced = true
			if err := os.Rename(path, filepath.Join(root, "releases/release-1/manifest.old")); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte("after"), 0o644); err != nil {
				return err
			}
		}
		return verifyOwner(info, uid, gid)
	}
	got, err := secureReleaseFileWithOwnerCheck(writer, "release-1", "manifest.json", 0o644, check)
	if err != nil || string(got) != "before" {
		t.Fatalf("descriptor content=%q err=%v", got, err)
	}
}

func TestVerifySecureReleaseRejectsExactSetViolations(t *testing.T) {
	store, root, activation, _, cleanup := candidateStore(t)
	defer cleanup()
	if err := store.verifyCandidateRelease(activation); err != nil {
		t.Fatalf("baseline release rejected: %v", err)
	}
	extra := filepath.Join(root, "opt/open-card/releases", activation.Release.ID, "unexpected")
	if err := os.WriteFile(extra, []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyCandidateRelease(activation); err == nil {
		t.Fatal("extra release file accepted")
	}
}

func TestUpgradeStoreRejectsIncompleteProductionCandidateBeforeSlotPublication(t *testing.T) {
	store, release, _, _, cleanup := productionCandidateUnitFixture(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	if err := os.Remove(filepath.Join(store.root, "opt/open-card/releases", release.ID, "web/dist/index.html")); err != nil {
		t.Fatal(err)
	}
	activationID := "activation-production"
	name, err := CandidateDatabaseName(activationID)
	if err != nil {
		t.Fatal(err)
	}
	env := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/" + name + "?sslmode=disable\n")
	activation := ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: activationID, Origin: "native", Release: release, Database: DatabaseV1{Name: name, Migration: "0024", SchemaMigrationsSHA256: strings.Repeat("a", 64)}, DatabaseEnvSHA256: sha256Bytes(env), CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: "txn-1"}
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err == nil {
		t.Fatal("incomplete production candidate was published")
	}
	if _, err := store.activationWriter.ops.Lstat(filepath.Join("activations", activationID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation slot was created before candidate verification: %v", err)
	}
}

func TestValidateLegacyCandidateUnitAcceptsProductionSemanticsAndRejectsUnsafeEnvironmentFiles(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "open-card-server.service"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyCandidateUnit(golden); err != nil {
		t.Fatalf("production unit rejected: %v", err)
	}
	valid := []byte("# signed production fragment\n[Unit]\nDescription=Open Card\nAfter=network-online.target\n\n[Service]\nUser=opencard\nEnvironmentFile=-/etc/open-card/server.env\nExecStart=/opt/open-card/current/bin/open-card-server\nEnvironmentFile=/opt/open-card/active/database.env\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n")
	if err := validateLegacyCandidateUnit(valid); err != nil {
		t.Fatalf("canonical unit rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":   []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\n"),
		"wrong-order": []byte("[Service]\nEnvironmentFile=/opt/open-card/active/database.env\nEnvironmentFile=-/etc/open-card/server.env\n"),
		"alternate":   []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/tmp/not-the-active-database.env\n"),
		"outside":     []byte("[Unit]\nEnvironmentFile=-/etc/open-card/server.env\n[Service]\nEnvironmentFile=/opt/open-card/active/database.env\n"),
		"missing":     []byte("[Service]\nExecStart=/bin/true\n"),
		"environment": []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\nEnvironment=OPEN_CARD_DATABASE_URL=postgresql://override\n"),
		"unset":       []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\nUnsetEnvironment=OPEN_CARD_DATABASE_URL\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLegacyCandidateUnit(raw); err == nil {
				t.Fatalf("unsafe unit accepted: %q", raw)
			}
		})
	}
}

func TestDescriptorReadBindsOpenedFileAcrossReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "evidence"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.OpenFile("evidence", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(filepath.Join(root, "evidence"), filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "evidence"), []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("before"))
	if _, err := io.ReadFull(f, buf); err != nil || string(buf) != "before" {
		t.Fatalf("descriptor changed=%q err=%v", buf, err)
	}
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

func TestUpgradeStorePreflightPlanRequiresOwnedLockAndIsReadOnly(t *testing.T) {
	store, root, activation, _, cleanup := candidateStore(t)
	defer cleanup()
	request := UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: activation.Release}
	before := filepath.Join(root, "opt/open-card")
	if _, err := store.PreflightPlan(context.Background(), request); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("preflight without lock accepted: %v", err)
	}
	if _, err := os.Stat(before); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeStoreNativePreflightPinsDatabaseEnvWithoutSerializingIt(t *testing.T) {
	store, _, activation, env, cleanup := candidateStore(t)
	defer cleanup()
	lock := acquireCandidate(t, store)
	defer lock.Release()
	if _, err := store.WriteCandidateActivation(context.Background(), activation, env); err != nil {
		t.Fatal(err)
	}
	if err := store.activationWriter.SwapActivationLink(ActivationLinkActive, activation.ActivationID, ""); err != nil {
		t.Fatal(err)
	}
	preflight, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: activation.Release})
	if err != nil || preflight.Existing == nil || !bytes.Equal(preflight.Existing.DatabaseEnv, env) {
		t.Fatalf("preflight=%#v err=%v", preflight, err)
	}
	raw, err := json.Marshal(preflight)
	if err != nil || bytes.Contains(raw, []byte("postgresql://")) {
		t.Fatalf("native preflight leaked env: %s err=%v", raw, err)
	}
	if err := os.WriteFile(filepath.Join(store.root, "opt/open-card/activations", activation.ActivationID, "database.env"), []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/other?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: activation.Release}); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("database env drift accepted: %v", err)
	}
}

func candidateStore(t *testing.T) (*UpgradeStore, string, ActivationV1, []byte, func()) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"var/lib/open-card/upgrade-transactions", "run/lock", "etc/open-card", "etc/systemd/system"} {
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
	prepareTaskLock(t, root)
	store, err := TaskUpgradeStore(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() { _ = store.Close() }
	return store, root, activation, env, cleanup
}

func productionCandidateUnitFixture(t *testing.T) (*UpgradeStore, ReleaseV1, Manifest, string, func()) {
	t.Helper()
	store, root, _, _, cleanup := candidateStore(t)
	releaseID := "candidate-rc1"
	releaseDir := filepath.Join(root, "opt", "open-card", "releases", releaseID)
	files := map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"bin/open-card-admin":                                     {[]byte("admin\n"), 0o755},
		"bin/open-card-upgrade":                                   {[]byte("upgrade\n"), 0o755},
		"systemd/open-card-server.service":                        {[]byte("[Unit]\nDescription=Open Card\n[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\nExecStart=/opt/open-card/current/bin/open-card-server\n[Install]\nWantedBy=multi-user.target\n"), 0o644},
		"systemd/open-card-edge.service":                          {[]byte("edge\n"), 0o644},
		"systemd/open-card-upgrade-recover.service":               {ProductionUpgradeRecoveryUnitBytes(), 0o644},
		"systemd/open-card-upgrade-safe.target":                   {ProductionUpgradeSafeBootTargetBytes(), 0o644},
		"systemd/open-card-upgrade-finalize.service":              {ProductionUpgradeFinalizeUnitBytes(), 0o644},
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": {ProductionUpgradeEdgeMarkerDropInBytes(), 0o644},
		"caddy/open-card-edge.Caddyfile.example":                  {[]byte("edge\n"), 0o644},
		"migrations/control-plane/0024_dns_change_ledger.sql":     {[]byte("migration\n"), 0o644},
		"web/dist/index.html":                                     {[]byte("web\n"), 0o644},
		"docs/licenses/licenses-manifest.json":                    {[]byte("{}\n"), 0o644},
		"sbom.spdx.json":                                          {[]byte("{}\n"), 0o644},
		"source-manifest.sha256":                                  {[]byte("source\n"), 0o644},
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: ProductionCandidateVersion, ReleaseID: releaseID, Architecture: "amd64", MigrationVersion: CurrentMigrationVersion, SourceCommit: strings.Repeat("a", 40), NMinusOne: &NMinusOne{Version: ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256}, Protocol: AgentProtocolVersion, ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir, Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion}}
	for path, value := range files {
		full := filepath.Join(releaseDir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, value.body, value.mode); err != nil {
			t.Fatal(err)
		}
		digest, err := SHA256File(full)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, FileDigest{Path: path, SHA256: digest, Mode: uint32(value.mode)})
	}
	manifestPath := filepath.Join(releaseDir, "manifest.json")
	if err := SaveManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := SHA256File(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	release := ReleaseV1{ID: releaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: digest}
	return store, release, manifest, manifestPath, cleanup
}

func TestCandidateServerUnitRequiresExactProductionCandidateManifest(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"valid": func(*Manifest) {},
		"wrong-version": func(m *Manifest) {
			m.Version, m.MigrationVersion, m.SourceCommit, m.NMinusOne = ProductionNMinusOneVersion, "0023", RC0SourceCommit, nil
		},
		"wrong-migration":   func(m *Manifest) { m.MigrationVersion = "0023" },
		"wrong-n-minus-one": func(m *Manifest) { m.NMinusOne.BundleManifestSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			store, release, manifest, manifestPath, cleanup := productionCandidateUnitFixture(t)
			defer cleanup()
			mutate(&manifest)
			if name != "valid" {
				raw, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifestPath, append(raw, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				digest, err := SHA256File(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				release.ManifestSHA256 = digest
			}
			_, err := (fixedLegacyReleaseVerifier{writer: store.activationWriter}).CandidateServerUnit(release)
			if name == "valid" && err != nil {
				t.Fatalf("valid production candidate rejected: %v", err)
			}
			if name != "valid" && !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("invalid %s candidate err=%v", name, err)
			}
		})
	}
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

// legacyStoreForProjectionFixture creates the real on-disk legacy layout.  The
// fake only supplies the immutable RC0 and candidate-unit evidence; all
// projection methods below operate on the DurableWriter-backed files.
func legacyStoreForProjectionFixture(t *testing.T, withPrevious bool) (*UpgradeStore, string, UpgradePreflight, ActivationV1, []byte, []byte, func()) {
	t.Helper()
	store, root, old, env, cleanup := candidateStore(t)
	legacyRelease := ReleaseV1{ID: old.Release.ID, Version: ProductionNMinusOneVersion, SourceCommit: RC0SourceCommit, Architecture: "amd64", ManifestSHA256: RC0ReleaseManifestSHA256}
	candidate := old.Release
	candidate.ID = "rc1"
	candidate.Version = ProductionCandidateVersion
	candidate.SourceCommit = strings.Repeat("a", 40)
	unitBefore := []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\n")
	unitAfter := []byte("[Service]\nEnvironmentFile=-/etc/open-card/server.env\nEnvironmentFile=/opt/open-card/active/database.env\n")
	candidateUnitDir := filepath.Join(root, "opt/open-card/releases", candidate.ID, "systemd")
	if err := os.MkdirAll(candidateUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	candidateUnitPath := filepath.Join(candidateUnitDir, "open-card-server.service")
	if err := os.WriteFile(candidateUnitPath, unitAfter, 0o644); err != nil {
		t.Fatal(err)
	}
	candidateManifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, Product: ManifestProduct, Version: ProductionCandidateVersion, ReleaseID: candidate.ID,
		Architecture: "amd64", MigrationVersion: CurrentMigrationVersion, SourceCommit: candidate.SourceCommit,
		NMinusOne: &NMinusOne{Version: ProductionNMinusOneVersion, MigrationVersion: "0023", SourceCommit: RC0SourceCommit, ReleaseManifestSHA256: RC0ReleaseManifestSHA256, ArchiveSHA256: RC0ArchiveSHA256, BundleManifestSHA256: RC0BundleManifestSHA256},
		Protocol:  AgentProtocolVersion, ConfigDir: DefaultConfigDir, DataDir: DefaultDataDir,
		Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion},
		Files:         []FileDigest{{Path: "systemd/open-card-server.service", SHA256: sha256Bytes(unitAfter), Mode: 0o644}},
	}
	candidateManifestPath := filepath.Join(root, "opt/open-card/releases", candidate.ID, "manifest.json")
	if err := SaveManifest(candidateManifestPath, candidateManifest); err != nil {
		t.Fatal(err)
	}
	var err error
	candidate.ManifestSHA256, err = SHA256File(candidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/open-card/server.env"), env, durableFileMode); err != nil {
		t.Fatal(err)
	}
	edgeInstalled, err := renderEdgeConfigTemplate(edgeSourceTemplateFixture(), "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/open-card/open-card-edge.Caddyfile"), edgeInstalled, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/open-card-server.service"), unitBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+legacyRelease.ID, filepath.Join(root, "opt/open-card/current")); err != nil {
		t.Fatal(err)
	}
	store.legacyVerifier = legacyVerifierFake{release: legacyRelease, rows: migrationRows(23), unit: unitAfter}
	lock := acquireCandidate(t, store)
	if withPrevious {
		if _, err := store.WriteCandidateActivation(context.Background(), old, env); err != nil {
			t.Fatalf("previous activation: %v", err)
		}
		if err := store.activationWriter.SwapActivationLink(ActivationLinkActive, old.ActivationID, ""); err != nil {
			t.Fatal(err)
		}
		if err := store.activationWriter.SwapActivationLink(ActivationLinkCurrent, "", ""); err != nil {
			t.Fatal(err)
		}
		if err := store.SetPrevious(context.Background(), old.ActivationID); err != nil {
			t.Fatalf("set previous: %v", err)
		}
		if err := os.Remove(filepath.Join(root, "opt/open-card/active")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "opt/open-card/current")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("releases/"+legacyRelease.ID, filepath.Join(root, "opt/open-card/current")); err != nil {
			t.Fatal(err)
		}
	}
	preflight, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: candidate})
	if err != nil || preflight.Legacy == nil {
		request := UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: candidate}
		t.Fatalf("preflight=%#v err=%v direct=%v", preflight, err, func() error { _, e := store.readLegacyPlan(request); return e }())
	}
	plan := *preflight.Legacy
	activation := ActivationV1{SchemaVersion: ActivationSchemaVersion, ActivationID: plan.ActivationID, Origin: "rc0_compat_projection", Release: plan.Release, Database: DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: plan.ExpectedRowsSHA256}, DatabaseEnvSHA256: plan.DatabaseEnvSHA256, CreatedAt: time.Unix(1, 0).UTC(), CreatedByTransactionID: plan.TransactionID, LegacyProjection: &LegacyProjectionV1{Target: plan.CurrentTarget, ServerEnvBeforeSHA256: plan.ServerEnvBeforeSHA256, ServerEnvAfterSHA256: plan.ServerEnvAfterSHA256, ServerUnitBeforeSHA256: plan.ServerUnitBeforeSHA256, ServerUnitAfterSHA256: plan.ServerUnitAfterSHA256, ServerUnitReleaseID: plan.ServerUnitReleaseID}}
	if withPrevious {
		activation.LegacyProjection.Target = plan.CurrentTarget
	}
	_ = lock
	return store, root, preflight, activation, env, unitAfter, func() { _ = lock.Release(); cleanup() }
}

func TestLegacyPrepareFinalizeEndToEnd(t *testing.T) {
	store, root, preflight, activation, beforeEnv, afterUnit, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	plan := *preflight.Legacy
	if _, err := store.WriteCandidateActivation(context.Background(), activation, plan.DatabaseEnv); err == nil {
		t.Fatal("public writer accepted legacy activation")
	}
	beforeJSON, err := os.ReadFile(filepath.Join(root, "etc/open-card/server.env"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatalf("prepare: %v plan=%v activation=%v state=%v", err, plan.Validate(), activation.Validate(), store.validateLegacyMutationState(plan, activation, true))
	}
	if got, _ := os.ReadFile(filepath.Join(root, "etc/open-card/server.env")); !bytes.Equal(got, beforeEnv) || !bytes.Contains(got, []byte("OPEN_CARD_DATABASE_URL=")) {
		t.Fatalf("prepare changed global env: %q", got)
	}
	if got, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/open-card-server.service")); err != nil || !bytes.Equal(got, afterUnit) {
		t.Fatalf("unit=%q err=%v", got, err)
	}
	if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc/open-card/server.env"))
	if err != nil {
		t.Fatal(err)
	}
	_, expectedAfter, _ := splitLegacyServerEnv(beforeJSON)
	if !bytes.Equal(got, expectedAfter) {
		t.Fatalf("final env=%q want=%q", got, expectedAfter)
	}
	obs, err := store.ReadLegacyProjection(context.Background(), plan, activation)
	if err != nil || obs.ActivationID != activation.ActivationID {
		t.Fatalf("obs=%#v err=%v", obs, err)
	}
	if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{plan, activation, UpgradeJournalV1{PlannedOldActivation: &activation}} {
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "user:pass") {
			t.Fatal("secret leaked in JSON")
		}
	}
}

func TestEdgeConfigPrepareFinalizeAndRereadAreFixedAndDurable(t *testing.T) {
	store, root, preflight, _, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	plan := *preflight.Legacy
	edge := *plan.EdgeConfigTransition
	installedPath := filepath.Join(root, "etc/open-card", installedEdgeConfigName)
	before, err := os.ReadFile(installedPath)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := store.PrepareEdgeConfig(context.Background(), edge)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.PreparedConfigSHA256 != edge.Evidence.InstalledAfterSHA256 || prepared.InstalledConfigSHA256 != edge.Evidence.InstalledBeforeSHA256 {
		t.Fatalf("prepare observation=%+v", prepared)
	}
	if after, err := os.ReadFile(installedPath); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("prepare mutated installed config: %q %v", after, err)
	}
	artifact := filepath.Join(root, "var/lib/open-card/upgrade-artifacts", edge.Evidence.TransactionID, edgeConfigArtifactName)
	info, err := os.Lstat(artifact)
	if err != nil || info.Mode().Perm() != 0o640 || !info.Mode().IsRegular() {
		t.Fatalf("prepared artifact=%v mode=%#o", err, info.Mode())
	}
	if _, err := store.FinalizeEdgeConfig(context.Background(), edge); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if installed, err := os.ReadFile(installedPath); err != nil || !bytes.Equal(installed, edge.Target) {
		t.Fatalf("installed=%q err=%v", installed, err)
	}
	if observed, err := store.ReadEdgeConfig(context.Background(), edge); err != nil || observed.PreparedConfigSHA256 != edge.Evidence.InstalledAfterSHA256 || observed.InstalledConfigSHA256 != edge.Evidence.InstalledAfterSHA256 {
		t.Fatalf("read observation=%+v err=%v", observed, err)
	}
	// Exact replay is safe; a foreign installed config is not.
	if _, err := store.FinalizeEdgeConfig(context.Background(), edge); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if err := os.WriteFile(installedPath, []byte("foreign\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeEdgeConfig(context.Background(), edge); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("foreign installed config accepted: %v", err)
	}
}

func TestEdgeConfigRenderingAndInstalledOwnershipFailClosed(t *testing.T) {
	source := edgeSourceTemplateFixture()
	candidate := edgeCandidateTemplateFixture()
	for _, host := range []string{"Console.example.test", "console.example.invalid", "console.example.test/escape", ""} {
		if _, err := renderEdgeConfigTemplate(source, host); err == nil {
			t.Fatalf("unsafe hostname accepted: %q", host)
		}
	}
	if _, err := renderEdgeConfigTemplate([]byte("console.example.invalid console.example.invalid"), "console.example.test"); err == nil {
		t.Fatal("multiple template placeholders accepted")
	}
	installed, err := renderEdgeConfigTemplate(source, "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edgeConfigTransitionPlan("txn-1", rc0ReleaseFixture(), ReleaseV1{ID: "release-1", Version: ProductionCandidateVersion, SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: sha("f")}, source, append(installed, 'x'), candidate, []byte("caddy")); err == nil {
		t.Fatal("non-exact installed rendering accepted")
	}
	store, root, preflight, _, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	path := filepath.Join(root, "etc/open-card", installedEdgeConfigName)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareEdgeConfig(context.Background(), *preflight.Legacy.EdgeConfigTransition); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("wrong mode accepted: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("server.env", path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareEdgeConfig(context.Background(), *preflight.Legacy.EdgeConfigTransition); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("symlink installed config accepted: %v", err)
	}
}

func TestEdgeConfigFinalizeReconcilesPostRenameUnknown(t *testing.T) {
	store, root, preflight, _, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	edge := *preflight.Legacy.EdgeConfigTransition
	if _, err := store.PrepareEdgeConfig(context.Background(), edge); err != nil {
		t.Fatal(err)
	}
	writer, fault := renameHookWriter(t, filepath.Join(root, "etc/open-card"))
	fault.fail = "parent-fsync"
	old := store.configDurable
	store.configDurable = writer
	defer func() {
		store.configDurable = old
		_ = writer.Close()
	}()
	if _, err := store.FinalizeEdgeConfig(context.Background(), edge); err != nil {
		t.Fatalf("post-rename unknown did not reconcile: %v", err)
	}
}

func TestLegacyProjectionRejectsReplacedLiveRootsBeforeFinalize(t *testing.T) {
	for _, relative := range []string{"opt/open-card", "etc/open-card", "etc/systemd/system", "var/lib/open-card"} {
		t.Run(strings.ReplaceAll(relative, "/", "-"), func(t *testing.T) {
			store, root, preflight, activation, beforeEnv, _, cleanup := legacyStoreForProjectionFixture(t, false)
			defer cleanup()
			plan := *preflight.Legacy
			if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
				t.Fatal(err)
			}
			live := filepath.Join(root, relative)
			if err := os.Rename(live, live+"-detached"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(live, durableDirMode); err != nil {
				t.Fatal(err)
			}
			if relative == "etc/open-card" {
				if err := os.WriteFile(filepath.Join(live, "server.env"), beforeEnv, durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("finalize after replacing %s: %v", relative, err)
			}
			if relative == "etc/open-card" {
				got, err := os.ReadFile(filepath.Join(live, "server.env"))
				if err != nil || !bytes.Equal(got, beforeEnv) {
					t.Fatalf("replacement server.env changed=%q err=%v", got, err)
				}
			}
		})
	}
}

func TestPreflightPlanRejectsActivationRootReplacement(t *testing.T) {
	store, root, preflight, _, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	live := filepath.Join(root, "opt", "open-card")
	if err := os.Rename(live, live+"-detached"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(live, durableDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PreflightPlan(context.Background(), UpgradePreflightRequest{TransactionID: preflight.Legacy.TransactionID, CandidateRelease: ReleaseV1{ID: "rc1", Version: ProductionCandidateVersion, SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("b", 64)}}); !errors.Is(err, ErrUpgradeJournalConflict) {
		t.Fatalf("preflight accepted replacement root: %v", err)
	}
}

func TestFinalizeLegacyProjectionRejectsForeignTransactionBeforeServerEnvWrite(t *testing.T) {
	store, root, preflight, activation, beforeEnv, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	plan := *preflight.Legacy
	if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	foreign := plan
	foreign.TransactionID = "txn-foreign"
	if _, err := store.FinalizeLegacyProjection(context.Background(), foreign, activation); err == nil {
		t.Fatal("foreign transaction finalized legacy projection")
	}
	got, err := os.ReadFile(filepath.Join(root, "etc/open-card/server.env"))
	if err != nil || !bytes.Equal(got, beforeEnv) {
		t.Fatalf("foreign transaction changed server.env=%q err=%v", got, err)
	}
}

func TestLegacyProjectionPartialStatesConverge(t *testing.T) {
	for _, withPrevious := range []bool{false, true} {
		t.Run(map[bool]string{false: "previous-absent", true: "previous-present"}[withPrevious], func(t *testing.T) {
			store, _, preflight, activation, _, _, cleanup := legacyStoreForProjectionFixture(t, withPrevious)
			defer cleanup()
			plan := *preflight.Legacy
			if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
				t.Fatal(err)
			}
			if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); err != nil {
				t.Fatal(err)
			}
			if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
				t.Fatal(err)
			}
			if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareLegacyProjectionConvergesExactSlotPrefixes(t *testing.T) {
	for _, boundary := range []string{"slot", "release", "database-env", "activation-json"} {
		t.Run(boundary, func(t *testing.T) {
			store, root, preflight, activation, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
			defer cleanup()
			plan := *preflight.Legacy
			slot := filepath.Join(root, "opt/open-card/activations", activation.ActivationID)
			if err := os.Mkdir(slot, activationSlotDirMode); err != nil {
				t.Fatal(err)
			}
			if boundary != "slot" {
				if err := os.Symlink(filepath.ToSlash(filepath.Join("..", "..", "releases", activation.Release.ID)), filepath.Join(slot, "release")); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "database-env" || boundary == "activation-json" {
				if err := os.WriteFile(filepath.Join(slot, "database.env"), plan.DatabaseEnv, durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "activation-json" {
				raw, err := MarshalActivationV1(activation)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(slot, "activation.json"), raw, durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if observation, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil || observation.ActivationID != activation.ActivationID {
				t.Fatalf("prepare after %s prefix: %v", boundary, err)
			}
		})
	}
}

func TestPrepareLegacyProjectionRejectsConflictingSlotPrefix(t *testing.T) {
	for _, conflict := range []string{"release", "database-env", "activation-json"} {
		t.Run(conflict, func(t *testing.T) {
			store, root, preflight, activation, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
			defer cleanup()
			plan := *preflight.Legacy
			slot := filepath.Join(root, "opt/open-card/activations", activation.ActivationID)
			if err := os.Mkdir(slot, activationSlotDirMode); err != nil {
				t.Fatal(err)
			}
			switch conflict {
			case "release":
				if err := os.Symlink("../../releases/foreign", filepath.Join(slot, "release")); err != nil {
					t.Fatal(err)
				}
			case "database-env":
				if err := os.WriteFile(filepath.Join(slot, "database.env"), []byte("OPEN_CARD_DATABASE_URL=postgresql://bad@localhost/foreign\n"), durableFileMode); err != nil {
					t.Fatal(err)
				}
			case "activation-json":
				if err := os.WriteFile(filepath.Join(slot, "activation.json"), []byte("{}\n"), durableFileMode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); !errors.Is(err, ErrUpgradeJournalConflict) {
				t.Fatalf("conflicting %s prefix err=%v", conflict, err)
			}
		})
	}
}

func TestSecureReleaseFileKeepsPinnedRootAfterPathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "open-card")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"releases", "releases/release-1"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(root, "releases/release-1/manifest.json")
	if err := os.WriteFile(manifest, []byte("trusted"), 0o644); err != nil {
		t.Fatal(err)
	}
	writer, err := TaskDurableWriter(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := os.Rename(root, filepath.Join(parent, "old-open-card")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "releases/release-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "releases/release-1/manifest.json"), []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := secureReleaseFile(writer, "release-1", "manifest.json", 0o644)
	if err != nil || string(got) != "trusted" {
		t.Fatalf("pinned descriptor trusted=%q err=%v", got, err)
	}
}

func TestRecoverLegacyPlanBeforeAndAfterPreservesSecretsInMemory(t *testing.T) {
	store, root, preflight, activation, _, _, cleanup := legacyStoreForProjectionFixture(t, false)
	defer cleanup()
	plan := *preflight.Legacy
	if plan.Release.ID == plan.ServerUnitReleaseID {
		t.Fatal("fixture must use distinct RC0 and RC1 release IDs")
	}
	manifestSHA, err := SHA256File(filepath.Join(root, "opt/open-card/releases", plan.ServerUnitReleaseID, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.RecoverLegacyPlan(context.Background(), activation, manifestSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.DatabaseEnv, plan.DatabaseEnv) {
		t.Fatal("recovered secret differs before projection")
	}
	if _, err := store.PrepareLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeLegacyProjection(context.Background(), plan, activation); err != nil {
		t.Fatal(err)
	}
	after, err := store.RecoverLegacyPlan(context.Background(), activation, manifestSHA)
	if err != nil {
		t.Fatal(err)
	}
	before.DatabaseEnv = nil
	after.DatabaseEnv = nil
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("recovered nonsecret plan differs: before=%#v after=%#v", before, after)
	}
	for _, name := range []string{"foreign-unit", "foreign-env", "foreign-current", "foreign-previous"} {
		t.Run(name, func(t *testing.T) {
			driftStore, driftRoot, driftPreflight, driftActivation, _, _, driftCleanup := legacyStoreForProjectionFixture(t, name == "foreign-previous")
			defer driftCleanup()
			driftPlan := *driftPreflight.Legacy
			if name == "foreign-unit" {
				_ = os.WriteFile(filepath.Join(driftRoot, "etc/systemd/system/open-card-server.service"), []byte("foreign\n"), durableFileMode)
			}
			if name == "foreign-env" {
				_ = os.WriteFile(filepath.Join(driftRoot, "etc/open-card/server.env"), []byte("OPEN_CARD_DATABASE_URL=postgresql://foreign\n"), durableFileMode)
			}
			if name == "foreign-current" {
				_ = os.Remove(filepath.Join(driftRoot, "opt/open-card/current"))
				_ = os.Symlink("releases/foreign", filepath.Join(driftRoot, "opt/open-card/current"))
			}
			if name == "foreign-previous" {
				_ = driftStore.activationWriter.SwapActivationLink(ActivationLinkPreviousActive, "foreign", "")
			}
			if _, err := driftStore.RecoverLegacyPlan(context.Background(), driftActivation, manifestSHAForTest(t, driftRoot, driftPlan.ServerUnitReleaseID)); err == nil {
				t.Fatal("foreign state accepted")
			}
		})
	}
}

func manifestSHAForTest(t *testing.T, root, releaseID string) string {
	t.Helper()
	digest, err := SHA256File(filepath.Join(root, "opt/open-card/releases", releaseID, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
