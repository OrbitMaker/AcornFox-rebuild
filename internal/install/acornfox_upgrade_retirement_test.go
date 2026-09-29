package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcornFoxCandidateSchema2HasNoWorkerOrPiPackage(t *testing.T) {
	if AcornFoxCandidateBindingCurrentSchema != 2 {
		t.Fatalf("current schema version = %d, want 2", AcornFoxCandidateBindingCurrentSchema)
	}

	required := AcornFoxV1RequiredFiles()
	for _, file := range required {
		if strings.HasPrefix(file.Path, "pi/") || file.Path == "bin/acornfox-pi-worker" || file.Path == "systemd/acornfox-pi-worker.service" {
			t.Fatalf("current schema 2 package must not contain pi/worker: %s", file.Path)
		}
	}
	for _, bin := range acornFoxV1Binaries {
		if strings.Contains(bin, "pi") || strings.Contains(bin, "worker") {
			t.Fatalf("current binaries must not contain worker: %s", bin)
		}
	}
	for _, unit := range acornFoxV1Units {
		if strings.Contains(unit, "pi") || strings.Contains(unit, "worker") {
			t.Fatalf("current units must not contain worker: %s", unit)
		}
	}

	schema1Binding := AcornFoxCandidateBindingV1{
		SchemaVersion:        AcornFoxCandidateBindingV1Schema,
		Product:              AcornFoxV1Product,
		Version:              "1.3.0-test.1",
		ReleaseID:            "release-1.3.0-test.1",
		SourceRepository:     "https://github.com/acornfox/acornfox",
		SourceCommit:         strings.Repeat("a", 40),
		Architecture:         AcornFoxV1Architecture,
		MigrationVersion:     AcornFoxV1MigrationVersion,
		ManifestSHA256:       acornFoxFixtureDigest("1"),
		ArchiveSHA256:        acornFoxFixtureDigest("2"),
		BundleManifestSHA256: acornFoxFixtureDigest("3"),
	}
	raw1, err := json.Marshal(schema1Binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAcornFoxCandidateBindingV1(raw1, sha256Hex(raw1)); err == nil {
		t.Fatal("new schema 1 candidate binding must be rejected")
	}

	schema2Binding := schema1Binding
	schema2Binding.SchemaVersion = AcornFoxCandidateBindingV2Schema
	raw2, err := json.Marshal(schema2Binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAcornFoxCandidateBindingV1(raw2, sha256Hex(raw2)); err != nil {
		t.Fatalf("schema 2 candidate binding rejected: %v", err)
	}
}

func TestAcornFoxHistoricalPredecessorsStillVerify(t *testing.T) {
	hist0040 := AcornFoxCandidateBindingV1{
		SchemaVersion:        AcornFoxCandidateBindingV1Schema,
		Product:              AcornFoxV1Product,
		Version:              "1.1.0-test.1",
		ReleaseID:            "release-1.1.0-test.1",
		SourceRepository:     "https://github.com/acornfox/acornfox",
		SourceCommit:         strings.Repeat("a", 40),
		Architecture:         AcornFoxV1Architecture,
		MigrationVersion:     AcornFoxV1MigrationVersion,
		ManifestSHA256:       acornFoxFixtureDigest("4"),
		ArchiveSHA256:        acornFoxFixtureDigest("5"),
		BundleManifestSHA256: acornFoxFixtureDigest("6"),
	}
	raw0040, _ := json.Marshal(hist0040)
	digest0040 := sha256Hex(raw0040)
	if _, err := ParseAcornFoxCandidateBindingV1(raw0040, digest0040); err == nil {
		t.Fatal("historical 0040 schema 1 accepted as new candidate")
	}
	if err := ParseAcornFoxPredecessorBindingV1(raw0040, digest0040); err != nil {
		t.Fatalf("historical 0040 schema 1 predecessor rejected: %v", err)
	}
	if _, err := verifiedAcornFoxUpgradePredecessor(raw0040, digest0040); err != nil {
		t.Fatalf("verifiedAcornFoxUpgradePredecessor rejected historical 0040 schema 1: %v", err)
	}

	hist0039 := hist0040
	hist0039.Version = "1.0.0-test.1"
	hist0039.ReleaseID = "release-1.0.0-test.1"
	hist0039.MigrationVersion = "0039"
	raw0039, _ := json.Marshal(hist0039)
	digest0039 := sha256Hex(raw0039)
	if _, err := ParseAcornFoxCandidateBindingV1(raw0039, digest0039); err == nil {
		t.Fatal("historical 0039 accepted as new candidate")
	}
	if err := ParseAcornFoxPredecessorBindingV1(raw0039, digest0039); err != nil {
		t.Fatalf("historical 0039 predecessor rejected: %v", err)
	}
	if _, err := verifiedAcornFoxUpgradePredecessor(raw0039, digest0039); err != nil {
		t.Fatalf("verifiedAcornFoxUpgradePredecessor rejected historical 0039: %v", err)
	}

	legacy0034Raw := []byte(`{"schema_version":1,"product":"acornfox","version":"0.1.0-beta.1","release_id":"release-0.1.0-beta.1","source_repository":"https://github.com/EleJiuDeiChi/acornfox","source_commit":"6ed40027c0ac892e404c31e5daafaf0749eec216","architecture":"amd64","migration_version":"0034","manifest_sha256":"77c8f27ad93012ef606bf9bbf5ad820989a9a2f40928f22584fdbddc4be23d47","archive_sha256":"ef4722471203272dc0961c63a1d32a275b6ec44a82cf600f992c16fb7aaf849d","bundle_manifest_sha256":"429130db1deffb69cf0bd2b9d40b1cf0dfcf620ad6bb7233f2c5e5d23b89dd69"}`)
	digest0034 := sha256Hex(legacy0034Raw)
	if err := ParseAcornFoxPredecessorBindingV1(legacy0034Raw, digest0034); err != nil {
		t.Fatalf("legacy 0034 predecessor rejected: %v", err)
	}
	if _, err := verifiedAcornFoxUpgradePredecessor(legacy0034Raw, digest0034); err != nil {
		t.Fatalf("verifiedAcornFoxUpgradePredecessor rejected legacy 0034: %v", err)
	}

	unlisted := hist0040
	unlisted.MigrationVersion = "0033"
	rawUnlisted, _ := json.Marshal(unlisted)
	if err := ParseAcornFoxPredecessorBindingV1(rawUnlisted, sha256Hex(rawUnlisted)); err == nil {
		t.Fatal("unlisted predecessor migration was accepted")
	}
}

func TestAcornFoxUpgradeSchema1To2EnabledWorkerRetirement(t *testing.T) {
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()

	request, services := setupFrozen0040HostForTest(t, u, p, true)
	defer services.assertDataPreserved(t)

	receipt, err := u.upgrade(context.Background(), request)
	if err != nil {
		t.Fatalf("upgrade failed: %v, calls: %q", err, services.calls)
	}
	if receipt.State != "UPGRADED" {
		t.Fatalf("receipt state = %s, want UPGRADED", receipt.State)
	}

	foundStop := false
	foundDisable := false
	for _, call := range services.calls {
		if call == "stop acornfox-pi-worker.service" {
			foundStop = true
		}
		if call == "disable acornfox-pi-worker.service" {
			foundDisable = true
		}
		if call == "start acornfox-pi-worker.service" {
			t.Fatalf("worker must never be started in forward schema 2 upgrade: %q", services.calls)
		}
	}
	if !foundStop || !foundDisable {
		t.Fatalf("expected stop and disable in calls: %q", services.calls)
	}

	liveUnitPath := filepath.Join(p.host, "etc/systemd/system/acornfox-pi-worker.service")
	if _, err := os.Lstat(liveUnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live unit file must be removed after retirement: %s", liveUnitPath)
	}
	wantsPath := filepath.Join(p.host, "etc/systemd/system/multi-user.target.wants/acornfox-pi-worker.service")
	if _, err := os.Lstat(wantsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wants link must be removed after retirement: %s", wantsPath)
	}

	chatFile := filepath.Join(p.host, "var/lib/acornfox/pi/sessions/session-001.json")
	if body, err := os.ReadFile(chatFile); err != nil || !bytes.Contains(body, []byte("hello")) {
		t.Fatalf("historical chat session data must be preserved: %s %v", body, err)
	}
	keyFile := filepath.Join(p.host, "etc/acornfox/pi/deepseek-api-key")
	if _, err := os.Lstat(keyFile); err != nil {
		t.Fatalf("historical key must be preserved: %v", err)
	}
}

func TestAcornFoxUpgradeSchema1To2DisabledWorkerRetirement(t *testing.T) {
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()

	request, services := setupFrozen0040HostForTest(t, u, p, false)
	defer services.assertDataPreserved(t)

	receipt, err := u.upgrade(context.Background(), request)
	if err != nil {
		t.Fatalf("upgrade failed: %v, calls: %q", err, services.calls)
	}
	if receipt.State != "UPGRADED" {
		t.Fatalf("receipt state = %s, want UPGRADED", receipt.State)
	}

	for _, call := range services.calls {
		if strings.Contains(call, "start acornfox-pi-worker.service") {
			t.Fatalf("disabled worker must never be started: %q", services.calls)
		}
	}
	liveUnitPath := filepath.Join(p.host, "etc/systemd/system/acornfox-pi-worker.service")
	if _, err := os.Lstat(liveUnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live unit file must be removed after retirement: %s", liveUnitPath)
	}
}

func TestAcornFoxUpgradeRetirementFailureTriggersRollbackAndRestoresEnabledState(t *testing.T) {
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()

	request, services := setupFrozen0040HostForTest(t, u, p, true)
	defer services.assertDataPreserved(t)
	services.failNext = true

	receipt, err := u.upgrade(context.Background(), request)
	if !errors.Is(err, ErrAcornFoxUpgradeRolledBack) {
		t.Fatalf("expected rolled back error, got: %v", err)
	}
	if receipt.State != "ROLLED_BACK" {
		t.Fatalf("receipt state = %s, want ROLLED_BACK", receipt.State)
	}

	foundEnable := false
	foundStart := false
	for _, call := range services.calls {
		if call == "enable acornfox-pi-worker.service" {
			foundEnable = true
		}
		if call == "start acornfox-pi-worker.service" {
			foundStart = true
		}
	}
	if !foundEnable || !foundStart {
		t.Fatalf("rollback must enable and start original enabled worker: %q", services.calls)
	}

	liveUnitPath := filepath.Join(p.host, "etc/systemd/system/acornfox-pi-worker.service")
	if info, err := os.Lstat(liveUnitPath); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("live unit file must be restored with mode 0644: %v", err)
	}
}

func TestAcornFoxUpgradeRetirementFailureRollbackPreservesDisabledState(t *testing.T) {
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()

	request, services := setupFrozen0040HostForTest(t, u, p, false)
	defer services.assertDataPreserved(t)
	services.failNext = true

	receipt, err := u.upgrade(context.Background(), request)
	if !errors.Is(err, ErrAcornFoxUpgradeRolledBack) {
		t.Fatalf("expected rolled back error, got: %v", err)
	}
	if receipt.State != "ROLLED_BACK" {
		t.Fatalf("receipt state = %s, want ROLLED_BACK", receipt.State)
	}

	for _, call := range services.calls {
		if call == "enable acornfox-pi-worker.service" || call == "start acornfox-pi-worker.service" {
			t.Fatalf("disabled worker must not be enabled or started on rollback: %q", services.calls)
		}
	}

	liveUnitPath := filepath.Join(p.host, "etc/systemd/system/acornfox-pi-worker.service")
	if info, err := os.Lstat(liveUnitPath); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("live unit file must be restored on rollback: %v", err)
	}
}

func TestAcornFoxUpgradeSwitchedBootRecoveryRestoresWorker(t *testing.T) {
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()

	request, services := setupFrozen0040HostForTest(t, u, p, true)
	defer services.assertDataPreserved(t)

	fired := false
	u.step = func(name string) error {
		if name == "healthy" && !fired {
			fired = true
			return errors.New("simulated power cut after SWITCHED")
		}
		return nil
	}

	if _, err := u.upgrade(context.Background(), request); !errors.Is(err, ErrAcornFoxUpgradeUnknown) || !fired {
		t.Fatalf("expected crash, got: %v", err)
	}

	services.calls = nil
	u.step = func(string) error { return nil }

	expected := AcornFoxBuildIdentityV1{
		SchemaVersion: 1,
		Product:       AcornFoxV1Product,
		LayoutVersion: 1,
		Role:          "upgrade",
		Version:       "1.2.4-test.1",
		ReleaseID:     "release-1.2.4-test.1",
		SourceCommit:  strings.Repeat("a", 40),
	}

	recovery := newAcornFoxUpgrade(p.layout)
	recovery.ownership = p.owners.edge()
	recovery.services = services
	recovery.self = u.self
	receipt, handled, err := recovery.recover(context.Background(), expected)
	if err != nil || !handled || receipt.State != "ROLLED_BACK" {
		t.Fatalf("recovery failed: %v handled=%t receipt=%#v", err, handled, receipt)
	}

	foundEnable := false
	foundStart := false
	for _, call := range services.calls {
		if call == "enable acornfox-pi-worker.service" {
			foundEnable = true
		}
		if call == "start acornfox-pi-worker.service" {
			foundStart = true
		}
	}
	if !foundEnable || !foundStart {
		t.Fatalf("boot recovery must enable and start worker: %q", services.calls)
	}

	liveUnitPath := filepath.Join(p.host, "etc/systemd/system/acornfox-pi-worker.service")
	if info, err := os.Lstat(liveUnitPath); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("live unit file must be restored after boot recovery: %v", err)
	}
}

func TestAcornFoxContinuousSchema2ToSchema2Upgrade(t *testing.T) {
	u, _, old, services := localRolloverFixture(t)
	for _, version := range []string{"1.2.4-test.1", "1.2.5-test.1"} {
		next := newAcornFoxFixture(t, version, &old)
		receipt, err := u.upgrade(context.Background(), localRolloverRequest(t, u, old, next))
		if err != nil || receipt.State != "UPGRADED" {
			t.Fatalf("%s: receipt=%s err=%v", version, receipt.State, err)
		}
		old = next
	}
	for _, call := range services.calls {
		if strings.Contains(call, "acornfox-pi-worker.service") {
			t.Fatalf("retired worker invoked: %s", call)
		}
	}
}

func TestAcornFoxMigrationsZeroChanges(t *testing.T) {
	if AcornFoxV1MigrationVersion != "0040" {
		t.Fatalf("migration version = %s, want 0040", AcornFoxV1MigrationVersion)
	}
	if AcornFoxV1DataVersion != 40 {
		t.Fatalf("data version = %d, want 40", AcornFoxV1DataVersion)
	}
	if len(acornFoxV1Migrations) != 40 {
		t.Fatalf("migration count = %d, want 40", len(acornFoxV1Migrations))
	}
	if acornFoxV1Migrations[0] != "0001_foundation.sql" {
		t.Fatalf("migration 0 = %s, want 0001_foundation.sql", acornFoxV1Migrations[0])
	}
	if acornFoxV1Migrations[39] != "0040_acornfox_fix_candidates.sql" {
		t.Fatalf("migration 39 = %s, want 0040_acornfox_fix_candidates.sql", acornFoxV1Migrations[39])
	}
}
