package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newAcornFoxPostCrossFixture(t *testing.T) (*acornFoxUpgrade, acornFoxProductionPreparedFixture, acornFoxUpgradeJournal) {
	t.Helper()
	u, p, request, base := upgradeFixture(t)
	provisionUpgradeAssistantConfig(t, p)
	services := &retirementServices{
		acornFoxUpgradePIServiceFake: &acornFoxUpgradePIServiceFake{acornFoxUpgradeServiceFake: base, enabled: true},
		p:                            p,
	}
	u.services = services
	if _, err := u.upgrade(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := u.load(s)
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join(p.state, acornFoxControlPlaneStateEnv))
	if err != nil {
		t.Fatal(err)
	}
	old := frozen0039ImageForTest(t, u, s, current, current.Old, nil, env)
	next := frozen0039ImageForTest(t, u, s, current, current.Next, &old, env)
	historical := acornFoxUpgradeJournal{SchemaVersion: 1, Phase: "UPGRADED", LayoutSHA256: u.layout.evidence(), PIEnabled: true, Old: old, Next: next}
	historical.Old.DatabaseEnv = nil
	historical.Next.DatabaseEnv = nil
	materializeFrozen0039ForTest(t, u, s, p, current, historical)
	if err := os.WriteFile(filepath.Join(p.host, acornFoxAssistantConfig), acornFoxAssistantLegacy0039Config(), 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(p.host, acornFoxAssistantKey)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfoBefore, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.verifyImage(s, historical, true); err != nil {
		t.Fatal("frozen host scope", err)
	}
	lock.Release()
	var predecessor acornFoxFixture
	json.Unmarshal(next.Binding, &predecessor.binding)
	predecessor.bindingRaw = next.Binding
	predecessor.bindingSHA = next.Repo.BindingSHA256
	candidate := newAcornFoxFixture(t, "1.2.5-test.1", &predecessor)
	recoveryHelper := changeAcornFoxRecoveryHelperFixture(t, &candidate)
	directory, self, selfSHA := writeAcornFoxBridgeCandidate(t, t.TempDir(), candidate)
	if err := os.WriteFile(self, recoveryHelper, 0755); err != nil {
		t.Fatal(err)
	}
	u.self.path = self
	u.hostProvisionSHA256, err = acornFoxRecent0039HostEvidenceSHA(next.Repo.BindingSHA256, candidate.bindingSHA, u.layout)
	if err != nil {
		t.Fatal(err)
	}
	u.database = func(layout acornFoxInstallLayout, tx, oldSHA, nextSHA string, active []byte, migrations acornFoxControlPlaneMigrations, sourceVersion int) (acornFoxCrossSchemaDatabase, error) {
		source := &acornFoxUpgradeDatabaseLedgerFake{rows: append([]MigrationRow(nil), migrations.rows[:sourceVersion]...), available: true}
		target := &acornFoxUpgradeDatabaseLedgerFake{}
		runner := &acornFoxUpgradeDatabaseRunnerFake{ledger: target, sourceRows: source.rows, forbidUnexpectedBinary: true}
		open := func(environment []byte) (BootstrapMigrationControl, error) {
			name, err := acornFoxControlPlaneDatabaseName(environment)
			if err != nil {
				return nil, err
			}
			if name == acornFoxControlPlaneDatabase {
				return source, nil
			}
			return target, nil
		}
		return newTaskAcornFoxUpgradeDatabase(layout, tx, oldSHA, nextSHA, active, migrations, sourceVersion, runner, &acornFoxUpgradeDatabaseAdminFake{}, open, &acornFoxUpgradeDatabaseHealthFake{})
	}
	u.candidateHealth = func(context.Context, *TaskAcornFoxRepoStore, acornFoxUpgradeImage) error { return nil }
	receipt, err := u.upgrade(context.Background(), AcornFoxUpgradeRequestV1{directory, candidate.bindingSHA, next.Repo.BindingSHA256, selfSHA})
	if err != nil || receipt.State != "UPGRADED" {
		t.Fatal("cross origin upgrade", err)
	}
	origin, err := u.load(s)
	if err != nil {
		t.Fatal(err)
	}
	keyAfter, _ := os.ReadFile(keyPath)
	keyInfoAfter, _ := os.Lstat(keyPath)
	if !bytes.Equal(keyBefore, keyAfter) || !os.SameFile(keyInfoBefore, keyInfoAfter) {
		t.Fatal("cross origin key changed")
	}
	return u, p, origin
}

func postCrossRequestForTest(t *testing.T, u *acornFoxUpgrade, current acornFoxUpgradeImage, version string) AcornFoxUpgradeRequestV1 {
	t.Helper()
	var predecessor acornFoxFixture
	if json.Unmarshal(current.Binding, &predecessor.binding) != nil {
		t.Fatal("predecessor")
	}
	predecessor.bindingRaw = current.Binding
	predecessor.bindingSHA = current.Repo.BindingSHA256
	candidate := newAcornFoxFixture(t, version, &predecessor)
	helper := changeAcornFoxRecoveryHelperFixture(t, &candidate)
	directory, self, selfSHA := writeAcornFoxBridgeCandidate(t, t.TempDir(), candidate)
	if err := os.WriteFile(self, helper, 0755); err != nil {
		t.Fatal(err)
	}
	u.self.path = self
	return AcornFoxUpgradeRequestV1{directory, candidate.bindingSHA, current.Repo.BindingSHA256, selfSHA}
}

func TestAcornFoxPostCrossSameSchemaPreservesDatabaseAuthority(t *testing.T) {
	u, p, origin := newAcornFoxPostCrossFixture(t)
	u.database = func(acornFoxInstallLayout, string, string, string, []byte, acornFoxControlPlaneMigrations, int) (acornFoxCrossSchemaDatabase, error) {
		t.Fatal("same-schema tried database migration")
		return nil, errors.New("forbidden")
	}
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkLock, checkErr := s.Acquire(context.Background())
	if checkErr != nil {
		t.Fatal(checkErr)
	}
	_, resumeErr := s.Resume(context.Background())
	_, _, runtimeErr := acornFoxRuntimeAuthority(context.Background(), s, s.hostRoot)
	dbName, dbErr := acornFoxExpectedCurrentDatabase(s, origin.Next.Repo.BindingSHA256)
	if resumeErr != nil || runtimeErr != nil || dbErr != nil || dbName != origin.CrossSchema.Database.ShadowDatabase {
		t.Fatal("origin runtime authority failed", resumeErr, runtimeErr, dbErr)
	}
	checkLock.Release()
	current := origin.Next
	for _, version := range []string{"1.2.6-test.1", "1.2.7-test.1"} {
		request := postCrossRequestForTest(t, u, current, version)
		receipt, err := u.upgrade(context.Background(), request)
		if err != nil || receipt.State != "UPGRADED" {
			t.Fatal("post-cross upgrade", err)
		}
		j, err := u.load(s)
		if err != nil {
			t.Fatal(err)
		}
		if j.PostCross == nil || j.CrossSchema != nil || !bytes.Equal(j.Next.DatabaseEnv, origin.Next.DatabaseEnv) {
			t.Fatal("database environment was not inherited")
		}
		lock, err := s.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		database, err := acornFoxExpectedCurrentDatabase(s, j.Next.Repo.BindingSHA256)
		if err != nil || database != origin.CrossSchema.Database.ShadowDatabase {
			t.Fatal("lost current database authority", err)
		}
		if err := u.verifyImage(s, j, true); err != nil {
			t.Fatal(err)
		}
		lock.Release()
		current = j.Next
	}
	p.assertExternalSentinel(t)
}

func postCrossIdentityForTest(t *testing.T, request AcornFoxUpgradeRequestV1) AcornFoxBuildIdentityV1 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(request.Directory, acornFoxCandidateBindingFile))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ParseAcornFoxCandidateBindingV1(raw, request.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	b := binding.binding
	return AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", b.Version, b.ReleaseID, b.SourceCommit}
}

func TestAcornFoxPostCrossPendingRecoveryAndBoundedHistory(t *testing.T) {
	u, p, origin := newAcornFoxPostCrossFixture(t)
	u.database = func(acornFoxInstallLayout, string, string, string, []byte, acornFoxControlPlaneMigrations, int) (acornFoxCrossSchemaDatabase, error) {
		t.Fatal("post-cross migration attempted")
		return nil, errors.New("forbidden")
	}
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	keyPath := filepath.Join(p.host, acornFoxAssistantKey)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfoBefore, _ := os.Lstat(keyPath)
	current := origin.Next
	points := []string{"post-cross-journal-staged", "post-cross-helper-published", "post-cross-journal-committed", "post-cross-phase-staged", "post-cross-stash-retired", "file-published", "healthy"}
	for index, point := range points {
		t.Run(point, func(t *testing.T) {
			previous, err := u.load(s)
			if err != nil {
				t.Fatal(err)
			}
			request := postCrossRequestForTest(t, u, current, fmt.Sprintf("1.2.%d-test.1", 6+index))
			detached := u.self.path
			expected := postCrossIdentityForTest(t, request)
			fired := false
			u.step = func(name string) error {
				if name == point && !fired {
					fired = true
					return errors.New("power loss")
				}
				return nil
			}
			_, err = u.upgrade(context.Background(), request)
			if !fired || (!errors.Is(err, ErrAcornFoxUpgradeUnknown) && !errors.Is(err, errAcornFoxUpgradeInjectedCrash)) {
				t.Fatal("fault not reached", err)
			}
			fixed := filepath.Join(p.host, AcornFoxUpgradeHelperPath)
			recovery := fixed
			if point == "post-cross-journal-staged" {
				old, readErr := u.load(s)
				if readErr != nil || !bytes.Equal(acornFoxUpgradeJSON(old), acornFoxUpgradeJSON(previous)) {
					t.Fatal("uncommitted journal changed old state")
				}
				runRetired0039RecoveryProcess(t, p, fixed, previous.Next.identity(), true, "UPGRADED")
				recovery = detached
			}
			// In helper-published the canonical journal is deliberately still the old
			// version; a fresh process at the fixed entrypoint authenticates/promotes
			// the durable pending journal before recovering it.
			if point == "post-cross-helper-published" {
				old, readErr := u.load(s)
				if readErr != nil || !bytes.Equal(acornFoxUpgradeJSON(old), acornFoxUpgradeJSON(previous)) {
					t.Fatal("precommit helper publication changed journal")
				}
			}
			for _, prepare := range []bool{true, true, false, false} {
				want := "ROLLED_BACK"
				if prepare {
					want = "RECOVERY_PREPARED"
				}
				runRetired0039RecoveryProcess(t, p, recovery, expected, prepare, want)
				recovery = fixed
			}
			for _, prepare := range []bool{true, false} {
				runRetired0039RecoveryProcess(t, p, fixed, expected, prepare, "ROLLED_BACK")
			}
			recovered, err := u.load(s)
			if err != nil || recovered.PostCross == nil || recovered.PostCross.Depth != index+1 {
				t.Fatal("recovery lost bounded history", err)
			}
			lock, err := s.Acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			database, err := acornFoxExpectedCurrentDatabase(s, recovered.Old.Repo.BindingSHA256)
			if err != nil || database != origin.CrossSchema.Database.ShadowDatabase {
				t.Fatal("rollback lost database authority", err)
			}
			lock.Release()
			if !bytes.Equal(recovered.Old.DatabaseEnv, origin.Next.DatabaseEnv) || !bytes.Equal(recovered.Next.DatabaseEnv, origin.Next.DatabaseEnv) {
				t.Fatal("database changed during recovery")
			}
			// A retry resumes this one immutable pair; it cannot consume another slot
			// or rerun a database migration.
			u.step = func(string) error { return nil }
			receipt, err := u.upgrade(context.Background(), request)
			if err != nil || receipt.State != "UPGRADED" {
				t.Fatal("same-candidate retry", err)
			}
			next, err := u.load(s)
			if err != nil || next.PostCross.Depth != index+1 {
				t.Fatal("retry changed depth", err)
			}
			current = next.Next
		})
		if t.Failed() {
			return
		}
	}
	// Complete the eighth permitted continuation, then reject the ninth before
	// any product journal, archive, binding or helper can be changed.
	request := postCrossRequestForTest(t, u, current, "1.2.13-test.1")
	receipt, err := u.upgrade(context.Background(), request)
	if err != nil || receipt.State != "UPGRADED" {
		t.Fatal("eighth continuation", err)
	}
	terminal, err := u.load(s)
	if err != nil || terminal.PostCross.Depth != acornFoxPostCrossMaxDepth {
		t.Fatal("eighth depth", err)
	}
	before := acornFoxUpgradeJSON(terminal)
	ninth := postCrossRequestForTest(t, u, terminal.Next, "1.2.14-test.1")
	if _, err := u.upgrade(context.Background(), ninth); !errors.Is(err, ErrAcornFoxUpgradeRetentionFull) {
		t.Fatal("ninth continuation accepted", err)
	}
	after, err := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("capacity rejection rewrote journal")
	}
	keyAfter, _ := os.ReadFile(keyPath)
	keyInfoAfter, _ := os.Lstat(keyPath)
	if !bytes.Equal(keyBefore, keyAfter) || !os.SameFile(keyInfoBefore, keyInfoAfter) {
		t.Fatal("assistant key changed")
	}
	assertAcornFoxPostCrossProofRejections(t, u, p, s, terminal)
	p.assertExternalSentinel(t)
}

func assertAcornFoxPostCrossProofRejections(t *testing.T, u *acornFoxUpgrade, p acornFoxProductionPreparedFixture, s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) {
	t.Helper()
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	origin, err := acornFoxPostCrossOrigin(j)
	if err != nil {
		t.Fatal(err)
	}
	catalog := newAcornFoxBindingStore(s)
	if _, err := catalog.Read(origin.Old.Repo.BindingSHA256); err != nil {
		t.Fatal("referenced old binding rejected", err)
	}
	// A descriptor can be valid for the frozen schema and still be unauthorized.
	var orphan AcornFoxCandidateBindingV1
	json.Unmarshal(origin.Old.Binding, &orphan)
	orphan.Version = "9.9.9-test.1"
	orphan.ReleaseID = "release-" + orphan.Version
	if validateAcornFoxRecent0039Binding(orphan) != nil {
		t.Fatal("invalid orphan fixture")
	}
	raw := acornFoxUpgradeJSON(orphan)
	path := filepath.Join(p.state, "bindings", sha256Hex(raw)+".json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Read(j.Next.Repo.BindingSHA256); err == nil {
		t.Fatal("unreferenced old binding admitted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(p.state, "bindings", origin.Old.Repo.BindingSHA256+".json")
	if err := os.WriteFile(oldPath, append(bytes.Clone(origin.Old.Binding), ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Read(j.Next.Repo.BindingSHA256); err == nil {
		t.Fatal("changed old binding bytes admitted")
	}
	if err := os.WriteFile(oldPath, origin.Old.Binding, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Read(j.Next.Repo.BindingSHA256); err != nil {
		t.Fatal("restored catalog rejected", err)
	}
	for _, change := range []func(*acornFoxUpgradeJournal){
		func(j *acornFoxUpgradeJournal) { j.PostCross.JournalSHA256 = strings.Repeat("f", 64) },
		func(j *acornFoxUpgradeJournal) { j.PostCross.Depth = acornFoxPostCrossMaxDepth + 1 },
		func(j *acornFoxUpgradeJournal) { j.PostCross.Depth = 1 },
		func(j *acornFoxUpgradeJournal) {
			j.Next.DatabaseEnv = bytes.ReplaceAll(j.Next.DatabaseEnv, []byte(origin.CrossSchema.Database.ShadowDatabase), []byte("acornfox_upg_00000000000000000000"))
		},
	} {
		var forged acornFoxUpgradeJournal
		json.Unmarshal(acornFoxUpgradeJSON(j), &forged)
		change(&forged)
		if forged.validate(u.layout) == nil {
			t.Fatal("forged post-cross source admitted")
		}
		if _, err := acornFoxExpectedCurrentDatabaseFromJournal(forged.Next.Repo, forged, forged.Next.Repo.BindingSHA256); err == nil {
			t.Fatal("forged database authority admitted")
		}
	}
}
