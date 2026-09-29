package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func frozen0039ImageForTest(t *testing.T, u *acornFoxUpgrade, s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage, predecessor *acornFoxUpgradeImage, env []byte) acornFoxUpgradeImage {
	t.Helper()
	var image acornFoxUpgradeImage
	if err := json.Unmarshal(acornFoxUpgradeJSON(current), &image); err != nil {
		t.Fatal(err)
	}
	var currentBinding AcornFoxCandidateBindingV1
	if err := json.Unmarshal(current.Binding, &currentBinding); err != nil {
		t.Fatal(err)
	}
	var prior *acornFoxFixture
	if predecessor != nil {
		var b AcornFoxCandidateBindingV1
		if err := json.Unmarshal(predecessor.Binding, &b); err != nil {
			t.Fatal(err)
		}
		prior = &acornFoxFixture{binding: b, bindingRaw: predecessor.Binding, bindingSHA: predecessor.Repo.BindingSHA256}
	}
	fixture := acornFoxFixtureForPolicy(t, currentBinding.Version, prior, AcornFoxCandidateBindingV1Schema, acornFoxRecent0039RequiredFiles(), "0039")
	image.Binding = bytes.Clone(fixture.bindingRaw)
	image.Substrate, _ = historicalSubstrateForTest(t, fixture)
	source, err := acornFoxRecent0039ExpectedEntries(u.layout, image.Substrate)
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.BindingSHA256 = fixture.bindingSHA
	image.Repo.SubstrateReceiptSHA256 = sha256Hex(acornFoxUpgradeJSON(image.Substrate))
	image.Live, err = acornFoxLiveMakeReceiptForLayout(u.layout, image.Repo, &PublishedAcornFoxSubstrateV1{receipt: image.Substrate}, source)
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.LiveTreeSHA256 = image.Live.LiveTreeSHA256
	image.Repo.StaticSetSHA256 = image.Live.StaticSetSHA256
	image.Repo.OwnershipPlanSHA256 = image.Live.OwnershipPlanSHA256
	image.Repo.TransactionID = "acornfox-layout-" + fixture.bindingSHA[:12]
	image.Activation, _, err = acornFoxRepoActivationForLayout(u.layout, image.Repo, image.Live, &PublishedAcornFoxSubstrateV1{receipt: image.Substrate})
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.ActivationSHA256 = sha256Hex(acornFoxUpgradeJSON(image.Activation))
	image.Repo.ActivePointerSHA256 = acornFoxRepoEvidence("acornfox-repo-active-v1\x00", fixture.bindingSHA, image.Repo.ActivationSHA256)
	image.Repo.CurrentPointerSHA256 = acornFoxRepoEvidence("acornfox-repo-current-v1\x00", fixture.bindingSHA, image.Repo.ActivationSHA256)
	for i := range image.Repo.History {
		image.Repo.History[i].EvidenceSHA256 = acornFoxRepoPhaseEvidence(image.Repo, image.Repo.History[i].To)
	}
	image.ControlPlane.BindingSHA256 = fixture.bindingSHA
	image.ControlPlane.MigrationVersion = "0039"
	var manifest Manifest
	if err := json.Unmarshal(fixture.manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	rows := []MigrationRow{}
	for _, name := range acornFoxRecent0039Migrations {
		for _, file := range manifest.Files {
			if file.Path == "migrations/control-plane/"+name {
				rows = append(rows, MigrationRow{Version: strings.TrimSuffix(name, ".sql"), Checksum: file.SHA256})
			}
		}
	}
	image.ControlPlane.MigrationRowsSHA256 = acornFoxMigrationRowsSHA256(rows)
	image.DatabaseEnv = bytes.Clone(env)
	image.Runtime, err = acornFoxUpgradeRebind(current.Runtime, fixture.binding, fixture.bindingSHA, current.Runtime.SetupToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAcornFoxRecent0039UpgradeImage(image, u.layout); err != nil {
		t.Fatal("historical 0039 image", err)
	}
	return image
}

func fixtureForHistoricalImage(t *testing.T, image acornFoxUpgradeImage) acornFoxFixture {
	t.Helper()
	var b AcornFoxCandidateBindingV1
	if err := json.Unmarshal(image.Binding, &b); err != nil {
		t.Fatal(err)
	}
	var prior *acornFoxFixture
	if n := b.NMinusOne; n != nil {
		prior = &acornFoxFixture{bindingSHA: n.BindingSHA256, binding: AcornFoxCandidateBindingV1{Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit, ManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256, BundleManifestSHA256: n.BundleManifestSHA256}}
	}
	f := acornFoxFixtureForPolicy(t, b.Version, prior, 1, acornFoxRecent0039RequiredFiles(), "0039")
	if f.bindingSHA != image.Repo.BindingSHA256 {
		t.Fatal("historical fixture binding differs")
	}
	return f
}

func TestAcornFoxRetired0039ValidationPreservesOriginalJournal(t *testing.T) {
	u, p, request, _ := upgradeFixture(t)
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
	defer lock.Release()
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
	historical := acornFoxUpgradeJournal{SchemaVersion: 1, Phase: "UPGRADED", LayoutSHA256: u.layout.evidence(), Old: old, Next: next}
	historical.Old.DatabaseEnv = nil
	historical.Next.DatabaseEnv = nil
	if err := validateAcornFoxCompleted0039(historical, u.layout, env); err != nil {
		t.Fatal(err)
	}
	if historical.validate(u.layout) == nil {
		t.Fatal("legacy journal accepted as current journal")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*acornFoxUpgradeJournal)
	}{
		{"unfinished", func(j *acornFoxUpgradeJournal) { j.Phase = "SWITCHED" }},
		{"rolled-back", func(j *acornFoxUpgradeJournal) { j.Phase = "ROLLED_BACK" }},
		{"foreign-layout", func(j *acornFoxUpgradeJournal) { j.LayoutSHA256 = strings.Repeat("f", 64) }},
		{"changed-database", func(j *acornFoxUpgradeJournal) { j.Next.ControlPlane.DatabaseEnvSHA256 = strings.Repeat("f", 64) }},
		{"changed-migrations", func(j *acornFoxUpgradeJournal) { j.Next.ControlPlane.MigrationRowsSHA256 = strings.Repeat("f", 64) }},
		{"recursive-history", func(j *acornFoxUpgradeJournal) { j.Retired0039 = &acornFoxRetired0039{} }},
		{"cross-schema", func(j *acornFoxUpgradeJournal) { j.CrossSchema = &acornFoxCrossSchemaUpgradeV1{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var j acornFoxUpgradeJournal
			json.Unmarshal(acornFoxUpgradeJSON(historical), &j)
			tc.mutate(&j)
			if validateAcornFoxCompleted0039(j, u.layout, env) == nil {
				t.Fatal("accepted")
			}
		})
	}
	raw := acornFoxUpgradeJSON(historical)
	if err := os.WriteFile(filepath.Join(p.state, acornFoxUpgradeJournalPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := u.load(s)
	if err != nil || !bytes.Equal(raw, acornFoxUpgradeJSON(loaded)) {
		t.Fatal("historical load changed original bytes", err)
	}
	h := &acornFoxRetired0039{JournalSHA256: sha256Hex(raw), Journal: raw}
	successor := acornFoxUpgradeJournal{Old: next, CrossSchema: &acornFoxCrossSchemaUpgradeV1{OldMigrationVersion: "0039", NextMigrationVersion: "0040"}, Retired0039: h}
	if h.validate(successor, u.layout) != nil {
		t.Fatal("exact successor rejected")
	}
	successor.Old.Runtime.SetupToken = bytes.Repeat([]byte("x"), len(next.Runtime.SetupToken))
	if h.validate(successor, u.layout) == nil {
		t.Fatal("changed current snapshot accepted")
	}
	successor.Old = next
	h.JournalSHA256 = strings.Repeat("f", 64)
	if h.validate(successor, u.layout) == nil {
		t.Fatal("wrong history SHA accepted")
	}
	if err := u.save(s, current, true); !errors.Is(err, ErrAcornFoxUpgradeConflict) {
		t.Fatal("ordinary initial journal replaced retained history", err)
	}
	after, _ := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
	if !bytes.Equal(after, raw) {
		t.Fatal("failed save mutated old journal")
	}
}

func materializeFrozen0039ForTest(t *testing.T, u *acornFoxUpgrade, s *TaskAcornFoxRepoStore, p acornFoxProductionPreparedFixture, current, frozen acornFoxUpgradeJournal) {
	t.Helper()
	for index, item := range []struct {
		old, next acornFoxUpgradeImage
		path      string
	}{{current.Old, frozen.Old, "upgrade/old-state"}, {current.Next, frozen.Next, "."}} {
		fixture := fixtureForHistoricalImage(t, item.next)
		raw := fixture.manifestRaw
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		var b AcornFoxCandidateBindingV1
		if err := json.Unmarshal(item.next.Binding, &b); err != nil {
			t.Fatal(err)
		}
		_, contents := fixtureManifestAndContents(t, fixture)
		prefix := "opt/acornfox/releases/" + b.ReleaseID
		for _, root := range []string{p.host, filepath.Join(p.state, item.path, acornFoxSubstrateRootfs)} {
			for _, file := range m.Files {
				target := filepath.Join(root, prefix, file.Path)
				if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, contents[file.Path], os.FileMode(file.Mode)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, os.FileMode(file.Mode)); err != nil {
					t.Fatal(err)
				}
				info, _ := os.Lstat(target)
				p.owners.set(info, acornFoxInstallPrincipal{})
				for parent := filepath.Dir(target); strings.HasPrefix(parent, filepath.Join(root, prefix)); parent = filepath.Dir(parent) {
					info, _ := os.Lstat(parent)
					p.owners.set(info, acornFoxInstallPrincipal{})
				}
			}
			unit := filepath.Join(root, "etc/systemd/system/acornfox-pi-worker.service")
			if err := os.WriteFile(unit, contents["systemd/acornfox-pi-worker.service"], 0644); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(unit)
			p.owners.set(info, acornFoxInstallPrincipal{})
			if root == p.host && frozen.PIEnabled {
				wants := filepath.Join(p.host, "etc/systemd/system/multi-user.target.wants/acornfox-pi-worker.service")
				if err := os.MkdirAll(filepath.Dir(wants), 0755); err != nil {
					t.Fatal(err)
				}
				parentInfo, err := os.Lstat(filepath.Dir(wants))
				if err != nil {
					t.Fatal(err)
				}
				p.owners.set(parentInfo, acornFoxInstallPrincipal{})
				_ = os.Remove(wants)
				if err := os.Symlink("../acornfox-pi-worker.service", wants); err != nil {
					t.Fatal(err)
				}
				wantsInfo, err := os.Lstat(wants)
				if err != nil {
					t.Fatal(err)
				}
				p.owners.set(wantsInfo, acornFoxInstallPrincipal{})
			}
			if err := os.WriteFile(filepath.Join(root, prefix, "manifest.json"), raw, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, prefix, "migrations/control-plane/0040_acornfox_fix_candidates.sql")); err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(root, "var/lib/acornfox/install/releases", b.ReleaseID+".json")
			if err := os.WriteFile(receiptPath, acornFoxUpgradeJSON(item.next.Substrate), 0600); err != nil {
				t.Fatal(err)
			}
		}
		root := filepath.Join(p.state, item.path)
		intent := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: item.next.Substrate.CandidateReceipt, ExpectedEntryEnvelopeSHA256: item.next.Substrate.InstalledTreeSHA256}
		for path, value := range map[string][]byte{acornFoxSubstrateIntent: acornFoxUpgradeJSON(intent), acornFoxSubstrateReceipt: acornFoxUpgradeJSON(item.next.Substrate)} {
			if err := os.WriteFile(filepath.Join(root, path), value, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Rename(filepath.Join(p.host, u.layout.activationDir(item.old.Activation.ActivationID)), filepath.Join(p.host, u.layout.activationDir(item.next.Activation.ActivationID))); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.host, u.layout.activationReceiptPath(item.next.Activation.ActivationID)), acornFoxUpgradeJSON(item.next.Activation), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.state, "bindings", item.next.Repo.BindingSHA256+".json"), item.next.Binding, 0600); err != nil {
			t.Fatal(err)
		}
		if index == 1 {
			for path, value := range map[string][]byte{acornFoxRepoInstallJournal: acornFoxUpgradeJSON(item.next.Repo), "live-receipt.json": acornFoxUpgradeJSON(item.next.Live), acornFoxControlPlaneReceipt: acornFoxUpgradeJSON(item.next.ControlPlane), acornFoxRuntimeIntentName: acornFoxUpgradeJSON(item.next.Runtime), acornFoxRuntimeReceiptName: acornFoxUpgradeJSON(item.next.Runtime.receipt(acornFoxUpgradeJSON(item.next.Runtime)))} {
				if err := os.WriteFile(filepath.Join(p.state, path), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			active := filepath.Join(p.host, u.layout.activePath())
			if err := os.Remove(active); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("activations/"+item.next.Activation.ActivationID, active); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(active)
			p.owners.set(info, acornFoxInstallPrincipal{})
		}
	}
	if err := os.WriteFile(filepath.Join(p.state, acornFoxUpgradeJournalPath), acornFoxUpgradeJSON(frozen), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAcornFoxRetired0039DetachedSuccessorRecoveryAfterJournalAndRename(t *testing.T) {
	for _, point := range []string{"legacy-0039-journal-staged", "prepared", "legacy-0039-stash-retired", "file-published"} {
		t.Run(point, func(t *testing.T) {
			u, p, request, base := upgradeFixture(t)
			provisionUpgradeAssistantConfig(t, p)
			u.services = &retirementServices{
				acornFoxUpgradePIServiceFake: &acornFoxUpgradePIServiceFake{acornFoxUpgradeServiceFake: base, enabled: true},
				p:                            p,
			}
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
			fired := false
			u.step = func(name string) error {
				if name == point && !fired {
					fired = true
					return errors.New("power loss")
				}
				return nil
			}
			upgradeRequest := AcornFoxUpgradeRequestV1{directory, candidate.bindingSHA, next.Repo.BindingSHA256, selfSHA}
			_, upgradeErr := u.upgrade(context.Background(), upgradeRequest)
			if point == "legacy-0039-journal-staged" {
				if !fired || !errors.Is(upgradeErr, errAcornFoxUpgradeInjectedCrash) {
					t.Fatal("journal staging fault not reached", upgradeErr)
				}
				unchanged, err := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
				if err != nil || !bytes.Equal(unchanged, acornFoxUpgradeJSON(historical)) {
					t.Fatal("precommit crash altered old journal")
				}
				retryLock, err := s.Acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := u.verifyImage(s, historical, true); err != nil {
					t.Fatal("precommit crash invalidated old host", err)
				}
				retryLock.Release()
				u.step = func(name string) error {
					if name == "prepared" {
						return errors.New("second power loss")
					}
					return nil
				}
				_, upgradeErr = u.upgrade(context.Background(), upgradeRequest)
			}
			if !errors.Is(upgradeErr, ErrAcornFoxUpgradeUnknown) || !fired {
				t.Fatal("retirement fault not reached", upgradeErr)
			}
			journal, err := u.load(s)
			if err != nil || journal.Retired0039 == nil {
				t.Fatal("new journal missing bound history", err)
			}
			if !bytes.Equal(journal.Retired0039.Journal, acornFoxUpgradeJSON(historical)) {
				t.Fatal("old journal changed")
			}
			// A strict old decoder cannot interpret the new history/cross-schema
			// transaction. This window is explicitly not automatic old-helper recovery.
			var oldDecoder struct {
				SchemaVersion int                  `json:"schema_version"`
				Phase         string               `json:"phase"`
				LayoutSHA256  string               `json:"layout_sha256"`
				PIEnabled     bool                 `json:"pi_enabled,omitempty"`
				Old           acornFoxUpgradeImage `json:"old"`
				Next          acornFoxUpgradeImage `json:"next"`
			}
			if strictCanonicalJSON(acornFoxUpgradeJSON(journal), &oldDecoder, "old helper") == nil {
				t.Fatal("old helper accepted new journal")
			}

			for _, prepare := range []bool{true, true, false, false} {
				want := "ROLLED_BACK"
				if prepare {
					want = "RECOVERY_PREPARED"
				}
				runRetired0039RecoveryProcess(t, p, self, journal.Next.identity(), prepare, want)
			}

			recovered, err := u.load(s)
			if err != nil {
				t.Fatal(err)
			}
			// The normal fixed systemd recovery entrypoint is now the exact
			// successor executable, while the application identity stays old.
			fixedHelper := filepath.Join(p.host, AcornFoxUpgradeHelperPath)
			fixedBytes, err := os.ReadFile(fixedHelper)
			if err != nil || !bytes.Equal(fixedBytes, recoveryHelper) {
				t.Fatal("fixed recovery helper rolled back")
			}
			oldReleaseHelper := filepath.Join(p.host, "opt/acornfox/releases", recovered.Old.Activation.ReleaseID, "bin/acornfox-upgrade")
			oldBytes, err := os.ReadFile(oldReleaseHelper)
			if err != nil || bytes.Equal(oldBytes, recoveryHelper) || sha256Hex(oldBytes) != recovered.Old.Substrate.UpgradeHelperSHA256 {
				t.Fatal("old immutable release helper changed")
			}
			if !bytes.Equal(acornFoxUpgradeJSON(journal.Old), acornFoxUpgradeJSON(recovered.Old)) {
				t.Fatal("old snapshot rewritten")
			}
			if point == "prepared" {
				if err := os.WriteFile(fixedHelper, oldBytes, 0755); err != nil {
					t.Fatal(err)
				}
				checkLock, err := s.Acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := u.verifyImage(s, recovered, false); err == nil {
					t.Fatal("old executable accepted at successor recovery entrypoint")
				}
				checkLock.Release()
				if err := os.WriteFile(fixedHelper, recoveryHelper, 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, prepare := range []bool{true, false} {
				runRetired0039RecoveryProcess(t, p, fixedHelper, journal.Next.identity(), prepare, "ROLLED_BACK")
			}

			if err := u.verifyRetired0039Stash(s, recovered); err != nil {
				t.Fatal("retained history after rollback", err)
			}
			if point == "prepared" {
				foreign := filepath.Join(p.state, acornFoxRetired0039Stash, "foreign")
				if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := u.verifyRetired0039Stash(s, recovered); err == nil {
					t.Fatal("archive accepted foreign descendant")
				}
				if err := os.Remove(foreign); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(filepath.Join(p.state, acornFoxControlPlaneStateEnv))
			if err != nil || !bytes.Equal(after, env) {
				t.Fatal("old database environment changed")
			}
			keyAfter, err := os.ReadFile(keyPath)
			if err != nil || !bytes.Equal(keyAfter, keyBefore) {
				t.Fatal("assistant key changed")
			}
			keyInfoAfter, err := os.Lstat(keyPath)
			if err != nil || !os.SameFile(keyInfoBefore, keyInfoAfter) {
				t.Fatal("assistant key inode changed")
			}
			p.assertExternalSentinel(t)
		})
	}
}

type retired0039RecoveryProcessInput struct {
	Host, State, Self string
	Expected          AcornFoxBuildIdentityV1
	Prepare           bool
	Owners            [][4]uint64
}
type retired0039RecoveryProcessResult struct {
	State  string
	Owners [][4]uint64
}

func retired0039OwnersForProcess(owners *acornFoxTestOwnerRecorder) [][4]uint64 {
	result := make([][4]uint64, 0, len(owners.values))
	for key, principal := range owners.values {
		result = append(result, [4]uint64{key[0], key[1], uint64(principal.uid), uint64(principal.gid)})
	}
	return result
}
func restoreRetired0039ProcessOwners(owners *acornFoxTestOwnerRecorder, values [][4]uint64) {
	owners.values = map[[2]uint64]acornFoxInstallPrincipal{}
	for _, v := range values {
		owners.values[[2]uint64{v[0], v[1]}] = acornFoxInstallPrincipal{uid: int(v[2]), gid: int(v[3])}
	}
}
func runRetired0039RecoveryProcess(t *testing.T, p acornFoxProductionPreparedFixture, self string, expected AcornFoxBuildIdentityV1, prepare bool, want string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recovery-process.json")
	input := retired0039RecoveryProcessInput{Host: p.host, State: p.state, Self: self, Expected: expected, Prepare: prepare, Owners: retired0039OwnersForProcess(p.owners)}
	if err := os.WriteFile(path, acornFoxUpgradeJSON(input), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAcornFoxRetired0039RecoveryChildProcess$", "-test.count=1")
	command.Env = append(os.Environ(), "ACORNFOX_TEST_RETIRED_0039_PROCESS="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh recovery process prepare=%t: %v: %s", prepare, err, output)
	}
	var result retired0039RecoveryProcessResult
	raw, err := os.ReadFile(path + ".result")
	if err != nil || json.Unmarshal(raw, &result) != nil || result.State != want {
		t.Fatal("unexpected fresh recovery result", err, result.State)
	}
	restoreRetired0039ProcessOwners(p.owners, result.Owners)
}
func TestAcornFoxRetired0039RecoveryChildProcess(t *testing.T) {
	path := os.Getenv("ACORNFOX_TEST_RETIRED_0039_PROCESS")
	if path == "" {
		t.Skip("subprocess entrypoint")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input retired0039RecoveryProcessInput
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("invalid child input")
	}
	layout, err := newTestProductionAcornFoxLayout(input.State, input.Host, os.Getuid(), os.Getgid(), acornFoxTestLayoutPrincipals())
	if err != nil {
		t.Fatal(err)
	}
	owners := acornFoxTestOwnershipRecorder(t)
	restoreRetired0039ProcessOwners(owners, input.Owners)
	u := newAcornFoxUpgrade(layout)
	u.ownership = owners.edge()
	u.self = acornFoxSelfVerifier{path: input.Self, uid: os.Getuid(), gid: os.Getgid()}
	pFixture := acornFoxProductionPreparedFixture{host: input.Host, owners: owners}
	services := &retirementServices{
		acornFoxUpgradePIServiceFake: &acornFoxUpgradePIServiceFake{acornFoxUpgradeServiceFake: &acornFoxUpgradeServiceFake{}, enabled: true},
		p:                            pFixture,
	}
	u.services = services
	if store, err := u.openStore(); err == nil {
		journal, loadErr := u.load(store)
		store.Close()
		if loadErr == nil && journal.isLocal() {
			services.acornFoxUpgradeServiceFake.forbidEdge = true
		}
	}
	receipt, handled, err := u.recoverMode(context.Background(), input.Expected, input.Prepare)
	if err != nil || !handled {
		t.Fatalf("recovery prepare=%t failed: %v", input.Prepare, err)
	}
	result := retired0039RecoveryProcessResult{State: receipt.State, Owners: retired0039OwnersForProcess(owners)}
	if err := os.WriteFile(path+".result", acornFoxUpgradeJSON(result), 0600); err != nil {
		t.Fatal(err)
	}
}
