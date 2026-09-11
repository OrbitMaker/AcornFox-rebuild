package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

func (u *acornFoxUpgrade) capture(ctx context.Context, s *TaskAcornFoxRepoStore, binding []byte) (acornFoxUpgradeImage, error) {
	var image acornFoxUpgradeImage
	j, e := s.Load(ctx)
	if e != nil {
		return image, e
	}
	installed, e := verifiedAcornFoxUpgradePredecessor(binding, j.BindingSHA256)
	if e != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	if installed.binding.MigrationVersion == AcornFoxLegacyPredecessorMigration {
		return u.captureLegacy0034(ctx, s, binding, installed.binding, j)
	}
	if installed.binding.MigrationVersion == acornFoxRecentPredecessorMigration && AcornFoxV1MigrationVersion != acornFoxRecentPredecessorMigration {
		return u.captureRecent0039(ctx, s, binding, installed.binding, j)
	}
	a, _, e := acornFoxRuntimeAuthority(ctx, s, s.hostRoot)
	if e != nil {
		return image, e
	}
	pub, e := newAcornFoxSubstratePublisherForLayout(u.layout)
	if e != nil {
		return image, e
	}
	defer pub.Close()
	sub, e := pub.Reopen(j.BindingSHA256)
	if e != nil {
		return image, e
	}
	defer sub.Close()
	raw, e := u.read(s.root, "live-receipt.json", 0600, acornFoxUpgradeMaxJournal)
	if e != nil {
		return image, e
	}
	live, e := ParseAcornFoxLiveReceiptV1(raw)
	if e != nil {
		return image, e
	}
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if e != nil {
		return image, e
	}
	if e = acornFoxValidateProductionManagedScopePrefixForLegacyUpgrade(s.hostRoot, s, entries, a, acornFoxUpgradeJSON(a), acornFoxRepoPrefixCurrent); e != nil {
		return image, e
	}
	raw, e = u.read(s.root, acornFoxControlPlaneReceipt, 0600, acornFoxUpgradeMaxJournal)
	if e != nil {
		return image, e
	}
	cp, e := parseAcornFoxControlPlaneMigrationReceiptForUpgrade(raw, installed.binding.MigrationVersion)
	if e != nil {
		return image, e
	}
	databaseEnv, e := u.read(s.root, acornFoxControlPlaneStateEnv, 0600, acornFoxUpgradeMaxJournal)
	expectedDatabase := acornFoxControlPlaneDatabase
	if e == nil {
		if observed, nameErr := acornFoxControlPlaneDatabaseName(databaseEnv); nameErr == nil && observed != expectedDatabase {
			expectedDatabase, e = acornFoxExpectedCurrentDatabase(s, j.BindingSHA256)
			if e == nil && observed != expectedDatabase {
				e = ErrAcornFoxUpgradeConflict
			}
		}
	}
	if e != nil || !validAcornFoxBoundControlPlaneEnvironment(databaseEnv, cp, expectedDatabase) {
		return image, ErrAcornFoxUpgradeConflict
	}
	raw, e = u.read(s.root, acornFoxRuntimeIntentName, 0600, acornFoxRuntimeMaxIntent)
	if e != nil {
		return image, e
	}
	runtime, e := parseAcornFoxRuntimeIntentForUpgrade(raw)
	if e != nil {
		return image, e
	}
	if len(runtime.SetupToken) == 0 {
		if installed.binding.MigrationVersion != "0034" {
			return image, ErrAcornFoxUpgradeConflict
		}
	}
	raw, e = u.read(s.root, acornFoxRuntimeReceiptName, 0600, acornFoxRuntimeMaxIntent)
	if e != nil {
		return image, e
	}
	receipt, e := ParseAcornFoxRuntimeConfigReceiptV1(raw)
	if e != nil || receipt != runtime.receipt(acornFoxUpgradeJSON(runtime)) {
		return image, ErrAcornFoxUpgradeConflict
	}
	var privateDatabaseEnv []byte
	if expectedDatabase != acornFoxControlPlaneDatabase || installed.binding.MigrationVersion == AcornFoxLegacyPredecessorMigration {
		privateDatabaseEnv = bytes.Clone(databaseEnv)
	}
	image = acornFoxUpgradeImage{Binding: append([]byte(nil), binding...), Substrate: sub.receipt, Repo: j, Live: live, Activation: a, ControlPlane: cp, DatabaseEnv: privateDatabaseEnv, Runtime: runtime}
	return image, image.validate(u.layout, false)
}

func (u *acornFoxUpgrade) captureRecent0039(ctx context.Context, s *TaskAcornFoxRepoStore, binding []byte, installed AcornFoxCandidateBindingV1, repo AcornFoxRepoJournalV1) (acornFoxUpgradeImage, error) {
	var image acornFoxUpgradeImage
	if ctx == nil || ctx.Err() != nil || !validSHA(u.hostProvisionSHA256) || validateAcornFoxRecent0039Binding(installed) != nil || u.layout.validate() != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	substrateRaw, err := u.read(s.root, acornFoxSubstrateReceipt, 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	substrate, err := parseAcornFoxRecent0039SubstrateReceipt(substrateRaw, installed, repo.BindingSHA256)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	liveRaw, err := u.read(s.root, "live-receipt.json", 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	var live AcornFoxLiveReceiptV1
	if strictCanonicalJSON(liveRaw, &live, "AcornFox 0039 live receipt") != nil || validateAcornFoxRecent0039LiveReceiptForLayout(u.layout, substrate, installed, repo.BindingSHA256, live) != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	activationID, err := AcornFoxRepoActivationID(repo.BindingSHA256)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	activationRaw, err := u.read(s.hostRoot, u.layout.activationReceiptPath(activationID), 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	activation, err := ParseAcornFoxRepoActivationV1(activationRaw)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	controlRaw, err := u.read(s.root, acornFoxControlPlaneReceipt, 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	control, err := parseAcornFoxControlPlaneMigrationReceiptForUpgrade(controlRaw, acornFoxRecentPredecessorMigration)
	if err != nil {
		return image, err
	}
	databaseEnv, err := u.read(s.root, acornFoxControlPlaneStateEnv, 0600, acornFoxUpgradeMaxJournal)
	if err != nil || !validAcornFoxBoundControlPlaneEnvironment(databaseEnv, control, acornFoxControlPlaneDatabase) {
		return image, ErrAcornFoxUpgradeConflict
	}
	runtimeRaw, err := u.read(s.root, acornFoxRuntimeIntentName, 0600, acornFoxRuntimeMaxIntent)
	if err != nil {
		return image, err
	}
	runtime, err := parseAcornFoxRuntimeIntentForUpgrade(runtimeRaw)
	if err != nil || runtime.validateExisting(true) != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	receiptRaw, err := u.read(s.root, acornFoxRuntimeReceiptName, 0600, acornFoxRuntimeMaxIntent)
	if err != nil {
		return image, err
	}
	receipt, err := ParseAcornFoxRuntimeConfigReceiptV1(receiptRaw)
	if err != nil || receipt != runtime.receipt(acornFoxUpgradeJSON(runtime)) {
		return image, ErrAcornFoxUpgradeConflict
	}
	image = acornFoxUpgradeImage{Binding: bytes.Clone(binding), Substrate: substrate, Repo: repo, Live: live, Activation: activation, ControlPlane: control, DatabaseEnv: bytes.Clone(databaseEnv), Runtime: runtime}
	if err := validateAcornFoxRecent0039UpgradeImage(image, u.layout); err != nil {
		return acornFoxUpgradeImage{}, err
	}
	if err := u.verifyRecent0039CapturedScope(s, image); err != nil {
		return acornFoxUpgradeImage{}, err
	}
	return image, nil
}

func (u *acornFoxUpgrade) verifyRecent0039HostScope(s *TaskAcornFoxRepoStore, image acornFoxUpgradeImage) error {
	if s == nil || !s.ownsLock() || validateAcornFoxRecent0039UpgradeImage(image, u.layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	entries, err := acornFoxRecent0039ExpectedEntries(u.layout, image.Substrate)
	if err != nil {
		return err
	}
	runtimeEntries, err := acornFoxRuntimeInspectWithTokenPolicy(s.hostRoot, s, image.Runtime, acornFoxUpgradeJSON(image.Runtime), true, true)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	entries = append(entries, runtimeEntries...)
	assistantEntries, err := acornFoxAssistantConfigScopeExpected(s.hostRoot, s, acornFoxAssistantLegacy0039Config())
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	entries = append(entries, assistantEntries...)
	want := make(map[string]SubstrateEntry, len(entries))
	for _, entry := range entries {
		if _, exists := want[entry.Path]; exists {
			return ErrAcornFoxUpgradeConflict
		}
		want[entry.Path] = entry
	}
	for _, parent := range []string{"opt", "etc", "var", "var/lib", "var/log", "etc/systemd", "etc/systemd/system"} {
		if !acornFoxSharedParentSafe(s.hostRoot, s, parent) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	seen := make(map[string]bool, len(want))
	activationRaw := acornFoxUpgradeJSON(image.Activation)
	for _, managed := range acornFoxProductionManagedRoots() {
		if managed == "opt/acornfox" {
			if err := acornFoxValidateProductionAcornFoxTree(s.hostRoot, s, want, seen, image.Activation, activationRaw, acornFoxRepoPrefixCurrent); err != nil {
				return err
			}
			continue
		}
		if err := acornFoxValidateProductionTreeWithRuntime(s.hostRoot, s, managed, want, seen, true); err != nil {
			return err
		}
	}
	if err := acornFoxValidateProductionSystemdWithBootLinks(s.hostRoot, s, want, seen, true); err != nil {
		return err
	}
	for path := range want {
		if acornFoxProductionStateChild(path) || acornFoxProductionSharedParent(path) {
			continue
		}
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}

func (u *acornFoxUpgrade) captureLegacy0034(ctx context.Context, s *TaskAcornFoxRepoStore, binding []byte, installed AcornFoxCandidateBindingV1, repo AcornFoxRepoJournalV1) (acornFoxUpgradeImage, error) {
	var image acornFoxUpgradeImage
	if ctx == nil || ctx.Err() != nil || !validSHA(u.hostProvisionSHA256) || validateAcornFoxLegacyPredecessorBinding(installed) != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	substrateRaw, err := u.read(s.root, acornFoxSubstrateReceipt, 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	substrate, err := parseAcornFoxLegacy0034SubstrateReceipt(substrateRaw, installed, repo.BindingSHA256)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	liveRaw, err := u.read(s.root, "live-receipt.json", 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	var live AcornFoxLiveReceiptV1
	legacyLayout, layoutErr := acornFoxLegacy0034LayoutFromCurrent(u.layout)
	if strictCanonicalJSON(liveRaw, &live, "AcornFox legacy 0034 live receipt") != nil || layoutErr != nil || validateAcornFoxLegacy0034LiveReceiptForLayout(legacyLayout, substrate, installed, repo.BindingSHA256, live) != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	activationID, err := AcornFoxRepoActivationID(repo.BindingSHA256)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	activationRaw, err := u.read(s.hostRoot, u.layout.activationReceiptPath(activationID), 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	activation, err := ParseAcornFoxRepoActivationV1(activationRaw)
	if err != nil {
		return image, ErrAcornFoxUpgradeConflict
	}
	controlRaw, err := u.read(s.root, acornFoxControlPlaneReceipt, 0600, acornFoxUpgradeMaxJournal)
	if err != nil {
		return image, err
	}
	control, err := parseAcornFoxControlPlaneMigrationReceiptForUpgrade(controlRaw, AcornFoxLegacyPredecessorMigration)
	if err != nil {
		return image, err
	}
	databaseEnv, err := u.read(s.root, acornFoxControlPlaneStateEnv, 0600, acornFoxUpgradeMaxJournal)
	if err != nil || !validAcornFoxBoundControlPlaneEnvironment(databaseEnv, control, acornFoxControlPlaneDatabase) {
		return image, ErrAcornFoxUpgradeConflict
	}
	runtimeRaw, err := u.read(s.root, acornFoxRuntimeIntentName, 0600, acornFoxRuntimeMaxIntent)
	if err != nil {
		return image, err
	}
	runtime, err := parseAcornFoxRuntimeIntentForUpgrade(runtimeRaw)
	if err != nil || len(runtime.SetupToken) != 0 {
		return image, ErrAcornFoxUpgradeConflict
	}
	receiptRaw, err := u.read(s.root, acornFoxRuntimeReceiptName, 0600, acornFoxRuntimeMaxIntent)
	if err != nil {
		return image, err
	}
	receipt, err := ParseAcornFoxRuntimeConfigReceiptV1(receiptRaw)
	if err != nil || receipt != runtime.receipt(acornFoxUpgradeJSON(runtime)) {
		return image, ErrAcornFoxUpgradeConflict
	}
	image = acornFoxUpgradeImage{Binding: bytes.Clone(binding), Substrate: substrate, Repo: repo, Live: live, Activation: activation, ControlPlane: control, DatabaseEnv: bytes.Clone(databaseEnv), Runtime: runtime}
	return image, validateAcornFoxLegacy0034UpgradeImage(image, u.layout)
}
func (u *acornFoxUpgrade) nextImage(old acornFoxUpgradeImage, set *acornFoxCandidateSet, sub *PublishedAcornFoxSubstrateV1, database *acornFoxUpgradeDatabasePrivate, migrations acornFoxControlPlaneMigrations) (acornFoxUpgradeImage, error) {
	var i acornFoxUpgradeImage
	j, e := newAcornFoxRepoJournalForLayout(u.layout, set.bindingSHA256, sha256Hex(acornFoxUpgradeJSON(sub.receipt)))
	if e != nil {
		return i, e
	}
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if e != nil {
		return i, e
	}
	live, e := acornFoxLiveMakeReceiptForLayout(u.layout, j, sub, entries)
	if e != nil {
		return i, e
	}
	for _, phase := range []AcornFoxRepoPhase{AcornFoxRepoLiveMaterialized, AcornFoxRepoStaticVerified} {
		j, e = acornFoxLiveAdvance(j, phase, live)
		if e != nil {
			return i, e
		}
	}
	a, raw, e := acornFoxRepoActivationForLayout(u.layout, j, live, sub)
	if e != nil {
		return i, e
	}
	digest := sha256Hex(raw)
	// This is an intended receipt in the private snapshot. It is published only
	// under the upgrade marker and observed against actual production ownership
	// before the transaction can claim success.
	for _, phase := range []AcornFoxRepoPhase{AcornFoxRepoActivationWritten, AcornFoxRepoActivePublished, AcornFoxRepoCurrentPublished, AcornFoxRepoPreparedFinal} {
		prior := j.Phase
		j.Revision++
		j.Phase = phase
		switch phase {
		case AcornFoxRepoActivationWritten:
			j.ActivationSHA256 = digest
		case AcornFoxRepoActivePublished:
			j.ActivePointerSHA256 = acornFoxRepoEvidence("acornfox-repo-active-v1\x00", j.BindingSHA256, digest)
		case AcornFoxRepoCurrentPublished:
			j.CurrentPointerSHA256 = acornFoxRepoEvidence("acornfox-repo-current-v1\x00", j.BindingSHA256, digest)
		}
		j.History = append(j.History, AcornFoxRepoHistoryV1{j.Revision, AcornFoxRepoHistoryAdvance, prior, phase, acornFoxRepoPhaseEvidence(j, phase)})
		if j.Validate() != nil {
			return i, ErrAcornFoxUpgradeConflict
		}
	}
	cp := old.ControlPlane
	cp.BindingSHA256, cp.ReleaseID, cp.SourceCommit = set.bindingSHA256, set.binding.binding.ReleaseID, set.binding.binding.SourceCommit
	var databaseEnv = bytes.Clone(old.DatabaseEnv)
	if database != nil {
		if database.Evidence.validate() != nil || !migrations.valid() || database.Evidence.State != acornFoxUpgradeDatabasePrefixVerified {
			return i, ErrAcornFoxUpgradeConflict
		}
		databaseEnv = database.candidateEnvironmentBytes()
		cp.MigrationVersion = AcornFoxV1MigrationVersion
		cp.MigrationRowsSHA256 = acornFoxMigrationRowsSHA256(migrations.rows)
		cp.DatabaseEnvSHA256 = sha256Bytes(databaseEnv)
		cp.DatabaseIdentitySHA256 = acornFoxControlPlaneIdentitySHA256ForDatabase(database.Evidence.ShadowDatabase)
	}
	setupToken := old.Runtime.SetupToken
	if len(setupToken) == 0 {
		if u.random == nil {
			return i, ErrAcornFoxUpgradeConflict
		}
		setupToken, e = acornfoxsetup.GenerateSetupToken(u.random)
		if e != nil {
			return i, ErrAcornFoxUpgradeConflict
		}
	}
	runtime, e := acornFoxUpgradeRebind(old.Runtime, set.binding.binding, set.bindingSHA256, setupToken)
	if e == nil {
		runtime, e = acornFoxUpgradeBoundedEdge(runtime)
	}
	if e != nil {
		return i, e
	}
	i = acornFoxUpgradeImage{Binding: append([]byte(nil), set.bindingRaw...), Substrate: sub.receipt, Repo: j, Live: live, Activation: a, ControlPlane: cp, DatabaseEnv: databaseEnv, Runtime: runtime}
	return i, i.validate(u.layout, true)
}
func (u *acornFoxUpgrade) phase(s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal, phase string) error {
	if j.CrossSchema != nil && !validAcornFoxCrossSchemaPhaseTransition(j.Phase, phase) {
		return ErrAcornFoxUpgradeConflict
	}
	j.Phase = phase
	if e := u.save(s, *j, false); e != nil {
		return e
	}
	return u.fault(strings.ToLower(phase))
}

type acornFoxUpgradePIState interface {
	PIEnabled(context.Context) (bool, error)
}

type acornFoxUpgradeLegacyPIState interface {
	PILegacyAbsent(context.Context) (bool, error)
}

func (u *acornFoxUpgrade) capturePIEnabled(ctx context.Context, store *TaskAcornFoxRepoStore, migration string) (bool, error) {
	if migration == AcornFoxLegacyPredecessorMigration {
		configured, err := acornFoxAssistantConfigurationState(store.hostRoot, store)
		if err != nil || configured {
			return false, ErrAcornFoxUpgradeConflict
		}
		services, ok := u.services.(acornFoxUpgradeLegacyPIState)
		if !ok {
			return false, nil
		}
		absent, err := services.PILegacyAbsent(ctx)
		if err != nil {
			return false, err
		}
		if !absent {
			return false, ErrAcornFoxUpgradeConflict
		}
		return false, nil
	}
	if migration != acornFoxRecentPredecessorMigration && migration != AcornFoxV1MigrationVersion {
		return false, ErrAcornFoxUpgradeConflict
	}
	services, ok := u.services.(acornFoxUpgradePIState)
	if !ok {
		// Package-local test fakes written before optional PI support remain
		// compatible. The production adapter implements the capability below.
		return false, nil
	}
	enabled, err := services.PIEnabled(ctx)
	if err != nil {
		return false, err
	}
	configured, err := acornFoxAssistantConfigurationState(store.hostRoot, store)
	if migration == acornFoxRecentPredecessorMigration {
		configured, err = acornFoxAssistantLegacy0039ConfigurationState(store.hostRoot, store)
	}
	if err != nil {
		return false, ErrAcornFoxUpgradeConflict
	}
	if enabled && !configured {
		return false, ErrAcornFoxUpgradeConflict
	}
	return enabled, nil
}

func (u *acornFoxUpgrade) stop(ctx context.Context, piEnabled, isLocal bool) error {
	if piEnabled {
		if e := u.services.Run(ctx, "stop", "acornfox-pi-worker.service"); e != nil {
			return e
		}
	}
	units := []string{"acornfox-agent.service", "acornfox-server.service", "acornfox-caddy.service", "acornfox-buildkit.service", "acornfox-build-network.service"}
	if !isLocal {
		units = append([]string{"acornfox-edge.service"}, units...)
	}
	for _, unit := range units {
		if e := u.services.Run(ctx, "stop", unit); e != nil {
			return e
		}
	}
	return nil
}
func (u *acornFoxUpgrade) start(ctx context.Context, piEnabled bool) error {
	if e := u.services.Run(ctx, "daemon-reload", ""); e != nil {
		return e
	}
	units := []string{"acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-caddy.service"}
	if piEnabled {
		units = append(units, "acornfox-pi-worker.service")
	}
	units = append(units, "acornfox-server.service", "acornfox-agent.service")
	for _, unit := range units {
		if e := u.services.Run(ctx, "start", unit); e != nil {
			return e
		}
	}
	return nil
}
func (u *acornFoxUpgrade) unblock(ctx context.Context, s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	// In local loopback mode, acornfox-edge is deliberately disabled/inactive and not started.
	if j.Next.Runtime.Inputs.Origin == acornfoxsetup.ExactLocalLoopbackOrigin {
		return u.marker(s, j, false)
	}
	// systemd ConditionPathExists on edge requires removing the marker first.
	// Any failure reinstates it and stops edge before rollback is attempted.
	if e := u.marker(s, j, false); e != nil {
		return e
	}
	if e := u.fault("marker-cleared"); e != nil {
		return e
	}
	if e := u.services.Run(ctx, "start", "acornfox-edge.service"); e != nil {
		return e
	}
	return u.services.EdgeHealthy(ctx)
}
func (u *acornFoxUpgrade) forward(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) error {
	if e := u.retireLocalRolloverStash(s, *j); e != nil {
		return e
	}
	if e := u.retirePostCrossStash(s, *j); e != nil {
		return e
	}
	if e := u.retire0039Stash(s, *j); e != nil {
		return e
	}
	if e := u.marker(s, *j, true); e != nil {
		return e
	}
	if e := u.phase(s, j, "BLOCKED"); e != nil {
		return e
	}
	if e := u.stop(ctx, j.PIEnabled, j.isLocal()); e != nil {
		return e
	}
	if e := u.fault("services-stopped"); e != nil {
		return e
	}
	if j.CrossSchema != nil {
		if u.activeDatabase == nil {
			return ErrAcornFoxUpgradeUnknown
		}
		if e := u.phase(s, j, "QUIESCED"); e != nil {
			return e
		}
		snapshot, e := u.activeDatabase.Snapshot(ctx, &j.CrossSchema.Database)
		if e != nil {
			return e
		}
		j.CrossSchema.Database = snapshot
		if e := u.phase(s, j, "SNAPSHOT_CREATED"); e != nil {
			return e
		}
		migrated, e := u.activeDatabase.RestoreMigrate(ctx, snapshot)
		if e != nil {
			return e
		}
		if !bytes.Equal(migrated.candidateEnvironmentBytes(), j.Next.DatabaseEnv) {
			return ErrAcornFoxUpgradeConflict
		}
		j.CrossSchema.Database = migrated.Evidence
		if e := u.phase(s, j, "MIGRATED"); e != nil {
			return e
		}
		validated, e := u.activeDatabase.Validate(ctx, migrated)
		if e != nil {
			return e
		}
		j.CrossSchema.Database = validated.Evidence
		if e := u.phase(s, j, "VALIDATED"); e != nil {
			return e
		}
	}
	if e := u.copyNextSubstrate(s, *j); e != nil {
		return e
	}
	if e := u.applyImage(s, *j, true); e != nil {
		return e
	}
	if e := u.applySetupCredential(s, *j, true); e != nil {
		return e
	}
	if e := applyAcornFoxUpgradeAssistantConfig(s, *j, true); e != nil {
		return e
	}
	if e := u.ensureLegacyPIDisabled(ctx, *j); e != nil {
		return e
	}
	if j.CrossSchema != nil {
		if u.candidateHealth == nil || u.candidateHealth(ctx, s, j.Next) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		if e := u.fault("candidate-healthy"); e != nil {
			return e
		}
	}
	if e := u.fault("setup-credential-published"); e != nil {
		return e
	}
	if e := u.phase(s, j, "PUBLISHED"); e != nil {
		return e
	}
	if e := u.switchSubstrate(s, *j, true); e != nil {
		return e
	}
	if e := u.pointer(s, u.layout.activePath(), "activations/"+j.Old.Activation.ActivationID, "activations/"+j.Next.Activation.ActivationID); e != nil {
		return e
	}
	if e := u.phase(s, j, "SWITCHED"); e != nil {
		return e
	}
	if e := u.verifyImage(s, *j, true); e != nil {
		return e
	}
	if e := u.start(ctx, j.PIEnabled); e != nil {
		return e
	}
	if e := u.healthy(ctx, *j, true); e != nil {
		return e
	}
	if e := u.fault("healthy"); e != nil {
		return e
	}
	if e := u.unblock(ctx, s, *j); e != nil {
		return e
	}
	return u.phase(s, j, "UPGRADED")
}
func (u *acornFoxUpgrade) restore(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) (err error) {
	if e := u.retireLocalRolloverStash(s, *j); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			_ = u.marker(s, *j, true)
			if !j.isLocal() {
				_ = u.services.Run(context.WithoutCancel(ctx), "stop", "acornfox-edge.service")
			}
		}
	}()
	if err = u.marker(s, *j, true); err != nil {
		return err
	}
	if err = u.phase(s, j, "ROLLING_BACK"); err != nil {
		return err
	}
	if err = u.stop(ctx, j.PIEnabled, j.isLocal()); err != nil {
		return err
	}
	if err = u.copyNextSubstrate(s, *j); err != nil {
		return err
	}
	if err = u.applyImage(s, *j, false); err != nil {
		return err
	}
	if err = u.applySetupCredential(s, *j, false); err != nil {
		return err
	}
	if err = applyAcornFoxUpgradeAssistantConfig(s, *j, false); err != nil {
		return err
	}
	if err = u.ensureLegacyPIDisabled(ctx, *j); err != nil {
		return err
	}
	if err = u.removeCrossSchemaDatabaseArtifacts(s, *j); err != nil {
		return err
	}
	if err = u.switchSubstrate(s, *j, false); err != nil {
		return err
	}
	if err = u.pointer(s, u.layout.activePath(), "activations/"+j.Next.Activation.ActivationID, "activations/"+j.Old.Activation.ActivationID); err != nil {
		return err
	}
	return u.verifyImage(s, *j, false)
}

func (u *acornFoxUpgrade) ensureLegacyPIDisabled(ctx context.Context, journal acornFoxUpgradeJournal) error {
	if journal.CrossSchema == nil || journal.CrossSchema.OldMigrationVersion != AcornFoxLegacyPredecessorMigration {
		return nil
	}
	if err := u.services.Run(ctx, "daemon-reload", ""); err != nil {
		return err
	}
	if err := u.services.Run(ctx, "disable", "acornfox-pi-worker.service"); err != nil {
		return err
	}
	state, ok := u.services.(acornFoxUpgradePIState)
	if !ok {
		return ErrAcornFoxUpgradeConflict
	}
	enabled, err := state.PIEnabled(ctx)
	if err != nil {
		return err
	}
	if enabled {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (u *acornFoxUpgrade) applySetupCredential(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool) error {
	image := j.Old
	if next {
		image = j.Next
	}
	var err error
	if len(image.Runtime.SetupToken) == 0 {
		err = acornFoxRuntimeRemoveSetupToken(s.hostRoot, s, j.Next.Runtime)
	} else {
		err = acornFoxRuntimePublishSetupToken(context.Background(), s.hostRoot, s, image.Runtime)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAcornFoxRuntimeConfigConflict) {
		return ErrAcornFoxUpgradeConflict
	}
	return ErrAcornFoxUpgradeUnknown
}
func (u *acornFoxUpgrade) rollback(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) (err error) {
	defer func() {
		if err != nil {
			_ = u.marker(s, *j, true)
			if !j.isLocal() {
				_ = u.services.Run(context.WithoutCancel(ctx), "stop", "acornfox-edge.service")
			}
		}
	}()
	if j.retainsSuccessorHelper() && j.Phase == "RECOVERY_PREPARED" {
		// Prepare already restored the exact previous image. Finalize must
		// follow RECOVERY_PREPARED -> ROLLED_BACK, never rewind the journal.
		if err = u.verifyImage(s, *j, false); err != nil {
			return err
		}
	} else if err = u.restore(ctx, s, j); err != nil {
		return err
	}
	if err = u.start(ctx, j.PIEnabled); err != nil {
		return err
	}
	if err = u.healthy(ctx, *j, false); err != nil {
		return err
	}
	if err = u.unblock(ctx, s, *j); err != nil {
		return err
	}
	return u.phase(s, j, "ROLLED_BACK")
}

func (u *acornFoxUpgrade) verifyImage(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool) error {
	return u.verifyImageWithPending(s, j, next, nil)
}
func (u *acornFoxUpgrade) verifyImageWithPending(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool, pending *acornFoxUpgradeJournal) error {
	if pending != nil && (!next || validateAcornFoxPostCrossPendingPair(j, *pending, u.layout) != nil) {
		return ErrAcornFoxUpgradeConflict
	}

	if j.CrossSchema == nil && j.Next.ControlPlane.MigrationVersion == acornFoxRecentPredecessorMigration {
		if err := u.verifyCompleted0039Manifests(s, j); err != nil {
			return err
		}
	}
	image := j.Old
	if next {
		image = j.Next
	}
	raw, e := u.read(s.root, acornFoxRepoInstallJournal, 0600, acornFoxRepoMaxJournalSize)
	if e != nil || !bytes.Equal(raw, acornFoxUpgradeJSON(image.Repo)) {
		return ErrAcornFoxUpgradeConflict
	}
	files, modes, e := u.imageFiles(s, j, image)
	if e != nil {
		return e
	}
	var recoveryHelper *SubstrateEntry
	if pending != nil || j.retainsSuccessorHelper() && !next {
		helperJournal := j
		if pending != nil {
			helperJournal = *pending
		}
		entry, raw, err := u.crossSchemaRecoveryHelper(s, helperJournal)
		if err != nil {
			return err
		}
		recoveryHelper = &entry
		files[entry.Path] = raw
		modes[entry.Path] = os.FileMode(entry.Mode)
	}
	principals := map[string]acornFoxInstallPrincipal{}
	for _, entry := range image.Substrate.Entries {
		if entry.Kind == SubstrateEntryFile {
			principals[entry.Path] = acornFoxLivePrincipalForEntry(u.layout, entry)
		}
	}
	for path, want := range files {
		got, e := u.readPrincipal(s.hostRoot, path, modes[path], acornFoxArchiveMaxBytes, principals[path])
		if e != nil || !bytes.Equal(got, want) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path, target := range map[string]string{u.layout.activePath(): "activations/" + image.Activation.ActivationID, u.layout.currentPath(): "active/release"} {
		if !acornFoxRepoPointerForLayout(s.hostRoot, s, u.layout, path, target, false) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	root, e := s.root.OpenRoot(".")
	if e != nil {
		return e
	}
	sub, e := u.openSubstrate(root, image)
	if e != nil {
		return e
	}
	defer sub.Close()
	// Observe every role and file at its real production path; the task artifact
	// is never accepted as a substitute for host materialization.
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if image.Substrate.CandidateReceipt.MigrationVersion != AcornFoxV1MigrationVersion {
		switch image.Substrate.CandidateReceipt.MigrationVersion {
		case AcornFoxLegacyPredecessorMigration:
			entries, e = acornFoxLegacy0034ExpectedEntries(u.layout, image.Substrate)
		case acornFoxRecentPredecessorMigration:
			entries, e = acornFoxRecent0039ExpectedEntries(u.layout, image.Substrate)
		default:
			return ErrAcornFoxUpgradeConflict
		}
	}
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if recoveryHelper != nil && entry.Path == AcornFoxUpgradeHelperPath {
			entry = *recoveryHelper
		}
		if acornFoxProductionSharedParent(entry.Path) {
			continue
		}
		if !acornFoxProductionEntryMatches(s.hostRoot, s, entry.Path, entry) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	if err := u.verifyRetainedScopeWithPending(s, j, image, pending); err != nil {
		return err
	}
	return verifyAcornFoxUpgradeAssistantConfig(s, j, next)
}

// acornFoxUpgradeRetainedScope is the Current-scope integration point. It
// recognizes exactly the journal-bound pair and verifies both retained
// releases/activations plus the selected host state. It never permits an
// arbitrary release directory or generic descendants under an upgrade prefix.
// Caller must already own the fixed repository lock.
func acornFoxUpgradeRetainedScope(root *os.Root, s *TaskAcornFoxRepoStore, activation AcornFoxRepoActivationV1) (bool, error) {
	if root == nil || s == nil || !s.ownsLock() {
		return false, ErrAcornFoxUpgradeConflict
	}
	host, e := root.Stat(".")
	if e != nil || !os.SameFile(host, s.layout.hostRootInfo) {
		return false, ErrAcornFoxUpgradeConflict
	}
	u := newAcornFoxUpgrade(s.layout)
	u.ownership = s.ownership
	j, e := u.load(s)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return true, e
	}
	image := j.Old
	if activation == j.Next.Activation {
		image = j.Next
	} else if activation != j.Old.Activation {
		return true, ErrAcornFoxUpgradeConflict
	}
	if j.Phase == "UPGRADED" && image.Repo.BindingSHA256 != j.Next.Repo.BindingSHA256 || j.Phase == "ROLLED_BACK" && image.Repo.BindingSHA256 != j.Old.Repo.BindingSHA256 {
		return true, ErrAcornFoxUpgradeConflict
	}
	return true, u.verifyImage(s, j, image.Repo.BindingSHA256 == j.Next.Repo.BindingSHA256)
}
func (u *acornFoxUpgrade) verifyRetainedScope(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage) error {
	return u.verifyRetainedScopeWithPending(s, j, current, nil)
}
func (u *acornFoxUpgrade) verifyRetainedScopeWithPending(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage, pending *acornFoxUpgradeJournal) error {
	if pending != nil && (current.Repo.BindingSHA256 != j.Next.Repo.BindingSHA256 || validateAcornFoxPostCrossPendingPair(j, *pending, u.layout) != nil) {
		return ErrAcornFoxUpgradeConflict
	}

	entries := map[string]SubstrateEntry{}
	files := map[string][]byte{}
	modes := map[string]os.FileMode{}
	pointers := map[string]string{}
	// Shared paths use the selected image. Only versioned immutable material from
	// the other image extends the inventory.
	images := []acornFoxUpgradeImage{j.Old, j.Next}
	if j.LocalRollover != nil {
		prev, e := j.LocalRollover.previous(j)
		if e != nil {
			return e
		}
		images = append(images, acornFoxLocalNonCurrent(prev))
	}
	if j.PostCross != nil {
		archives, origin, err := acornFoxPostCrossArchives(j)
		if err != nil {
			return err
		}
		for _, archive := range archives {
			images = append(images, archive.image)
		}
		if origin.Retired0039 != nil {
			prior, err := origin.Retired0039.decode(origin, u.layout)
			if err != nil {
				return err
			}
			prior.Old.DatabaseEnv = bytes.Clone(origin.Old.DatabaseEnv)
			images = append(images, prior.Old)
		}
	}
	if j.Retired0039 != nil {
		prior, err := j.Retired0039.decode(j, u.layout)
		if err != nil {
			return err
		}
		prior.Old.DatabaseEnv = bytes.Clone(j.Old.DatabaseEnv)
		images = append(images, prior.Old)
	}
	for _, image := range images {
		prefix := "opt/acornfox/releases/" + image.Activation.ReleaseID
		for _, entry := range image.Substrate.Entries {
			if entry.Path == prefix || strings.HasPrefix(entry.Path, prefix+"/") || image.Repo.BindingSHA256 == current.Repo.BindingSHA256 {
				if entry.Path == "var/lib/acornfox/install" && entry.Kind == SubstrateEntryDirectory {
					entry.Mode = 0700
				}
				entries[entry.Path] = entry
			}
		}
		dir := u.layout.activationDir(image.Activation.ActivationID)
		entries["opt/acornfox/activations"] = SubstrateEntry{Path: "opt/acornfox/activations", Kind: SubstrateEntryDirectory, Mode: uint32(u.layout.activationDirectoryMode()), Role: OwnerRoleRoot, Group: GroupRoleRoot}
		entries[dir] = SubstrateEntry{Path: dir, Kind: SubstrateEntryDirectory, Mode: uint32(u.layout.activationDirectoryMode()), Role: OwnerRoleRoot, Group: GroupRoleRoot}
		path := u.layout.activationReceiptPath(image.Activation.ActivationID)
		files[path] = acornFoxUpgradeJSON(image.Activation)
		modes[path] = 0600
		env := bytes.Clone(image.DatabaseEnv)
		if len(env) == 0 {
			var readErr error
			env, readErr = u.read(s.root, acornFoxControlPlaneStateEnv, 0600, 16384)
			if readErr != nil {
				return ErrAcornFoxUpgradeConflict
			}
		}
		database, databaseErr := acornFoxControlPlaneDatabaseName(env)
		if databaseErr != nil || !validAcornFoxBoundControlPlaneEnvironment(env, image.ControlPlane, database) {
			return ErrAcornFoxUpgradeConflict
		}
		files[dir+"/database.env"] = env
		modes[dir+"/database.env"] = 0600
		pointers[u.layout.activationReleasePath(image.Activation.ActivationID)] = "../../releases/" + image.Activation.ReleaseID
	}
	if j.CrossSchema != nil && current.Repo.BindingSHA256 == j.Old.Repo.BindingSHA256 {
		// Cross-schema host provisioning and candidate publication intentionally
		// retain only exact candidate additions (PI/runtime units and data roots)
		// after rollback. Existing predecessor paths keep predecessor bytes.
		for _, entry := range j.Next.Substrate.Entries {
			if _, exists := entries[entry.Path]; !exists {
				entries[entry.Path] = entry
			}
		}
	}
	if pending != nil || j.retainsSuccessorHelper() && current.Repo.BindingSHA256 == j.Old.Repo.BindingSHA256 {
		helperJournal := j
		if pending != nil {
			helperJournal = *pending
		}
		entry, err := acornFoxCrossSchemaRecoveryHelperEntry(helperJournal, u.layout)
		if err != nil {
			return err
		}
		entries[entry.Path] = entry
	}
	pointers[u.layout.activePath()] = "activations/" + current.Activation.ActivationID
	pointers[u.layout.currentPath()] = "active/release"
	entries[acornFoxRuntimeTarget] = SubstrateEntry{Path: acornFoxRuntimeTarget, Kind: SubstrateEntryDirectory, Mode: 0755, Role: OwnerRoleRoot, Group: GroupRoleRoot}
	for _, f := range current.Runtime.Files {
		path := strings.TrimPrefix(f.Path, "/")
		files[path] = f.Data
		modes[path] = os.FileMode(f.Mode)
	}
	if len(current.Runtime.SetupToken) != 0 {
		entries[acornFoxSetupCredentialDirectory] = SubstrateEntry{Path: acornFoxSetupCredentialDirectory, Kind: SubstrateEntryDirectory, Mode: 0700, Role: OwnerRoleRoot, Group: GroupRoleRoot}
		files[acornFoxSetupCredentialPath] = current.Runtime.SetupToken
		modes[acornFoxSetupCredentialPath] = 0600
	}
	if len(current.DatabaseEnv) != 0 {
		files["var/lib/acornfox/install/"+acornFoxControlPlaneStateEnv] = current.DatabaseEnv
		modes["var/lib/acornfox/install/"+acornFoxControlPlaneStateEnv] = 0600
	}
	assistant, e := acornFoxAssistantConfigScope(s.hostRoot, s)
	if current.ControlPlane.MigrationVersion == acornFoxRecentPredecessorMigration {
		assistant, e = acornFoxAssistantConfigScopeExpected(s.hostRoot, s, acornFoxAssistantLegacy0039Config())
	}
	if e != nil {
		return ErrAcornFoxUpgradeConflict
	}
	for _, entry := range assistant {
		if _, exists := entries[entry.Path]; exists {
			return ErrAcornFoxUpgradeConflict
		}
		entries[entry.Path] = entry
	}
	marker, me := u.read(s.hostRoot, acornFoxUpgradeMarkerPath, 0600, 256)
	if me == nil {
		if !bytes.Equal(marker, []byte(j.Old.Repo.BindingSHA256+"\n"+j.Next.Repo.BindingSHA256+"\n")) {
			return ErrAcornFoxUpgradeConflict
		}
		files[acornFoxUpgradeMarkerPath] = marker
		modes[acornFoxUpgradeMarkerPath] = 0600
	} else if !errors.Is(me, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	seen := map[string]bool{}
	var walk func(string) error
	walk = func(path string) error {
		if target, ok := pointers[path]; ok {
			if !acornFoxRepoPointerForLayout(s.hostRoot, s, u.layout, path, target, false) {
				return ErrAcornFoxUpgradeConflict
			}
			seen[path] = true
			return nil
		}
		if want, ok := files[path]; ok {
			raw, e := u.read(s.hostRoot, path, modes[path], acornFoxArchiveMaxBytes)
			if e != nil || !bytes.Equal(raw, want) {
				return ErrAcornFoxUpgradeConflict
			}
			seen[path] = true
			return nil
		}
		entry, ok := entries[path]
		if !ok || !acornFoxProductionEntryMatches(s.hostRoot, s, path, entry) {
			return ErrAcornFoxUpgradeConflict
		}
		seen[path] = true
		if entry.Kind == SubstrateEntryFile || path == "var/lib/acornfox/install" {
			return nil
		}
		if acornFoxServiceDataRoot(path) {
			for child := range entries {
				if parentDirectory(child) == path {
					if e := walk(child); e != nil {
						return e
					}
				}
			}
			return nil
		}
		d, e := s.hostRoot.OpenFile(path, os.O_RDONLY, 0)
		if e != nil {
			return e
		}
		children, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			return e
		}
		for _, child := range children {
			if e = walk(path + "/" + child.Name()); e != nil {
				return e
			}
		}
		return nil
	}
	for _, path := range acornFoxProductionManagedRoots() {
		if e := walk(path); e != nil {
			return e
		}
	}
	unitEntries := map[string]SubstrateEntry{}
	for p, e := range entries {
		unitEntries[p] = e
	}
	if e := acornFoxValidateProductionSystemdWithBootLinks(s.hostRoot, s, unitEntries, seen, true); e != nil {
		return e
	}
	for path := range entries {
		if acornFoxProductionStateChild(path) || acornFoxProductionSharedParent(path) {
			continue
		}
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path, expected := range files {
		// The private install root is deliberately not walked as a host tree.
		// Cross-schema snapshots additionally bind its one active database
		// environment; verify that fixed computed file explicitly.
		if acornFoxProductionStateChild(path) {
			actual, err := u.read(s.hostRoot, path, modes[path], acornFoxArchiveMaxBytes)
			if err != nil || !bytes.Equal(actual, expected) {
				return ErrAcornFoxUpgradeConflict
			}
			continue
		}
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path := range pointers {
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return u.verifyPrivateStore(s, j, current)
}
func (u *acornFoxUpgrade) verifyPrivateStore(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage) error {
	info, e := s.root.Lstat(acornFoxUpgradeDirectory)
	if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxUpgradeConflict
	}
	dir, e := s.root.OpenFile(acornFoxUpgradeDirectory, os.O_RDONLY, 0)
	if e != nil {
		return e
	}
	children, e := dir.ReadDir(-1)
	dir.Close()
	if e != nil {
		return e
	}

	wantChildren := map[string]bool{"journal.json": true, "old-state": true, "new-state": true}
	if j.LocalRollover != nil {
		wantChildren["local-retiring"] = true
	}
	if j.CrossSchema != nil && current.Repo.BindingSHA256 == j.Next.Repo.BindingSHA256 {
		wantChildren[acornFoxUpgradeDatabaseRoot] = true
	}
	if j.Retired0039 != nil {
		wantChildren[acornFoxRetired0039StashName] = true
	}
	if j.PostCross != nil {
		archives, origin, err := acornFoxPostCrossArchives(j)
		if err != nil {
			return err
		}
		for _, archive := range archives {
			wantChildren[strings.TrimPrefix(archive.path, "upgrade/")] = true
		}
		wantChildren[acornFoxUpgradeDatabaseRoot] = true
		if origin.Retired0039 != nil {
			wantChildren[acornFoxRetired0039StashName] = true
		}
	}
	if len(children) != len(wantChildren) {
		return ErrAcornFoxUpgradeConflict
	}
	for _, child := range children {
		if !wantChildren[child.Name()] {
			return ErrAcornFoxUpgradeConflict
		}
	}

	for _, item := range []struct {
		path  string
		image acornFoxUpgradeImage
	}{{"upgrade/old-state", j.Old}, {"upgrade/new-state", j.Next}} {
		info, e := s.root.Lstat(item.path)
		if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return ErrAcornFoxUpgradeConflict
		}
		d, e := s.root.OpenFile(item.path, os.O_RDONLY, 0)
		if e != nil {
			return e
		}
		list, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			return e
		}
		if current.Repo.BindingSHA256 == item.image.Repo.BindingSHA256 {
			if len(list) != 0 {
				return ErrAcornFoxUpgradeConflict
			}
			continue
		}
		if len(list) != 1 || list[0].Name() != "substrate" {
			return ErrAcornFoxUpgradeConflict
		}
		root, e := s.root.OpenRoot(item.path)
		if e != nil {
			return e
		}
		h, e := u.openSubstrate(root, item.image)
		if e != nil {
			return e
		}
		h.Close()
		if j.CrossSchema == nil && j.Next.ControlPlane.MigrationVersion == acornFoxRecentPredecessorMigration {
			if err := u.retired0039SubstrateAt(s, item.path, item.image); err != nil {
				return err
			}
		}
	}
	if j.LocalRollover != nil {
		prev, e := j.LocalRollover.previous(j)
		if e != nil {
			return e
		}
		if e := u.retired0039SubstrateAt(s, "upgrade/local-retiring", acornFoxLocalNonCurrent(prev)); e != nil {
			return e
		}
	}
	if j.Retired0039 != nil {
		if err := u.verifyRetired0039Stash(s, j); err != nil {
			return err
		}
	}
	if j.PostCross != nil {
		return u.verifyPostCrossArchives(s, j)
	}
	if j.CrossSchema == nil || current.Repo.BindingSHA256 == j.Old.Repo.BindingSHA256 {
		return nil
	}
	return u.verifyCrossSchemaDatabaseArtifacts(s, *j.CrossSchema)
}

func acornFoxCrossSchemaArtifactID(c acornFoxCrossSchemaUpgradeV1) (string, error) {
	if c.Database.validate() != nil || !validSHA(c.Database.RecoveryEvidenceSHA256) {
		return "", ErrAcornFoxUpgradeConflict
	}
	return "cross-schema-" + c.Database.RecoveryEvidenceSHA256[:20], nil
}

var acornFoxUpgradeDatabaseDurableTemp = regexp.MustCompile(`^\.open-card-file-[a-f0-9]{32}$`)

func (u *acornFoxUpgrade) verifyCrossSchemaDatabaseArtifacts(s *TaskAcornFoxRepoStore, cross acornFoxCrossSchemaUpgradeV1) error {
	artifactID, err := acornFoxCrossSchemaArtifactID(cross)
	if err != nil || cross.Database.State != acornFoxUpgradeDatabaseHealthValidated {
		return ErrAcornFoxUpgradeConflict
	}
	base := acornFoxUpgradeDirectory + "/" + acornFoxUpgradeDatabaseRoot
	artifact := base + "/" + artifactID
	for _, path := range []string{base, artifact} {
		info, statErr := s.root.Lstat(path)
		if statErr != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	baseDir, err := s.root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	baseChildren, readErr := baseDir.ReadDir(-1)
	closeErr := baseDir.Close()
	if readErr != nil || closeErr != nil || len(baseChildren) != 1 || baseChildren[0].Name() != artifactID {
		return ErrAcornFoxUpgradeConflict
	}
	artifactDir, err := s.root.OpenFile(artifact, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	children, readErr := artifactDir.ReadDir(-1)
	closeErr = artifactDir.Close()
	want := map[string]bool{acornFoxUpgradeDatabaseDump: true, acornFoxUpgradeDatabaseSnapshot: true, acornFoxUpgradeDatabaseShadowIntent: true, acornFoxUpgradeDatabaseMigrated: true, acornFoxUpgradeDatabaseValidated: true}
	if readErr != nil || closeErr != nil || len(children) != len(want) {
		return ErrAcornFoxUpgradeConflict
	}
	for _, child := range children {
		if !want[child.Name()] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	dump, err := snapshotEvidence(filepath.Join(s.layout.stateRootPath, artifact, acornFoxUpgradeDatabaseDump))
	if err != nil || dump.SHA256 != cross.Database.SnapshotSHA256 || dump.Size != cross.Database.SnapshotSize {
		return ErrAcornFoxUpgradeConflict
	}
	snapshot := cross.Database
	snapshot.State = acornFoxUpgradeDatabaseSnapshotCreated
	snapshot.CandidateRowsSHA256 = ""
	migrated := cross.Database
	migrated.State = acornFoxUpgradeDatabaseMigrationsDone
	for name, expected := range map[string]acornFoxUpgradeDatabaseEvidence{acornFoxUpgradeDatabaseSnapshot: snapshot, acornFoxUpgradeDatabaseShadowIntent: snapshot, acornFoxUpgradeDatabaseMigrated: migrated, acornFoxUpgradeDatabaseValidated: cross.Database} {
		raw, readErr := u.read(s.root, artifact+"/"+name, 0600, acornFoxUpgradeMaxJournal)
		if readErr != nil || !bytes.Equal(raw, acornFoxUpgradeJSON(expected)) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}

func (u *acornFoxUpgrade) removeCrossSchemaDatabaseArtifacts(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.CrossSchema == nil {
		return nil
	}
	artifactID, err := acornFoxCrossSchemaArtifactID(*j.CrossSchema)
	if err != nil {
		return err
	}
	base := acornFoxUpgradeDirectory + "/" + acornFoxUpgradeDatabaseRoot
	baseInfo, err := s.root.Lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeAcornFoxRepoDir(baseInfo, s.uid, s.gid) {
		return ErrAcornFoxUpgradeConflict
	}
	baseDir, err := s.root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	baseChildren, readErr := baseDir.ReadDir(-1)
	closeErr := baseDir.Close()
	if readErr != nil || closeErr != nil || len(baseChildren) > 1 || len(baseChildren) == 1 && baseChildren[0].Name() != artifactID {
		return ErrAcornFoxUpgradeConflict
	}
	if len(baseChildren) == 1 {
		artifact := base + "/" + artifactID
		info, statErr := s.root.Lstat(artifact)
		if statErr != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return ErrAcornFoxUpgradeConflict
		}
		dir, openErr := s.root.OpenFile(artifact, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return ErrAcornFoxUpgradeConflict
		}
		children, listErr := dir.ReadDir(-1)
		closeErr = dir.Close()
		allowed := map[string]bool{acornFoxUpgradeDatabaseDump: true, acornFoxUpgradeDatabaseSnapshot: true, acornFoxUpgradeDatabaseShadowIntent: true, acornFoxUpgradeDatabaseMigrated: true, acornFoxUpgradeDatabaseValidated: true}
		if listErr != nil || closeErr != nil || len(children) > len(allowed)*2 {
			return ErrAcornFoxUpgradeConflict
		}
		for _, child := range children {
			if allowed[child.Name()] {
				continue
			}
			if !acornFoxUpgradeDatabaseDurableTemp.MatchString(child.Name()) {
				return ErrAcornFoxUpgradeConflict
			}
			childPath := artifact + "/" + child.Name()
			childInfo, statErr := s.root.Lstat(childPath)
			if statErr != nil || !childInfo.Mode().IsRegular() || childInfo.Mode().Perm() != 0600 || (acornFoxRepoNlink(childInfo) != 1 && acornFoxRepoNlink(childInfo) != 2) || verifyOwner(childInfo, s.uid, s.gid) != nil || s.root.Remove(childPath) != nil {
				return ErrAcornFoxUpgradeConflict
			}
		}
		for _, child := range children {
			if !allowed[child.Name()] {
				continue
			}
			childPath := artifact + "/" + child.Name()
			childInfo, statErr := s.root.Lstat(childPath)
			if statErr != nil || !childInfo.Mode().IsRegular() || childInfo.Mode().Perm()&0022 != 0 || acornFoxRepoNlink(childInfo) != 1 || verifyOwner(childInfo, s.uid, s.gid) != nil || s.root.Remove(childPath) != nil {
				return ErrAcornFoxUpgradeConflict
			}
		}
		if s.root.Remove(artifact) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
	}
	if s.root.Remove(base) != nil || acornFoxLiveSyncDir(s.root, acornFoxUpgradeDirectory) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}
