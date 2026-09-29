package install

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
)

func verifiedAcornFoxUpgradePredecessor(raw []byte, digest string) (VerifiedAcornFoxBindingV1, error) {
	binding, err := parseAcornFoxCandidateBindingV1(raw, digest)
	if err != nil {
		return VerifiedAcornFoxBindingV1{}, err
	}
	if validateAcornFoxBinding(binding) != nil && validateAcornFoxFrozen0040Binding(binding) != nil && validateAcornFoxRecent0039Binding(binding) != nil && validateAcornFoxLegacyPredecessorBinding(binding) != nil {
		return VerifiedAcornFoxBindingV1{}, ErrAcornFoxUpgradeConflict
	}
	return VerifiedAcornFoxBindingV1{binding: cloneAcornFoxBinding(binding), digest: digest}, nil
}

func acornFoxCrossSchemaSourceDataVersion(migration string) (int, bool) {
	switch migration {
	case AcornFoxLegacyPredecessorMigration:
		return 34, true
	case acornFoxRecentPredecessorMigration:
		return 39, AcornFoxV1MigrationVersion != acornFoxRecentPredecessorMigration
	default:
		return 0, false
	}
}

func validateAcornFoxPreviousUpgradeImage(image acornFoxUpgradeImage, layout acornFoxInstallLayout) error {
	binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	switch binding.binding.MigrationVersion {
	case AcornFoxLegacyPredecessorMigration:
		return validateAcornFoxLegacy0034UpgradeImage(image, layout)
	case acornFoxRecentPredecessorMigration:
		if AcornFoxV1MigrationVersion == acornFoxRecentPredecessorMigration {
			return ErrAcornFoxUpgradeConflict
		}
		return validateAcornFoxRecent0039UpgradeImage(image, layout)
	default:
		return ErrAcornFoxUpgradeConflict
	}
}

func acornFoxLegacy0034ExpectedEntries(layout acornFoxInstallLayout, substrate InactiveSubstrateReceiptV1) ([]SubstrateEntry, error) {
	legacy, err := acornFoxLegacy0034LayoutFromCurrent(layout)
	if err != nil || legacy.evidence() == "" {
		return nil, ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(substrate)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	entries := append([]SubstrateEntry(nil), substrate.Entries...)
	entries = append(entries, SubstrateEntry{Path: "var/lib/acornfox/install/releases/" + substrate.CandidateReceipt.ReleaseID + ".json", Kind: SubstrateEntryFile, Mode: 0600, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(raw)), SHA256: sha256Hex(raw)})
	for index := range entries {
		if entries[index].Path == "var/lib/acornfox/install" && entries[index].Kind == SubstrateEntryDirectory {
			entries[index].Mode = 0700
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if validateAcornFoxLiveSourceEntries(entries) != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return entries, nil
}

func acornFoxLegacy0034LayoutFromCurrent(layout acornFoxInstallLayout) (acornFoxInstallLayout, error) {
	if layout.validate() != nil || layout.mode != acornFoxInstallLayoutProduction {
		return acornFoxInstallLayout{}, ErrAcornFoxUpgradeConflict
	}
	legacy := layout
	legacy.principals = make(map[AcornFoxLiveRole]acornFoxInstallPrincipal, len(acornFoxLegacy0034InstallLayoutRoles))
	for _, role := range acornFoxLegacy0034InstallLayoutRoles {
		legacy.principals[role] = layout.principals[role]
	}
	legacy.evidenceSHA256 = ""
	if legacy.validateLegacy0034() != nil {
		return acornFoxInstallLayout{}, ErrAcornFoxUpgradeConflict
	}
	legacy.evidenceSHA256 = legacy.digestForRoles(acornFoxLegacy0034InstallLayoutRoles)
	return legacy, nil
}

func validateAcornFoxLegacy0034UpgradeImage(image acornFoxUpgradeImage, currentLayout acornFoxInstallLayout) error {
	legacyLayout, err := acornFoxLegacy0034LayoutFromCurrent(currentLayout)
	if err != nil {
		return err
	}
	binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
	if err != nil || validateAcornFoxLegacyPredecessorBinding(binding.binding) != nil || image.Repo.Validate() != nil || image.Repo.LayoutSHA256 != legacyLayout.evidence() || validateAcornFoxLegacy0034SubstrateReceipt(image.Substrate, binding.binding, binding.digest) != nil || validateAcornFoxLegacy0034LiveReceiptForLayout(legacyLayout, image.Substrate, binding.binding, binding.digest, image.Live) != nil || image.Activation.Validate() != nil || image.ControlPlane.validateMigration(AcornFoxLegacyPredecessorMigration) != nil || image.Runtime.validateForUpgrade() != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if len(image.DatabaseEnv) == 0 || !validAcornFoxBoundControlPlaneEnvironment(image.DatabaseEnv, image.ControlPlane, acornFoxControlPlaneDatabase) || image.Repo.BindingSHA256 != binding.digest || image.Repo.SubstrateReceiptSHA256 != sha256Hex(acornFoxUpgradeJSON(image.Substrate)) || image.Repo.LiveTreeSHA256 != image.Live.LiveTreeSHA256 || image.Repo.StaticSetSHA256 != image.Live.StaticSetSHA256 || image.Repo.OwnershipPlanSHA256 != image.Live.OwnershipPlanSHA256 || image.Repo.ActivationSHA256 != sha256Hex(acornFoxUpgradeJSON(image.Activation)) {
		return ErrAcornFoxUpgradeConflict
	}
	if image.Activation.Mode != "production_host" || image.Activation.LayoutSHA256 != legacyLayout.evidence() || image.Activation.BindingSHA256 != binding.digest || image.Activation.SubstrateReceiptSHA256 != image.Repo.SubstrateReceiptSHA256 || image.Activation.LiveTreeSHA256 != image.Live.LiveTreeSHA256 || image.Activation.StaticSetSHA256 != image.Live.StaticSetSHA256 || image.Activation.OwnershipPlanSHA256 != image.Live.OwnershipPlanSHA256 || image.Activation.ReleaseID != binding.binding.ReleaseID || image.Activation.ReleaseTreeSHA256 != image.Substrate.ReleaseTreeSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	if image.ControlPlane.BindingSHA256 != binding.digest || image.ControlPlane.ReleaseID != binding.binding.ReleaseID || image.ControlPlane.SourceCommit != binding.binding.SourceCommit || image.Runtime.BindingSHA256 != binding.digest || image.Runtime.ReleaseID != binding.binding.ReleaseID || image.Runtime.SourceCommit != binding.binding.SourceCommit {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

type acornFoxCrossSchemaUpgradeV1 struct {
	SchemaVersion        int                             `json:"schema_version"`
	HostProvisionSHA256  string                          `json:"host_provision_sha256"`
	OldMigrationVersion  string                          `json:"old_migration_version"`
	NextMigrationVersion string                          `json:"next_migration_version"`
	TargetRowsSHA256     string                          `json:"target_rows_sha256"`
	Database             acornFoxUpgradeDatabaseEvidence `json:"database"`
	Assistant            *acornFoxUpgradeAssistantConfig `json:"assistant,omitempty"`
}

func (c acornFoxCrossSchemaUpgradeV1) validate(j acornFoxUpgradeJournal) error {
	sourceDataVersion, sourceOK := acornFoxCrossSchemaSourceDataVersion(c.OldMigrationVersion)
	if c.SchemaVersion != 1 || !sourceOK || !validSHA(c.HostProvisionSHA256) || c.NextMigrationVersion != AcornFoxV1MigrationVersion || !validSHA(c.TargetRowsSHA256) || c.Database.validate() != nil {
		return ErrAcornFoxUpgradeConflict
	}
	old, err := verifiedAcornFoxUpgradePredecessor(j.Old.Binding, j.Old.Repo.BindingSHA256)
	if err != nil || old.binding.MigrationVersion != c.OldMigrationVersion {
		return ErrAcornFoxUpgradeConflict
	}
	next, err := ParseAcornFoxCandidateBindingV1(j.Next.Binding, j.Next.Repo.BindingSHA256)
	if err != nil || next.binding.MigrationVersion != c.NextMigrationVersion || c.Database.TransactionID != j.Next.Repo.TransactionID || c.Database.OldBindingSHA256 != j.Old.Repo.BindingSHA256 || c.Database.NextBindingSHA256 != j.Next.Repo.BindingSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	if j.Old.ControlPlane.MigrationRowsSHA256 != c.Database.SourceRowsSHA256 || j.Next.ControlPlane.MigrationRowsSHA256 != c.TargetRowsSHA256 || j.Next.ControlPlane.DatabaseEnvSHA256 != c.Database.CandidateDatabaseEnvSHA256 || j.Next.ControlPlane.DatabaseIdentitySHA256 != acornFoxControlPlaneIdentitySHA256ForDatabase(c.Database.ShadowDatabase) {
		return ErrAcornFoxUpgradeConflict
	}
	if len(j.Old.DatabaseEnv) == 0 || len(j.Next.DatabaseEnv) == 0 || !validAcornFoxBoundControlPlaneEnvironment(j.Old.DatabaseEnv, j.Old.ControlPlane, acornFoxControlPlaneDatabase) || !validAcornFoxBoundControlPlaneEnvironment(j.Next.DatabaseEnv, j.Next.ControlPlane, c.Database.ShadowDatabase) {
		return ErrAcornFoxUpgradeConflict
	}
	if sha256Bytes(j.Next.DatabaseEnv) != c.Database.CandidateDatabaseEnvSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	if sourceDataVersion >= AcornFoxV1DataVersion {
		return ErrAcornFoxUpgradeConflict
	}
	if c.OldMigrationVersion == AcornFoxLegacyPredecessorMigration {
		if c.Assistant != nil || j.PIEnabled {
			return ErrAcornFoxUpgradeConflict
		}
	} else if c.Assistant != nil && c.Assistant.validate() != nil {
		return ErrAcornFoxUpgradeConflict
	} else if j.PIEnabled && c.Assistant == nil {
		return ErrAcornFoxUpgradeConflict
	}
	rank := acornFoxUpgradeDatabaseStateRank(c.Database.State)
	minimum := map[string]int{
		"PREPARED": 2, "BLOCKED": 2, "QUIESCED": 2,
		"SNAPSHOT_CREATED": 3, "MIGRATED": 5, "VALIDATED": 6,
		"PUBLISHED": 6, "SWITCHED": 6, "UPGRADED": 6,
		"ROLLING_BACK": 2, "RECOVERY_PREPARED": 2, "ROLLED_BACK": 2,
	}[j.Phase]
	if minimum == 0 || rank < minimum {
		return ErrAcornFoxUpgradeConflict
	}
	if rank >= acornFoxUpgradeDatabaseStateRank(acornFoxUpgradeDatabaseMigrationsDone) && c.Database.CandidateRowsSHA256 != c.TargetRowsSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func acornFoxCrossSchemaManifests(oldRaw, nextRaw []byte, oldBinding, nextBinding AcornFoxCandidateBindingV1) (Manifest, Manifest, bool) {
	var oldManifest, nextManifest Manifest
	if strictCanonicalJSON(oldRaw, &oldManifest, "legacy AcornFox manifest") != nil || strictCanonicalJSON(nextRaw, &nextManifest, "AcornFox manifest") != nil {
		return Manifest{}, Manifest{}, false
	}
	if validateAcornFoxCandidateManifest(nextManifest, nextBinding) != nil {
		return Manifest{}, Manifest{}, false
	}
	var names []string
	switch oldBinding.MigrationVersion {
	case AcornFoxLegacyPredecessorMigration:
		if validateAcornFoxLegacy0034Manifest(oldManifest, oldBinding) != nil {
			return Manifest{}, Manifest{}, false
		}
		names = acornFoxLegacy0034Migrations
	case acornFoxRecentPredecessorMigration:
		if AcornFoxV1MigrationVersion == acornFoxRecentPredecessorMigration || validateAcornFoxRecent0039Manifest(oldManifest, oldBinding) != nil {
			return Manifest{}, Manifest{}, false
		}
		names = acornFoxRecent0039Migrations
	default:
		return Manifest{}, Manifest{}, false
	}
	oldRows, ok := acornFoxManifestMigrationRows(oldManifest, names)
	if !ok {
		return Manifest{}, Manifest{}, false
	}
	nextRows, ok := acornFoxManifestMigrationRows(nextManifest, acornFoxV1Migrations)
	if !ok || len(oldRows) != len(names) || len(nextRows) != AcornFoxV1DataVersion || len(oldRows) >= len(nextRows) || !matchesExpected(oldRows, nextRows[:len(oldRows)]) {
		return Manifest{}, Manifest{}, false
	}
	return oldManifest, nextManifest, true
}

func validateAcornFoxLegacy0034Manifest(manifest Manifest, binding AcornFoxCandidateBindingV1) error {
	if validateAcornFoxLegacyPredecessorBinding(binding) != nil || manifest.SchemaVersion != ManifestSchemaVersion || manifest.Product != AcornFoxV1Product || manifest.Version != binding.Version || manifest.ReleaseID != binding.ReleaseID || manifest.Architecture != AcornFoxV1Architecture || manifest.MigrationVersion != AcornFoxLegacyPredecessorMigration || manifest.SourceCommit != binding.SourceCommit || manifest.NMinusOne != nil || manifest.Protocol != AgentProtocolVersion || manifest.ConfigDir != AcornFoxV1ConfigDir || manifest.DataDir != AcornFoxV1DataDir || manifest.Compatibility.MinDataVersion != 34 || manifest.Compatibility.MaxDataVersion != 34 || manifest.Compatibility.MinAgentProtocol != PreviousAgentProtocol || manifest.Compatibility.MaxAgentProtocol != AgentProtocolVersion || validateManifestIdentityStructure(manifest) != nil || validateManifestContentStructure(manifest) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	return validateAcornFoxLegacy0034PackageInventory(manifest.Files)
}

func validateAcornFoxLegacy0034PackageInventory(files []FileDigest) error {
	return validateAcornFoxPackageInventory(files, acornFoxLegacy0034RequiredFiles())
}

func acornFoxManifestMigrationRows(manifest Manifest, names []string) ([]MigrationRow, bool) {
	byPath := make(map[string]FileDigest, len(manifest.Files))
	count := 0
	for _, file := range manifest.Files {
		byPath[file.Path] = file
		if len(file.Path) > len("migrations/") && file.Path[:len("migrations/")] == "migrations/" {
			count++
		}
	}
	if count != len(names) {
		return nil, false
	}
	rows := make([]MigrationRow, 0, len(names))
	for _, name := range names {
		file, ok := byPath["migrations/control-plane/"+name]
		if !ok || file.Mode != 0o640 || !validSHA(file.SHA256) {
			return nil, false
		}
		rows = append(rows, MigrationRow{Version: name[:len(name)-4], Checksum: file.SHA256})
	}
	return rows, true
}

type acornFoxCrossSchemaDatabase interface {
	Plan() (acornFoxUpgradeDatabasePrivate, error)
	InspectPrefix(context.Context) (acornFoxUpgradeDatabaseEvidence, error)
	Snapshot(context.Context, *acornFoxUpgradeDatabaseEvidence) (acornFoxUpgradeDatabaseEvidence, error)
	RestoreMigrate(context.Context, acornFoxUpgradeDatabaseEvidence) (acornFoxUpgradeDatabasePrivate, error)
	Validate(context.Context, acornFoxUpgradeDatabasePrivate) (acornFoxUpgradeDatabasePrivate, error)
	Close() error
}

type acornFoxCrossSchemaDatabaseFactory func(acornFoxInstallLayout, string, string, string, []byte, acornFoxControlPlaneMigrations, int) (acornFoxCrossSchemaDatabase, error)

func sameAcornFoxUpgradeDatabaseEvidence(left, right acornFoxUpgradeDatabaseEvidence) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func sameAcornFoxUpgradeDatabaseIdentity(left, right acornFoxUpgradeDatabaseEvidence) bool {
	return left.validate() == nil && right.validate() == nil && left.SchemaVersion == right.SchemaVersion && left.TransactionID == right.TransactionID && left.OldBindingSHA256 == right.OldBindingSHA256 && left.NextBindingSHA256 == right.NextBindingSHA256 && left.ShadowDatabase == right.ShadowDatabase && left.RecoveryEvidenceSHA256 == right.RecoveryEvidenceSHA256 && left.SourceRowsSHA256 == right.SourceRowsSHA256 && left.CandidateDatabaseEnvSHA256 == right.CandidateDatabaseEnvSHA256
}

func validAcornFoxCrossSchemaPhaseTransition(from, to string) bool {
	next := map[string]string{
		"PREPARED": "BLOCKED", "BLOCKED": "QUIESCED", "QUIESCED": "SNAPSHOT_CREATED",
		"SNAPSHOT_CREATED": "MIGRATED", "MIGRATED": "VALIDATED", "VALIDATED": "PUBLISHED",
		"PUBLISHED": "SWITCHED", "SWITCHED": "UPGRADED", "ROLLING_BACK": "RECOVERY_PREPARED",
		"RECOVERY_PREPARED": "ROLLED_BACK",
	}
	if next[from] == to || from == "ROLLING_BACK" && to == "ROLLED_BACK" {
		return true
	}
	return to == "ROLLING_BACK" && from != "UPGRADED" && from != "ROLLED_BACK" && from != "RECOVERY_PREPARED"
}
