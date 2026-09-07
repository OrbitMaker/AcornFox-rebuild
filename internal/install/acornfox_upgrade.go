package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

var ErrAcornFoxUpgradeConflict = errors.New("AcornFox upgrade conflicts with retained state")
var ErrAcornFoxUpgradeUnknown = errors.New("AcornFox upgrade requires recovery with ingress blocked")
var ErrAcornFoxUpgradeRetentionFull = errors.New("AcornFox retained upgrade pair is full")
var ErrAcornFoxUpgradeRolledBack = errors.New("AcornFox upgrade failed and the previous version was restored")

const acornFoxUpgradeDirectory = "upgrade"
const acornFoxUpgradeJournalPath = "upgrade/journal.json"
const acornFoxUpgradeMarkerPath = "var/lib/acornfox/upgrade-in-progress"
const acornFoxUpgradeMaxJournal = 8 << 20

type AcornFoxUpgradeRequestV1 struct{ Directory, BindingSHA256, CurrentBindingSHA256, SelfSHA256 string }
type AcornFoxUpgradeReceiptV1 struct {
	SchemaVersion         int    `json:"schema_version"`
	State                 string `json:"state"`
	BindingSHA256         string `json:"binding_sha256"`
	PreviousBindingSHA256 string `json:"previous_binding_sha256"`
	ReleaseID             string `json:"release_id"`
	SourceCommit          string `json:"source_commit"`
	LayoutSHA256          string `json:"layout_sha256"`
}

func (r AcornFoxUpgradeReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || (r.State != "UPGRADED" && r.State != "ROLLED_BACK" && r.State != "RECOVERY_PREPARED") || !validSHA(r.BindingSHA256) || !validSHA(r.PreviousBindingSHA256) || !validID(r.ReleaseID) || !acornFoxHostSourceCommit.MatchString(r.SourceCommit) || !validSHA(r.LayoutSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

// Private snapshots contain runtime keys. They are written only to a root-only
// journal, never returned in receipts, diagnostics, or formatted values.
type acornFoxUpgradeImage struct {
	Binding      json.RawMessage                        `json:"binding"`
	Substrate    InactiveSubstrateReceiptV1             `json:"substrate"`
	Repo         AcornFoxRepoJournalV1                  `json:"repo"`
	Live         AcornFoxLiveReceiptV1                  `json:"live"`
	Activation   AcornFoxRepoActivationV1               `json:"activation"`
	ControlPlane AcornFoxControlPlaneMigrationReceiptV1 `json:"control_plane"`
	DatabaseEnv  []byte                                 `json:"database_env,omitempty"`
	Runtime      acornFoxRuntimeIntent                  `json:"runtime"`
}

func (acornFoxUpgradeImage) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "upgrade image [redacted]")
}

type acornFoxUpgradeJournal struct {
	SchemaVersion int                           `json:"schema_version"`
	Phase         string                        `json:"phase"`
	LayoutSHA256  string                        `json:"layout_sha256"`
	PIEnabled     bool                          `json:"pi_enabled,omitempty"`
	CrossSchema   *acornFoxCrossSchemaUpgradeV1 `json:"cross_schema,omitempty"`
	Retired0039   *acornFoxRetired0039          `json:"retired_0039,omitempty"`
	Old           acornFoxUpgradeImage          `json:"old"`
	Next          acornFoxUpgradeImage          `json:"next"`
}

func (acornFoxUpgradeJournal) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "upgrade journal [redacted]")
}
func acornFoxUpgradeJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }
func (i acornFoxUpgradeImage) identity() AcornFoxBuildIdentityV1 {
	c := i.Substrate.CandidateReceipt
	return AcornFoxBuildIdentityV1{SchemaVersion: 1, Product: AcornFoxV1Product, LayoutVersion: 1, Role: "upgrade", Version: c.Version, ReleaseID: c.ReleaseID, SourceCommit: c.SourceCommit}
}
func (i acornFoxUpgradeImage) validate(layout acornFoxInstallLayout, requireSetupToken bool) error {
	b, e := ParseAcornFoxCandidateBindingV1(i.Binding, i.Repo.BindingSHA256)
	if e != nil || i.Substrate.Validate() != nil || i.Repo.Validate() != nil || i.Live.Validate() != nil || i.Activation.Validate() != nil || i.ControlPlane.validateMigration(b.binding.MigrationVersion) != nil || (requireSetupToken && i.Runtime.validate() != nil) || (!requireSetupToken && i.Runtime.validateForUpgrade() != nil) {
		return ErrAcornFoxUpgradeConflict
	}
	if len(i.DatabaseEnv) != 0 {
		database, err := acornFoxControlPlaneDatabaseName(i.DatabaseEnv)
		if err != nil || !validAcornFoxBoundControlPlaneEnvironment(i.DatabaseEnv, i.ControlPlane, database) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	c := i.Substrate.CandidateReceipt
	if i.Repo.Phase != AcornFoxRepoPreparedFinal || i.Repo.NeedsRecovery || i.Repo.LayoutSHA256 != layout.evidence() || i.Repo.BindingSHA256 != c.BindingSHA256 || c.ReleaseID != b.binding.ReleaseID || c.SourceCommit != b.binding.SourceCommit || i.Repo.SubstrateReceiptSHA256 != sha256Hex(acornFoxUpgradeJSON(i.Substrate)) || i.Live.BindingSHA256 != c.BindingSHA256 || i.Live.LayoutSHA256 != layout.evidence() || i.Live.OwnershipEvidence != "host_uid_gid_verified" || i.Live.SubstrateReceiptSHA256 != i.Repo.SubstrateReceiptSHA256 || i.Live.LiveTreeSHA256 != i.Repo.LiveTreeSHA256 || i.Live.StaticSetSHA256 != i.Repo.StaticSetSHA256 || i.Live.OwnershipPlanSHA256 != i.Repo.OwnershipPlanSHA256 || i.Repo.ActivationSHA256 != sha256Hex(acornFoxUpgradeJSON(i.Activation)) {
		return ErrAcornFoxUpgradeConflict
	}
	entries, e := acornFoxLiveExpectedEntriesForLayout(layout, &PublishedAcornFoxSubstrateV1{receipt: i.Substrate})
	if e != nil {
		return ErrAcornFoxUpgradeConflict
	}
	computed, e := acornFoxLiveMakeReceiptForLayout(layout, i.Repo, &PublishedAcornFoxSubstrateV1{receipt: i.Substrate}, entries)
	if e != nil || !bytes.Equal(acornFoxUpgradeJSON(computed), acornFoxUpgradeJSON(i.Live)) {
		return ErrAcornFoxUpgradeConflict
	}
	a, raw, e := acornFoxRepoActivationForLayout(layout, i.Repo, i.Live, &PublishedAcornFoxSubstrateV1{receipt: i.Substrate})
	if e != nil || a != i.Activation || sha256Hex(raw) != i.Repo.ActivationSHA256 || i.ControlPlane.BindingSHA256 != c.BindingSHA256 || i.ControlPlane.ReleaseID != c.ReleaseID || i.ControlPlane.SourceCommit != c.SourceCommit || i.Runtime.BindingSHA256 != c.BindingSHA256 || i.Runtime.ReleaseID != c.ReleaseID || i.Runtime.SourceCommit != c.SourceCommit {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
func (j acornFoxUpgradeJournal) validate(layout acornFoxInstallLayout) error {
	if j.Retired0039 != nil && j.Retired0039.validate(j, layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	switch j.Phase {
	case "PREPARED", "BLOCKED", "PUBLISHED", "SWITCHED", "UPGRADED", "ROLLING_BACK", "RECOVERY_PREPARED", "ROLLED_BACK":
	case "QUIESCED", "SNAPSHOT_CREATED", "MIGRATED", "VALIDATED":
		if j.CrossSchema == nil {
			return ErrAcornFoxUpgradeConflict
		}
	default:
		return ErrAcornFoxUpgradeConflict
	}
	if j.SchemaVersion != 1 || j.LayoutSHA256 != layout.evidence() || j.Next.validate(layout, true) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if j.CrossSchema == nil {
		if j.Old.validate(layout, false) != nil {
			return ErrAcornFoxUpgradeConflict
		}
	} else if validateAcornFoxPreviousUpgradeImage(j.Old, layout) != nil || j.CrossSchema.validate(j) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	old, e := verifiedAcornFoxUpgradePredecessor(j.Old.Binding, j.Old.Repo.BindingSHA256)
	if e != nil {
		return ErrAcornFoxUpgradeConflict
	}
	next, e := ParseAcornFoxCandidateBindingV1(j.Next.Binding, j.Next.Repo.BindingSHA256)
	if e != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if len(j.Old.Runtime.SetupToken) == 0 && old.binding.MigrationVersion != "0034" {
		return ErrAcornFoxUpgradeConflict
	}
	n := next.binding.NMinusOne
	if n == nil || n.BindingSHA256 != old.digest || verifyAcornFoxPredecessor(j.Old.Binding, next.binding, &NMinusOne{Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit, ReleaseManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256, BundleManifestSHA256: n.BundleManifestSHA256}) != nil || !acornFoxUpgradeVersionAfter(next.binding.Version, old.binding.Version) {
		return ErrAcornFoxUpgradeConflict
	}
	if j.CrossSchema == nil && (j.Old.ControlPlane.MigrationRowsSHA256 != j.Next.ControlPlane.MigrationRowsSHA256 || j.Old.ControlPlane.DatabaseEnvSHA256 != j.Next.ControlPlane.DatabaseEnvSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	rebound, e := acornFoxUpgradeRebind(j.Old.Runtime, next.binding, next.digest, j.Next.Runtime.SetupToken)
	if e != nil || !bytes.Equal(acornFoxUpgradeJSON(rebound), acornFoxUpgradeJSON(j.Next.Runtime)) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
func (j acornFoxUpgradeJournal) receipt() AcornFoxUpgradeReceiptV1 {
	i := j.Next
	if j.Phase == "ROLLED_BACK" || j.Phase == "RECOVERY_PREPARED" {
		i = j.Old
	}
	return AcornFoxUpgradeReceiptV1{1, j.Phase, i.Repo.BindingSHA256, j.Old.Repo.BindingSHA256, i.identity().ReleaseID, i.identity().SourceCommit, j.LayoutSHA256}
}
func acornFoxUpgradeRebind(old acornFoxRuntimeIntent, next AcornFoxCandidateBindingV1, digest string, setupToken []byte) (acornFoxRuntimeIntent, error) {
	bundle, input, e := acornfoxsetup.RebindVersion(old.bundle(), old.Inputs, next.Version)
	if e != nil {
		return acornFoxRuntimeIntent{}, ErrAcornFoxUpgradeConflict
	}
	if acornfoxsetup.ValidateSetupToken(setupToken) != nil || len(old.SetupToken) != 0 && !bytes.Equal(old.SetupToken, setupToken) {
		return acornFoxRuntimeIntent{}, ErrAcornFoxUpgradeConflict
	}
	i := acornFoxRuntimeIntent{SchemaVersion: 1, BindingSHA256: digest, ReleaseID: next.ReleaseID, SourceCommit: next.SourceCommit, Inputs: input, SetupToken: bytes.Clone(setupToken)}
	for _, f := range bundle.Files {
		i.Files = append(i.Files, acornFoxRuntimeFileWire{f.Path, f.Mode, f.Owner, f.Group, f.Data})
	}
	return i, i.validate()
}

type acornFoxUpgrade struct {
	layout              acornFoxInstallLayout
	self                acornFoxSelfVerifier
	ownership           acornFoxOwnershipEdge
	services            acornFoxUpgradeServices
	database            acornFoxCrossSchemaDatabaseFactory
	activeDatabase      acornFoxCrossSchemaDatabase
	candidateHealth     func(context.Context, *TaskAcornFoxRepoStore, acornFoxUpgradeImage) error
	hostProvisionSHA256 string
	random              io.Reader
	step                func(string) error
}

func newAcornFoxUpgrade(layout acornFoxInstallLayout) *acornFoxUpgrade {
	return &acornFoxUpgrade{layout: layout, self: newAcornFoxProductionSelfVerifier(), ownership: newAcornFoxRealOwnershipEdge(), services: acornFoxRealUpgradeServices{}, database: func(layout acornFoxInstallLayout, transactionID, oldBinding, nextBinding string, activeEnv []byte, migrations acornFoxControlPlaneMigrations, sourceDataVersion int) (acornFoxCrossSchemaDatabase, error) {
		return newProductionAcornFoxUpgradeDatabase(layout, transactionID, oldBinding, nextBinding, activeEnv, migrations, sourceDataVersion)
	}, candidateHealth: validateProductionAcornFoxCandidateHealth, random: rand.Reader, step: func(string) error { return nil }}
}
func UpgradeAcornFoxHostV1(ctx context.Context, request AcornFoxUpgradeRequestV1) (AcornFoxUpgradeReceiptV1, error) {
	if acornFoxUpgradeInitialHost() != nil {
		return AcornFoxUpgradeReceiptV1{}, ErrAcornFoxUpgradeConflict
	}
	layout, hostProvision, e := prepareProductionAcornFoxUpgradeLayout(ctx, request)
	if e != nil {
		return AcornFoxUpgradeReceiptV1{}, e
	}
	upgrade := newAcornFoxUpgrade(layout)
	upgrade.hostProvisionSHA256 = hostProvision
	return upgrade.upgrade(ctx, request)
}

func prepareProductionAcornFoxUpgradeLayout(ctx context.Context, request AcornFoxUpgradeRequestV1) (acornFoxInstallLayout, string, error) {
	if ctx == nil || ctx.Err() != nil || !validSHA(request.CurrentBindingSHA256) {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	state, err := os.OpenRoot("/var/lib/acornfox/install")
	if err != nil {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	oldRaw, err := readAcornFoxLegacyEvidence(state, "bindings/"+request.CurrentBindingSHA256+".json", acornFoxInstallPrincipal{}, acornFoxCandidateBindingMaxBytes)
	_ = state.Close()
	if err != nil {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	set, err := loadAcornFoxCandidateSet(AcornFoxCandidateSetRequestV1{Directory: request.Directory, BindingSHA256: request.BindingSHA256, SelfSHA256: request.SelfSHA256}, oldRaw, newAcornFoxProductionSelfVerifier())
	if err != nil {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	defer set.Close()
	old, err := verifiedAcornFoxUpgradePredecessor(oldRaw, request.CurrentBindingSHA256)
	if err != nil {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	if old.binding.MigrationVersion != AcornFoxLegacyPredecessorMigration {
		layout, err := newProductionAcornFoxLayout()
		if err != nil {
			return acornFoxInstallLayout{}, "", err
		}
		if old.binding.MigrationVersion == acornFoxRecentPredecessorMigration && AcornFoxV1MigrationVersion != acornFoxRecentPredecessorMigration {
			evidence, evidenceErr := acornFoxRecent0039HostEvidenceSHA(old.digest, set.binding.digest, layout)
			return layout, evidence, evidenceErr
		}
		return layout, "", nil
	}
	layout, evidence, err := ensureAcornFoxLegacyUpgradeHost(ctx, oldRaw, request.CurrentBindingSHA256, set.binding)
	if err != nil {
		return acornFoxInstallLayout{}, "", err
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
	}
	return layout, sha256Hex(raw), nil
}
func RecoverAcornFoxUpgradeV1(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxUpgradeReceiptV1, bool, error) {
	if acornFoxUpgradeInitialHost() != nil {
		return AcornFoxUpgradeReceiptV1{}, false, ErrAcornFoxUpgradeConflict
	}
	layout, provisionSHA, e := productionAcornFoxRecoveryLayout(ctx)
	if e != nil {
		return AcornFoxUpgradeReceiptV1{}, false, e
	}
	upgrade := newAcornFoxUpgrade(layout)
	upgrade.hostProvisionSHA256 = provisionSHA
	return upgrade.recover(ctx, expected)
}

func productionAcornFoxRecoveryLayout(ctx context.Context) (acornFoxInstallLayout, string, error) {
	layout, evidence, handled, err := recoverAcornFoxLegacyUpgradeHost(ctx)
	if err != nil {
		return acornFoxInstallLayout{}, "", err
	}
	if handled {
		raw, marshalErr := json.Marshal(evidence)
		if marshalErr != nil {
			return acornFoxInstallLayout{}, "", ErrAcornFoxUpgradeConflict
		}
		return layout, sha256Hex(raw), nil
	}
	layout, err = newProductionAcornFoxLayout()
	return layout, "", err
}
func (u *acornFoxUpgrade) openStore() (*TaskAcornFoxRepoStore, error) {
	s, e := newAcornFoxRepoStoreForLayout(u.layout)
	if e == nil {
		s.ownership = u.ownership
	}
	return s, e
}

func (u *acornFoxUpgrade) upgrade(ctx context.Context, request AcornFoxUpgradeRequestV1) (AcornFoxUpgradeReceiptV1, error) {
	var empty AcornFoxUpgradeReceiptV1
	if ctx == nil || ctx.Err() != nil || !validSHA(request.CurrentBindingSHA256) || u.layout.validate() != nil {
		return empty, ErrAcornFoxUpgradeConflict
	}
	s, e := u.openStore()
	if e != nil {
		return empty, e
	}
	defer s.Close()
	// Pure descriptor reads and the candidate/self verifier precede lock creation,
	// journals, artifact staging, service calls, and all other writes.
	oldRaw, e := u.read(s.root, "bindings/"+request.CurrentBindingSHA256+".json", 0600, acornFoxCandidateBindingMaxBytes)
	if e != nil {
		return empty, ErrAcornFoxUpgradeConflict
	}
	set, e := loadAcornFoxCandidateSet(AcornFoxCandidateSetRequestV1{request.Directory, request.BindingSHA256, request.SelfSHA256}, oldRaw, u.self)
	if e != nil {
		return empty, ErrAcornFoxUpgradeConflict
	}
	defer set.Close()
	old, e := verifiedAcornFoxUpgradePredecessor(oldRaw, request.CurrentBindingSHA256)
	if e != nil || !acornFoxUpgradeVersionAfter(set.binding.binding.Version, old.binding.Version) {
		return empty, ErrAcornFoxUpgradeConflict
	}
	oldManifest, e := u.read(s.hostRoot, "opt/acornfox/releases/"+old.binding.ReleaseID+"/manifest.json", 0644, acornFoxManifestMaxBytes)
	if e != nil || sha256Hex(oldManifest) != old.binding.ManifestSHA256 {
		return empty, ErrAcornFoxUpgradeConflict
	}
	crossSchema := false
	if acornFoxUpgradeSameMigrations(oldManifest, set.manifestRaw) != nil {
		_, _, crossSchema = acornFoxCrossSchemaManifests(oldManifest, set.manifestRaw, old.binding, set.binding.binding)
		if !crossSchema || !validSHA(u.hostProvisionSHA256) {
			return empty, ErrAcornFoxUpgradeConflict
		}
	}
	lock, e := s.Acquire(ctx)
	if e != nil {
		return empty, e
	}
	defer lock.Release()
	var retired *acornFoxRetired0039
	if j, e := u.load(s); e == nil {
		if j.Next.Repo.BindingSHA256 == request.BindingSHA256 && (j.Phase == "UPGRADED" || j.Phase == "ROLLED_BACK") {
			if e := u.verifyImage(s, j, j.Phase == "UPGRADED"); e != nil {
				return empty, e
			}
			if j.Phase == "ROLLED_BACK" {
				if j.CrossSchema != nil {
					return j.receipt(), ErrAcornFoxUpgradeRolledBack
				}
				if request.CurrentBindingSHA256 != j.Old.Repo.BindingSHA256 {
					return empty, ErrAcornFoxUpgradeConflict
				}
				j.Phase = "PREPARED"
				if e := u.save(s, j, false); e != nil {
					return empty, e
				}
				return u.attempt(ctx, s, &j)
			}
			return j.receipt(), nil
		}
		if crossSchema && old.binding.MigrationVersion == acornFoxRecentPredecessorMigration && j.Next.Repo.BindingSHA256 == request.CurrentBindingSHA256 && j.CrossSchema == nil && j.Retired0039 == nil && j.Phase == "UPGRADED" {
			if e := u.verifyImage(s, j, true); e != nil {
				return empty, e
			}
			raw := acornFoxUpgradeJSON(j)
			retired = &acornFoxRetired0039{JournalSHA256: sha256Hex(raw), Journal: raw}
		} else {
			if j.Phase == "UPGRADED" || j.Phase == "ROLLED_BACK" {
				return empty, ErrAcornFoxUpgradeRetentionFull
			}
			return empty, ErrAcornFoxUpgradeUnknown
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return empty, e
	}
	prior, e := u.capture(ctx, s, oldRaw)
	if e != nil {
		return empty, e
	}
	if prior.Repo.BindingSHA256 != request.CurrentBindingSHA256 {
		return empty, ErrAcornFoxUpgradeConflict
	}
	piEnabled, e := u.capturePIEnabled(ctx, s, old.binding.MigrationVersion)
	if e != nil {
		return empty, e
	}
	var assistant *acornFoxUpgradeAssistantConfig
	if crossSchema && old.binding.MigrationVersion == acornFoxRecentPredecessorMigration {
		assistant, e = captureAcornFoxUpgradeAssistantConfig(s)
		if e != nil {
			return empty, e
		}
	}
	nextSub, e := u.stage(ctx, s, set)
	if e != nil {
		return empty, e
	}
	defer nextSub.Close()
	var databasePrivate *acornFoxUpgradeDatabasePrivate
	var migrations acornFoxControlPlaneMigrations
	if crossSchema {
		if u.database == nil || len(prior.DatabaseEnv) == 0 {
			return empty, ErrAcornFoxUpgradeConflict
		}
		migrations, e = loadAcornFoxUpgradeMigrations(nextSub, set.bindingSHA256)
		if e != nil {
			return empty, e
		}
		transactionID := "acornfox-layout-" + set.bindingSHA256[:12]
		sourceDataVersion, sourceOK := acornFoxCrossSchemaSourceDataVersion(prior.ControlPlane.MigrationVersion)
		if !sourceOK {
			return empty, ErrAcornFoxUpgradeConflict
		}
		database, openErr := u.database(u.layout, transactionID, prior.Repo.BindingSHA256, set.bindingSHA256, prior.DatabaseEnv, migrations, sourceDataVersion)
		if openErr != nil || database == nil {
			return empty, ErrAcornFoxUpgradeUnknown
		}
		defer database.Close()
		u.activeDatabase = database
		planned, planErr := database.Plan()
		prefix, prefixErr := database.InspectPrefix(ctx)
		if planErr != nil || prefixErr != nil || !sameAcornFoxUpgradeDatabaseIdentity(planned.Evidence, prefix) {
			return empty, ErrAcornFoxUpgradeConflict
		}
		planned.Evidence = prefix
		databasePrivate = &planned
	}
	next, e := u.nextImage(prior, set, nextSub, databasePrivate, migrations)
	if e != nil {
		return empty, e
	}
	j := acornFoxUpgradeJournal{SchemaVersion: 1, Phase: "PREPARED", LayoutSHA256: u.layout.evidence(), PIEnabled: piEnabled, Retired0039: retired, Old: prior, Next: next}
	if databasePrivate != nil {
		j.CrossSchema = &acornFoxCrossSchemaUpgradeV1{SchemaVersion: 1, HostProvisionSHA256: u.hostProvisionSHA256, OldMigrationVersion: prior.ControlPlane.MigrationVersion, NextMigrationVersion: AcornFoxV1MigrationVersion, TargetRowsSHA256: acornFoxMigrationRowsSHA256(migrations.rows), Database: databasePrivate.Evidence, Assistant: assistant}
	}
	if j.validate(u.layout) != nil {
		return empty, ErrAcornFoxUpgradeConflict
	}
	if e = u.save(s, j, true); e != nil {
		return empty, e
	}
	return u.attempt(ctx, s, &j)
}
func (u *acornFoxUpgrade) attempt(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) (AcornFoxUpgradeReceiptV1, error) {
	var empty AcornFoxUpgradeReceiptV1
	if e := u.step("prepared"); e != nil {
		return empty, ErrAcornFoxUpgradeUnknown
	}
	e := u.forward(ctx, s, j)
	if e == nil {
		return j.receipt(), nil
	}
	if errors.Is(e, errAcornFoxUpgradeInjectedCrash) {
		return empty, ErrAcornFoxUpgradeUnknown
	}
	if recovery := u.rollback(context.WithoutCancel(ctx), s, j); recovery != nil {
		return empty, ErrAcornFoxUpgradeUnknown
	}
	return j.receipt(), errors.Join(ErrAcornFoxUpgradeRolledBack, e)
}

var errAcornFoxUpgradeInjectedCrash = errors.New("AcornFox injected upgrade crash")

func (u *acornFoxUpgrade) fault(name string) error {
	if u.step(name) != nil {
		return errAcornFoxUpgradeInjectedCrash
	}
	return nil
}
func (u *acornFoxUpgrade) recover(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxUpgradeReceiptV1, bool, error) {
	return u.recoverMode(ctx, expected, false)
}
func PrepareAcornFoxUpgradeRecoveryV1(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxUpgradeReceiptV1, bool, error) {
	if acornFoxUpgradeInitialHost() != nil {
		return AcornFoxUpgradeReceiptV1{}, false, ErrAcornFoxUpgradeConflict
	}
	layout, provisionSHA, e := productionAcornFoxRecoveryLayout(ctx)
	if e != nil {
		return AcornFoxUpgradeReceiptV1{}, false, e
	}
	upgrade := newAcornFoxUpgrade(layout)
	upgrade.hostProvisionSHA256 = provisionSHA
	return upgrade.recoverMode(ctx, expected, true)
}
func FinalizeAcornFoxUpgradeRecoveryV1(ctx context.Context, expected AcornFoxBuildIdentityV1) (AcornFoxUpgradeReceiptV1, bool, error) {
	return RecoverAcornFoxUpgradeV1(ctx, expected)
}
func (u *acornFoxUpgrade) recoverMode(ctx context.Context, expected AcornFoxBuildIdentityV1, prepareOnly bool) (AcornFoxUpgradeReceiptV1, bool, error) {
	var empty AcornFoxUpgradeReceiptV1
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil {
		return empty, false, ErrAcornFoxUpgradeConflict
	}
	s, e := u.openStore()
	if e != nil {
		return empty, false, e
	}
	defer s.Close()
	j, e := u.load(s)
	if errors.Is(e, os.ErrNotExist) {
		return empty, false, nil
	}
	if e != nil {
		return empty, true, e
	}
	if j.CrossSchema != nil {
		hostEvidence := u.hostProvisionSHA256
		if j.CrossSchema.OldMigrationVersion == acornFoxRecentPredecessorMigration {
			hostEvidence, e = acornFoxRecent0039HostEvidenceSHA(j.Old.Repo.BindingSHA256, j.Next.Repo.BindingSHA256, u.layout)
		}
		if e != nil || j.CrossSchema.HostProvisionSHA256 != hostEvidence {
			return empty, true, ErrAcornFoxUpgradeConflict
		}
	}
	image := j.Next
	if expected == j.Old.identity() {
		image = j.Old
	} else if expected != j.Next.identity() {
		return empty, true, ErrAcornFoxUpgradeConflict
	}
	// Self is checked once, before replacing the helper inode. An old-result
	// rollback is valid even when this invocation started from the next helper.
	manifest, e := u.imageManifest(s, j, image)
	if e != nil || u.self.verify(image.Substrate.UpgradeHelperSHA256, manifest) != nil {
		return empty, true, ErrAcornFoxUpgradeConflict
	}
	lock, e := s.Acquire(ctx)
	if e != nil {
		return empty, true, e
	}
	defer lock.Release()
	latest, e := u.load(s)
	if e != nil || !bytes.Equal(acornFoxUpgradeJSON(j), acornFoxUpgradeJSON(latest)) {
		return empty, true, ErrAcornFoxUpgradeConflict
	}
	if j.Phase == "UPGRADED" || j.Phase == "ROLLED_BACK" {
		if e := u.verifyImage(s, j, j.Phase == "UPGRADED"); e != nil {
			return empty, true, e
		}
		return j.receipt(), true, nil
	}
	if prepareOnly && j.CrossSchema != nil && j.Phase == "RECOVERY_PREPARED" {
		if e := u.verifyImage(s, j, false); e != nil {
			return empty, true, e
		}
		return j.receipt(), true, nil
	}
	if prepareOnly {
		e = u.restore(ctx, s, &j)
		if e == nil {
			e = u.phase(s, &j, "RECOVERY_PREPARED")
		}
	} else {
		e = u.rollback(ctx, s, &j)
	}
	if e != nil {
		return empty, true, ErrAcornFoxUpgradeUnknown
	}
	return j.receipt(), true, nil
}
func acornFoxUpgradeSameMigrations(oldRaw, nextRaw []byte) error {
	var old, next Manifest
	if strictCanonicalJSON(oldRaw, &old, "old manifest") != nil || strictCanonicalJSON(nextRaw, &next, "next manifest") != nil || old.MigrationVersion != AcornFoxV1MigrationVersion || next.MigrationVersion != AcornFoxV1MigrationVersion {
		return ErrAcornFoxUpgradeConflict
	}
	known := map[string]FileDigest{}
	for _, f := range old.Files {
		if strings.HasPrefix(f.Path, "migrations/") {
			known[f.Path] = f
		}
	}
	count := 0
	for _, f := range next.Files {
		if strings.HasPrefix(f.Path, "migrations/") {
			if known[f.Path] != f {
				return ErrAcornFoxUpgradeConflict
			}
			count++
		}
	}
	if count == 0 || count != len(known) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
func acornFoxUpgradeInitialHost() error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return ErrAcornFoxUpgradeConflict
	}
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || strings.Join(strings.Fields(string(raw)), " ") != "0 0 4294967295" {
		return ErrAcornFoxUpgradeConflict
	}
	for _, name := range []string{"user", "mnt", "net", "pid"} {
		a, e := os.Stat("/proc/self/ns/" + name)
		b, f := os.Stat("/proc/1/ns/" + name)
		if e != nil || f != nil || !os.SameFile(a, b) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	root, e := os.Stat("/")
	init, e2 := os.Stat("/proc/1/root")
	if e != nil || e2 != nil || !os.SameFile(root, init) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

// Version precedence follows SemVer, ignoring build metadata. Numeric fields
// compare by length, avoiding overflow for valid but unusually long versions.
func acornFoxUpgradeVersionAfter(next, old string) bool {
	parse := func(s string) ([]string, []string, bool) {
		if ParseVersion(s) != nil || strings.TrimSpace(s) != s {
			return nil, nil, false
		}
		parts := strings.SplitN(s, "+", 2)
		for _, section := range parts[1:] {
			for _, id := range strings.Split(section, ".") {
				if id == "" {
					return nil, nil, false
				}
			}
		}
		s = parts[0]
		p := strings.SplitN(s, "-", 2)
		base := strings.Split(p[0], ".")
		if len(base) != 3 {
			return nil, nil, false
		}
		var pre []string
		if len(p) == 2 {
			pre = strings.Split(p[1], ".")
			for _, id := range pre {
				if id == "" {
					return nil, nil, false
				}
				allDigits := true
				for _, r := range id {
					if r < '0' || r > '9' {
						allDigits = false
					}
				}
				if allDigits && len(id) > 1 && id[0] == '0' {
					return nil, nil, false
				}
			}
		}
		return base, pre, true
	}
	a, ap, ok := parse(next)
	b, bp, ok2 := parse(old)
	if !ok || !ok2 {
		return false
	}
	numeric := func(s string) bool {
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return s != ""
	}
	cmp := func(x, y string) int {
		if len(x) < len(y) {
			return -1
		}
		if len(x) > len(y) {
			return 1
		}
		return strings.Compare(x, y)
	}
	for n := range a {
		if c := cmp(a[n], b[n]); c != 0 {
			return c > 0
		}
	}
	if len(ap) == 0 || len(bp) == 0 {
		return len(ap) == 0 && len(bp) > 0
	}
	for n := 0; n < len(ap) && n < len(bp); n++ {
		x, y := ap[n], bp[n]
		if x == y {
			continue
		}
		xn, yn := numeric(x), numeric(y)
		if xn && yn {
			return cmp(x, y) > 0
		}
		if xn != yn {
			return !xn
		}
		return x > y
	}
	return len(ap) > len(bp)
}

// Read never follows a final symlink and verifies the descriptor against the
// named inode before and after reading. It never includes file bytes in errors.
func (u *acornFoxUpgrade) read(root *os.Root, path string, mode os.FileMode, max int) ([]byte, error) {
	return u.readOwnership(root, path, mode, max, nil)
}
func (u *acornFoxUpgrade) readPrincipal(root *os.Root, path string, mode os.FileMode, max int, principal acornFoxInstallPrincipal) ([]byte, error) {
	if principal == (acornFoxInstallPrincipal{}) {
		return u.read(root, path, mode, max)
	}
	return u.readOwnership(root, path, mode, max, &principal)
}
func (u *acornFoxUpgrade) readOwnership(root *os.Root, path string, mode os.FileMode, max int, principal *acornFoxInstallPrincipal) ([]byte, error) {
	info, e := root.Lstat(path)
	if e != nil {
		return nil, e
	}
	ownerOK := verifyOwner(info, u.layout.stateOwner.uid, u.layout.stateOwner.gid) == nil
	if principal != nil {
		owner, ok := u.ownership.observe(info)
		ownerOK = ok && owner == *principal
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || acornFoxRepoNlink(info) != 1 || info.Size() > int64(max) || !ownerOK {
		return nil, ErrAcornFoxUpgradeConflict
	}
	f, e := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	after, e2 := root.Lstat(path)
	if e != nil || e2 != nil || len(raw) > max || int64(len(raw)) != info.Size() || !os.SameFile(info, after) {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return raw, nil
}
func (u *acornFoxUpgrade) load(s *TaskAcornFoxRepoStore) (acornFoxUpgradeJournal, error) {
	var j acornFoxUpgradeJournal
	raw, e := u.read(s.root, acornFoxUpgradeJournalPath, 0600, acornFoxUpgradeMaxJournal)
	if e != nil {
		return j, e
	}
	if strictCanonicalJSON(raw, &j, "upgrade journal") != nil {
		return j, ErrAcornFoxUpgradeConflict
	}
	if j.validate(u.layout) != nil {
		env, err := u.read(s.root, acornFoxControlPlaneStateEnv, 0600, 16384)
		if err != nil || validateAcornFoxCompleted0039(j, u.layout, env) != nil {
			return j, ErrAcornFoxUpgradeConflict
		}
	}
	return j, nil
}
func (u *acornFoxUpgrade) save(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, initial bool) error {
	if !s.ownsLock() || j.validate(u.layout) != nil || len(acornFoxUpgradeJSON(j)) > acornFoxUpgradeMaxJournal {
		return ErrAcornFoxUpgradeConflict
	}
	if e := u.ensureDirectory(s, s.root, acornFoxUpgradeDirectory, 0700, acornFoxInstallPrincipal{u.layout.stateOwner.uid, u.layout.stateOwner.gid}); e != nil {
		return e
	}
	old, e := u.read(s.root, acornFoxUpgradeJournalPath, 0600, acornFoxUpgradeMaxJournal)
	retiring := initial && j.Retired0039 != nil
	if retiring {
		if e != nil || !bytes.Equal(old, j.Retired0039.Journal) {
			return ErrAcornFoxUpgradeConflict
		}
		initial = false
	}
	if initial && !errors.Is(e, os.ErrNotExist) || !initial && e != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if e != nil {
		old = nil
	}
	if retiring {
		// Until the atomic journal replacement, the completed 0039 upgrade
		// directory must remain an exact closed pair, including after a crash.
		temp := ".acornfox-retired-0039-" + j.Retired0039.JournalSHA256
		return u.atomicFileOwnedAtTemp(s, s.root, acornFoxUpgradeJournalPath, old, acornFoxUpgradeJSON(j), 0600, acornFoxInstallPrincipal{}, temp)
	}
	return u.atomicFile(s, s.root, acornFoxUpgradeJournalPath, old, acornFoxUpgradeJSON(j), 0600)
}
