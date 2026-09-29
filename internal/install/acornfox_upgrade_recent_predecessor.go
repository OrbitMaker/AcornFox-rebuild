package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/pibundle"
)

// acornFoxRecentPredecessorMigration freezes the last seven-role release that
// predates the 0040 fix-candidate schema. It is authenticated only as an
// installed predecessor; new candidates still use the current package policy.
const acornFoxRecentPredecessorMigration = "0039"

func acornFoxRecent0039HostEvidenceSHA(oldSHA256, nextSHA256 string, layout acornFoxInstallLayout) (string, error) {
	if !validSHA(oldSHA256) || !validSHA(nextSHA256) || oldSHA256 == nextSHA256 || layout.validate() != nil || !validSHA(layout.evidence()) {
		return "", ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(struct {
		SchemaVersion int    `json:"schema_version"`
		State         string `json:"state"`
		OldBinding    string `json:"old_binding_sha256"`
		NextBinding   string `json:"next_binding_sha256"`
		Layout        string `json:"layout_sha256"`
	}{1, "RECENT_0039_HOST_VERIFIED", oldSHA256, nextSHA256, layout.evidence()})
	if err != nil {
		return "", ErrAcornFoxUpgradeConflict
	}
	return sha256Hex(raw), nil
}

var acornFoxRecent0039Binaries = []string{
	"bin/acornfox-server", "bin/acornfox-agent", "bin/acornfox-static-server",
	"bin/acornfox-secretctl", "bin/acornfox-security-probe", "bin/acornfox-imagegc",
	"bin/acornfox", "bin/acornfox-admin", "bin/acornfox-upgrade", "bin/acornfox-healthcheck",
	"bin/acornfox-pi-worker", "bin/buildkitd", "bin/buildctl", "bin/buildkit-runc", "bin/rootlesskit", "bin/caddy",
}

var acornFoxRecent0039Units = []string{
	"systemd/acornfox-build-network.service", "systemd/acornfox-runtime-network.service",
	"systemd/acornfox-server.service", "systemd/acornfox-agent.service", "systemd/acornfox-buildkit.service",
	"systemd/acornfox-caddy.service", "systemd/acornfox-edge.service", "systemd/acornfox-healthcheck.service",
	"systemd/acornfox-healthcheck.timer", "systemd/acornfox-upgrade-recover.service",
	"systemd/acornfox-upgrade-safe.target", "systemd/acornfox-upgrade-finalize.service",
	"systemd/acornfox-pi-worker.service", "systemd/acornfox-edge.service.d/10-upgrade-marker.conf",
}

var acornFoxRecent0039Scripts = []string{
	"scripts/acornfox/install-host.sh", "scripts/acornfox/install.sh", "scripts/acornfox/upgrade.sh",
	"scripts/acornfox/control-plane-migrate.sh", "scripts/acornfox/host-preflight.sh",
}

var acornFoxRecent0039Migrations = []string{
	"0001_foundation.sql", "0002_invariants.sql", "0003_audit_chain_serialization.sql", "0004_repository_runtime.sql",
	"0005_observability.sql", "0006_controller_worker.sql", "0007_compatibility_contract.sql", "0008_m1_delivery.sql",
	"0009_m1_runtime_observation.sql", "0010_m1_publish_idempotency.sql", "0011_m1_source_reupload.sql",
	"0012_m2_service_groups.sql", "0013_m3_access_routes.sql", "0014_m4_operations_notifications.sql",
	"0015_m4_rollout_coordinator.sql", "0016_m4_staged_route_sets.sql", "0017_m4_independent_runtime_facts.sql",
	"0018_m4_atomic_rollout_plan.sql", "0019_m4_durable_candidate_cleanup.sql", "0020_m5_usage.sql",
	"0021_m6_controlled_ai.sql", "0022_admin_auth.sql", "0023_source_uploads.sql", "0024_dns_change_ledger.sql",
	"0025_acornfox_build_plan_binding.sql", "0026_acornfox_build_network_policy.sql", "0027_acornfox_probe_observations.sql",
	"0028_acornfox_log_metadata.sql", "0029_acornfox_log_provenance.sql", "0030_dns_change_provider_neutral.sql",
	"0031_acornfox_public_access.sql", "0032_dns_change_execution.sql", "0033_acornfox_discovery_task_lookup.sql",
	"0034_artifacts_per_build.sql", "0035_acornfox_source_metadata.sql", "0036_acornfox_source_updates.sql",
	"0037_acornfox_assistant.sql", "0038_acornfox_assistant_actions.sql", "0039_acornfox_access_observations.sql",
}

func acornFoxRecent0039RequiredFiles() []AcornFoxV1PackageFile {
	piFiles, _ := pibundle.Entries()
	files := make([]AcornFoxV1PackageFile, 0, len(acornFoxRecent0039Binaries)+len(acornFoxRecent0039Units)+len(acornFoxRecent0039Scripts)+len(acornFoxRecent0039Migrations)+len(piFiles)+18)
	for _, path := range acornFoxRecent0039Binaries {
		files = append(files, AcornFoxV1PackageFile{Path: path, Mode: 0o755})
	}
	for _, path := range acornFoxRecent0039Units {
		files = append(files, AcornFoxV1PackageFile{Path: path, Mode: 0o644})
	}
	for _, path := range acornFoxRecent0039Scripts {
		files = append(files, AcornFoxV1PackageFile{Path: path, Mode: 0o755})
	}
	for _, name := range acornFoxRecent0039Migrations {
		files = append(files, AcornFoxV1PackageFile{Path: "migrations/control-plane/" + name, Mode: 0o640})
	}
	for _, file := range piFiles {
		files = append(files, AcornFoxV1PackageFile{Path: file.Path, Mode: file.Mode})
	}
	return append(files,
		AcornFoxV1PackageFile{"pi/extensions/acornfox-tools.ts", 0o644},
		AcornFoxV1PackageFile{"pi/UPSTREAM-ASSETS.json", 0o644},
		AcornFoxV1PackageFile{"config/acornfox-build-network-policy-v1.json", 0o644},
		AcornFoxV1PackageFile{"config/acornfox-build-resolv.conf", 0o644},
		AcornFoxV1PackageFile{"config/acornfox-rootlesskit.apparmor", 0o644},
		AcornFoxV1PackageFile{"config/acornfox-buildkitd.toml", 0o644},
		AcornFoxV1PackageFile{"caddy/acornfox.Caddyfile.example", 0o644},
		AcornFoxV1PackageFile{"caddy/acornfox-edge.env.example", 0o640},
		AcornFoxV1PackageFile{"caddy/acornfox-edge.Caddyfile.example", 0o644},
		AcornFoxV1PackageFile{"api/openapi/acornfox.yaml", 0o644},
		AcornFoxV1PackageFile{"web/dist/index.html", 0o644},
		AcornFoxV1PackageFile{"web/dist/build-metadata.json", 0o644},
		AcornFoxV1PackageFile{"docs/licenses/licenses-manifest.json", 0o644},
		AcornFoxV1PackageFile{"docs/licenses/README.md", 0o644},
		AcornFoxV1PackageFile{"docs/licenses/THIRD_PARTY_NOTICES.md", 0o644},
		AcornFoxV1PackageFile{"docs/licenses/AGPL-3.0-only.txt", 0o644},
		AcornFoxV1PackageFile{"sbom.spdx.json", 0o644},
		AcornFoxV1PackageFile{"source-manifest.sha256", 0o644},
	)
}

func validateAcornFoxRecent0039Binding(b AcornFoxCandidateBindingV1) error {
	if b.SchemaVersion != AcornFoxCandidateBindingV1Schema || b.Product != AcornFoxV1Product || b.ReleaseID != "release-"+b.Version || ParseVersion(b.Version) != nil || strings.TrimSpace(b.Version) != b.Version || !validAcornFoxGitHubRepository(b.SourceRepository) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(b.SourceCommit) || b.Architecture != AcornFoxV1Architecture || b.MigrationVersion != acornFoxRecentPredecessorMigration || !validSHA(b.ManifestSHA256) || !validSHA(b.ArchiveSHA256) || !validSHA(b.BundleManifestSHA256) {
		return errors.New("AcornFox 0039 predecessor binding is invalid")
	}
	if b.NMinusOne != nil && validateAcornFoxRecent0039NMinusOne(*b.NMinusOne) != nil {
		return errors.New("AcornFox 0039 predecessor n_minus_one is invalid")
	}
	return nil
}

func validateAcornFoxRecent0039NMinusOne(n AcornFoxNMinusOneV1) error {
	if ParseVersion(n.Version) != nil || strings.TrimSpace(n.Version) != n.Version || (n.MigrationVersion != AcornFoxLegacyPredecessorMigration && n.MigrationVersion != acornFoxRecentPredecessorMigration) || ValidateMigrationVersion(n.MigrationVersion) != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(n.SourceCommit) || !validSHA(n.ReleaseManifestSHA256) || !validSHA(n.ArchiveSHA256) || !validSHA(n.BundleManifestSHA256) || !validSHA(n.BindingSHA256) {
		return errors.New("AcornFox 0039 predecessor n_minus_one is invalid")
	}
	return nil
}

func validateAcornFoxRecent0039Manifest(manifest Manifest, binding AcornFoxCandidateBindingV1) error {
	if _, err := pibundle.Entries(); err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if validateAcornFoxRecent0039Binding(binding) != nil || manifest.SchemaVersion != ManifestSchemaVersion || manifest.Product != AcornFoxV1Product || manifest.Version != binding.Version || manifest.ReleaseID != binding.ReleaseID || manifest.Architecture != AcornFoxV1Architecture || manifest.MigrationVersion != acornFoxRecentPredecessorMigration || manifest.SourceCommit != binding.SourceCommit || manifest.Protocol != AgentProtocolVersion || manifest.ConfigDir != AcornFoxV1ConfigDir || manifest.DataDir != AcornFoxV1DataDir || manifest.Compatibility.MinDataVersion != 39 || manifest.Compatibility.MaxDataVersion != 39 || manifest.Compatibility.MinAgentProtocol != PreviousAgentProtocol || manifest.Compatibility.MaxAgentProtocol != AgentProtocolVersion || !sameAcornFoxNMinusOne(manifest.NMinusOne, binding.NMinusOne) || validateManifestIdentityStructure(manifest) != nil || validateManifestContentStructure(manifest) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	return validateAcornFoxPackageInventory(manifest.Files, acornFoxRecent0039RequiredFiles())
}

func validateAcornFoxPackageInventory(files []FileDigest, required []AcornFoxV1PackageFile) error {
	expected := make(map[string]uint32, len(required))
	for _, file := range required {
		expected[file.Path] = file.Mode
	}
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		mode, ok := expected[file.Path]
		if !ok && strings.HasPrefix(file.Path, "web/dist/assets/") {
			ok = validAcornFoxV1WebAsset(file.Path) && file.Mode == 0o644
			mode = file.Mode
		}
		if !ok || mode != file.Mode || seen[file.Path] {
			return ErrAcornFoxUpgradeConflict
		}
		seen[file.Path] = true
	}
	for path := range expected {
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}

func validateAcornFoxRecent0039StageReceipt(candidate AcornFoxStageReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	predecessor := ""
	if old.NMinusOne != nil {
		predecessor = old.NMinusOne.BindingSHA256
	}
	if validateAcornFoxRecent0039Binding(old) != nil || !validSHA(oldSHA256) || candidate.SchemaVersion != 1 || candidate.Product != AcornFoxV1Product || candidate.Version != old.Version || candidate.ReleaseID != old.ReleaseID || candidate.ManifestSHA256 != old.ManifestSHA256 || candidate.ArchiveSHA256 != old.ArchiveSHA256 || candidate.BindingSHA256 != oldSHA256 || candidate.BundleManifestSHA256 != old.BundleManifestSHA256 || candidate.SourceCommit != old.SourceCommit || candidate.Architecture != AcornFoxV1Architecture || candidate.MigrationVersion != acornFoxRecentPredecessorMigration || candidate.PredecessorBindingSHA256 != predecessor || candidate.FileCount < 1 || !validSHA(candidate.TreeSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func validateAcornFoxRecent0039SubstrateReceipt(receipt InactiveSubstrateReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	const historicalMaxMembers = 512
	const historicalMaxEntries = historicalMaxMembers + (historicalMaxMembers-1)*((acornFoxUstarPathMaxBytes-1)/2) + acornFoxSubstrateFixedEntryMax
	if receipt.SchemaVersion != InactiveSubstrateReceiptV1Schema || receipt.State != "inactive_complete" || receipt.LayoutVersion != AcornFoxSubstrateLayoutV1 || validateAcornFoxRecent0039StageReceipt(receipt.CandidateReceipt, old, oldSHA256) != nil || receipt.CandidateReceipt.FileCount+1 > historicalMaxMembers || len(receipt.Entries) == 0 || len(receipt.Entries) > historicalMaxEntries {
		return ErrAcornFoxUpgradeConflict
	}
	for _, digest := range []string{receipt.ReleaseTreeSHA256, receipt.InstalledTreeSHA256, receipt.UpgradeHelperSHA256, receipt.HealthHelperSHA256} {
		if !validSHA(digest) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	if receipt.ReleaseTreeSHA256 != receipt.CandidateReceipt.TreeSHA256 || validateAcornFoxSubstrateInventory(receipt.CandidateReceipt, receipt.Entries, acornFoxRecent0039RequiredFiles(), acornFoxFrozen0040FixedSubstrateEntries(receipt.CandidateReceipt)) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	release, releaseErr := ComputeAcornFoxReleaseTreeSHA256(receipt.CandidateReceipt, receipt.Entries)
	installed, installedErr := ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
	upgrade := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
	health := substrateEntryAt(receipt.Entries, AcornFoxHealthcheckHelperPath(receipt.CandidateReceipt))
	if releaseErr != nil || installedErr != nil || release != receipt.ReleaseTreeSHA256 || installed != receipt.InstalledTreeSHA256 || upgrade == nil || health == nil || upgrade.SHA256 != receipt.UpgradeHelperSHA256 || health.SHA256 != receipt.HealthHelperSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func parseAcornFoxRecent0039SubstrateReceipt(raw []byte, old AcornFoxCandidateBindingV1, oldSHA256 string) (InactiveSubstrateReceiptV1, error) {
	var receipt InactiveSubstrateReceiptV1
	if strictCanonicalJSON(raw, &receipt, "AcornFox 0039 inactive substrate receipt") != nil || validateAcornFoxRecent0039SubstrateReceipt(receipt, old, oldSHA256) != nil {
		return InactiveSubstrateReceiptV1{}, ErrAcornFoxUpgradeConflict
	}
	return receipt, nil
}

func acornFoxRecent0039ExpectedEntries(layout acornFoxInstallLayout, substrate InactiveSubstrateReceiptV1) ([]SubstrateEntry, error) {
	if layout.validate() != nil || substrate.CandidateReceipt.MigrationVersion != acornFoxRecentPredecessorMigration {
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

func validateAcornFoxRecent0039LiveReceiptForLayout(layout acornFoxInstallLayout, substrate InactiveSubstrateReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string, live AcornFoxLiveReceiptV1) error {
	if layout.validate() != nil || validateAcornFoxRecent0039SubstrateReceipt(substrate, old, oldSHA256) != nil || live.Validate() != nil || live.State != "host_live_materialized" {
		return ErrAcornFoxUpgradeConflict
	}
	substrateRaw, err := json.Marshal(substrate)
	if err != nil || live.BindingSHA256 != oldSHA256 || live.SubstrateReceiptSHA256 != sha256Hex(substrateRaw) || live.ReleaseID != old.ReleaseID || live.LayoutSHA256 != layout.evidence() || live.OwnershipEvidence != "host_uid_gid_verified" {
		return ErrAcornFoxUpgradeConflict
	}
	source, err := acornFoxRecent0039ExpectedEntries(layout, substrate)
	if err != nil {
		return err
	}
	want := make([]AcornFoxLiveEntryV1, 0, len(source))
	for _, entry := range source {
		if acornFoxProductionSharedParent(entry.Path) {
			continue
		}
		converted, convertErr := acornFoxLiveEntryForLayout(layout, entry)
		if convertErr != nil {
			return convertErr
		}
		want = append(want, converted)
	}
	wantRaw, err := json.Marshal(want)
	gotRaw, gotErr := json.Marshal(live.Entries)
	if err != nil || gotErr != nil || !bytes.Equal(wantRaw, gotRaw) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func validateAcornFoxRecent0039UpgradeImage(image acornFoxUpgradeImage, layout acornFoxInstallLayout) error {
	binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
	if err != nil || validateAcornFoxRecent0039Binding(binding.binding) != nil || layout.validate() != nil || image.Repo.Validate() != nil || image.Repo.LayoutSHA256 != layout.evidence() || validateAcornFoxRecent0039SubstrateReceipt(image.Substrate, binding.binding, binding.digest) != nil || validateAcornFoxRecent0039LiveReceiptForLayout(layout, image.Substrate, binding.binding, binding.digest, image.Live) != nil || image.Activation.Validate() != nil || image.ControlPlane.validateMigration(acornFoxRecentPredecessorMigration) != nil || image.Runtime.validateExisting(true) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if len(image.DatabaseEnv) == 0 || !validAcornFoxBoundControlPlaneEnvironment(image.DatabaseEnv, image.ControlPlane, acornFoxControlPlaneDatabase) || image.Repo.BindingSHA256 != binding.digest || image.Repo.SubstrateReceiptSHA256 != sha256Hex(acornFoxUpgradeJSON(image.Substrate)) || image.Repo.LiveTreeSHA256 != image.Live.LiveTreeSHA256 || image.Repo.StaticSetSHA256 != image.Live.StaticSetSHA256 || image.Repo.OwnershipPlanSHA256 != image.Live.OwnershipPlanSHA256 || image.Repo.ActivationSHA256 != sha256Hex(acornFoxUpgradeJSON(image.Activation)) {
		return ErrAcornFoxUpgradeConflict
	}
	if image.Activation.Mode != "production_host" || image.Activation.LayoutSHA256 != layout.evidence() || image.Activation.BindingSHA256 != binding.digest || image.Activation.SubstrateReceiptSHA256 != image.Repo.SubstrateReceiptSHA256 || image.Activation.LiveTreeSHA256 != image.Live.LiveTreeSHA256 || image.Activation.StaticSetSHA256 != image.Live.StaticSetSHA256 || image.Activation.OwnershipPlanSHA256 != image.Live.OwnershipPlanSHA256 || image.Activation.ReleaseID != binding.binding.ReleaseID || image.Activation.ReleaseTreeSHA256 != image.Substrate.ReleaseTreeSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	if image.ControlPlane.BindingSHA256 != binding.digest || image.ControlPlane.ReleaseID != binding.binding.ReleaseID || image.ControlPlane.SourceCommit != binding.binding.SourceCommit || image.Runtime.BindingSHA256 != binding.digest || image.Runtime.ReleaseID != binding.binding.ReleaseID || image.Runtime.SourceCommit != binding.binding.SourceCommit {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}
