package install

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/pibundle"
)

var (
	acornFoxFrozen0040Binaries = []string{
		"bin/acornfox-server", "bin/acornfox-agent", "bin/acornfox-static-server",
		"bin/acornfox-secretctl", "bin/acornfox-security-probe", "bin/acornfox-imagegc",
		"bin/acornfox", "bin/acornfox-admin", "bin/acornfox-upgrade", "bin/acornfox-healthcheck",
		"bin/acornfox-pi-worker",
		"bin/buildkitd", "bin/buildctl", "bin/buildkit-runc", "bin/rootlesskit", "bin/caddy",
	}
	acornFoxFrozen0040Units = []string{
		"systemd/acornfox-build-network.service",
		"systemd/acornfox-runtime-network.service",
		"systemd/acornfox-server.service", "systemd/acornfox-agent.service", "systemd/acornfox-buildkit.service",
		"systemd/acornfox-caddy.service", "systemd/acornfox-edge.service", "systemd/acornfox-healthcheck.service",
		"systemd/acornfox-healthcheck.timer", "systemd/acornfox-upgrade-recover.service",
		"systemd/acornfox-upgrade-safe.target", "systemd/acornfox-upgrade-finalize.service",
		"systemd/acornfox-pi-worker.service",
		"systemd/acornfox-edge.service.d/10-upgrade-marker.conf",
	}
)

func acornFoxFrozen0040RequiredFiles() []AcornFoxV1PackageFile {
	piFiles, _ := pibundle.Entries()
	files := make([]AcornFoxV1PackageFile, 0, len(acornFoxFrozen0040Binaries)+len(acornFoxFrozen0040Units)+len(acornFoxFrozen0040Scripts)+len(acornFoxFrozen0040Migrations)+len(piFiles)+20)
	for _, path := range acornFoxFrozen0040Binaries {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, path := range acornFoxFrozen0040Units {
		files = append(files, AcornFoxV1PackageFile{path, 0o644})
	}
	for _, path := range acornFoxFrozen0040Scripts {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, name := range acornFoxFrozen0040Migrations {
		files = append(files, AcornFoxV1PackageFile{"migrations/control-plane/" + name, 0o640})
	}
	for _, file := range piFiles {
		files = append(files, AcornFoxV1PackageFile{file.Path, file.Mode})
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

func acornFoxFrozen0040FixedSubstrateEntries(candidate AcornFoxStageReceiptV1) map[string]SubstrateEntry {
	directory := func(path string, mode uint32, role OwnerRole, group GroupRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: mode, Role: role, Group: group}
	}
	file := func(path string, mode uint32, role OwnerRole, group GroupRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Role: role, Group: group}
	}
	entries := map[string]SubstrateEntry{}
	for _, path := range []string{"opt", "opt/acornfox", "opt/acornfox/releases", "opt/acornfox/releases/" + candidate.ReleaseID, "opt/acornfox/upgrade-tools", "etc", "etc/acornfox", "etc/systemd", "etc/systemd/system", "etc/systemd/system/acornfox-edge.service.d", "var", "var/lib", "var/lib/acornfox", "var/lib/acornfox/install", "var/lib/acornfox/install/releases", "var/log", "var/log/acornfox"} {
		entries[path] = directory(path, 0o755, OwnerRoleRoot, GroupRoleRoot)
	}
	for _, path := range []string{"var/lib/acornfox/uploads", "var/lib/acornfox/workspaces", "var/lib/acornfox/build-work", "var/lib/acornfox/oci", "var/log/acornfox/server"} {
		entries[path] = directory(path, 0o750, OwnerRoleServer, GroupRoleServer)
	}
	for _, path := range []string{"var/lib/acornfox/secrets", "var/lib/acornfox/secret-materials"} {
		entries[path] = directory(path, 0o700, OwnerRoleServer, GroupRoleServer)
	}
	entries["var/lib/acornfox/health-secret-materials"] = directory("var/lib/acornfox/health-secret-materials", 0o700, OwnerRoleRoot, GroupRoleRoot)
	entries["var/lib/acornfox/agent"], entries["var/log/acornfox/agent"] = directory("var/lib/acornfox/agent", 0o750, OwnerRoleAgent, GroupRoleAgent), directory("var/log/acornfox/agent", 0o750, OwnerRoleAgent, GroupRoleAgent)
	entries["var/lib/acornfox/buildkit"] = directory("var/lib/acornfox/buildkit", 0o700, OwnerRoleBuildKit, GroupRoleBuildKit)
	for _, path := range []string{"var/lib/acornfox/pi", "var/lib/acornfox/pi/work", "var/lib/acornfox/pi/agent", "var/lib/acornfox/pi/sessions"} {
		entries[path] = directory(path, 0o700, OwnerRolePI, GroupRolePI)
	}
	entries["var/lib/acornfox/caddy"], entries["var/log/acornfox/caddy"] = directory("var/lib/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy), directory("var/log/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy)
	for _, path := range []string{"var/lib/acornfox/edge", "var/log/acornfox/edge"} {
		entries[path] = directory(path, 0o750, OwnerRoleEdge, GroupRoleEdge)
	}
	for _, path := range []string{"var/lib/acornfox/edge/home", "var/lib/acornfox/edge/data", "var/lib/acornfox/edge/config"} {
		entries[path] = directory(path, 0o700, OwnerRoleEdge, GroupRoleEdge)
	}
	entries["var/lib/acornfox/healthcheck"] = directory("var/lib/acornfox/healthcheck", 0o700, OwnerRoleRoot, GroupRoleRoot)
	entries[AcornFoxUpgradeHelperPath] = file(AcornFoxUpgradeHelperPath, 0o755, OwnerRoleRoot, GroupRoleRoot)
	for _, unit := range acornFoxFrozen0040Units {
		path := "etc/systemd/system/" + strings.TrimPrefix(unit, "systemd/")
		entries[path] = file(path, 0o644, OwnerRoleRoot, GroupRoleRoot)
	}
	for destination := range map[string]string{"etc/acornfox/Caddyfile": "caddy/acornfox.Caddyfile.example", "etc/acornfox/acornfox-edge.Caddyfile": "caddy/acornfox-edge.Caddyfile.example", "etc/acornfox/acornfox-edge.env": "caddy/acornfox-edge.env.example", "etc/acornfox/buildkitd.toml": "config/acornfox-buildkitd.toml", "etc/acornfox/build-network-policy.json": "config/acornfox-build-network-policy-v1.json", "etc/acornfox/build-resolv.conf": "config/acornfox-build-resolv.conf", "etc/acornfox/rootlesskit.apparmor": "config/acornfox-rootlesskit.apparmor"} {
		mode, group := uint32(0o644), GroupRoleRoot
		if strings.HasSuffix(destination, ".env") {
			mode, group = 0o640, GroupRoleEdge
		}
		entries[destination] = file(destination, mode, OwnerRoleRoot, group)
	}
	if len(entries) > acornFoxSubstrateFixedEntryMax {
		panic("AcornFox substrate fixed entry bound is stale")
	}
	return entries
}

func validateAcornFoxFrozen0040Binding(b AcornFoxCandidateBindingV1) error {
	if b.SchemaVersion != AcornFoxCandidateBindingV1Schema {
		return errors.New("unsupported AcornFox frozen 0040 predecessor binding schema")
	}
	if b.Product != AcornFoxV1Product || b.ReleaseID != "release-"+b.Version {
		return errors.New("AcornFox frozen 0040 predecessor binding product or release_id is invalid")
	}
	if err := ParseVersion(b.Version); err != nil || strings.TrimSpace(b.Version) != b.Version {
		return errors.New("AcornFox frozen 0040 predecessor binding version is invalid")
	}
	if !validAcornFoxGitHubRepository(b.SourceRepository) {
		return errors.New("AcornFox frozen 0040 predecessor binding source_repository is invalid")
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(b.SourceCommit) {
		return errors.New("AcornFox frozen 0040 predecessor binding source_commit is invalid")
	}
	if b.Architecture != AcornFoxV1Architecture || b.MigrationVersion != AcornFoxV1MigrationVersion {
		return errors.New("AcornFox frozen 0040 predecessor binding layout identity is invalid")
	}
	if !digestPattern.MatchString(b.ManifestSHA256) || !digestPattern.MatchString(b.ArchiveSHA256) || !digestPattern.MatchString(b.BundleManifestSHA256) {
		return errors.New("AcornFox frozen 0040 predecessor binding digest is invalid")
	}
	if b.NMinusOne != nil {
		if err := validateAcornFoxNMinusOne(*b.NMinusOne); err != nil {
			return errors.New("AcornFox frozen 0040 predecessor binding n_minus_one is invalid")
		}
	}
	return nil
}

func validateAcornFoxFrozen0040StageReceipt(candidate AcornFoxStageReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	predecessor := ""
	if old.NMinusOne != nil {
		predecessor = old.NMinusOne.BindingSHA256
	}
	if validateAcornFoxFrozen0040Binding(old) != nil || !validSHA(oldSHA256) || candidate.SchemaVersion != 1 || candidate.Product != AcornFoxV1Product || candidate.Version != old.Version || candidate.ReleaseID != old.ReleaseID || candidate.ManifestSHA256 != old.ManifestSHA256 || candidate.ArchiveSHA256 != old.ArchiveSHA256 || candidate.BindingSHA256 != oldSHA256 || candidate.BundleManifestSHA256 != old.BundleManifestSHA256 || candidate.SourceCommit != old.SourceCommit || candidate.Architecture != AcornFoxV1Architecture || candidate.MigrationVersion != AcornFoxV1MigrationVersion || candidate.PredecessorBindingSHA256 != predecessor || candidate.FileCount < 1 || !validSHA(candidate.TreeSHA256) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func validateAcornFoxFrozen0040SubstrateReceipt(receipt InactiveSubstrateReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	const historicalMaxMembers = 512
	const historicalMaxEntries = historicalMaxMembers + (historicalMaxMembers-1)*((acornFoxUstarPathMaxBytes-1)/2) + acornFoxSubstrateFixedEntryMax
	if receipt.SchemaVersion != InactiveSubstrateReceiptV1Schema || receipt.State != "inactive_complete" || receipt.LayoutVersion != AcornFoxSubstrateLayoutV1 || validateAcornFoxFrozen0040StageReceipt(receipt.CandidateReceipt, old, oldSHA256) != nil || receipt.CandidateReceipt.FileCount+1 > historicalMaxMembers || len(receipt.Entries) == 0 || len(receipt.Entries) > historicalMaxEntries {
		return ErrAcornFoxUpgradeConflict
	}
	for _, digest := range []string{receipt.ReleaseTreeSHA256, receipt.InstalledTreeSHA256, receipt.UpgradeHelperSHA256, receipt.HealthHelperSHA256} {
		if !validSHA(digest) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	if receipt.ReleaseTreeSHA256 != receipt.CandidateReceipt.TreeSHA256 || validateAcornFoxSubstrateInventory(receipt.CandidateReceipt, receipt.Entries, acornFoxFrozen0040RequiredFiles(), acornFoxFrozen0040FixedSubstrateEntries(receipt.CandidateReceipt)) != nil {
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

func acornFoxFrozen0040ExpectedEntries(layout acornFoxInstallLayout, substrate InactiveSubstrateReceiptV1) ([]SubstrateEntry, error) {
	if layout.validate() != nil || substrate.CandidateReceipt.MigrationVersion != AcornFoxV1MigrationVersion {
		return nil, ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(substrate)
	if err != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	entries := append([]SubstrateEntry(nil), substrate.Entries...)
	entries = append(entries, SubstrateEntry{Path: "var/lib/acornfox/install/releases/" + substrate.CandidateReceipt.ReleaseID + ".json", Kind: SubstrateEntryFile, Mode: 0600, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(raw)), SHA256: sha256Hex(raw)})
	if layout.mode == acornFoxInstallLayoutProduction {
		for index := range entries {
			if entries[index].Path == "var/lib/acornfox/install" && entries[index].Kind == SubstrateEntryDirectory {
				entries[index].Mode, entries[index].Role, entries[index].Group = 0700, OwnerRoleRoot, GroupRoleRoot
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if validateAcornFoxLiveSourceEntries(entries) != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	return entries, nil
}

func isFrozen0040(image acornFoxUpgradeImage) bool {
	var b AcornFoxCandidateBindingV1
	if json.Unmarshal(image.Binding, &b) != nil {
		return false
	}
	return b.SchemaVersion == AcornFoxCandidateBindingV1Schema && b.MigrationVersion == AcornFoxV1MigrationVersion
}

func isSchema2Image(image acornFoxUpgradeImage) bool {
	var b AcornFoxCandidateBindingV1
	if json.Unmarshal(image.Binding, &b) != nil {
		return false
	}
	return b.SchemaVersion == AcornFoxCandidateBindingV2Schema
}

func imageHasWorkerUnit(image acornFoxUpgradeImage) bool {
	for _, entry := range image.Substrate.Entries {
		if entry.Path == "etc/systemd/system/acornfox-pi-worker.service" {
			return true
		}
	}
	return false
}

func parseAcornFoxUpgradeImageBinding(raw []byte, digest string) (AcornFoxCandidateBindingV1, bool, error) {
	b, err := parseAcornFoxCandidateBindingV1(raw, digest)
	if err != nil {
		return AcornFoxCandidateBindingV1{}, false, err
	}
	if validateAcornFoxBinding(b) == nil {
		return b, false, nil
	}
	if validateAcornFoxFrozen0040Binding(b) == nil {
		return b, true, nil
	}
	return AcornFoxCandidateBindingV1{}, false, ErrAcornFoxUpgradeConflict
}

// Installed authority is a read compatibility boundary. A schema-1 value
// returned here deliberately remains invalid as a new candidate witness.
func verifiedAcornFoxInstalled0040Binding(raw []byte, digest string) (VerifiedAcornFoxBindingV1, error) {
	binding, err := parseAcornFoxCandidateBindingV1(raw, digest)
	if err != nil || (validateAcornFoxBinding(binding) != nil && validateAcornFoxFrozen0040Binding(binding) != nil) {
		return VerifiedAcornFoxBindingV1{}, ErrAcornFoxUpgradeConflict
	}
	return VerifiedAcornFoxBindingV1{binding: cloneAcornFoxBinding(binding), digest: digest}, nil
}

var acornFoxFrozen0040Scripts = []string{
	"scripts/acornfox/install-host.sh", "scripts/acornfox/install.sh", "scripts/acornfox/upgrade.sh",
	"scripts/acornfox/control-plane-migrate.sh", "scripts/acornfox/host-preflight.sh",
}

var acornFoxFrozen0040Migrations = []string{
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
	"0034_artifacts_per_build.sql", "0035_acornfox_source_metadata.sql", "0036_acornfox_source_updates.sql", "0037_acornfox_assistant.sql", "0038_acornfox_assistant_actions.sql", "0039_acornfox_access_observations.sql",
	"0040_acornfox_fix_candidates.sql",
}

func validateAcornFoxFrozen0040Manifest(m Manifest, b AcornFoxCandidateBindingV1) error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return errors.New("unsupported historical manifest schema")
	}
	if err := validateManifestIdentityStructure(m); err != nil {
		return err
	}
	if err := validateManifestContentStructure(m); err != nil {
		return err
	}
	if m.Product != AcornFoxV1Product || m.Version != b.Version || m.ReleaseID != b.ReleaseID || m.Architecture != AcornFoxV1Architecture || m.MigrationVersion != AcornFoxV1MigrationVersion || m.SourceCommit != b.SourceCommit {
		return errors.New("AcornFox manifest identity does not match binding")
	}
	if m.ConfigDir != AcornFoxV1ConfigDir || m.DataDir != AcornFoxV1DataDir {
		return errors.New("AcornFox manifest layout is invalid")
	}
	if m.Protocol != AgentProtocolVersion || m.Compatibility.MinAgentProtocol != PreviousAgentProtocol || m.Compatibility.MaxAgentProtocol != AgentProtocolVersion || m.Compatibility.MinDataVersion != AcornFoxV1DataVersion || m.Compatibility.MaxDataVersion != AcornFoxV1DataVersion {
		return errors.New("AcornFox manifest protocol compatibility is invalid")
	}
	if !sameAcornFoxNMinusOne(m.NMinusOne, b.NMinusOne) {
		return errors.New("AcornFox manifest n_minus_one does not match binding")
	}
	return validateAcornFoxPackageInventory(m.Files, acornFoxFrozen0040RequiredFiles())
}
