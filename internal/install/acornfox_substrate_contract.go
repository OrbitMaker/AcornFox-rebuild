package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	InactiveSubstrateReceiptV1Schema = 1
	AcornFoxSubstrateLayoutV1        = 1
	AcornFoxSubstrateTreeV1Schema    = 1
	// USTAR names are at most 255 bytes; a one-byte component plus separator
	// gives at most 127 parent directories per release member. The archive
	// member bound includes manifest.json, and the fixed table is audited below.
	acornFoxUstarPathMaxBytes             = 255
	acornFoxSubstrateMaxReleaseParentDirs = (acornFoxArchiveMaxMembers - 1) * ((acornFoxUstarPathMaxBytes - 1) / 2)
	acornFoxSubstrateFixedEntryMax        = 64
	acornFoxSubstrateMaxEntries           = acornFoxArchiveMaxMembers + acornFoxSubstrateMaxReleaseParentDirs + acornFoxSubstrateFixedEntryMax
)

const (
	AcornFoxUpgradeHelperPath = "opt/acornfox/upgrade-tools/acornfox-upgrade"
)

func AcornFoxHealthcheckHelperPath(receipt AcornFoxStageReceiptV1) string {
	return "opt/acornfox/releases/" + receipt.ReleaseID + "/bin/acornfox-healthcheck"
}

// OwnerRole is a fixed role label, never a uid/gid. Receipts deliberately do
// not carry host identity data.
type OwnerRole string
type GroupRole string

const (
	OwnerRoleRoot     OwnerRole = "root"
	OwnerRoleServer   OwnerRole = "server"
	OwnerRoleAgent    OwnerRole = "agent"
	OwnerRoleBuildKit OwnerRole = "buildkit"
	OwnerRoleCaddy    OwnerRole = "caddy"
	OwnerRoleEdge     OwnerRole = "edge"
	OwnerRolePI       OwnerRole = "pi"
)

const (
	GroupRoleRoot     GroupRole = "root"
	GroupRoleServer   GroupRole = "server"
	GroupRoleAgent    GroupRole = "agent"
	GroupRoleBuildKit GroupRole = "buildkit"
	GroupRoleCaddy    GroupRole = "caddy"
	GroupRoleEdge     GroupRole = "edge"
	GroupRolePI       GroupRole = "pi"
)

type SubstrateEntryKind string

const (
	SubstrateEntryFile      SubstrateEntryKind = "file"
	SubstrateEntryDirectory SubstrateEntryKind = "directory"
)

// SubstrateEntry names a relative, candidate-owned entry. Absolute paths,
// credentials, uid/gid values, and device nodes have no representation here.
type SubstrateEntry struct {
	Path   string             `json:"path"`
	Kind   SubstrateEntryKind `json:"kind"`
	Mode   uint32             `json:"mode"`
	Role   OwnerRole          `json:"role"`
	Group  GroupRole          `json:"group"`
	Size   int64              `json:"size"`
	SHA256 string             `json:"sha256"`
}

type acornFoxSubstrateTreeEnvelopeV1 struct {
	SchemaVersion int              `json:"schema_version"`
	Entries       []SubstrateEntry `json:"entries"`
}

// InactiveSubstrateReceiptV1 records only verified candidate and tree digests.
// Binding, manifest, archive, and receipt digests are external references: do
// not embed any of those binaries into a digest-bearing contract, or the hash
// topology becomes circular.
type InactiveSubstrateReceiptV1 struct {
	SchemaVersion       int                    `json:"schema_version"`
	State               string                 `json:"state"`
	LayoutVersion       int                    `json:"layout_version"`
	CandidateReceipt    AcornFoxStageReceiptV1 `json:"candidate_receipt"`
	ReleaseTreeSHA256   string                 `json:"release_tree_sha256"`
	InstalledTreeSHA256 string                 `json:"installed_tree_sha256"`
	UpgradeHelperSHA256 string                 `json:"upgrade_helper_sha256"`
	HealthHelperSHA256  string                 `json:"health_helper_sha256"`
	Entries             []SubstrateEntry       `json:"entries"`
}

func (r InactiveSubstrateReceiptV1) Validate() error {
	if r.SchemaVersion != InactiveSubstrateReceiptV1Schema || r.State != "inactive_complete" || r.LayoutVersion != AcornFoxSubstrateLayoutV1 {
		return errors.New("AcornFox inactive substrate receipt identity is invalid")
	}
	if r.CandidateReceipt.Validate() != nil {
		return errors.New("AcornFox inactive substrate candidate receipt is invalid")
	}
	for _, digest := range []string{r.ReleaseTreeSHA256, r.InstalledTreeSHA256, r.UpgradeHelperSHA256, r.HealthHelperSHA256} {
		if !digestPattern.MatchString(digest) {
			return errors.New("AcornFox inactive substrate digest is invalid")
		}
	}
	if r.ReleaseTreeSHA256 != r.CandidateReceipt.TreeSHA256 {
		return errors.New("AcornFox inactive substrate release tree is not candidate-bound")
	}
	if err := validateAcornFoxV1SubstrateInventory(r.CandidateReceipt, r.Entries); err != nil {
		return err
	}
	computedRelease, err := ComputeAcornFoxReleaseTreeSHA256(r.CandidateReceipt, r.Entries)
	if err != nil || computedRelease != r.ReleaseTreeSHA256 {
		return errors.New("AcornFox inactive substrate release tree digest is invalid")
	}
	computed, err := ComputeAcornFoxSubstrateTreeSHA256(r.Entries)
	if err != nil || r.InstalledTreeSHA256 != computed {
		return errors.New("AcornFox inactive substrate installed tree digest is invalid")
	}
	upgrade, health := substrateEntryAt(r.Entries, AcornFoxUpgradeHelperPath), substrateEntryAt(r.Entries, AcornFoxHealthcheckHelperPath(r.CandidateReceipt))
	if upgrade == nil || health == nil || upgrade.SHA256 != r.UpgradeHelperSHA256 || health.SHA256 != r.HealthHelperSHA256 {
		return errors.New("AcornFox inactive substrate helper entries are invalid")
	}
	return nil
}

// ComputeAcornFoxReleaseTreeSHA256 is intentionally congruent with the stage
// receipt tree: manifest.json is first, then manifest.Files paths sorted by
// relative release path. The publisher verifies source bytes against the pinned
// manifest before emitting entries; this contract recomputes their tree shape.
func ComputeAcornFoxReleaseTreeSHA256(candidate AcornFoxStageReceiptV1, entries []SubstrateEntry) (string, error) {
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	files := make([]SubstrateEntry, 0, candidate.FileCount)
	var manifest *SubstrateEntry
	for index := range entries {
		entry := &entries[index]
		if !strings.HasPrefix(entry.Path, prefix) || entry.Kind != SubstrateEntryFile {
			continue
		}
		relative := strings.TrimPrefix(entry.Path, prefix)
		if relative == "manifest.json" {
			manifest = entry
			continue
		}
		files = append(files, *entry)
	}
	if manifest == nil || manifest.Mode != 0o644 || manifest.SHA256 != candidate.ManifestSHA256 || len(files) != candidate.FileCount {
		return "", errors.New("AcornFox release tree members are invalid")
	}
	sort.Slice(files, func(i, j int) bool {
		return strings.TrimPrefix(files[i].Path, prefix) < strings.TrimPrefix(files[j].Path, prefix)
	})
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "manifest.json\x00%04o\x00%s\n", 0o644, candidate.ManifestSHA256)
	for _, entry := range files {
		relative := strings.TrimPrefix(entry.Path, prefix)
		_, _ = fmt.Fprintf(hash, "%s\x00%04o\x00%s\n", relative, entry.Mode, entry.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (e acornFoxSubstrateTreeEnvelopeV1) Validate() error {
	if e.SchemaVersion != AcornFoxSubstrateTreeV1Schema {
		return errors.New("AcornFox substrate tree schema is invalid")
	}
	return validateAcornFoxSubstrateEntries(e.Entries)
}

func parseAcornFoxSubstrateTreeEnvelopeV1(raw []byte) (acornFoxSubstrateTreeEnvelopeV1, error) {
	var envelope acornFoxSubstrateTreeEnvelopeV1
	if err := strictCanonicalJSON(raw, &envelope, "AcornFox substrate tree envelope"); err != nil {
		return acornFoxSubstrateTreeEnvelopeV1{}, err
	}
	if err := envelope.Validate(); err != nil {
		return acornFoxSubstrateTreeEnvelopeV1{}, err
	}
	return envelope, nil
}

func marshalAcornFoxSubstrateTreeEnvelopeV1(envelope acornFoxSubstrateTreeEnvelopeV1) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// ComputeAcornFoxSubstrateTreeSHA256 is the single tree digest definition for
// inactive substrate contracts. The envelope bytes are canonical and entries
// are already required to be strictly sorted; no caller-controlled hash shape
// exists here.
func ComputeAcornFoxSubstrateTreeSHA256(entries []SubstrateEntry) (string, error) {
	raw, err := marshalAcornFoxSubstrateTreeEnvelopeV1(acornFoxSubstrateTreeEnvelopeV1{SchemaVersion: AcornFoxSubstrateTreeV1Schema, Entries: entries})
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func MarshalInactiveSubstrateReceiptV1(receipt InactiveSubstrateReceiptV1) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func ParseInactiveSubstrateReceiptV1(raw []byte) (InactiveSubstrateReceiptV1, error) {
	var receipt InactiveSubstrateReceiptV1
	if err := strictCanonicalJSON(raw, &receipt, "AcornFox inactive substrate receipt"); err != nil {
		return InactiveSubstrateReceiptV1{}, err
	}
	if err := receipt.Validate(); err != nil {
		return InactiveSubstrateReceiptV1{}, err
	}
	return receipt, nil
}

func validateAcornFoxSubstrateEntries(entries []SubstrateEntry) error {
	if len(entries) == 0 || len(entries) > acornFoxSubstrateMaxEntries {
		return errors.New("AcornFox substrate entry count is invalid")
	}
	for index, entry := range entries {
		if err := validateAcornFoxSubstrateEntry(entry); err != nil {
			return fmt.Errorf("AcornFox substrate entry %d: %w", index, err)
		}
		if index > 0 && entries[index-1].Path >= entry.Path {
			return errors.New("AcornFox substrate entries are not strictly sorted")
		}
	}
	return nil
}

func validateAcornFoxSubstrateEntry(entry SubstrateEntry) error {
	if err := validateRelativePath(entry.Path); err != nil || strings.HasPrefix(entry.Path, "release/") || strings.Contains(entry.Path, "..") {
		return errors.New("path is invalid")
	}
	if entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory {
		return errors.New("kind is invalid")
	}
	if entry.Mode > 0o777 || entry.Mode&0o022 != 0 || !validAcornFoxOwnerRole(entry.Role) || !validAcornFoxGroupRole(entry.Group) || entry.Size < 0 {
		return errors.New("metadata is invalid")
	}
	if entry.Kind == SubstrateEntryDirectory {
		if entry.Size != 0 || entry.SHA256 != "" || (entry.Mode != 0o700 && entry.Mode != 0o750 && entry.Mode != 0o755) {
			return errors.New("directory metadata is invalid")
		}
		return nil
	}
	if !digestPattern.MatchString(entry.SHA256) || !validAcornFoxSubstrateFileMode(entry.Mode) {
		return errors.New("file metadata is invalid")
	}
	return nil
}

func validAcornFoxGroupRole(role GroupRole) bool {
	switch role {
	case GroupRoleRoot, GroupRoleServer, GroupRoleAgent, GroupRoleBuildKit, GroupRoleCaddy, GroupRoleEdge, GroupRolePI:
		return true
	default:
		return false
	}
}

func validAcornFoxOwnerRole(role OwnerRole) bool {
	switch role {
	case OwnerRoleRoot, OwnerRoleServer, OwnerRoleAgent, OwnerRoleBuildKit, OwnerRoleCaddy, OwnerRoleEdge, OwnerRolePI:
		return true
	default:
		return false
	}
}

func validAcornFoxSubstrateFileMode(mode uint32) bool {
	return mode == 0o600 || mode == 0o640 || mode == 0o644 || mode == 0o700 || mode == 0o750 || mode == 0o755
}

func substrateEntryAt(entries []SubstrateEntry, path string) *SubstrateEntry {
	for index := range entries {
		if entries[index].Path == path {
			return &entries[index]
		}
	}
	return nil
}

// These slices freeze the 0034 package policy from f329af37. They must not be
// derived from the current package lists: doing so would silently widen what
// can be authenticated as an installed predecessor.
var acornFoxLegacy0034Binaries = []string{
	"bin/acornfox-server", "bin/acornfox-agent", "bin/acornfox-static-server",
	"bin/acornfox-secretctl", "bin/acornfox-security-probe", "bin/acornfox-imagegc",
	"bin/acornfox", "bin/acornfox-admin", "bin/acornfox-upgrade", "bin/acornfox-healthcheck",
	"bin/buildkitd", "bin/buildctl", "bin/buildkit-runc", "bin/rootlesskit", "bin/caddy",
}

var acornFoxLegacy0034Units = []string{
	"systemd/acornfox-build-network.service",
	"systemd/acornfox-server.service", "systemd/acornfox-agent.service", "systemd/acornfox-buildkit.service",
	"systemd/acornfox-caddy.service", "systemd/acornfox-edge.service", "systemd/acornfox-healthcheck.service",
	"systemd/acornfox-healthcheck.timer", "systemd/acornfox-upgrade-recover.service",
	"systemd/acornfox-upgrade-safe.target", "systemd/acornfox-upgrade-finalize.service",
	"systemd/acornfox-edge.service.d/10-upgrade-marker.conf",
}

var acornFoxLegacy0034Scripts = []string{
	"scripts/acornfox/install-host.sh", "scripts/acornfox/install.sh", "scripts/acornfox/upgrade.sh",
	"scripts/acornfox/control-plane-migrate.sh", "scripts/acornfox/host-preflight.sh",
}

var acornFoxLegacy0034Migrations = []string{
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
	"0034_artifacts_per_build.sql",
}

const (
	acornFoxLegacy0034ArchiveMaxMembers      = 256
	acornFoxLegacy0034MaxReleaseParentDirs   = (acornFoxLegacy0034ArchiveMaxMembers - 1) * ((acornFoxUstarPathMaxBytes - 1) / 2)
	acornFoxLegacy0034SubstrateMaxEntryCount = acornFoxLegacy0034ArchiveMaxMembers + acornFoxLegacy0034MaxReleaseParentDirs + acornFoxSubstrateFixedEntryMax
)

func acornFoxLegacy0034RequiredFiles() []AcornFoxV1PackageFile {
	files := make([]AcornFoxV1PackageFile, 0, len(acornFoxLegacy0034Binaries)+len(acornFoxLegacy0034Units)+len(acornFoxLegacy0034Scripts)+len(acornFoxLegacy0034Migrations)+18)
	for _, path := range acornFoxLegacy0034Binaries {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, path := range acornFoxLegacy0034Units {
		files = append(files, AcornFoxV1PackageFile{path, 0o644})
	}
	for _, path := range acornFoxLegacy0034Scripts {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, name := range acornFoxLegacy0034Migrations {
		files = append(files, AcornFoxV1PackageFile{"migrations/control-plane/" + name, 0o640})
	}
	return append(files,
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

func validateAcornFoxLegacy0034StageReceipt(candidate AcornFoxStageReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	if validateAcornFoxLegacyPredecessorBinding(old) != nil || !validSHA(oldSHA256) || candidate.SchemaVersion != 1 || candidate.Product != AcornFoxV1Product || candidate.Version != old.Version || candidate.ReleaseID != old.ReleaseID || candidate.ManifestSHA256 != old.ManifestSHA256 || candidate.ArchiveSHA256 != old.ArchiveSHA256 || candidate.BindingSHA256 != oldSHA256 || candidate.BundleManifestSHA256 != old.BundleManifestSHA256 || candidate.SourceCommit != old.SourceCommit || candidate.Architecture != AcornFoxV1Architecture || candidate.MigrationVersion != AcornFoxLegacyPredecessorMigration || candidate.PredecessorBindingSHA256 != "" || candidate.FileCount < 1 || !validSHA(candidate.TreeSHA256) {
		return errors.New("AcornFox legacy 0034 stage receipt is invalid")
	}
	return nil
}

func validateAcornFoxLegacy0034SubstrateReceipt(receipt InactiveSubstrateReceiptV1, old AcornFoxCandidateBindingV1, oldSHA256 string) error {
	if receipt.SchemaVersion != InactiveSubstrateReceiptV1Schema || receipt.State != "inactive_complete" || receipt.LayoutVersion != AcornFoxSubstrateLayoutV1 || validateAcornFoxLegacy0034StageReceipt(receipt.CandidateReceipt, old, oldSHA256) != nil {
		return errors.New("AcornFox legacy 0034 inactive substrate identity is invalid")
	}
	if receipt.CandidateReceipt.FileCount+1 > acornFoxLegacy0034ArchiveMaxMembers || len(receipt.Entries) == 0 || len(receipt.Entries) > acornFoxLegacy0034SubstrateMaxEntryCount {
		return errors.New("AcornFox legacy 0034 substrate exceeds historical bounds")
	}
	for _, digest := range []string{receipt.ReleaseTreeSHA256, receipt.InstalledTreeSHA256, receipt.UpgradeHelperSHA256, receipt.HealthHelperSHA256} {
		if !validSHA(digest) {
			return errors.New("AcornFox legacy 0034 inactive substrate digest is invalid")
		}
	}
	if receipt.ReleaseTreeSHA256 != receipt.CandidateReceipt.TreeSHA256 {
		return errors.New("AcornFox legacy 0034 release tree is not candidate-bound")
	}
	if err := validateAcornFoxSubstrateInventory(receipt.CandidateReceipt, receipt.Entries, acornFoxLegacy0034RequiredFiles(), acornFoxLegacy0034FixedSubstrateEntries(receipt.CandidateReceipt)); err != nil {
		return err
	}
	release, err := ComputeAcornFoxReleaseTreeSHA256(receipt.CandidateReceipt, receipt.Entries)
	if err != nil || release != receipt.ReleaseTreeSHA256 {
		return errors.New("AcornFox legacy 0034 release tree digest is invalid")
	}
	installed, err := ComputeAcornFoxSubstrateTreeSHA256(receipt.Entries)
	if err != nil || installed != receipt.InstalledTreeSHA256 {
		return errors.New("AcornFox legacy 0034 installed tree digest is invalid")
	}
	upgrade := substrateEntryAt(receipt.Entries, AcornFoxUpgradeHelperPath)
	health := substrateEntryAt(receipt.Entries, AcornFoxHealthcheckHelperPath(receipt.CandidateReceipt))
	if upgrade == nil || health == nil || upgrade.SHA256 != receipt.UpgradeHelperSHA256 || health.SHA256 != receipt.HealthHelperSHA256 {
		return errors.New("AcornFox legacy 0034 helper entries are invalid")
	}
	return nil
}

func parseAcornFoxLegacy0034SubstrateReceipt(raw []byte, old AcornFoxCandidateBindingV1, oldSHA256 string) (InactiveSubstrateReceiptV1, error) {
	var receipt InactiveSubstrateReceiptV1
	if err := strictCanonicalJSON(raw, &receipt, "AcornFox legacy 0034 inactive substrate receipt"); err != nil {
		return receipt, err
	}
	return receipt, validateAcornFoxLegacy0034SubstrateReceipt(receipt, old, oldSHA256)
}

// validateAcornFoxV1SubstrateInventory validates the complete inactive V1
// layout. The publisher must separately verify each release member's digest
// against the pinned manifest before constructing this receipt; this contract
// binds that verified tree through CandidateReceipt.TreeSHA256, exact member
// count, and the closed installed-path/mapping inventory below.
func validateAcornFoxV1SubstrateInventory(candidate AcornFoxStageReceiptV1, entries []SubstrateEntry) error {
	if err := validateAcornFoxSubstrateInventory(candidate, entries, AcornFoxV1RequiredFiles(), acornFoxFixedSubstrateEntries(candidate)); err == nil {
		return nil
	}
	return validateAcornFoxSubstrateInventory(candidate, entries, acornFoxFrozen0040RequiredFiles(), acornFoxFrozen0040FixedSubstrateEntries(candidate))
}

func validateAcornFoxSubstrateInventory(candidate AcornFoxStageReceiptV1, entries []SubstrateEntry, required []AcornFoxV1PackageFile, fixed map[string]SubstrateEntry) error {
	if candidate.FileCount+1 > acornFoxArchiveMaxMembers {
		return errors.New("AcornFox substrate candidate file count exceeds archive bound")
	}
	if err := validateAcornFoxSubstrateEntries(entries); err != nil {
		return err
	}
	byPath := make(map[string]SubstrateEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	releasePrefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	releaseMembers := 0
	releaseDirectories := map[string]struct{}{"opt/acornfox/releases/" + candidate.ReleaseID: {}}
	actualReleaseDirectories := map[string]struct{}{}
	seenRequired := map[string]bool{}
	for path, entry := range byPath {
		if strings.HasPrefix(path, releasePrefix) {
			if entry.Kind == SubstrateEntryDirectory {
				actualReleaseDirectories[path] = struct{}{}
				continue
			}
			relative := strings.TrimPrefix(path, releasePrefix)
			if err := validateAcornFoxReleaseMemberForPolicy(candidate, relative, entry, required); err != nil {
				return err
			}
			releaseMembers++
			for parent := parentDirectory(path); strings.HasPrefix(parent, "opt/acornfox/releases/"+candidate.ReleaseID); parent = parentDirectory(parent) {
				releaseDirectories[parent] = struct{}{}
				if parent == "opt/acornfox/releases/"+candidate.ReleaseID {
					break
				}
			}
			for _, requiredFile := range required {
				if relative == requiredFile.Path {
					seenRequired[relative] = true
				}
			}
			continue
		}
		if _, ok := fixed[path]; !ok {
			return fmt.Errorf("AcornFox substrate path is not allowed: %s", path)
		}
	}
	for path := range releaseDirectories {
		entry, ok := byPath[path]
		if !ok || entry.Kind != SubstrateEntryDirectory || entry.Mode != 0o755 || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot || entry.Size != 0 || entry.SHA256 != "" {
			return fmt.Errorf("AcornFox release directory is invalid: %s", path)
		}
	}
	releaseRoot := strings.TrimSuffix(releasePrefix, "/")
	if entry, ok := byPath[releaseRoot]; ok && entry.Kind == SubstrateEntryDirectory {
		actualReleaseDirectories[releaseRoot] = struct{}{}
	}
	if len(actualReleaseDirectories) != len(releaseDirectories) {
		return errors.New("AcornFox release directory set is not exact")
	}
	for path := range actualReleaseDirectories {
		if _, ok := releaseDirectories[path]; !ok {
			return fmt.Errorf("AcornFox release directory is extra: %s", path)
		}
	}
	for _, requiredFile := range required {
		if !seenRequired[requiredFile.Path] {
			return fmt.Errorf("AcornFox substrate misses release member: %s", requiredFile.Path)
		}
	}
	// AcornFoxStageReceiptV1.FileCount is the pinned manifest.Files count;
	// manifest.json is the one additional release-tree member.
	if releaseMembers != candidate.FileCount+1 {
		return errors.New("AcornFox substrate release member count is invalid")
	}
	for path, want := range fixed {
		got, ok := byPath[path]
		if !ok || got.Kind != want.Kind || got.Mode != want.Mode || got.Role != want.Role || got.Group != want.Group || (got.Kind == SubstrateEntryDirectory && (got.Size != want.Size || got.SHA256 != want.SHA256)) {
			return fmt.Errorf("AcornFox substrate fixed entry is invalid: %s", path)
		}
		if source := acornFoxInstalledSource(candidate, path); source != "" {
			member, ok := byPath[releasePrefix+source]
			if !ok || got.SHA256 != member.SHA256 || got.Size != member.Size {
				return fmt.Errorf("AcornFox substrate installed mapping is invalid: %s", path)
			}
		}
	}
	return nil
}

func parentDirectory(path string) string {
	if index := strings.LastIndex(path, "/"); index > 0 {
		return path[:index]
	}
	return ""
}

func validateAcornFoxReleaseMember(candidate AcornFoxStageReceiptV1, relative string, entry SubstrateEntry) error {
	return validateAcornFoxReleaseMemberForPolicy(candidate, relative, entry, AcornFoxV1RequiredFiles())
}

func validateAcornFoxReleaseMemberForPolicy(candidate AcornFoxStageReceiptV1, relative string, entry SubstrateEntry, required []AcornFoxV1PackageFile) error {
	if entry.Kind != SubstrateEntryFile || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot {
		return errors.New("AcornFox release member metadata is invalid")
	}
	if relative == "manifest.json" {
		if entry.Mode != 0o644 || entry.SHA256 != candidate.ManifestSHA256 {
			return errors.New("AcornFox release manifest is invalid")
		}
		return nil
	}
	for _, requiredFile := range required {
		if relative == requiredFile.Path {
			if entry.Mode != requiredFile.Mode {
				return errors.New("AcornFox release member mode is invalid")
			}
			return nil
		}
	}
	if strings.HasPrefix(relative, "web/dist/assets/") && validAcornFoxV1WebAsset(relative) && entry.Mode == 0o644 {
		return nil
	}
	return fmt.Errorf("AcornFox release member is not allowed: %s", relative)
}

func acornFoxFixedSubstrateEntry(candidate AcornFoxStageReceiptV1, path string) (SubstrateEntry, bool) {
	entry, ok := acornFoxFixedSubstrateEntries(candidate)[path]
	return entry, ok
}

func acornFoxFixedSubstrateEntries(candidate AcornFoxStageReceiptV1) map[string]SubstrateEntry {
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
	for _, unit := range acornFoxV1Units {
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

func acornFoxLegacy0034FixedSubstrateEntries(candidate AcornFoxStageReceiptV1) map[string]SubstrateEntry {
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
	entries["var/lib/acornfox/caddy"], entries["var/log/acornfox/caddy"] = directory("var/lib/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy), directory("var/log/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy)
	for _, path := range []string{"var/lib/acornfox/edge", "var/log/acornfox/edge"} {
		entries[path] = directory(path, 0o750, OwnerRoleEdge, GroupRoleEdge)
	}
	for _, path := range []string{"var/lib/acornfox/edge/home", "var/lib/acornfox/edge/data", "var/lib/acornfox/edge/config"} {
		entries[path] = directory(path, 0o700, OwnerRoleEdge, GroupRoleEdge)
	}
	entries["var/lib/acornfox/healthcheck"] = directory("var/lib/acornfox/healthcheck", 0o700, OwnerRoleRoot, GroupRoleRoot)
	entries[AcornFoxUpgradeHelperPath] = file(AcornFoxUpgradeHelperPath, 0o755, OwnerRoleRoot, GroupRoleRoot)
	for _, unit := range acornFoxLegacy0034Units {
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
	return entries
}

func acornFoxInstalledSource(candidate AcornFoxStageReceiptV1, path string) string {
	if path == AcornFoxUpgradeHelperPath {
		return "bin/acornfox-upgrade"
	}
	if strings.HasPrefix(path, "etc/systemd/system/") {
		return "systemd/" + strings.TrimPrefix(path, "etc/systemd/system/")
	}
	return map[string]string{"etc/acornfox/Caddyfile": "caddy/acornfox.Caddyfile.example", "etc/acornfox/acornfox-edge.Caddyfile": "caddy/acornfox-edge.Caddyfile.example", "etc/acornfox/acornfox-edge.env": "caddy/acornfox-edge.env.example", "etc/acornfox/buildkitd.toml": "config/acornfox-buildkitd.toml", "etc/acornfox/build-network-policy.json": "config/acornfox-build-network-policy-v1.json", "etc/acornfox/build-resolv.conf": "config/acornfox-build-resolv.conf", "etc/acornfox/rootlesskit.apparmor": "config/acornfox-rootlesskit.apparmor"}[path]
}

type AcornFoxInactiveSubstrateIntentV1 struct {
	SchemaVersion               int                    `json:"schema_version"`
	LayoutVersion               int                    `json:"layout_version"`
	CandidateReceipt            AcornFoxStageReceiptV1 `json:"candidate_receipt"`
	ExpectedEntryEnvelopeSHA256 string                 `json:"expected_entry_envelope_sha256"`
}

func (i AcornFoxInactiveSubstrateIntentV1) Validate() error {
	if i.SchemaVersion != InactiveSubstrateReceiptV1Schema || i.LayoutVersion != AcornFoxSubstrateLayoutV1 || i.CandidateReceipt.Validate() != nil || !digestPattern.MatchString(i.ExpectedEntryEnvelopeSHA256) {
		return errors.New("AcornFox inactive substrate intent is invalid")
	}
	return nil
}

func ParseAcornFoxInactiveSubstrateIntentV1(raw []byte) (AcornFoxInactiveSubstrateIntentV1, error) {
	var intent AcornFoxInactiveSubstrateIntentV1
	if err := strictCanonicalJSON(raw, &intent, "AcornFox inactive substrate intent"); err != nil {
		return AcornFoxInactiveSubstrateIntentV1{}, err
	}
	return intent, intent.Validate()
}

func MarshalAcornFoxInactiveSubstrateIntentV1(intent AcornFoxInactiveSubstrateIntentV1) ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(intent)
}

type AcornFoxReconciliationOutcome string

const (
	AcornFoxReconcileAbsent           AcornFoxReconciliationOutcome = "absent"
	AcornFoxReconcileResume           AcornFoxReconciliationOutcome = "resume"
	AcornFoxReconcileCompleted        AcornFoxReconciliationOutcome = "completed"
	AcornFoxReconcileRecoveryRequired AcornFoxReconciliationOutcome = "recovery_required"
	AcornFoxReconcileConflict         AcornFoxReconciliationOutcome = "conflict"
	AcornFoxReconcileCommitUnknown    AcornFoxReconciliationOutcome = "commit_unknown"
	AcornFoxReconcileCleanupUnknown   AcornFoxReconciliationOutcome = "cleanup_unknown"
)
