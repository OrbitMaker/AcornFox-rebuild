package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/open-card/open-card/internal/pibundle"
)

// AcornFox V1 names are fixed package policy, not installer configuration.
const (
	AcornFoxV1Product          = "acornfox"
	AcornFoxV1MigrationVersion = "0040"
	AcornFoxV1DataVersion      = 40
	AcornFoxV1InstallPrefix    = "/opt/acornfox"
	AcornFoxV1ConfigDir        = "/etc/acornfox"
	AcornFoxV1DataDir          = "/var/lib/acornfox"
	AcornFoxV1LogDir           = "/var/log/acornfox"
	AcornFoxV1ServerAccount    = "acornfox"
	AcornFoxV1AgentAccount     = "acornfox-agent"
	AcornFoxV1BuildKitAccount  = "acornfox-buildkit"
	AcornFoxV1CaddyAccount     = "acornfox-caddy"
	AcornFoxV1EdgeAccount      = "acornfox-edge"

	AcornFoxCandidateBindingV1Schema = 1
	// AcornFoxLegacyPredecessorMigration is accepted only while parsing an
	// already-installed, independently pinned predecessor binding. New
	// candidates continue to require AcornFoxV1MigrationVersion.
	AcornFoxLegacyPredecessorMigration = "0034"
	acornFoxCandidateBindingMaxBytes   = 64 * 1024
	acornFoxManifestMaxBytes           = 2 * 1024 * 1024
	acornFoxBundleManifestMaxBytes     = 4 * 1024
	acornFoxArchiveMaxBytes            = 512 * 1024 * 1024
	acornFoxArchiveMaxMembers          = 512
	acornFoxArchiveMaxMemberBytes      = 128 * 1024 * 1024
	acornFoxArchiveMaxTotalBytes       = 1024 * 1024 * 1024
)

var (
	acornFoxV1Binaries = []string{
		"bin/acornfox-server", "bin/acornfox-agent", "bin/acornfox-static-server",
		"bin/acornfox-secretctl", "bin/acornfox-security-probe", "bin/acornfox-imagegc",
		"bin/acornfox", "bin/acornfox-admin", "bin/acornfox-upgrade", "bin/acornfox-healthcheck",
		"bin/acornfox-pi-worker",
		"bin/buildkitd", "bin/buildctl", "bin/buildkit-runc", "bin/rootlesskit", "bin/caddy",
	}
	acornFoxV1Units = []string{
		"systemd/acornfox-build-network.service",
		"systemd/acornfox-runtime-network.service",
		"systemd/acornfox-server.service", "systemd/acornfox-agent.service", "systemd/acornfox-buildkit.service",
		"systemd/acornfox-caddy.service", "systemd/acornfox-edge.service", "systemd/acornfox-healthcheck.service",
		"systemd/acornfox-healthcheck.timer", "systemd/acornfox-upgrade-recover.service",
		"systemd/acornfox-upgrade-safe.target", "systemd/acornfox-upgrade-finalize.service",
		"systemd/acornfox-pi-worker.service",
		"systemd/acornfox-edge.service.d/10-upgrade-marker.conf",
	}
	acornFoxV1Scripts = []string{
		"scripts/acornfox/install-host.sh", "scripts/acornfox/install.sh", "scripts/acornfox/upgrade.sh",
		"scripts/acornfox/control-plane-migrate.sh", "scripts/acornfox/host-preflight.sh",
	}
	acornFoxV1Migrations = []string{
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
	acornFoxV1WebAssetName = regexp.MustCompile(`^[A-Za-z0-9_.-]+-[A-Za-z0-9_-]{8,}\.(?:(?:css|js)(?:\.map)?|map|png|jpe?g|svg|gif|webp|ico|woff2?|ttf)$`)
	acornFoxGitHubPath     = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

type AcornFoxV1PackageFile struct {
	Path string
	Mode uint32
}

// AcornFoxV1RequiredFiles returns a defensive copy of the fixed required set.
// Only direct, hashed web/dist/assets members may be added by a release.
func AcornFoxV1RequiredFiles() []AcornFoxV1PackageFile {
	piFiles, _ := pibundle.Entries()
	files := make([]AcornFoxV1PackageFile, 0, len(acornFoxV1Binaries)+len(acornFoxV1Units)+len(acornFoxV1Scripts)+len(acornFoxV1Migrations)+len(piFiles)+20)
	for _, path := range acornFoxV1Binaries {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, path := range acornFoxV1Units {
		files = append(files, AcornFoxV1PackageFile{path, 0o644})
	}
	for _, path := range acornFoxV1Scripts {
		files = append(files, AcornFoxV1PackageFile{path, 0o755})
	}
	for _, name := range acornFoxV1Migrations {
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

// AcornFoxCandidateBindingV1 is an untrusted JSON DTO. Calling code cannot
// turn this struct into an authority; only ParseAcornFoxCandidateBindingV1
// creates a sealed witness after independently checking its raw-byte digest.
type AcornFoxCandidateBindingV1 struct {
	SchemaVersion        int                  `json:"schema_version"`
	Product              string               `json:"product"`
	Version              string               `json:"version"`
	ReleaseID            string               `json:"release_id"`
	SourceRepository     string               `json:"source_repository"`
	SourceCommit         string               `json:"source_commit"`
	Architecture         string               `json:"architecture"`
	MigrationVersion     string               `json:"migration_version"`
	ManifestSHA256       string               `json:"manifest_sha256"`
	ArchiveSHA256        string               `json:"archive_sha256"`
	BundleManifestSHA256 string               `json:"bundle_manifest_sha256"`
	NMinusOne            *AcornFoxNMinusOneV1 `json:"n_minus_one,omitempty"`
}

type AcornFoxNMinusOneV1 struct {
	Version               string `json:"version"`
	MigrationVersion      string `json:"migration_version"`
	SourceCommit          string `json:"source_commit"`
	ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
	ArchiveSHA256         string `json:"archive_sha256"`
	BundleManifestSHA256  string `json:"bundle_manifest_sha256"`
	BindingSHA256         string `json:"binding_sha256"`
}

// VerifiedAcornFoxBindingV1 intentionally exposes no fields. Its zero value
// is invalid and its contents can only be created by the strict parser.
type VerifiedAcornFoxBindingV1 struct {
	binding AcornFoxCandidateBindingV1
	digest  string
}

func (b VerifiedAcornFoxBindingV1) valid() bool {
	return b.digest != "" && validateAcornFoxBinding(b.binding) == nil
}

func ParseAcornFoxCandidateBindingV1(data []byte, expectedSHA256 string) (VerifiedAcornFoxBindingV1, error) {
	binding, err := parseAcornFoxCandidateBindingV1(data, expectedSHA256)
	if err != nil {
		return VerifiedAcornFoxBindingV1{}, err
	}
	if err := validateAcornFoxBinding(binding); err != nil {
		return VerifiedAcornFoxBindingV1{}, err
	}
	return VerifiedAcornFoxBindingV1{binding: cloneAcornFoxBinding(binding), digest: expectedSHA256}, nil
}

// ParseAcornFoxPredecessorBindingV1 validates an exact, caller-pinned
// predecessor only. It is intentionally not a candidate parser: new package
// inputs must keep using ParseAcornFoxCandidateBindingV1 and the current
// migration policy.
func ParseAcornFoxPredecessorBindingV1(data []byte, expectedSHA256 string) error {
	_, err := parseAcornFoxPredecessorBindingV1(data, expectedSHA256)
	return err
}

func parseAcornFoxCandidateBindingV1(data []byte, expectedSHA256 string) (AcornFoxCandidateBindingV1, error) {
	if len(data) == 0 || len(data) > acornFoxCandidateBindingMaxBytes {
		return AcornFoxCandidateBindingV1{}, errors.New("AcornFox candidate binding size is invalid")
	}
	if !digestPattern.MatchString(expectedSHA256) {
		return AcornFoxCandidateBindingV1{}, errors.New("AcornFox candidate binding expected sha256 is invalid")
	}
	if sha256Hex(data) != expectedSHA256 {
		return AcornFoxCandidateBindingV1{}, errors.New("AcornFox candidate binding sha256 mismatch")
	}
	var binding AcornFoxCandidateBindingV1
	if err := strictCanonicalJSON(data, &binding, "AcornFox candidate binding"); err != nil {
		return AcornFoxCandidateBindingV1{}, err
	}
	return binding, nil
}

func parseAcornFoxPredecessorBindingV1(data []byte, expectedSHA256 string) (AcornFoxCandidateBindingV1, error) {
	binding, err := parseAcornFoxCandidateBindingV1(data, expectedSHA256)
	if err != nil {
		return AcornFoxCandidateBindingV1{}, err
	}
	if err := validateAcornFoxBinding(binding); err == nil {
		return binding, nil
	}
	if err := validateAcornFoxRecent0039Binding(binding); err == nil {
		return binding, nil
	}
	if err := validateAcornFoxLegacyPredecessorBinding(binding); err != nil {
		return AcornFoxCandidateBindingV1{}, err
	}
	return binding, nil
}

func cloneAcornFoxBinding(binding AcornFoxCandidateBindingV1) AcornFoxCandidateBindingV1 {
	clone := binding
	if binding.NMinusOne != nil {
		value := *binding.NMinusOne
		clone.NMinusOne = &value
	}
	return clone
}

func validateAcornFoxBinding(b AcornFoxCandidateBindingV1) error {
	if b.SchemaVersion != AcornFoxCandidateBindingV1Schema {
		return fmt.Errorf("unsupported AcornFox candidate binding schema %d", b.SchemaVersion)
	}
	if b.Product != AcornFoxV1Product || b.ReleaseID != "release-"+b.Version {
		return errors.New("AcornFox candidate binding product or release_id is invalid")
	}
	if err := ParseVersion(b.Version); err != nil || strings.TrimSpace(b.Version) != b.Version {
		return errors.New("AcornFox candidate binding version is invalid")
	}
	if !validAcornFoxGitHubRepository(b.SourceRepository) {
		return errors.New("AcornFox candidate binding source_repository is invalid")
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(b.SourceCommit) {
		return errors.New("AcornFox candidate binding source_commit is invalid")
	}
	if b.Architecture != AcornFoxV1Architecture || b.MigrationVersion != AcornFoxV1MigrationVersion {
		return errors.New("AcornFox candidate binding layout identity is invalid")
	}
	if !digestPattern.MatchString(b.ManifestSHA256) || !digestPattern.MatchString(b.ArchiveSHA256) || !digestPattern.MatchString(b.BundleManifestSHA256) {
		return errors.New("AcornFox candidate binding digest is invalid")
	}
	if b.NMinusOne != nil {
		if err := validateAcornFoxNMinusOne(*b.NMinusOne); err != nil {
			return fmt.Errorf("AcornFox candidate binding n_minus_one: %w", err)
		}
	}
	return nil
}

func validateAcornFoxNMinusOne(n AcornFoxNMinusOneV1) error {
	if err := ParseVersion(n.Version); err != nil || strings.TrimSpace(n.Version) != n.Version {
		return errors.New("version is invalid")
	}
	if (n.MigrationVersion != AcornFoxV1MigrationVersion && n.MigrationVersion != acornFoxRecentPredecessorMigration && n.MigrationVersion != AcornFoxLegacyPredecessorMigration) || ValidateMigrationVersion(n.MigrationVersion) != nil {
		return errors.New("migration_version is invalid")
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(n.SourceCommit) {
		return errors.New("source_commit is invalid")
	}
	if !digestPattern.MatchString(n.ReleaseManifestSHA256) || !digestPattern.MatchString(n.ArchiveSHA256) || !digestPattern.MatchString(n.BundleManifestSHA256) || !digestPattern.MatchString(n.BindingSHA256) {
		return errors.New("digest is invalid")
	}
	return nil
}

func validateAcornFoxLegacyPredecessorBinding(b AcornFoxCandidateBindingV1) error {
	if b.SchemaVersion != AcornFoxCandidateBindingV1Schema || b.Product != AcornFoxV1Product || b.ReleaseID != "release-"+b.Version {
		return errors.New("AcornFox predecessor binding product or release_id is invalid")
	}
	if err := ParseVersion(b.Version); err != nil || strings.TrimSpace(b.Version) != b.Version {
		return errors.New("AcornFox predecessor binding version is invalid")
	}
	if !validAcornFoxGitHubRepository(b.SourceRepository) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(b.SourceCommit) {
		return errors.New("AcornFox predecessor binding source identity is invalid")
	}
	if b.Architecture != AcornFoxV1Architecture || b.MigrationVersion != AcornFoxLegacyPredecessorMigration || ValidateMigrationVersion(b.MigrationVersion) != nil {
		return errors.New("AcornFox predecessor binding layout identity is invalid")
	}
	if !digestPattern.MatchString(b.ManifestSHA256) || !digestPattern.MatchString(b.ArchiveSHA256) || !digestPattern.MatchString(b.BundleManifestSHA256) || b.NMinusOne != nil {
		return errors.New("AcornFox predecessor binding immutable identity is invalid")
	}
	return nil
}

func validAcornFoxGitHubRepository(raw string) bool {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "\x00") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "github.com" && u.Hostname() == "github.com" && u.Port() == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && u.EscapedPath() == u.Path && !strings.HasSuffix(u.Path, ".git") && acornFoxGitHubPath.MatchString(u.Path) && u.String() == raw
}

// VerifyAcornFoxCandidateArtifactsV1Input is the complete immutable input
// topology. It has no filesystem paths and verification never extracts data.
type VerifyAcornFoxCandidateArtifactsV1Input struct {
	Binding            []byte
	BindingSHA256      string
	Manifest           []byte
	BundleManifest     []byte
	Archive            io.Reader
	ArchiveSize        int64
	PredecessorBinding []byte
}

// VerifiedAcornFoxCandidateV1 is a sealed result for a future applier. This
// leaf deliberately provides no accessor or activation operation.
type VerifiedAcornFoxCandidateV1 struct {
	binding                       VerifiedAcornFoxBindingV1
	manifestSHA256, archiveSHA256 string
}

func (c VerifiedAcornFoxCandidateV1) valid() bool {
	return c.binding.valid() && c.manifestSHA256 != "" && c.archiveSHA256 != ""
}

func VerifyAcornFoxCandidateArtifactsV1(input VerifyAcornFoxCandidateArtifactsV1Input) (VerifiedAcornFoxCandidateV1, error) {
	binding, err := ParseAcornFoxCandidateBindingV1(input.Binding, input.BindingSHA256)
	if err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	if len(input.Manifest) == 0 || len(input.Manifest) > acornFoxManifestMaxBytes || sha256Hex(input.Manifest) != binding.binding.ManifestSHA256 {
		return VerifiedAcornFoxCandidateV1{}, errors.New("AcornFox manifest sha256 mismatch")
	}
	var manifest Manifest
	if err := strictCanonicalJSON(input.Manifest, &manifest, "AcornFox manifest"); err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	if err := validateAcornFoxCandidateManifest(manifest, binding.binding); err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	if err := verifyAcornFoxBundleManifest(input.BundleManifest, binding.binding); err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	if err := verifyAcornFoxPredecessor(input.PredecessorBinding, binding.binding, manifest.NMinusOne); err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	if err := verifyAcornFoxArchive(input.Archive, input.ArchiveSize, binding.binding.ArchiveSHA256, input.Manifest, manifest, nil); err != nil {
		return VerifiedAcornFoxCandidateV1{}, err
	}
	return VerifiedAcornFoxCandidateV1{binding: binding, manifestSHA256: binding.binding.ManifestSHA256, archiveSHA256: binding.binding.ArchiveSHA256}, nil
}

func validateAcornFoxCandidateManifest(m Manifest, b AcornFoxCandidateBindingV1) error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema version %d", m.SchemaVersion)
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
	return validateAcornFoxV1PackageInventory(m.Files)
}

func sameAcornFoxNMinusOne(m *NMinusOne, b *AcornFoxNMinusOneV1) bool {
	if m == nil || b == nil {
		return m == nil && b == nil
	}
	return m.Version == b.Version && m.MigrationVersion == b.MigrationVersion && m.SourceCommit == b.SourceCommit && m.ReleaseManifestSHA256 == b.ReleaseManifestSHA256 && m.ArchiveSHA256 == b.ArchiveSHA256 && m.BundleManifestSHA256 == b.BundleManifestSHA256
}

func validateAcornFoxV1PackageInventory(files []FileDigest) error {
	if _, err := pibundle.Entries(); err != nil {
		return errors.New("AcornFox Pi package inventory is invalid")
	}
	required := AcornFoxV1RequiredFiles()
	if len(files) < len(required) {
		return errors.New("AcornFox package misses required entries")
	}
	expected := make(map[string]uint32, len(required))
	for _, file := range required {
		expected[file.Path] = file.Mode
	}
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		lower := strings.ToLower(file.Path)
		if strings.Contains(lower, "open-card") || strings.Contains(lower, "open_card") || strings.Contains(lower, "opencard") {
			return fmt.Errorf("legacy Open Card package entry is forbidden: %s", file.Path)
		}
		mode, ok := expected[file.Path]
		if !ok && strings.HasPrefix(file.Path, "web/dist/assets/") {
			ok = validAcornFoxV1WebAsset(file.Path) && file.Mode == 0o644
		}
		if !ok || (mode != 0 && mode != file.Mode) {
			return fmt.Errorf("AcornFox package entry is not allowed: %s", file.Path)
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return fmt.Errorf("AcornFox package has duplicate entry: %s", file.Path)
		}
		seen[file.Path] = struct{}{}
	}
	for path := range expected {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("AcornFox package is missing %s", path)
		}
	}
	return nil
}

func validAcornFoxV1WebAsset(path string) bool {
	name := strings.TrimPrefix(path, "web/dist/assets/")
	return name != "" && !strings.Contains(name, "/") && acornFoxV1WebAssetName.MatchString(name)
}

// IsAcornFoxV1WebAssetPath reports whether path is an installer-permitted
// direct hashed web asset. Release assembly must use this policy rather than
// maintaining a second asset-name classifier.
func IsAcornFoxV1WebAssetPath(path string) bool { return validAcornFoxV1WebAsset(path) }

func verifyAcornFoxBundleManifest(raw []byte, binding AcornFoxCandidateBindingV1) error {
	if len(raw) == 0 || len(raw) > acornFoxBundleManifestMaxBytes || sha256Hex(raw) != binding.BundleManifestSHA256 {
		return errors.New("AcornFox bundle manifest sha256 mismatch")
	}
	want := fmt.Sprintf("%s  acornfox-%s-production.tar.gz\n%s  release/manifest.json\n", binding.ArchiveSHA256, binding.Version, binding.ManifestSHA256)
	if !bytes.Equal(raw, []byte(want)) {
		return errors.New("AcornFox bundle manifest content is invalid")
	}
	return nil
}

func verifyAcornFoxPredecessor(raw []byte, successor AcornFoxCandidateBindingV1, manifestPredecessor *NMinusOne) error {
	if successor.NMinusOne == nil {
		if len(raw) != 0 || manifestPredecessor != nil {
			return errors.New("AcornFox bootstrap predecessor input is invalid")
		}
		return nil
	}
	if len(raw) == 0 || sha256Hex(raw) != successor.NMinusOne.BindingSHA256 {
		return errors.New("AcornFox predecessor binding sha256 mismatch")
	}
	predecessor, err := parseAcornFoxPredecessorBindingV1(raw, successor.NMinusOne.BindingSHA256)
	if err != nil {
		return fmt.Errorf("AcornFox predecessor binding: %w", err)
	}
	n := successor.NMinusOne
	p := predecessor
	if manifestPredecessor == nil || p.Version != n.Version || p.MigrationVersion != n.MigrationVersion || p.SourceCommit != n.SourceCommit || p.ManifestSHA256 != n.ReleaseManifestSHA256 || p.ArchiveSHA256 != n.ArchiveSHA256 || p.BundleManifestSHA256 != n.BundleManifestSHA256 || !sameAcornFoxNMinusOne(manifestPredecessor, n) {
		return errors.New("AcornFox predecessor identity does not match successor")
	}
	return nil
}

func strictCanonicalJSON(data []byte, target any, label string) error {
	if err := decodeStrict(data, target); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", label, err)
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("%s is not canonical JSON", label)
	}
	return nil
}
