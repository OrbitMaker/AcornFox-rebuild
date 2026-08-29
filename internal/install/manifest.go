// Package install contains the on-disk contracts used by the Open Card
// installer.  The package deliberately has no dependencies outside the Go
// standard library so an installer can be built and audited independently of
// the control-plane implementation.
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	ManifestSchemaVersion      = 1
	ManifestProduct            = "open-card"
	AgentProtocolVersion       = "1.1"
	PreviousAgentProtocol      = "1.0"
	LegacyAgentProtocol        = "v1"
	CurrentMigrationVersion    = "0024"
	ProductionCandidateVersion = "0.8.0-rc.1"
	ProductionNMinusOneVersion = "0.8.0-rc.0"
	RC0SourceCommit            = "35a2b198ac52949af3477475d89d4813b46a9490"
	RC0ReleaseManifestSHA256   = "3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253"
	RC0ArchiveSHA256           = "abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc"
	RC0BundleManifestSHA256    = "960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392"
	DefaultInstallPrefix       = "/opt/open-card"
	DefaultConfigDir           = "/etc/open-card"
	DefaultDataDir             = "/var/lib/open-card"
	DefaultEvidenceDir         = "/var/lib/open-card/evidence"
	DefaultBackupDir           = "/var/lib/open-card/backups"
)

var semanticVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var protocolPattern = regexp.MustCompile(`^1\.(0|1)$`)
var migrationVersionPattern = regexp.MustCompile(`^[0-9]{4}$`)
var migrationNamePattern = regexp.MustCompile(`^[0-9]{4}_[a-z0-9_]+$`)

// FileDigest is a release file and its content digest. Paths are always
// slash-separated, relative to the release directory.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode,omitempty"`
}

// ValidateProductionCandidate makes the 0.8 deployment contract explicit
// without changing the retained 0.7 RC manifest semantics. It rejects a
// test-only payload before the installer can switch a release pointer.
func ValidateProductionCandidate(manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if manifest.Version != ProductionCandidateVersion || manifest.MigrationVersion != CurrentMigrationVersion {
		return errors.New("manifest is not the 0.8.0-rc.1 production candidate")
	}
	required := map[string]bool{
		"bin/open-card-admin":                                     false,
		"bin/open-card-upgrade":                                   false,
		"systemd/open-card-edge.service":                          false,
		"systemd/open-card-upgrade-recover.service":               false,
		"systemd/open-card-upgrade-safe.target":                   false,
		"systemd/open-card-upgrade-finalize.service":              false,
		"systemd/open-card-edge.service.d/10-upgrade-marker.conf": false,
		"caddy/open-card-edge.Caddyfile.example":                  false,
		"migrations/control-plane/0024_dns_change_ledger.sql":     false,
		"web/dist/index.html":                                     false,
		"docs/licenses/licenses-manifest.json":                    false,
		"sbom.spdx.json":                                          false,
		"source-manifest.sha256":                                  false,
	}
	for _, file := range manifest.Files {
		if strings.Contains(file.Path, "fixture") || strings.Contains(file.Path, "/tests/") || strings.HasSuffix(file.Path, ".test") || strings.Contains(file.Path, "open-card-caddy-fixture") {
			return fmt.Errorf("test-only file is forbidden in production manifest: %s", file.Path)
		}
		if _, ok := required[file.Path]; ok {
			required[file.Path] = true
		}
	}
	for path, found := range required {
		if !found {
			return fmt.Errorf("production manifest is missing %s", path)
		}
	}
	return nil
}

// Compatibility describes the oldest and newest data/protocol contracts that
// a release can read. A range is inclusive. SchemaVersion is the manifest
// format, while data versions are controlled by the control-plane migrations.
type Compatibility struct {
	MinDataVersion     int    `json:"min_data_version"`
	MaxDataVersion     int    `json:"max_data_version"`
	MinAgentProtocol   string `json:"min_agent_protocol"`
	MaxAgentProtocol   string `json:"max_agent_protocol"`
	RequiresDataBackup bool   `json:"requires_data_backup,omitempty"`
}

// Manifest is the checksum-verified description of a release bundle. The
// checksum file itself is not listed in Files; it is verified by the manifest
// loader before the release is considered eligible for activation.
type Manifest struct {
	SchemaVersion    int           `json:"schema_version"`
	Product          string        `json:"product"`
	Version          string        `json:"version"`
	ReleaseID        string        `json:"release_id"`
	Architecture     string        `json:"architecture,omitempty"`
	MigrationVersion string        `json:"migration_version,omitempty"`
	SourceCommit     string        `json:"source_commit,omitempty"`
	NMinusOne        *NMinusOne    `json:"n_minus_one,omitempty"`
	Protocol         string        `json:"protocol"`
	ConfigDir        string        `json:"config_dir"`
	DataDir          string        `json:"data_dir"`
	Compatibility    Compatibility `json:"compatibility"`
	Files            []FileDigest  `json:"files"`
}

type NMinusOne struct {
	Version               string `json:"version"`
	MigrationVersion      string `json:"migration_version"`
	SourceCommit          string `json:"source_commit"`
	ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
	ArchiveSHA256         string `json:"archive_sha256"`
	BundleManifestSHA256  string `json:"bundle_manifest_sha256"`
}

// Directories is the complete path contract. Root is only used by tests and
// staging installers; with an empty root the paths are the production paths.
type Directories struct {
	Root     string
	Prefix   string
	Config   string
	Data     string
	Releases string
	Current  string
	Previous string
	Backups  string
	Evidence string
}

// BackupMetadata accompanies every control-plane backup archive.
type BackupMetadata struct {
	SchemaVersion      int       `json:"schema_version"`
	BackupID           string    `json:"backup_id"`
	CreatedAt          time.Time `json:"created_at"`
	SourceDataDir      string    `json:"source_data_dir"`
	SourceConfigDir    string    `json:"source_config_dir,omitempty"`
	Archive            string    `json:"archive"`
	ArchiveSHA256      string    `json:"archive_sha256"`
	Consistency        string    `json:"consistency"`
	DatabaseDump       string    `json:"database_dump,omitempty"`
	DatabaseDumpSHA256 string    `json:"database_dump_sha256,omitempty"`
	ReleaseVersion     string    `json:"release_version,omitempty"`
	MigrationVersion   string    `json:"migration_version,omitempty"`
	ArchiveSize        int64     `json:"archive_size,omitempty"`
	FileCount          int       `json:"file_count,omitempty"`
	SourceMode         uint32    `json:"source_mode,omitempty"`
	ConfigMode         uint32    `json:"config_mode,omitempty"`
	SourceDigest       string    `json:"source_digest,omitempty"`
	ConfigDigest       string    `json:"config_digest,omitempty"`
	ConfigFileCount    int       `json:"config_file_count,omitempty"`
	ArchiveLayout      string    `json:"archive_layout,omitempty"`
	Reason             string    `json:"reason,omitempty"`
}

// ReleasePointerPlan is the state transition used for an atomic current
// symlink switch. The temporary link is created in the same directory, then
// renamed over Current, so readers observe either the old or new release.
type ReleasePointerPlan struct {
	CurrentRelease  string
	PreviousRelease string
	NextRelease     string
	TemporaryLink   string
}

// ParseVersion validates and returns the semantic release version.
func ParseVersion(version string) error {
	if !semanticVersionPattern.MatchString(strings.TrimSpace(version)) {
		return fmt.Errorf("invalid semantic version %q", version)
	}
	return nil
}

type semanticVersion struct{ major, minor, patch int }

func parseSemanticVersion(value string) (semanticVersion, error) {
	if err := ParseVersion(value); err != nil {
		return semanticVersion{}, err
	}
	base := strings.SplitN(strings.TrimSpace(value), "-", 2)[0]
	base = strings.SplitN(base, "+", 2)[0]
	var parsed semanticVersion
	if _, err := fmt.Sscanf(base, "%d.%d.%d", &parsed.major, &parsed.minor, &parsed.patch); err != nil {
		return semanticVersion{}, fmt.Errorf("parse semantic version %q: %w", value, err)
	}
	return parsed, nil
}

// NormalizeProtocolVersion converts the legacy v1 wire spelling to the
// canonical 1.0 protocol version. Stored manifests and compatibility ranges
// use semantic major.minor values: current 1.1 and N-1 1.0.
func NormalizeProtocolVersion(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == LegacyAgentProtocol {
		return PreviousAgentProtocol, nil
	}
	if !protocolPattern.MatchString(raw) {
		return "", fmt.Errorf("unsupported Agent protocol version %q", raw)
	}
	return raw, nil
}

// NormalizeArchitecture accepts the common kernel spellings and persists one
// stable release-bundle spelling. An omitted architecture remains a legacy
// manifest that can still be validated; callers installing an RC bundle
// should populate it and call CheckArchitecture before activation.
func NormalizeArchitecture(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "any", "all":
		return "", nil
	case "amd64", "x86_64", "x86-64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported release architecture %q", raw)
	}
}

// RuntimeArchitecture returns the normalized architecture spelling used in
// manifests. It is intentionally separate from the shell installer so unit
// tests and alternate installers use the same compatibility rule.
func RuntimeArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

// CheckArchitecture rejects a release that cannot run on the target host.
// Empty/legacy architecture metadata remains compatible for existing bundles.
func CheckArchitecture(manifest Manifest, target string) error {
	architecture, err := NormalizeArchitecture(manifest.Architecture)
	if err != nil {
		return err
	}
	if architecture == "" {
		return nil
	}
	target, err = NormalizeArchitecture(target)
	if err != nil || target == "" {
		return fmt.Errorf("target architecture is invalid: %q", target)
	}
	if architecture != target {
		return fmt.Errorf("release architecture %s is incompatible with target %s", architecture, target)
	}
	return nil
}

// ValidateMigrationVersion checks the four-digit migration identity used by
// RC artifacts. The current production application schema is migration 0024.
func ValidateMigrationVersion(value string) error {
	value = strings.TrimSpace(value)
	if !migrationVersionPattern.MatchString(value) {
		return fmt.Errorf("migration version %q is invalid", value)
	}
	return nil
}

func CheckCurrentMigration(value string) error {
	if err := ValidateMigrationVersion(value); err != nil {
		return err
	}
	if strings.TrimSpace(value) != CurrentMigrationVersion {
		return fmt.Errorf("current migration %s is not required RC migration %s", value, CurrentMigrationVersion)
	}
	return nil
}

// LatestMigrationVersion returns the highest ordered migration filename in a
// directory, e.g. 0024 for 0024_dns_change_ledger.sql. It rejects malformed
// migration names instead of silently skipping a file that could change the
// schema contract.
func LatestMigrationVersion(directory string) (string, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || directory == "" {
		return "", errors.New("migration directory is required")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", fmt.Errorf("read migration directory: %w", err)
	}
	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".sql")
		if !migrationNamePattern.MatchString(base) {
			return "", fmt.Errorf("invalid migration filename %q", name)
		}
		versions = append(versions, base[:4])
	}
	if len(versions) == 0 {
		return "", errors.New("migration directory contains no SQL migrations")
	}
	sort.Strings(versions)
	return versions[len(versions)-1], nil
}

func RequireCurrentMigration(directory string) error {
	latest, err := LatestMigrationVersion(directory)
	if err != nil {
		return err
	}
	return CheckCurrentMigration(latest)
}

// NormalizeManifest returns a canonical copy of a manifest, accepting legacy
// protocol input without allowing that spelling into persisted metadata.
func NormalizeManifest(manifest Manifest) (Manifest, error) {
	normalized := manifest
	var err error
	if normalized.Architecture, err = NormalizeArchitecture(normalized.Architecture); err != nil {
		return Manifest{}, err
	}
	if normalized.MigrationVersion != "" {
		if err := ValidateMigrationVersion(normalized.MigrationVersion); err != nil {
			return Manifest{}, err
		}
	}
	if normalized.Protocol, err = NormalizeProtocolVersion(normalized.Protocol); err != nil {
		return Manifest{}, err
	}
	if normalized.Compatibility.MinAgentProtocol, err = NormalizeProtocolVersion(normalized.Compatibility.MinAgentProtocol); err != nil {
		return Manifest{}, err
	}
	if normalized.Compatibility.MaxAgentProtocol, err = NormalizeProtocolVersion(normalized.Compatibility.MaxAgentProtocol); err != nil {
		return Manifest{}, err
	}
	return normalized, nil
}

func compareSemanticVersions(left, right string) (int, error) {
	l, err := parseSemanticVersion(left)
	if err != nil {
		return 0, err
	}
	r, err := parseSemanticVersion(right)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]int{{l.major, r.major}, {l.minor, r.minor}, {l.patch, r.patch}} {
		if pair[0] < pair[1] {
			return -1, nil
		}
		if pair[0] > pair[1] {
			return 1, nil
		}
	}
	return 0, nil
}

// Validate checks all manifest values that affect filesystem or compatibility
// safety. It is safe to call before opening any file from the bundle.
func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema version %d", m.SchemaVersion)
	}
	if m.Product != ManifestProduct {
		return fmt.Errorf("manifest product %q is not %q", m.Product, ManifestProduct)
	}
	if err := ParseVersion(m.Version); err != nil {
		return err
	}
	if !releaseIDPattern.MatchString(m.ReleaseID) {
		return errors.New("manifest release_id is unsafe")
	}
	if _, err := NormalizeArchitecture(m.Architecture); err != nil {
		return err
	}
	if m.MigrationVersion != "" {
		if err := ValidateMigrationVersion(m.MigrationVersion); err != nil {
			return err
		}
	}
	if m.SourceCommit != "" && !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(m.SourceCommit) {
		return errors.New("manifest source_commit is invalid")
	}
	if m.Version == "0.8.0-rc.0" && m.MigrationVersion == "0023" {
		if m.SourceCommit != RC0SourceCommit || m.NMinusOne != nil {
			return errors.New("rc0 manifest lineage is invalid")
		}
	} else if m.Version == "0.8.0-rc.1" && m.MigrationVersion == "0024" {
		if m.SourceCommit == "" || m.NMinusOne == nil {
			return errors.New("rc1 manifest lineage is required")
		}
		n := m.NMinusOne
		if n.Version != "0.8.0-rc.0" || n.MigrationVersion != "0023" || n.SourceCommit != RC0SourceCommit || n.ReleaseManifestSHA256 != RC0ReleaseManifestSHA256 || n.ArchiveSHA256 != RC0ArchiveSHA256 || n.BundleManifestSHA256 != RC0BundleManifestSHA256 {
			return errors.New("rc1 n_minus_one lineage is invalid")
		}
	} else if m.NMinusOne != nil {
		return errors.New("only rc1/0024 manifests may carry n_minus_one lineage")
	} else if m.SourceCommit != "" {
		return errors.New("only rc0/0023 and rc1/0024 manifests may carry source_commit")
	}
	if _, err := NormalizeProtocolVersion(m.Protocol); err != nil {
		return errors.New("manifest protocol is invalid")
	}
	if strings.TrimSpace(m.ConfigDir) == "" || !filepath.IsAbs(m.ConfigDir) || filepath.Clean(m.ConfigDir) != m.ConfigDir {
		return errors.New("manifest config_dir must be absolute")
	}
	if strings.TrimSpace(m.DataDir) == "" || !filepath.IsAbs(m.DataDir) || filepath.Clean(m.DataDir) != m.DataDir {
		return errors.New("manifest data_dir must be absolute")
	}
	if m.Compatibility.MinDataVersion < 0 || m.Compatibility.MaxDataVersion < 0 || m.Compatibility.MinDataVersion > m.Compatibility.MaxDataVersion {
		return errors.New("manifest data compatibility range is invalid")
	}
	if strings.TrimSpace(m.Compatibility.MinAgentProtocol) == "" || strings.TrimSpace(m.Compatibility.MaxAgentProtocol) == "" {
		return errors.New("manifest agent protocol compatibility range is required")
	}
	if _, err := NormalizeProtocolVersion(m.Compatibility.MinAgentProtocol); err != nil {
		return errors.New("manifest agent protocol compatibility range is invalid")
	}
	if _, err := NormalizeProtocolVersion(m.Compatibility.MaxAgentProtocol); err != nil {
		return errors.New("manifest agent protocol compatibility range is invalid")
	}
	if !protocolInRange(m.Compatibility.MinAgentProtocol, m.Compatibility.MinAgentProtocol, m.Compatibility.MaxAgentProtocol) || !protocolInRange(m.Compatibility.MaxAgentProtocol, m.Compatibility.MinAgentProtocol, m.Compatibility.MaxAgentProtocol) {
		return errors.New("manifest agent protocol compatibility range is invalid")
	}
	if len(m.Files) == 0 {
		return errors.New("manifest files must not be empty")
	}
	seen := make(map[string]struct{}, len(m.Files))
	for _, file := range m.Files {
		if err := validateRelativePath(file.Path); err != nil {
			return fmt.Errorf("manifest file %q: %w", file.Path, err)
		}
		if _, ok := seen[file.Path]; ok {
			return fmt.Errorf("manifest contains duplicate file %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		if !digestPattern.MatchString(file.SHA256) {
			return fmt.Errorf("manifest file %q has invalid sha256", file.Path)
		}
		if file.Mode == 0 || file.Mode > 0o777 || file.Mode&0o022 != 0 {
			return fmt.Errorf("manifest file %q has unsafe mode", file.Path)
		}
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." {
		return errors.New("path must be clean and relative")
	}
	if strings.Contains(path, "\\") {
		return errors.New("path must use slash separators")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path contains an unsafe component")
		}
	}
	return nil
}

// LoadManifest reads and validates a manifest JSON file. Unknown JSON fields
// are rejected so a typo cannot silently weaken a package contract.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("manifest contains trailing JSON")
		}
		return Manifest{}, fmt.Errorf("decode trailing manifest JSON: %w", err)
	}
	manifest, err = NormalizeManifest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// SaveManifest writes deterministic, indented JSON. The caller may use
// AtomicWriteFile when publishing the file into a release directory.
func SaveManifest(path string, manifest Manifest) error {
	normalized, err := NormalizeManifest(manifest)
	if err != nil {
		return err
	}
	if err := normalized.Validate(); err != nil {
		return err
	}
	files := append([]FileDigest(nil), normalized.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	normalized.Files = files
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	data = append(data, '\n')
	return AtomicWriteFile(path, data, 0o644)
}

// SHA256File returns the lower-case SHA-256 digest of a regular file.
func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyRelease verifies every manifest file and rejects symlinks anywhere in
// the release tree. A release is not eligible for activation until this
// function succeeds.
func VerifyRelease(releaseDir string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	releaseDir, err := filepath.Abs(releaseDir)
	if err != nil {
		return fmt.Errorf("resolve release directory: %w", err)
	}
	if info, err := os.Lstat(releaseDir); err != nil {
		return fmt.Errorf("inspect release directory: %w", err)
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("release directory must be a real directory")
	}
	expected := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		expected[filepath.FromSlash(file.Path)] = struct{}{}
	}
	actual := make(map[string]struct{}, len(manifest.Files))
	if err := filepath.WalkDir(releaseDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == releaseDir || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(releaseDir, path)
		if err != nil {
			return err
		}
		if relative == "manifest.json" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unlisted or symlink release entry %q", filepath.ToSlash(relative))
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release entry %q is not regular", filepath.ToSlash(relative))
		}
		actual[relative] = struct{}{}
		return nil
	}); err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("release file set does not match manifest")
	}
	for path := range expected {
		if _, ok := actual[path]; !ok {
			return errors.New("release file set does not match manifest")
		}
	}
	for _, file := range manifest.Files {
		path := filepath.Join(releaseDir, filepath.FromSlash(file.Path))
		if err := ensureNoSymlinkBetween(releaseDir, path); err != nil {
			return fmt.Errorf("release file %q: %w", file.Path, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("release file %q: %w", file.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release file %q is not regular", file.Path)
		}
		if info.Mode().Perm() != os.FileMode(file.Mode) {
			return fmt.Errorf("release file %q mode mismatch: got %04o want %04o", file.Path, info.Mode().Perm(), file.Mode)
		}
		got, err := SHA256File(path)
		if err != nil {
			return err
		}
		if got != file.SHA256 {
			return fmt.Errorf("release file %q checksum mismatch: got %s want %s", file.Path, got, file.SHA256)
		}
	}
	return nil
}

func ensureNoSymlinkBetween(base, path string) error {
	base, err := filepath.Abs(base)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("path escapes release directory")
	}
	current := base
	parts := strings.Split(rel, string(os.PathSeparator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink is not allowed in release path")
		}
	}
	return nil
}

// DirectoriesForRoot maps production absolute paths beneath a staging root.
// An empty root means production paths and should only be used by a caller
// that has already passed its own live-system safety gate.
func DirectoriesForRoot(root string) (Directories, error) {
	if root != "" {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
			return Directories{}, errors.New("staging root must be a clean absolute non-root path")
		}
		root, _ = filepath.Abs(root)
	}
	join := func(path string) string {
		if root == "" {
			return path
		}
		return filepath.Join(root, path)
	}
	return Directories{
		Root: root, Prefix: join(DefaultInstallPrefix), Config: join(DefaultConfigDir), Data: join(DefaultDataDir),
		Releases: join(filepath.Join(DefaultInstallPrefix, "releases")), Current: join(filepath.Join(DefaultInstallPrefix, "current")),
		Previous: join(filepath.Join(DefaultInstallPrefix, "previous")), Backups: join(DefaultBackupDir), Evidence: join(DefaultEvidenceDir),
	}, nil
}

// CheckCompatibility performs the release gate before an upgrade. It rejects
// product changes, manifest incompatibility, protocol drift, and a major
// semantic-version jump. N-1 and patch/minor upgrades remain valid.
func CheckCompatibility(current, candidate Manifest, currentDataVersion int, currentProtocol string) error {
	var err error
	if current, err = NormalizeManifest(current); err != nil {
		return fmt.Errorf("current manifest: %w", err)
	}
	if candidate, err = NormalizeManifest(candidate); err != nil {
		return fmt.Errorf("candidate manifest: %w", err)
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("current manifest: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("candidate manifest: %w", err)
	}
	if candidate.MigrationVersion != "" {
		if err := CheckCurrentMigration(candidate.MigrationVersion); err != nil {
			return fmt.Errorf("candidate migration: %w", err)
		}
	}
	if current.Product != candidate.Product {
		return errors.New("current and candidate products differ")
	}
	currentVersion, err := parseSemanticVersion(current.Version)
	if err != nil {
		return err
	}
	candidateVersion, err := parseSemanticVersion(candidate.Version)
	if err != nil {
		return err
	}
	if candidateVersion.major != currentVersion.major {
		return fmt.Errorf("major version transition %s -> %s is not compatible", current.Version, candidate.Version)
	}
	if candidateVersion.major == currentVersion.major && candidateVersion.minor < currentVersion.minor || candidateVersion.major == currentVersion.major && candidateVersion.minor == currentVersion.minor && candidateVersion.patch < currentVersion.patch {
		return fmt.Errorf("release downgrade %s -> %s requires explicit authorization", current.Version, candidate.Version)
	}
	if currentDataVersion < candidate.Compatibility.MinDataVersion || currentDataVersion > candidate.Compatibility.MaxDataVersion {
		return fmt.Errorf("data version %d is outside candidate compatibility range %d..%d", currentDataVersion, candidate.Compatibility.MinDataVersion, candidate.Compatibility.MaxDataVersion)
	}
	if !protocolInRange(currentProtocol, candidate.Compatibility.MinAgentProtocol, candidate.Compatibility.MaxAgentProtocol) {
		return fmt.Errorf("protocol %q is outside candidate compatibility range %q..%q", currentProtocol, candidate.Compatibility.MinAgentProtocol, candidate.Compatibility.MaxAgentProtocol)
	}
	if !protocolInRange(current.Protocol, candidate.Compatibility.MinAgentProtocol, candidate.Compatibility.MaxAgentProtocol) {
		return fmt.Errorf("current release protocol %q is outside candidate compatibility range", current.Protocol)
	}
	return nil
}

func protocolInRange(value, minimum, maximum string) bool {
	parse := func(input string) (int, bool) {
		canonical, err := NormalizeProtocolVersion(input)
		if err != nil {
			return 0, false
		}
		var major, minor int
		if _, err := fmt.Sscanf(canonical, "%d.%d", &major, &minor); err != nil {
			return 0, false
		}
		return major*100 + minor, true
	}
	v, vok := parse(value)
	min, minok := parse(minimum)
	max, maxok := parse(maximum)
	return vok && minok && maxok && v >= min && v <= max
}

// PlanReleasePointer validates a same-filesystem atomic switch and returns
// paths for the temporary symlink and previous pointer.
func PlanReleasePointer(dirs Directories, currentRelease, nextRelease string) (ReleasePointerPlan, error) {
	if dirs.Prefix == "" || dirs.Releases == "" || dirs.Current == "" {
		return ReleasePointerPlan{}, errors.New("release directory contract is incomplete")
	}
	if err := validateReleasePath(dirs.Releases, nextRelease); err != nil {
		return ReleasePointerPlan{}, fmt.Errorf("next release: %w", err)
	}
	if currentRelease != "" {
		if err := validateReleasePath(dirs.Releases, currentRelease); err != nil {
			return ReleasePointerPlan{}, fmt.Errorf("current release: %w", err)
		}
	}
	return ReleasePointerPlan{
		CurrentRelease:  currentRelease,
		PreviousRelease: currentRelease,
		NextRelease:     nextRelease,
		TemporaryLink:   filepath.Join(dirs.Prefix, ".current.next"),
	}, nil
}

func validateReleasePath(releasesDir, release string) error {
	if release == "" || filepath.IsAbs(release) || filepath.Clean(release) != release || strings.Contains(release, "\\") || strings.Contains(release, string(filepath.Separator)+string(filepath.Separator)) {
		return errors.New("release must be a clean relative path")
	}
	if release == "." || release == ".." || strings.HasPrefix(release, ".."+string(filepath.Separator)) {
		return errors.New("release escapes releases directory")
	}
	_ = releasesDir
	return nil
}

// AtomicSwitchRelease creates a temporary symlink beside Current and renames
// it over Current. Existing Current must itself be a symlink or absent; a real
// directory is rejected to avoid deleting an unmanaged installation.
func AtomicSwitchRelease(dirs Directories, plan ReleasePointerPlan) error {
	if plan.NextRelease == "" {
		return errors.New("release switch target is required")
	}
	releasePath := filepath.Join(dirs.Releases, plan.NextRelease)
	if info, err := os.Lstat(releasePath); err != nil {
		return fmt.Errorf("inspect release switch target: %w", err)
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("release switch target must be a real directory")
	}
	if err := os.MkdirAll(dirs.Prefix, 0o755); err != nil {
		return fmt.Errorf("create install prefix: %w", err)
	}
	if info, err := os.Lstat(dirs.Current); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("current pointer is not a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current pointer: %w", err)
	}
	_ = os.Remove(plan.TemporaryLink)
	if err := os.Symlink(filepath.Join("releases", plan.NextRelease), plan.TemporaryLink); err != nil {
		return fmt.Errorf("create temporary release pointer: %w", err)
	}
	if err := os.Rename(plan.TemporaryLink, dirs.Current); err != nil {
		_ = os.Remove(plan.TemporaryLink)
		return fmt.Errorf("activate release pointer: %w", err)
	}
	return nil
}

// AtomicWriteFile writes a file in the destination directory and renames it
// into place. It does not follow a destination symlink.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if path == "" || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return errors.New("invalid atomic file path")
	}
	parent := filepath.Dir(path)
	if err := ensureNoSymlinkComponents(parent); err != nil {
		return fmt.Errorf("atomic file parent: %w", err)
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", parent, err)
	}
	tmp, err := os.CreateTemp(parent, ".open-card-atomic-*")
	if err != nil {
		return fmt.Errorf("create atomic temporary file: %w", err)
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("atomic destination must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect atomic destination: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("activate atomic file: %w", err)
	}
	return nil
}

func ensureNoSymlinkComponents(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			// macOS exposes /var (and sometimes /tmp) as a stable system
			// symlink to /private/*; accepting only these fixed OS aliases keeps
			// temp-file tests portable without allowing an arbitrary escape.
			if resolveErr == nil && ((current == "/var" && resolved == "/private/var") || (current == "/tmp" && resolved == "/private/tmp")) {
				continue
			}
			return fmt.Errorf("symlink path component %q is not allowed", current)
		}
	}
	return nil
}

// SaveBackupMetadata writes metadata with a deterministic checksum field. The
// archive itself is checked by VerifyBackup before restore.
func SaveBackupMetadata(path string, metadata BackupMetadata) error {
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = ManifestSchemaVersion
	}
	if metadata.Consistency == "" {
		metadata.Consistency = "filesystem-fixture"
	}
	if metadata.SourceDataDir == "" {
		metadata.SourceDataDir = DefaultDataDir
	}
	if metadata.SourceConfigDir == "" {
		metadata.SourceConfigDir = DefaultConfigDir
	}
	if metadata.ArchiveLayout == "" {
		metadata.ArchiveLayout = "m7-v2"
	}
	if err := ValidateBackupMetadata(metadata); err != nil {
		return err
	}
	if metadata.ArchiveSize == 0 && metadata.Archive != "" {
		archive := metadata.Archive
		if !filepath.IsAbs(archive) {
			archive = filepath.Join(filepath.Dir(path), archive)
		}
		if info, err := os.Stat(archive); err == nil {
			metadata.ArchiveSize = info.Size()
		}
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteFile(path, append(data, '\n'), 0o600)
}

// LoadBackupMetadata reads and validates backup metadata.
func LoadBackupMetadata(path string) (BackupMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BackupMetadata{}, err
	}
	var metadata BackupMetadata
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return BackupMetadata{}, fmt.Errorf("decode backup metadata: %w", err)
	}
	if err := ValidateBackupMetadata(metadata); err != nil {
		return BackupMetadata{}, err
	}
	return metadata, nil
}

// ValidateBackupMetadata is shared by file and script-facing callers so a
// restore cannot accept a structurally valid JSON document with unsafe paths,
// a stale RC migration, or world-writable artifact metadata.
func ValidateBackupMetadata(metadata BackupMetadata) error {
	if metadata.SchemaVersion != ManifestSchemaVersion || strings.TrimSpace(metadata.BackupID) == "" || !releaseIDPattern.MatchString(metadata.BackupID) || !digestPattern.MatchString(metadata.ArchiveSHA256) {
		return errors.New("invalid backup metadata")
	}
	if metadata.CreatedAt.IsZero() {
		return errors.New("backup metadata created_at is required")
	}
	if metadata.SourceDataDir != DefaultDataDir {
		return errors.New("backup source data directory is invalid")
	}
	if metadata.SourceConfigDir != "" && metadata.SourceConfigDir != DefaultConfigDir {
		return errors.New("backup source config directory is invalid")
	}
	if !validateBackupRelativePath(metadata.Archive) {
		return errors.New("backup archive path is unsafe")
	}
	if metadata.Consistency != "filesystem-fixture" && metadata.Consistency != "pg-dump" {
		return errors.New("invalid backup consistency")
	}
	if metadata.Consistency == "pg-dump" && (!validateBackupRelativePath(metadata.DatabaseDump) || !digestPattern.MatchString(metadata.DatabaseDumpSHA256)) {
		return errors.New("invalid database dump metadata")
	}
	if metadata.MigrationVersion != "" {
		if err := ValidateMigrationVersion(metadata.MigrationVersion); err != nil {
			return fmt.Errorf("backup migration: %w", err)
		}
	}
	if metadata.ArchiveSize < 0 || metadata.FileCount < 0 || metadata.SourceMode > 999 || metadata.ConfigMode > 999 {
		return errors.New("backup size/count metadata is invalid")
	}
	if metadata.SourceDigest != "" && !digestPattern.MatchString(metadata.SourceDigest) {
		return errors.New("backup source digest is invalid")
	}
	if metadata.ConfigDigest != "" && !digestPattern.MatchString(metadata.ConfigDigest) {
		return errors.New("backup config digest is invalid")
	}
	if metadata.ConfigFileCount < 0 {
		return errors.New("backup config file count is invalid")
	}
	if metadata.ArchiveLayout != "" && metadata.ArchiveLayout != "m7-v2" {
		return errors.New("backup archive layout is invalid")
	}
	return nil
}

func validateBackupRelativePath(path string) bool {
	return path != "" && filepath.Base(path) == path && path != "." && path != ".." && !strings.Contains(path, "\\")
}

// VerifyBackup validates metadata and the archive checksum.
func VerifyBackup(metadataPath string) (BackupMetadata, error) {
	metadata, err := LoadBackupMetadata(metadataPath)
	if err != nil {
		return BackupMetadata{}, err
	}
	archive := filepath.Join(filepath.Dir(metadataPath), metadata.Archive)
	if info, err := os.Lstat(archive); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return BackupMetadata{}, errors.New("backup archive must not be a symlink")
	}
	got, err := SHA256File(archive)
	if err != nil {
		return BackupMetadata{}, err
	}
	if got != metadata.ArchiveSHA256 {
		return BackupMetadata{}, fmt.Errorf("backup checksum mismatch: got %s want %s", got, metadata.ArchiveSHA256)
	}
	if info, err := os.Stat(archive); err == nil && metadata.ArchiveSize > 0 && info.Size() != metadata.ArchiveSize {
		return BackupMetadata{}, fmt.Errorf("backup archive size mismatch: got %d want %d", info.Size(), metadata.ArchiveSize)
	}
	return metadata, nil
}
