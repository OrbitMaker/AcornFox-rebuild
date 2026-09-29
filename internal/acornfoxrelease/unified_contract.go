package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// UnifiedReleaseManifestSchemaV1 is the canonical schema version for UR-20260927-v1.
	UnifiedReleaseManifestSchemaV1 = 1

	// UnifiedProduct locks the product identity.
	UnifiedProduct = "acornfox"

	// UnifiedTargetOS and architecture lock the primary target platform.
	UnifiedTargetOS                  = "linux"
	UnifiedTargetDistribution        = "ubuntu"
	UnifiedTargetDistributionVersion = "24.04"
	UnifiedTargetArchitecture        = "amd64"

	// Bounded size limits for manifest and artifacts.
	maxUnifiedManifestBytes = 64 << 10 // 64 KiB
	maxArtifactSizeBytes    = 1 << 30  // 1 GiB

	// Four fixed named dependencies for the unified release.
	DependencyDocker   = "docker"
	DependencyGit      = "git"
	DependencyBuildKit = "buildkit"
	DependencyCaddy    = "caddy"

	// Fixed components in the unified release.
	ComponentCore                 = "acornfox-core"
	ComponentCLI                  = "acornfox"
	ComponentUI                   = "acornfox-ui"
	ComponentHostUpdate           = "acornfox-host-update"
	ComponentBuildNetworkExecutor = "acornfox-build-network"

	// Exactly three official business roles for the unified release.
	RoleContainerRuntime   = "container-runtime"
	RoleSourceBuild        = "source-build"
	RoleApplicationGateway = "application-gateway"

	// Authorized SQLite migrations (0001–0013).
	Migration0001AdminAuth             = "0001_admin_auth"
	Migration0002ApplicationRepository = "0002_application_repository"
	Migration0003TaskFencing           = "0003_task_fencing"
	Migration0004AuditEvidence         = "0004_audit_evidence"
	Migration0005PackIntents           = "0005_pack_intents"
	Migration0006PackProtocolExecution = "0006_pack_protocol_execution"
	Migration0007PackArtifactStaging   = "0007_pack_artifact_staging"
	Migration0008PackActivation        = "0008_pack_activation"
	Migration0009ImageDelivery         = "0009_image_delivery"
	Migration0010ImageExecution        = "0010_image_execution"
	Migration0011ImageLifecycle        = "0011_image_lifecycle"
	Migration0012SourceBuild           = "0012_source_build"
	Migration0013ImagePublicAccess     = "0013_image_public_access"
)

var (
	ErrUnifiedManifest = errors.New("acornfox unified release manifest is invalid")
	ErrUnifiedTrust    = errors.New("acornfox unified release manifest trust verification failed")

	unifiedSafeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	unifiedReleaseIDPattern = regexp.MustCompile(`^ur-[a-z0-9._-]+$|^release-[a-z0-9._-]+$`)
)

// RollbackPolicyV1 distinguishes binary-only rollback vs a required consistent data restore.
type RollbackPolicyV1 string

const (
	RollbackCompatibleBinaryOnly RollbackPolicyV1 = "binary_only"
	RollbackRequiresDataRestore  RollbackPolicyV1 = "requires_consistent_restore"
)

// SQLiteMigrationPinV1 pairs an authoritative migration version with its expected sha256 checksum.
type SQLiteMigrationPinV1 struct {
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

// SQLiteCompatibilityV1 declares the storage compatibility envelope for the unified release.
type SQLiteCompatibilityV1 struct {
	MinSchemaVersion   string                 `json:"min_schema_version"`
	MaxSchemaVersion   string                 `json:"max_schema_version"`
	RequiredMigrations []SQLiteMigrationPinV1 `json:"required_migrations"`
	ReadWriteMode      string                 `json:"read_write_mode"`
	RollbackPolicy     RollbackPolicyV1       `json:"rollback_policy"`
}

// Validate checks the SQLite compatibility invariants.
func (c SQLiteCompatibilityV1) Validate() error {
	if c.ReadWriteMode != "exclusive_writer" {
		return fmt.Errorf("%w: read_write_mode must be exclusive_writer", ErrUnifiedManifest)
	}
	if c.RollbackPolicy != RollbackCompatibleBinaryOnly && c.RollbackPolicy != RollbackRequiresDataRestore {
		return fmt.Errorf("%w: invalid rollback policy %q", ErrUnifiedManifest, c.RollbackPolicy)
	}
	if c.MinSchemaVersion != Migration0001AdminAuth {
		return fmt.Errorf("%w: min_schema_version must be %s", ErrUnifiedManifest, Migration0001AdminAuth)
	}
	if c.MaxSchemaVersion != Migration0013ImagePublicAccess {
		return fmt.Errorf("%w: max_schema_version must be %s", ErrUnifiedManifest, Migration0013ImagePublicAccess)
	}

	expectedOrder := []string{
		Migration0001AdminAuth,
		Migration0002ApplicationRepository,
		Migration0003TaskFencing,
		Migration0004AuditEvidence,
		Migration0005PackIntents,
		Migration0006PackProtocolExecution,
		Migration0007PackArtifactStaging,
		Migration0008PackActivation,
		Migration0009ImageDelivery,
		Migration0010ImageExecution,
		Migration0011ImageLifecycle,
		Migration0012SourceBuild,
		Migration0013ImagePublicAccess,
	}

	if len(c.RequiredMigrations) != len(expectedOrder) {
		return fmt.Errorf("%w: exactly %d migrations required (0001-0013)", ErrUnifiedManifest, len(expectedOrder))
	}
	for i, m := range c.RequiredMigrations {
		if m.Version != expectedOrder[i] {
			return fmt.Errorf("%w: migration index %d expected %s, got %s", ErrUnifiedManifest, i, expectedOrder[i], m.Version)
		}
		if !digestText.MatchString(m.Checksum) {
			return fmt.Errorf("%w: migration %s has invalid checksum format", ErrUnifiedManifest, m.Version)
		}
	}
	return nil
}

// DeepCopy produces an independent copy of SQLiteCompatibilityV1 with cloned slices.
func (c SQLiteCompatibilityV1) DeepCopy() SQLiteCompatibilityV1 {
	clone := c
	if c.RequiredMigrations != nil {
		clone.RequiredMigrations = make([]SQLiteMigrationPinV1, len(c.RequiredMigrations))
		copy(clone.RequiredMigrations, c.RequiredMigrations)
	}
	return clone
}

// UnifiedProvenanceV1 describes the build and source repository origin of the release.
type UnifiedProvenanceV1 struct {
	SourceRepository string `json:"source_repository"`
	SourceCommit     string `json:"source_commit"`
	BuildTimestamp   string `json:"build_timestamp"`
	ToolchainSHA256  string `json:"toolchain_sha256"`
}

// Validate checks source repository, commit, timestamp and toolchain hashes.
func (p UnifiedProvenanceV1) Validate() error {
	if !validGitHubRepository(p.SourceRepository) {
		return fmt.Errorf("%w: invalid github source repository URL %q", ErrUnifiedManifest, p.SourceRepository)
	}
	if !commitText.MatchString(p.SourceCommit) {
		return fmt.Errorf("%w: invalid git commit format %q", ErrUnifiedManifest, p.SourceCommit)
	}
	if !digestText.MatchString(p.ToolchainSHA256) {
		return fmt.Errorf("%w: invalid toolchain sha256 %q", ErrUnifiedManifest, p.ToolchainSHA256)
	}
	if _, err := time.Parse(time.RFC3339, p.BuildTimestamp); err != nil {
		return fmt.Errorf("%w: invalid build_timestamp format %q: %v", ErrUnifiedManifest, p.BuildTimestamp, err)
	}
	return nil
}

// UnifiedArtifactV1 defines a concrete file artifact in the release tree.
type UnifiedArtifactV1 struct {
	ID           string `json:"id"`
	RelativePath string `json:"relative_path"`
	SizeBytes    int64  `json:"size_bytes"`
	SHA256       string `json:"sha256"`
	Executable   bool   `json:"executable"`
}

// Validate checks artifact metadata for safety, path containment, and digest format.
func (a UnifiedArtifactV1) Validate() error {
	if !unifiedSafeIDPattern.MatchString(a.ID) {
		return fmt.Errorf("%w: invalid artifact id %q", ErrUnifiedManifest, a.ID)
	}
	if a.RelativePath == "" || strings.Contains(a.RelativePath, "\x00") || filepath.IsAbs(a.RelativePath) {
		return fmt.Errorf("%w: artifact %q relative_path must be a clean relative path", ErrUnifiedManifest, a.ID)
	}
	clean := filepath.Clean(a.RelativePath)
	if clean != a.RelativePath || clean == "." || strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("%w: artifact %q path traversal or unclean path %q", ErrUnifiedManifest, a.ID, a.RelativePath)
	}
	if a.SizeBytes <= 0 || a.SizeBytes > maxArtifactSizeBytes {
		return fmt.Errorf("%w: artifact %q size_bytes %d out of bounds (1..%d)", ErrUnifiedManifest, a.ID, a.SizeBytes, maxArtifactSizeBytes)
	}
	if !digestText.MatchString(a.SHA256) {
		return fmt.Errorf("%w: artifact %q sha256 %q is invalid", ErrUnifiedManifest, a.ID, a.SHA256)
	}
	return nil
}

// UnifiedComponentsV1 references the core, CLI, static UI, and host update helper artifacts.
type UnifiedComponentsV1 struct {
	Core                 UnifiedComponentRefV1 `json:"core"`
	CLI                  UnifiedComponentRefV1 `json:"cli"`
	UI                   UnifiedComponentRefV1 `json:"ui"`
	HostUpdate           UnifiedComponentRefV1 `json:"host_update"`
	BuildNetworkExecutor UnifiedComponentRefV1 `json:"build_network_executor"`
}

// UnifiedComponentRefV1 references an artifact by ID.
type UnifiedComponentRefV1 struct {
	ArtifactID string `json:"artifact_id"`
}

// UnifiedRoleV1 declares one official business role. Declarations do not assert that
// missing adapter code is implemented; a role may refer to a shared real runner artifact.
type UnifiedRoleV1 struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	RunnerArtifactID string `json:"runner_artifact_id"`
}

// Validate checks role name and non-empty runner reference.
func (r UnifiedRoleV1) Validate() error {
	if !unifiedSafeIDPattern.MatchString(r.Name) {
		return fmt.Errorf("%w: invalid role name %q", ErrUnifiedManifest, r.Name)
	}
	if r.RunnerArtifactID == "" || !unifiedSafeIDPattern.MatchString(r.RunnerArtifactID) {
		return fmt.Errorf("%w: role %q runner_artifact_id %q is invalid", ErrUnifiedManifest, r.Name, r.RunnerArtifactID)
	}
	return nil
}

// DependencySupportedConditionV1 defines conditions for reusing an existing host tool/service.
// Reused external dependencies do not receive config overwrite or upgrade authority.
type DependencySupportedConditionV1 struct {
	MinVersion  string `json:"min_version"`
	ProbeSocket string `json:"probe_socket,omitempty"`
	ReusePolicy string `json:"reuse_policy"` // must be "reuse_existing_compatible"
}

// DependencyPinnedRecipeV1 is the existing single-archive recipe for Docker
// and Caddy. BuildKit and Git use their own finite multi-source/host-package
// branches instead of pretending one archive contains every runtime member.
type DependencyPinnedRecipeV1 struct {
	ArtifactID         string `json:"artifact_id"`
	SourceURL          string `json:"source_url"`
	SourceSHA256       string `json:"source_sha256"`
	SizeBytes          int64  `json:"size_bytes"`
	TargetRelativePath string `json:"target_relative_path"`
}

// BuildKit has two separately pinned upstream archives. The member map below
// prevents a RootlessKit binary from borrowing BuildKit archive provenance.
type DependencySourceArchiveV1 struct {
	Name         string `json:"name"`
	SourceURL    string `json:"source_url"`
	SourceSHA256 string `json:"source_sha256"`
	SizeBytes    int64  `json:"size_bytes"`
}
type DependencyMemberSourceV1 struct {
	ArtifactID string `json:"artifact_id"`
	SourceName string `json:"source_name"`
}

// Only the two Git-owned Ubuntu packages are provisioned here. Shared OS
// libraries are observed compatibility facts, never claimed as AcornFox files.
type GitHostPackagePinV1 struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	SourceURL     string `json:"source_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	SizeBytes     int64  `json:"size_bytes"`
}
type GitExecutionPinV1 struct {
	Path         string `json:"path"`
	ResolvedPath string `json:"resolved_path"` // exact ELF bytes, not a symlink's text
	SHA256       string `json:"sha256"`
}
type GitHostPackagePolicyV1 struct {
	Packages    []GitHostPackagePinV1 `json:"packages"`
	Executables []GitExecutionPinV1   `json:"executables"`
}

// Validate validates the pinned provisioning recipe without escape hatches.
func (r DependencyPinnedRecipeV1) Validate() error {
	if r.ArtifactID == "" || !unifiedSafeIDPattern.MatchString(r.ArtifactID) {
		return fmt.Errorf("%w: pinned recipe missing or invalid artifact_id %q", ErrUnifiedManifest, r.ArtifactID)
	}
	u, err := url.Parse(r.SourceURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: pinned recipe source_url %q must be a valid https URL", ErrUnifiedManifest, r.SourceURL)
	}
	if !digestText.MatchString(r.SourceSHA256) {
		return fmt.Errorf("%w: pinned recipe invalid source_sha256 %q", ErrUnifiedManifest, r.SourceSHA256)
	}
	if r.SizeBytes <= 0 || r.SizeBytes > maxArtifactSizeBytes {
		return fmt.Errorf("%w: pinned recipe size_bytes %d out of bounds (1..%d)", ErrUnifiedManifest, r.SizeBytes, maxArtifactSizeBytes)
	}
	if r.TargetRelativePath == "" || strings.Contains(r.TargetRelativePath, "\x00") || filepath.IsAbs(r.TargetRelativePath) {
		return fmt.Errorf("%w: pinned recipe target_relative_path %q must be a clean relative path", ErrUnifiedManifest, r.TargetRelativePath)
	}
	clean := filepath.Clean(r.TargetRelativePath)
	if clean != r.TargetRelativePath || clean == "." || strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("%w: pinned recipe target_relative_path traversal %q", ErrUnifiedManifest, r.TargetRelativePath)
	}
	return nil
}

func (s DependencySourceArchiveV1) Validate() error {
	u, err := url.Parse(s.SourceURL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !digestText.MatchString(s.SourceSHA256) || s.SizeBytes <= 0 || s.SizeBytes > maxArtifactSizeBytes {
		return fmt.Errorf("%w: invalid pinned BuildKit source", ErrUnifiedManifest)
	}
	switch s.Name {
	case "buildkit":
		if !strings.HasPrefix(u.Path, "/moby/buildkit/releases/download/v") || !strings.HasPrefix(filepath.Base(u.Path), "buildkit-v") || !strings.HasSuffix(u.Path, ".linux-amd64.tar.gz") {
			return ErrUnifiedManifest
		}
	case "rootlesskit":
		if !strings.HasPrefix(u.Path, "/rootless-containers/rootlesskit/releases/download/v") || filepath.Base(u.Path) != "rootlesskit-x86_64.tar.gz" {
			return ErrUnifiedManifest
		}
	default:
		return ErrUnifiedManifest
	}
	return nil
}

func (p GitHostPackagePolicyV1) Validate() error {
	if len(p.Packages) != 2 || len(p.Executables) != 2 {
		return fmt.Errorf("%w: Git package and executable closure must be finite", ErrUnifiedManifest)
	}
	packages := map[string]bool{}
	packageVersion := ""
	for _, pkg := range p.Packages {
		u, err := url.Parse(pkg.SourceURL)
		if err != nil || u.Scheme != "https" || (u.Host != "archive.ubuntu.com" && u.Host != "security.ubuntu.com") || !strings.HasPrefix(u.Path, "/ubuntu/pool/main/g/git/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !digestText.MatchString(pkg.ArchiveSHA256) || pkg.SizeBytes <= 0 || pkg.SizeBytes > maxArtifactSizeBytes || pkg.Version == "" || len(pkg.Version) > 128 || strings.ContainsAny(pkg.Version, " /\\\t\r\n") || packages[pkg.Name] {
			return fmt.Errorf("%w: Git Ubuntu package pin invalid", ErrUnifiedManifest)
		}
		if pkg.Name == "git" && pkg.Architecture != "amd64" || pkg.Name == "git-man" && pkg.Architecture != "all" || pkg.Name != "git" && pkg.Name != "git-man" {
			return fmt.Errorf("%w: unrelated host package in Git closure", ErrUnifiedManifest)
		}
		archiveVersion := pkg.Version
		if _, withoutEpoch, hasEpoch := strings.Cut(pkg.Version, ":"); hasEpoch {
			archiveVersion = withoutEpoch
		}
		filename := filepath.Base(u.Path)
		if filename != pkg.Name+"_"+archiveVersion+"_"+pkg.Architecture+".deb" ||
			packageVersion != "" && pkg.Version != packageVersion {
			return fmt.Errorf("%w: Git package file or version differs", ErrUnifiedManifest)
		}
		packageVersion = pkg.Version
		packages[pkg.Name] = true
	}
	if !packages["git"] || !packages["git-man"] {
		return ErrUnifiedManifest
	}
	executables := map[string]bool{}
	for _, executable := range p.Executables {
		wantResolved := executable.Path
		if executable.Path == "/usr/lib/git-core/git-remote-https" {
			wantResolved = "/usr/lib/git-core/git-remote-http"
		}
		if executable.Path != "/usr/bin/git" && executable.Path != "/usr/lib/git-core/git-remote-https" || executable.ResolvedPath != wantResolved || !digestText.MatchString(executable.SHA256) || executables[executable.Path] {
			return fmt.Errorf("%w: Git execution closure invalid", ErrUnifiedManifest)
		}
		executables[executable.Path] = true
	}
	if !executables["/usr/bin/git"] || !executables["/usr/lib/git-core/git-remote-https"] {
		return ErrUnifiedManifest
	}
	return nil
}

// UnifiedDependencyPolicyV1 binds external reuse to one of three closed
// provisioning shapes: existing single archive, two BuildKit sources, or the
// Git-owned Ubuntu host packages.
type UnifiedDependencyPolicyV1 struct {
	Name               string                         `json:"name"`
	SupportedCondition DependencySupportedConditionV1 `json:"supported_condition"`
	PinnedProvisioning DependencyPinnedRecipeV1       `json:"pinned_provisioning"`
	RuntimeArtifactIDs []string                       `json:"runtime_artifact_ids"`
	BuildKitSources    []DependencySourceArchiveV1    `json:"buildkit_sources,omitempty"`
	BuildKitMembers    []DependencyMemberSourceV1     `json:"buildkit_members,omitempty"`
	GitHostPackages    *GitHostPackagePolicyV1        `json:"git_host_packages,omitempty"`
}

func validateBuildKitSources(dep UnifiedDependencyPolicyV1, artifacts map[string]UnifiedArtifactV1) error {
	if dep.PinnedProvisioning != (DependencyPinnedRecipeV1{}) || dep.GitHostPackages != nil || len(dep.BuildKitSources) != 2 || len(dep.BuildKitMembers) != 3 || len(dep.RuntimeArtifactIDs) != 3 {
		return fmt.Errorf("%w: BuildKit requires two source archives and three members", ErrUnifiedManifest)
	}
	sources := map[string]bool{}
	for _, source := range dep.BuildKitSources {
		if source.Validate() != nil || sources[source.Name] {
			return ErrUnifiedManifest
		}
		sources[source.Name] = true
	}
	if !sources["buildkit"] || !sources["rootlesskit"] {
		return ErrUnifiedManifest
	}
	memberIDs := map[string]bool{}
	memberPaths := map[string]bool{}
	for _, ref := range dep.BuildKitMembers {
		art, ok := artifacts[ref.ArtifactID]
		if !ok || !art.Executable || memberIDs[ref.ArtifactID] || memberPaths[art.RelativePath] || !slicesContainsString(dep.RuntimeArtifactIDs, ref.ArtifactID) {
			return ErrUnifiedManifest
		}
		wantSource := "buildkit"
		if art.RelativePath == "embedded/bin/rootlesskit" {
			wantSource = "rootlesskit"
		} else if art.RelativePath != "embedded/bin/buildkitd" && art.RelativePath != "embedded/bin/buildctl" {
			return ErrUnifiedManifest
		}
		if ref.SourceName != wantSource {
			return fmt.Errorf("%w: BuildKit member borrowed the wrong archive", ErrUnifiedManifest)
		}
		memberIDs[ref.ArtifactID] = true
		memberPaths[art.RelativePath] = true
	}
	for _, path := range fixedUnifiedDependencyPaths(DependencyBuildKit) {
		if !memberPaths[path] {
			return ErrUnifiedManifest
		}
	}
	return nil
}

// UnifiedReleaseManifestV1 is the authoritative immutable manifest for the unified release.
type UnifiedReleaseManifestV1 struct {
	SchemaVersion             int                         `json:"schema_version"`
	Product                   string                      `json:"product"`
	ReleaseID                 string                      `json:"release_id"`
	Version                   string                      `json:"version"`
	TargetOS                  string                      `json:"target_os"`
	TargetDistribution        string                      `json:"target_distribution"`
	TargetDistributionVersion string                      `json:"target_distribution_version"`
	TargetArchitecture        string                      `json:"target_architecture"`
	Provenance                UnifiedProvenanceV1         `json:"provenance"`
	Components                UnifiedComponentsV1         `json:"components"`
	Roles                     []UnifiedRoleV1             `json:"roles"`
	Artifacts                 []UnifiedArtifactV1         `json:"artifacts"`
	Dependencies              []UnifiedDependencyPolicyV1 `json:"dependencies"`
	SQLiteCompatibility       SQLiteCompatibilityV1       `json:"sqlite_compatibility"`
}

// Validate enforces the complete fixed composition and safety invariants.
func (m UnifiedReleaseManifestV1) Validate() error {
	if m.SchemaVersion != UnifiedReleaseManifestSchemaV1 {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrUnifiedManifest, m.SchemaVersion)
	}
	if m.Product != UnifiedProduct {
		return fmt.Errorf("%w: product must be %s", ErrUnifiedManifest, UnifiedProduct)
	}
	if !unifiedReleaseIDPattern.MatchString(m.ReleaseID) {
		return fmt.Errorf("%w: invalid release_id %q", ErrUnifiedManifest, m.ReleaseID)
	}
	if !versionText.MatchString(m.Version) {
		return fmt.Errorf("%w: invalid version format %q", ErrUnifiedManifest, m.Version)
	}
	if m.TargetOS != UnifiedTargetOS || m.TargetArchitecture != UnifiedTargetArchitecture {
		return fmt.Errorf("%w: target OS/arch must be %s/%s, got %s/%s",
			ErrUnifiedManifest, UnifiedTargetOS, UnifiedTargetArchitecture, m.TargetOS, m.TargetArchitecture)
	}
	if m.TargetDistribution != UnifiedTargetDistribution || m.TargetDistributionVersion != UnifiedTargetDistributionVersion {
		return fmt.Errorf("%w: target distribution must be %s %s, got %s %s",
			ErrUnifiedManifest, UnifiedTargetDistribution, UnifiedTargetDistributionVersion, m.TargetDistribution, m.TargetDistributionVersion)
	}

	if err := m.Provenance.Validate(); err != nil {
		return err
	}
	if err := m.SQLiteCompatibility.Validate(); err != nil {
		return err
	}

	// Validate Artifacts and ensure uniqueness of both ID and RelativePath
	artifactMap := make(map[string]UnifiedArtifactV1, len(m.Artifacts))
	pathMap := make(map[string]string, len(m.Artifacts))
	for _, a := range m.Artifacts {
		if err := a.Validate(); err != nil {
			return err
		}
		if _, exists := artifactMap[a.ID]; exists {
			return fmt.Errorf("%w: duplicate artifact id %q", ErrUnifiedManifest, a.ID)
		}
		if existingID, exists := pathMap[a.RelativePath]; exists {
			return fmt.Errorf("%w: artifact path collision %q between %q and %q", ErrUnifiedManifest, a.RelativePath, a.ID, existingID)
		}
		artifactMap[a.ID] = a
		pathMap[a.RelativePath] = a.ID
	}

	// Validate Components references and verify executable attribute
	componentRefs := []struct {
		name       string
		ref        UnifiedComponentRefV1
		executable bool
	}{
		{ComponentCore, m.Components.Core, true},
		{ComponentCLI, m.Components.CLI, true},
		{ComponentUI, m.Components.UI, false},
		{ComponentHostUpdate, m.Components.HostUpdate, true},
		{ComponentBuildNetworkExecutor, m.Components.BuildNetworkExecutor, true},
	}
	for _, cr := range componentRefs {
		if cr.ref.ArtifactID == "" {
			return fmt.Errorf("%w: component %s missing artifact_id", ErrUnifiedManifest, cr.name)
		}
		art, ok := artifactMap[cr.ref.ArtifactID]
		if !ok {
			return fmt.Errorf("%w: component %s references unknown artifact %q", ErrUnifiedManifest, cr.name, cr.ref.ArtifactID)
		}
		if cr.executable && !art.Executable {
			return fmt.Errorf("%w: component %s artifact %q must be marked executable", ErrUnifiedManifest, cr.name, cr.ref.ArtifactID)
		}
	}

	// Validate Roles: must contain exactly the three official business roles
	requiredRoles := map[string]bool{
		RoleContainerRuntime:   false,
		RoleSourceBuild:        false,
		RoleApplicationGateway: false,
	}
	if len(m.Roles) != len(requiredRoles) {
		return fmt.Errorf("%w: exactly %d official business roles required", ErrUnifiedManifest, len(requiredRoles))
	}
	for _, r := range m.Roles {
		if err := r.Validate(); err != nil {
			return err
		}
		seen, exists := requiredRoles[r.Name]
		if !exists {
			return fmt.Errorf("%w: unexpected role %q", ErrUnifiedManifest, r.Name)
		}
		if seen {
			return fmt.Errorf("%w: duplicate role %q", ErrUnifiedManifest, r.Name)
		}
		requiredRoles[r.Name] = true
		art, ok := artifactMap[r.RunnerArtifactID]
		if !ok {
			return fmt.Errorf("%w: role %q references unknown runner artifact %q", ErrUnifiedManifest, r.Name, r.RunnerArtifactID)
		}
		if !art.Executable {
			return fmt.Errorf("%w: role %q runner artifact %q must be marked executable", ErrUnifiedManifest, r.Name, r.RunnerArtifactID)
		}
		if art.RelativePath != fixedUnifiedRolePath(r.Name) {
			return fmt.Errorf("%w: role %q runner path is not its product adapter", ErrUnifiedManifest, r.Name)
		}
	}

	// Validate Dependencies: must declare exactly the 4 named dependencies with full pinned recipes
	requiredDeps := map[string]bool{
		DependencyDocker:   false,
		DependencyGit:      false,
		DependencyBuildKit: false,
		DependencyCaddy:    false,
	}
	if len(m.Dependencies) != len(requiredDeps) {
		return fmt.Errorf("%w: exactly %d named dependencies required", ErrUnifiedManifest, len(requiredDeps))
	}
	for _, dep := range m.Dependencies {
		seen, exists := requiredDeps[dep.Name]
		if !exists {
			return fmt.Errorf("%w: unexpected dependency %q", ErrUnifiedManifest, dep.Name)
		}
		if seen {
			return fmt.Errorf("%w: duplicate dependency %q", ErrUnifiedManifest, dep.Name)
		}
		requiredDeps[dep.Name] = true
		if dep.SupportedCondition.MinVersion == "" {
			return fmt.Errorf("%w: dependency %s missing supported min_version", ErrUnifiedManifest, dep.Name)
		}
		if dep.SupportedCondition.ReusePolicy != "reuse_existing_compatible" {
			return fmt.Errorf("%w: dependency %s reuse_policy must be reuse_existing_compatible", ErrUnifiedManifest, dep.Name)
		}
		if dep.Name == DependencyGit {
			if dep.PinnedProvisioning != (DependencyPinnedRecipeV1{}) || len(dep.RuntimeArtifactIDs) != 0 || len(dep.BuildKitSources) != 0 || len(dep.BuildKitMembers) != 0 || dep.GitHostPackages == nil || dep.GitHostPackages.Validate() != nil {
				return fmt.Errorf("%w: Git requires only the fixed Ubuntu host package closure", ErrUnifiedManifest)
			}
			for _, artifact := range m.Artifacts {
				if artifact.RelativePath == "embedded/bin/git" {
					return fmt.Errorf("%w: Git host package cannot masquerade as a private ELF", ErrUnifiedManifest)
				}
			}
			continue
		}
		if dep.Name == DependencyBuildKit {
			if dep.SupportedCondition.ProbeSocket != "/run/acornfox-buildkit/buildkitd.sock" {
				return fmt.Errorf("%w: BuildKit worker probe socket is required", ErrUnifiedManifest)
			}
			if err := validateBuildKitSources(dep, artifactMap); err != nil {
				return err
			}
			continue
		}
		if len(dep.BuildKitSources) != 0 || len(dep.BuildKitMembers) != 0 || dep.GitHostPackages != nil {
			return fmt.Errorf("%w: unrelated dependency cannot claim BuildKit or Git provenance", ErrUnifiedManifest)
		}
		if err := dep.PinnedProvisioning.Validate(); err != nil {
			return fmt.Errorf("%w: dependency %s: %v", ErrUnifiedManifest, dep.Name, err)
		}
		art, ok := artifactMap[dep.PinnedProvisioning.ArtifactID]
		if !ok {
			return fmt.Errorf("%w: dependency %s pinned recipe references unknown artifact %q",
				ErrUnifiedManifest, dep.Name, dep.PinnedProvisioning.ArtifactID)
		}
		if dep.Name == DependencyDocker && dep.SupportedCondition.ProbeSocket != "/var/run/docker.sock" {
			return fmt.Errorf("%w: Docker Engine probe socket is required", ErrUnifiedManifest)
		}
		paths := fixedUnifiedDependencyPaths(dep.Name)
		if len(dep.RuntimeArtifactIDs) != len(paths) {
			return fmt.Errorf("%w: dependency %s runtime closure is incomplete", ErrUnifiedManifest, dep.Name)
		}
		members := make(map[string]bool, len(paths))
		for _, id := range dep.RuntimeArtifactIDs {
			member, found := artifactMap[id]
			if !found || members[member.RelativePath] || !member.Executable {
				return fmt.Errorf("%w: dependency %s runtime member is invalid", ErrUnifiedManifest, dep.Name)
			}
			members[member.RelativePath] = true
		}
		for _, path := range paths {
			if !members[path] {
				return fmt.Errorf("%w: dependency %s missing runtime member %s", ErrUnifiedManifest, dep.Name, path)
			}
		}
		if !slicesContainsString(dep.RuntimeArtifactIDs, dep.PinnedProvisioning.ArtifactID) {
			return fmt.Errorf("%w: dependency %s recipe is outside runtime closure", ErrUnifiedManifest, dep.Name)
		}
		if art.RelativePath != dep.PinnedProvisioning.TargetRelativePath {
			return fmt.Errorf("%w: dependency %s target path mismatch between recipe (%s) and artifact (%s)",
				ErrUnifiedManifest, dep.Name, dep.PinnedProvisioning.TargetRelativePath, art.RelativePath)
		}
	}
	policyExecutor := artifactMap[m.Components.BuildNetworkExecutor.ArtifactID]
	if policyExecutor.RelativePath != "bin/acornfox-build-network" {
		return fmt.Errorf("%w: root build policy executor is not the managed AcornFox component", ErrUnifiedManifest)
	}
	// Each business adapter and the root policy executor is a distinct executable,
	// even when an inventory assigns different paths and artifact IDs to copied bytes.
	roleSHA := make(map[string]bool, len(m.Roles))
	for _, role := range m.Roles {
		runner := artifactMap[role.RunnerArtifactID]
		if roleSHA[runner.SHA256] {
			return fmt.Errorf("%w: business role executables share bytes", ErrUnifiedManifest)
		}
		roleSHA[runner.SHA256] = true
	}
	for _, id := range []string{m.Components.Core.ArtifactID, m.Components.CLI.ArtifactID, m.Components.HostUpdate.ArtifactID} {
		if policyExecutor.SHA256 == artifactMap[id].SHA256 {
			return fmt.Errorf("%w: build policy executor impersonates a core component", ErrUnifiedManifest)
		}
	}
	if roleSHA[policyExecutor.SHA256] {
		return fmt.Errorf("%w: build policy executor impersonates a business role", ErrUnifiedManifest)
	}
	for _, role := range m.Roles {
		runner := artifactMap[role.RunnerArtifactID]
		for _, dep := range m.Dependencies {
			for _, id := range dep.RuntimeArtifactIDs {
				member := artifactMap[id]
				if runner.ID == member.ID || runner.SHA256 == member.SHA256 || policyExecutor.ID == member.ID || policyExecutor.SHA256 == member.SHA256 {
					return fmt.Errorf("%w: managed role or policy executor impersonates dependency member", ErrUnifiedManifest)
				}
			}
		}
	}
	return nil
}

func fixedUnifiedRolePath(name string) string {
	switch name {
	case RoleContainerRuntime:
		return "bin/acornfox-container"
	case RoleSourceBuild:
		return "bin/acornfox-source-build"
	case RoleApplicationGateway:
		return "bin/acornfox-gateway"
	default:
		return ""
	}
}
func fixedUnifiedDependencyPaths(name string) []string {
	switch name {
	case DependencyDocker:
		return []string{"embedded/bin/docker", "embedded/bin/dockerd", "embedded/bin/containerd", "embedded/bin/containerd-shim-runc-v2", "embedded/bin/runc", "embedded/bin/docker-proxy"}
	case DependencyGit:
		return nil // Ubuntu host package, never a private copied ELF.
	case DependencyBuildKit:
		return []string{"embedded/bin/buildkitd", "embedded/bin/buildctl", "embedded/bin/rootlesskit"}
	case DependencyCaddy:
		return []string{"embedded/bin/caddy"}
	default:
		return nil
	}
}
func slicesContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// CanonicalUnifiedManifestV1 serializes a valid manifest into canonical JSON bytes.
func CanonicalUnifiedManifestV1(manifest UnifiedReleaseManifestV1) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

// UnifiedManifestWitness is an immutable wrapper over a parsed and verified manifest.
type UnifiedManifestWitness struct {
	manifest        UnifiedReleaseManifestV1
	canonicalSHA256 string
	valid           bool
}

// Valid returns whether the witness wraps a valid parsed manifest.
func (w UnifiedManifestWitness) Valid() bool {
	return w.valid && w.manifest.Validate() == nil
}

// ManifestSHA256 returns the canonical SHA256 digest of the manifest bytes.
func (w UnifiedManifestWitness) ManifestSHA256() (string, error) {
	if !w.Valid() {
		return "", ErrUnifiedManifest
	}
	return w.canonicalSHA256, nil
}

// Snapshot returns a completely deep-copied, independent snapshot of the verified manifest.
func (w UnifiedManifestWitness) Snapshot() (UnifiedReleaseManifestV1, error) {
	if !w.Valid() {
		return UnifiedReleaseManifestV1{}, ErrUnifiedManifest
	}
	m := w.manifest
	if w.manifest.Artifacts != nil {
		m.Artifacts = make([]UnifiedArtifactV1, len(w.manifest.Artifacts))
		copy(m.Artifacts, w.manifest.Artifacts)
	}
	if w.manifest.Roles != nil {
		m.Roles = make([]UnifiedRoleV1, len(w.manifest.Roles))
		copy(m.Roles, w.manifest.Roles)
	}
	if w.manifest.Dependencies != nil {
		m.Dependencies = make([]UnifiedDependencyPolicyV1, len(w.manifest.Dependencies))
		copy(m.Dependencies, w.manifest.Dependencies)
		for i := range m.Dependencies {
			if ids := w.manifest.Dependencies[i].RuntimeArtifactIDs; ids != nil {
				m.Dependencies[i].RuntimeArtifactIDs = make([]string, len(ids))
				copy(m.Dependencies[i].RuntimeArtifactIDs, ids)
			}
			m.Dependencies[i].BuildKitSources = append([]DependencySourceArchiveV1(nil), w.manifest.Dependencies[i].BuildKitSources...)
			m.Dependencies[i].BuildKitMembers = append([]DependencyMemberSourceV1(nil), w.manifest.Dependencies[i].BuildKitMembers...)
			if policy := w.manifest.Dependencies[i].GitHostPackages; policy != nil {
				copyPolicy := *policy
				copyPolicy.Packages = append([]GitHostPackagePinV1(nil), policy.Packages...)
				copyPolicy.Executables = append([]GitExecutionPinV1(nil), policy.Executables...)
				m.Dependencies[i].GitHostPackages = &copyPolicy
			}
		}
	}
	m.SQLiteCompatibility = w.manifest.SQLiteCompatibility.DeepCopy()
	return m, nil
}

// Artifact returns a single artifact by ID.
func (w UnifiedManifestWitness) Artifact(id string) (UnifiedArtifactV1, error) {
	if !w.Valid() {
		return UnifiedArtifactV1{}, ErrUnifiedManifest
	}
	for _, a := range w.manifest.Artifacts {
		if a.ID == id {
			return a, nil
		}
	}
	return UnifiedArtifactV1{}, fmt.Errorf("%w: artifact %q not found", ErrUnifiedManifest, id)
}

// ComponentArtifact returns the artifact backing a named core component.
func (w UnifiedManifestWitness) ComponentArtifact(component string) (UnifiedArtifactV1, error) {
	if !w.Valid() {
		return UnifiedArtifactV1{}, ErrUnifiedManifest
	}
	var artID string
	switch component {
	case ComponentCore:
		artID = w.manifest.Components.Core.ArtifactID
	case ComponentCLI:
		artID = w.manifest.Components.CLI.ArtifactID
	case ComponentUI:
		artID = w.manifest.Components.UI.ArtifactID
	case ComponentHostUpdate:
		artID = w.manifest.Components.HostUpdate.ArtifactID
	case ComponentBuildNetworkExecutor:
		artID = w.manifest.Components.BuildNetworkExecutor.ArtifactID
	default:
		return UnifiedArtifactV1{}, fmt.Errorf("%w: unknown component %q", ErrUnifiedManifest, component)
	}
	return w.Artifact(artID)
}

// ParseUnifiedManifestV1 parses raw JSON into a validated witness.
// Structural parsing alone does not verify trusted provenance.
func ParseUnifiedManifestV1(raw []byte) (UnifiedManifestWitness, error) {
	if len(raw) == 0 || len(raw) > maxUnifiedManifestBytes {
		return UnifiedManifestWitness{}, fmt.Errorf("%w: raw manifest size %d out of bounds (1..%d)", ErrUnifiedManifest, len(raw), maxUnifiedManifestBytes)
	}

	var manifest UnifiedReleaseManifestV1
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return UnifiedManifestWitness{}, fmt.Errorf("%w: json decode: %v", ErrUnifiedManifest, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return UnifiedManifestWitness{}, fmt.Errorf("%w: unexpected trailing tokens", ErrUnifiedManifest)
	}

	canonical, err := CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		return UnifiedManifestWitness{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return UnifiedManifestWitness{}, fmt.Errorf("%w: raw bytes are not in canonical JSON form", ErrUnifiedManifest)
	}

	cSHA := sha256Text(canonical)
	return UnifiedManifestWitness{
		manifest:        manifest,
		canonicalSHA256: cSHA,
		valid:           true,
	}, nil
}

// TrustedReleasePinV1 is an independently supplied trusted provenance pin.
// A self-declared digest inside a manifest is never accepted as trusted verification.
type TrustedReleasePinV1 struct {
	ExpectedReleaseID      string `json:"expected_release_id"`
	ExpectedManifestSHA256 string `json:"expected_manifest_sha256"`
	ExpectedSourceCommit   string `json:"expected_source_commit"`
}

// VerifyUnifiedManifestTrust checks a parsed witness against an independently supplied pin.
// It performs trusted comparison of expected manifest SHA256, release ID, and source commit.
func VerifyUnifiedManifestTrust(witness UnifiedManifestWitness, pin TrustedReleasePinV1) error {
	if !witness.Valid() {
		return ErrUnifiedManifest
	}
	if !digestText.MatchString(pin.ExpectedManifestSHA256) {
		return fmt.Errorf("%w: invalid expected manifest sha256 format", ErrUnifiedTrust)
	}
	if !commitText.MatchString(pin.ExpectedSourceCommit) {
		return fmt.Errorf("%w: invalid expected source commit format", ErrUnifiedTrust)
	}

	actualSHA, err := witness.ManifestSHA256()
	if err != nil || actualSHA != pin.ExpectedManifestSHA256 {
		return fmt.Errorf("%w: manifest sha256 mismatch (actual %s, expected %s)", ErrUnifiedTrust, actualSHA, pin.ExpectedManifestSHA256)
	}

	snap, err := witness.Snapshot()
	if err != nil {
		return err
	}

	if snap.ReleaseID != pin.ExpectedReleaseID {
		return fmt.Errorf("%w: release id mismatch (actual %s, expected %s)", ErrUnifiedTrust, snap.ReleaseID, pin.ExpectedReleaseID)
	}

	if snap.Provenance.SourceCommit != pin.ExpectedSourceCommit {
		return fmt.Errorf("%w: source commit mismatch (actual %s, expected %s)", ErrUnifiedTrust, snap.Provenance.SourceCommit, pin.ExpectedSourceCommit)
	}

	return nil
}
