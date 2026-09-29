package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// UnifiedInstallPrefix is the root installation path for AcornFox.
	UnifiedInstallPrefix = "/opt/acornfox"

	// UnifiedReleasesDir is the root directory for immutable versioned releases.
	UnifiedReleasesDir = "/opt/acornfox/releases"

	// UnifiedCurrentSymlink is the atomic pointer to the active release.
	UnifiedCurrentSymlink = "/opt/acornfox/current"

	// UnifiedConfigDir is the root directory for host configuration.
	UnifiedConfigDir = "/etc/acornfox"

	// UnifiedCoreConfigFile is the private configuration file for Core.
	UnifiedCoreConfigFile = "/etc/acornfox/core.json"

	// UnifiedManifestFile is the current active manifest copy.
	UnifiedManifestFile = "/etc/acornfox/manifest.json"

	// UnifiedTrustDir is the root-owned trust policy directory.
	UnifiedTrustDir = "/etc/acornfox/trust"

	// UnifiedDataRootDir is the parent state directory for AcornFox.
	UnifiedDataRootDir = "/var/lib/acornfox"

	// UnifiedCoreDataDir is the private SQLite directory owned exclusively by Core.
	// Store requires an absolute directory owned by the current UID with mode 0700.
	UnifiedCoreDataDir = "/var/lib/acornfox/core"

	// UnifiedDefaultDBName is the default SQLite file basename.
	UnifiedDefaultDBName = "acornfox.db"

	// UnifiedBackupDir is the private backup directory for Core state.
	UnifiedBackupDir = "/var/lib/acornfox/backups"

	// Role-private state directories under UnifiedDataRootDir.
	UnifiedContainerStateDir = "/var/lib/acornfox/container"
	UnifiedBuildStateDir     = "/var/lib/acornfox/build"
	UnifiedGatewayStateDir   = "/var/lib/acornfox/gateway"

	// UnifiedLogRootDir is the system logging root for AcornFox services.
	UnifiedLogRootDir = "/var/log/acornfox"

	// UnifiedRunRootDir is the runtime socket/PID root directory.
	UnifiedRunRootDir = "/run/acornfox"

	// Service account names for the unified architecture.
	AccountCore             = "acornfox-core"
	AccountContainerRuntime = "acornfox-container"
	AccountSourceBuild      = "acornfox-build"
	AccountGateway          = "acornfox-gateway"
	AccountPeerIPC          = "acornfox-ipc"

	// Canonical role names.
	RoleNameCore               = "core"
	RoleNameContainerRuntime   = "container-runtime"
	RoleNameSourceBuild        = "source-build"
	RoleNameApplicationGateway = "application-gateway"

	// Standard shell for daemon accounts.
	DefaultNoLoginShell = "/usr/sbin/nologin"
)

var (
	ErrLayoutValidation = errors.New("unified layout security validation failed")
	safeBasenameRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

// RoleIdentityRequirement purely specifies the security and capability constraints
// required for each service role without mutating host users or groups.
type RoleIdentityRequirement struct {
	ServiceUser           string   `json:"service_user"`
	PrimaryGroup          string   `json:"primary_group"`
	SupplementaryGroups   []string `json:"supplementary_groups,omitempty"`
	LoginShell            string   `json:"login_shell"`
	AllowRoot             bool     `json:"allow_root"`
	AllowSudo             bool     `json:"allow_sudo"`
	AllowDockerGroup      bool     `json:"allow_docker_group"`
	RootlessUserNamespace bool     `json:"rootless_user_namespace"`
	AmbientCapabilities   []string `json:"ambient_capabilities,omitempty"`
}

// UnifiedIPCRequirement is the fixed shared access contract for the protected
// binding and local peer/helper sockets. The host publisher must actually set
// these group/mode facts; this pure layout descriptor does not mutate them.
type UnifiedIPCRequirement struct {
	Group            string `json:"group"`
	BindingOwner     string `json:"binding_owner"`
	BindingMode      uint32 `json:"binding_mode"`
	PeerSocketMode   uint32 `json:"peer_socket_mode"`
	HelperSocketMode uint32 `json:"helper_socket_mode"`
}

// HostIdentityAllocation honestly describes whether a role's UID/GID has been
// resolved by the host or is still pending allocation. No fake preallocated UIDs are used.
type HostIdentityAllocation struct {
	RoleName  string `json:"role_name"`
	Allocated bool   `json:"allocated"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	Status    string `json:"status"` // "pending_host_allocation" | "resolved"
}

func isValidRoleName(roleName string) bool {
	switch roleName {
	case RoleNameCore, RoleNameContainerRuntime, RoleNameSourceBuild, RoleNameApplicationGateway:
		return true
	default:
		return false
	}
}

// NewUnallocatedIdentity returns an honest pending allocation descriptor for a known role.
func NewUnallocatedIdentity(roleName string) (HostIdentityAllocation, error) {
	if !isValidRoleName(roleName) {
		return HostIdentityAllocation{}, fmt.Errorf("unknown role name %q for identity allocation", roleName)
	}
	return HostIdentityAllocation{
		RoleName:  roleName,
		Allocated: false,
		UID:       -1,
		GID:       -1,
		Status:    "pending_host_allocation",
	}, nil
}

// NewResolvedIdentity returns a resolved identity descriptor from actual host state.
// All service roles are strictly non-root; UID 0 and GID 0 are rejected.
func NewResolvedIdentity(roleName string, uid, gid int) (HostIdentityAllocation, error) {
	if !isValidRoleName(roleName) {
		return HostIdentityAllocation{}, fmt.Errorf("unknown role name %q for identity resolution", roleName)
	}
	if uid <= 0 || gid <= 0 {
		return HostIdentityAllocation{}, fmt.Errorf("invalid non-root uid/gid (%d/%d) for role %s", uid, gid, roleName)
	}
	return HostIdentityAllocation{
		RoleName:  roleName,
		Allocated: true,
		UID:       uid,
		GID:       gid,
		Status:    "resolved",
	}, nil
}

// DefaultRoleIdentityRequirements returns the canonical security requirements for all roles.
func DefaultRoleIdentityRequirements() map[string]RoleIdentityRequirement {
	return map[string]RoleIdentityRequirement{
		RoleNameCore: {
			ServiceUser:           AccountCore,
			PrimaryGroup:          AccountCore,
			SupplementaryGroups:   []string{AccountPeerIPC},
			LoginShell:            DefaultNoLoginShell,
			AllowRoot:             false,
			AllowSudo:             false,
			AllowDockerGroup:      false, // Core MUST NOT receive docker-group capability
			RootlessUserNamespace: false,
			AmbientCapabilities:   nil,
		},
		RoleNameContainerRuntime: {
			ServiceUser:           AccountContainerRuntime,
			PrimaryGroup:          AccountContainerRuntime,
			SupplementaryGroups:   []string{AccountPeerIPC, "docker"}, // IPC plus the container role's fixed Docker boundary.
			LoginShell:            DefaultNoLoginShell,
			AllowRoot:             false,
			AllowSudo:             false,
			AllowDockerGroup:      true,
			RootlessUserNamespace: false,
			AmbientCapabilities:   nil,
		},
		RoleNameSourceBuild: {
			ServiceUser:           AccountSourceBuild,
			PrimaryGroup:          AccountSourceBuild,
			SupplementaryGroups:   []string{AccountPeerIPC},
			LoginShell:            DefaultNoLoginShell,
			AllowRoot:             false,
			AllowSudo:             false,
			AllowDockerGroup:      false,
			RootlessUserNamespace: false, // Rootlesskit belongs to the separate BuildKit worker, not this adapter.
			AmbientCapabilities:   nil,
		},
		RoleNameApplicationGateway: {
			ServiceUser:           AccountGateway,
			PrimaryGroup:          AccountGateway,
			SupplementaryGroups:   []string{AccountPeerIPC},
			LoginShell:            DefaultNoLoginShell,
			AllowRoot:             false,
			AllowSudo:             false,
			AllowDockerGroup:      false,
			RootlessUserNamespace: false,
			AmbientCapabilities:   nil, // The separate Caddy edge unit binds 443.
		},
	}
}

// UnifiedLayoutSpec contains the complete static directory and permission layout specification.
type UnifiedLayoutSpec struct {
	ReleasesDir         string                             `json:"releases_dir"`
	CurrentSymlink      string                             `json:"current_symlink"`
	ConfigDir           string                             `json:"config_dir"`
	CoreConfigFile      string                             `json:"core_config_file"`
	CoreConfigFileOwner string                             `json:"core_config_file_owner"` // "root"
	CoreConfigFileGroup string                             `json:"core_config_file_group"` // AccountCore ("acornfox-core")
	CoreConfigFileMode  uint32                             `json:"core_config_file_mode"`  // 0640 (root:acornfox-core)
	ManifestFile        string                             `json:"manifest_file"`
	ManifestFileOwner   string                             `json:"manifest_file_owner"` // "root"
	ManifestFileGroup   string                             `json:"manifest_file_group"` // "root"
	ManifestFileMode    uint32                             `json:"manifest_file_mode"`  // 0644 (root:root)
	TrustDir            string                             `json:"trust_dir"`
	TrustDirOwner       string                             `json:"trust_dir_owner"` // "root"
	TrustDirGroup       string                             `json:"trust_dir_group"` // "root"
	TrustDirMode        uint32                             `json:"trust_dir_mode"`  // 0755 (root:root)
	DataRootDir         string                             `json:"data_root_dir"`
	CoreDataDir         string                             `json:"core_data_dir"`
	CoreDataDirMode     uint32                             `json:"core_data_dir_mode"` // 0700 (acornfox-core)
	CoreDBName          string                             `json:"core_db_name"`
	BackupDir           string                             `json:"backup_dir"`
	BackupDirMode       uint32                             `json:"backup_dir_mode"` // 0700 (acornfox-core)
	RoleStateDirs       map[string]string                  `json:"role_state_dirs"`
	RoleStateDirModes   map[string]uint32                  `json:"role_state_dir_modes"` // 0700 per role
	RoleIdentities      map[string]RoleIdentityRequirement `json:"role_identities"`
	IPC                 UnifiedIPCRequirement              `json:"ipc"`
}

// DefaultUnifiedLayoutSpec returns the canonical pure layout specification.
func DefaultUnifiedLayoutSpec() UnifiedLayoutSpec {
	return UnifiedLayoutSpec{
		ReleasesDir:         UnifiedReleasesDir,
		CurrentSymlink:      UnifiedCurrentSymlink,
		ConfigDir:           UnifiedConfigDir,
		CoreConfigFile:      UnifiedCoreConfigFile,
		CoreConfigFileOwner: "root",
		CoreConfigFileGroup: AccountCore,
		CoreConfigFileMode:  0o640,
		ManifestFile:        UnifiedManifestFile,
		ManifestFileOwner:   "root",
		ManifestFileGroup:   "root",
		ManifestFileMode:    0o644,
		TrustDir:            UnifiedTrustDir,
		TrustDirOwner:       "root",
		TrustDirGroup:       "root",
		TrustDirMode:        0o755,
		DataRootDir:         UnifiedDataRootDir,
		CoreDataDir:         UnifiedCoreDataDir,
		CoreDataDirMode:     0o700,
		CoreDBName:          UnifiedDefaultDBName,
		BackupDir:           UnifiedBackupDir,
		BackupDirMode:       0o700,
		RoleStateDirs: map[string]string{
			RoleNameContainerRuntime:   UnifiedContainerStateDir,
			RoleNameSourceBuild:        UnifiedBuildStateDir,
			RoleNameApplicationGateway: UnifiedGatewayStateDir,
		},
		RoleStateDirModes: map[string]uint32{
			RoleNameContainerRuntime:   0o700,
			RoleNameSourceBuild:        0o700,
			RoleNameApplicationGateway: 0o700,
		},
		RoleIdentities: DefaultRoleIdentityRequirements(),
		IPC: UnifiedIPCRequirement{
			Group:            AccountPeerIPC,
			BindingOwner:     "root",
			BindingMode:      0o640,
			PeerSocketMode:   0o660,
			HelperSocketMode: 0o660,
		},
	}
}

// ValidateDBBasename enforces the exact SQLite Store contract for database file names:
// clean single file basename, not ".", no path separators, not acornfox.lock, not wal/shm.
func ValidateDBBasename(dbName string) error {
	trimmed := strings.TrimSpace(dbName)
	if trimmed == "" {
		return errors.New("sqlite db name cannot be empty")
	}
	if trimmed == "." || filepath.Base(trimmed) != trimmed || strings.ContainsAny(trimmed, "/\\:\x00") || strings.Contains(trimmed, "..") {
		return errors.New("sqlite db name must be a clean single file basename")
	}
	if trimmed == "acornfox.lock" || strings.HasSuffix(trimmed, "-wal") || strings.HasSuffix(trimmed, "-shm") {
		return errors.New("sqlite db name is reserved")
	}
	return nil
}

// ValidateUnifiedLayoutSecurity performs pure structural and security validation of the layout.
// It enforces that Core owns an isolated 0700 data dir, Core does not receive root/sudo/docker group,
// trusted config is root-owned and read-only for Core (0640), all role state dirs are isolated and
// under data root, and paths match the canonical UR constants and parent/child hierarchy.
func ValidateUnifiedLayoutSecurity(spec UnifiedLayoutSpec) error {
	// 1. Enforce canonical root paths
	if spec.ReleasesDir != UnifiedReleasesDir {
		return fmt.Errorf("%w: releases_dir must be %s, got %s", ErrLayoutValidation, UnifiedReleasesDir, spec.ReleasesDir)
	}
	if spec.CurrentSymlink != UnifiedCurrentSymlink {
		return fmt.Errorf("%w: current_symlink must be %s, got %s", ErrLayoutValidation, UnifiedCurrentSymlink, spec.CurrentSymlink)
	}
	if spec.ConfigDir != UnifiedConfigDir {
		return fmt.Errorf("%w: config_dir must be %s, got %s", ErrLayoutValidation, UnifiedConfigDir, spec.ConfigDir)
	}
	if spec.DataRootDir != UnifiedDataRootDir {
		return fmt.Errorf("%w: data_root_dir must be %s, got %s", ErrLayoutValidation, UnifiedDataRootDir, spec.DataRootDir)
	}

	// 2. Enforce strict config parent/child hierarchy
	if filepath.Dir(spec.CoreConfigFile) != spec.ConfigDir || filepath.Base(spec.CoreConfigFile) != "core.json" {
		return fmt.Errorf("%w: core_config_file %s must reside directly in config_dir %s as core.json",
			ErrLayoutValidation, spec.CoreConfigFile, spec.ConfigDir)
	}
	if filepath.Dir(spec.ManifestFile) != spec.ConfigDir || filepath.Base(spec.ManifestFile) != "manifest.json" {
		return fmt.Errorf("%w: manifest_file %s must reside directly in config_dir %s as manifest.json",
			ErrLayoutValidation, spec.ManifestFile, spec.ConfigDir)
	}
	if filepath.Dir(spec.TrustDir) != spec.ConfigDir || filepath.Base(spec.TrustDir) != "trust" {
		return fmt.Errorf("%w: trust_dir %s must reside directly in config_dir %s as trust",
			ErrLayoutValidation, spec.TrustDir, spec.ConfigDir)
	}

	// 3. Enforce trusted config ownership and permissions (root-owned, group core-readable, never core-writable)
	if spec.CoreConfigFileOwner != "root" || spec.CoreConfigFileGroup != AccountCore || spec.CoreConfigFileMode != 0o640 {
		return fmt.Errorf("%w: core_config_file must be owned by root:%s with mode 0640 (got %s:%s %o)",
			ErrLayoutValidation, AccountCore, spec.CoreConfigFileOwner, spec.CoreConfigFileGroup, spec.CoreConfigFileMode)
	}
	if spec.ManifestFileOwner != "root" || spec.ManifestFileGroup != "root" || spec.ManifestFileMode != 0o644 {
		return fmt.Errorf("%w: manifest_file must be owned by root:root with mode 0644 (got %s:%s %o)",
			ErrLayoutValidation, spec.ManifestFileOwner, spec.ManifestFileGroup, spec.ManifestFileMode)
	}
	if spec.TrustDirOwner != "root" || spec.TrustDirGroup != "root" || spec.TrustDirMode != 0o755 {
		return fmt.Errorf("%w: trust_dir must be owned by root:root with mode 0755 (got %s:%s %o)",
			ErrLayoutValidation, spec.TrustDirOwner, spec.TrustDirGroup, spec.TrustDirMode)
	}

	// 4. Enforce Core data directory & backup directory parent/child hierarchy
	if filepath.Dir(spec.CoreDataDir) != spec.DataRootDir || filepath.Base(spec.CoreDataDir) != "core" {
		return fmt.Errorf("%w: core_data_dir %s must reside directly under data_root_dir %s as core",
			ErrLayoutValidation, spec.CoreDataDir, spec.DataRootDir)
	}
	if filepath.Dir(spec.BackupDir) != spec.DataRootDir || filepath.Base(spec.BackupDir) != "backups" {
		return fmt.Errorf("%w: backup_dir %s must reside directly under data_root_dir %s as backups",
			ErrLayoutValidation, spec.BackupDir, spec.DataRootDir)
	}
	if spec.CoreDataDirMode != 0o700 {
		return fmt.Errorf("%w: core_data_dir_mode must be 0700, got %o", ErrLayoutValidation, spec.CoreDataDirMode)
	}
	if spec.BackupDirMode != 0o700 {
		return fmt.Errorf("%w: backup_dir_mode must be 0700, got %o", ErrLayoutValidation, spec.BackupDirMode)
	}

	// 5. Validate DB name per Store contract
	if err := ValidateDBBasename(spec.CoreDBName); err != nil {
		return fmt.Errorf("%w: core_db_name: %v", ErrLayoutValidation, err)
	}

	// 6. Enforce exact role-set completeness for RoleIdentities (exactly 4 fixed roles)
	expectedIdentities := []string{RoleNameCore, RoleNameContainerRuntime, RoleNameSourceBuild, RoleNameApplicationGateway}
	if len(spec.RoleIdentities) != len(expectedIdentities) {
		return fmt.Errorf("%w: exactly %d role identities required, got %d",
			ErrLayoutValidation, len(expectedIdentities), len(spec.RoleIdentities))
	}
	for _, expected := range expectedIdentities {
		if _, ok := spec.RoleIdentities[expected]; !ok {
			return fmt.Errorf("%w: missing required role identity %q", ErrLayoutValidation, expected)
		}
	}

	// 7. Validate each closed Role Identity descriptor
	if spec.IPC.Group != AccountPeerIPC || spec.IPC.BindingOwner != "root" || spec.IPC.BindingMode != 0o640 || spec.IPC.PeerSocketMode != 0o660 || spec.IPC.HelperSocketMode != 0o660 {
		return fmt.Errorf("%w: protected peer binding and socket group/modes are not canonical", ErrLayoutValidation)
	}
	coreID := spec.RoleIdentities[RoleNameCore]
	if coreID.ServiceUser != AccountCore || coreID.PrimaryGroup != AccountCore ||
		len(coreID.SupplementaryGroups) != 1 || coreID.SupplementaryGroups[0] != AccountPeerIPC || len(coreID.AmbientCapabilities) != 0 ||
		coreID.LoginShell != DefaultNoLoginShell ||
		coreID.AllowRoot || coreID.AllowSudo || coreID.AllowDockerGroup || coreID.RootlessUserNamespace {
		return fmt.Errorf("%w: invalid role identity descriptor for core", ErrLayoutValidation)
	}

	containerID := spec.RoleIdentities[RoleNameContainerRuntime]
	if containerID.ServiceUser != AccountContainerRuntime || containerID.PrimaryGroup != AccountContainerRuntime ||
		len(containerID.SupplementaryGroups) != 2 || containerID.SupplementaryGroups[0] != AccountPeerIPC || containerID.SupplementaryGroups[1] != "docker" ||
		len(containerID.AmbientCapabilities) != 0 || containerID.LoginShell != DefaultNoLoginShell ||
		containerID.AllowRoot || containerID.AllowSudo || !containerID.AllowDockerGroup || containerID.RootlessUserNamespace {
		return fmt.Errorf("%w: invalid role identity descriptor for container-runtime", ErrLayoutValidation)
	}

	buildID := spec.RoleIdentities[RoleNameSourceBuild]
	if buildID.ServiceUser != AccountSourceBuild || buildID.PrimaryGroup != AccountSourceBuild ||
		len(buildID.SupplementaryGroups) != 1 || buildID.SupplementaryGroups[0] != AccountPeerIPC || len(buildID.AmbientCapabilities) != 0 ||
		buildID.LoginShell != DefaultNoLoginShell ||
		buildID.AllowRoot || buildID.AllowSudo || buildID.AllowDockerGroup || buildID.RootlessUserNamespace {
		return fmt.Errorf("%w: invalid role identity descriptor for source-build", ErrLayoutValidation)
	}

	gwID := spec.RoleIdentities[RoleNameApplicationGateway]
	if gwID.ServiceUser != AccountGateway || gwID.PrimaryGroup != AccountGateway ||
		len(gwID.SupplementaryGroups) != 1 || gwID.SupplementaryGroups[0] != AccountPeerIPC || len(gwID.AmbientCapabilities) != 0 ||
		gwID.LoginShell != DefaultNoLoginShell ||
		gwID.AllowRoot || gwID.AllowSudo || gwID.AllowDockerGroup || gwID.RootlessUserNamespace {
		return fmt.Errorf("%w: invalid role identity descriptor for application-gateway", ErrLayoutValidation)
	}

	// 8. Enforce exact canonical role state directories and modes
	expectedBusinessRoles := []string{RoleNameContainerRuntime, RoleNameSourceBuild, RoleNameApplicationGateway}
	if len(spec.RoleStateDirs) != len(expectedBusinessRoles) {
		return fmt.Errorf("%w: exactly %d role state dirs required, got %d",
			ErrLayoutValidation, len(expectedBusinessRoles), len(spec.RoleStateDirs))
	}
	if len(spec.RoleStateDirModes) != len(expectedBusinessRoles) {
		return fmt.Errorf("%w: exactly %d role state dir modes required, got %d",
			ErrLayoutValidation, len(expectedBusinessRoles), len(spec.RoleStateDirModes))
	}
	if spec.RoleStateDirs[RoleNameContainerRuntime] != UnifiedContainerStateDir {
		return fmt.Errorf("%w: container-runtime state dir must be %s, got %s",
			ErrLayoutValidation, UnifiedContainerStateDir, spec.RoleStateDirs[RoleNameContainerRuntime])
	}
	if spec.RoleStateDirs[RoleNameSourceBuild] != UnifiedBuildStateDir {
		return fmt.Errorf("%w: source-build state dir must be %s, got %s",
			ErrLayoutValidation, UnifiedBuildStateDir, spec.RoleStateDirs[RoleNameSourceBuild])
	}
	if spec.RoleStateDirs[RoleNameApplicationGateway] != UnifiedGatewayStateDir {
		return fmt.Errorf("%w: application-gateway state dir must be %s, got %s",
			ErrLayoutValidation, UnifiedGatewayStateDir, spec.RoleStateDirs[RoleNameApplicationGateway])
	}
	for _, role := range expectedBusinessRoles {
		if mode := spec.RoleStateDirModes[role]; mode != 0o700 {
			return fmt.Errorf("%w: role %s state dir mode must be 0700, got %o", ErrLayoutValidation, role, mode)
		}
	}

	return nil
}

// CoreDatabasePath returns the absolute path to the Core database given a data directory and dbName.
func CoreDatabasePath(coreDataDir, dbName string) (string, error) {
	cleanDir := filepath.Clean(strings.TrimSpace(coreDataDir))
	if cleanDir == "" || !filepath.IsAbs(cleanDir) {
		return "", errors.New("core data directory must be an absolute path")
	}
	name := strings.TrimSpace(dbName)
	if name == "" {
		name = UnifiedDefaultDBName
	}
	if err := ValidateDBBasename(name); err != nil {
		return "", err
	}
	return filepath.Join(cleanDir, name), nil
}

// ReleaseDirectory returns the absolute path for an immutable release version.
func ReleaseDirectory(releasesRoot, releaseID string) (string, error) {
	cleanRoot := filepath.Clean(strings.TrimSpace(releasesRoot))
	if cleanRoot == "" || !filepath.IsAbs(cleanRoot) {
		return "", errors.New("releases root must be an absolute path")
	}
	id := strings.TrimSpace(releaseID)
	if !safeBasenameRegex.MatchString(id) {
		return "", fmt.Errorf("invalid release id format %q", id)
	}
	target := filepath.Join(cleanRoot, id)
	rel, err := filepath.Rel(cleanRoot, target)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errors.New("release directory escapes releases root")
	}
	return target, nil
}

// ReleaseBinPath returns the absolute path to an executable in a release version.
func ReleaseBinPath(releasesRoot, releaseID, binaryName string) (string, error) {
	relDir, err := ReleaseDirectory(releasesRoot, releaseID)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(binaryName)
	if !safeBasenameRegex.MatchString(name) {
		return "", fmt.Errorf("invalid binary name format %q", name)
	}
	return filepath.Join(relDir, "bin", name), nil
}

// ReleaseWebPath returns the absolute path to the static web directory in a release version.
func ReleaseWebPath(releasesRoot, releaseID string) (string, error) {
	relDir, err := ReleaseDirectory(releasesRoot, releaseID)
	if err != nil {
		return "", err
	}
	return filepath.Join(relDir, "web"), nil
}
