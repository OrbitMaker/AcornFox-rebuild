package install

import (
	"path/filepath"
	"testing"
)

func TestDefaultUnifiedLayoutSecurity(t *testing.T) {
	spec := DefaultUnifiedLayoutSpec()
	if err := ValidateUnifiedLayoutSecurity(spec); err != nil {
		t.Fatalf("expected default unified layout spec to be valid, got: %v", err)
	}

	if spec.CoreDataDir != "/var/lib/acornfox/core" {
		t.Fatalf("expected core data dir /var/lib/acornfox/core, got %s", spec.CoreDataDir)
	}
	if spec.CoreDataDirMode != 0o700 {
		t.Fatalf("expected core data dir mode 0700, got %o", spec.CoreDataDirMode)
	}
	if spec.CoreConfigFile != "/etc/acornfox/core.json" {
		t.Fatalf("expected core config file /etc/acornfox/core.json, got %s", spec.CoreConfigFile)
	}
	if spec.CoreConfigFileMode != 0o640 {
		t.Fatalf("expected core config file mode 0640, got %o", spec.CoreConfigFileMode)
	}
	if spec.CoreConfigFileOwner != "root" || spec.CoreConfigFileGroup != AccountCore {
		t.Fatalf("expected core config owner/group root:%s, got %s:%s",
			AccountCore, spec.CoreConfigFileOwner, spec.CoreConfigFileGroup)
	}
	if spec.IPC.Group != AccountPeerIPC || spec.IPC.BindingOwner != "root" || spec.IPC.BindingMode != 0o640 || spec.IPC.PeerSocketMode != 0o660 || spec.IPC.HelperSocketMode != 0o660 {
		t.Fatal("protected binding and peer/helper socket IPC contract differs")
	}
	core := spec.RoleIdentities[RoleNameCore]
	container := spec.RoleIdentities[RoleNameContainerRuntime]
	build := spec.RoleIdentities[RoleNameSourceBuild]
	gateway := spec.RoleIdentities[RoleNameApplicationGateway]
	if len(core.SupplementaryGroups) != 1 || core.SupplementaryGroups[0] != AccountPeerIPC ||
		len(container.SupplementaryGroups) != 2 || container.SupplementaryGroups[0] != AccountPeerIPC || container.SupplementaryGroups[1] != "docker" ||
		len(build.SupplementaryGroups) != 1 || build.SupplementaryGroups[0] != AccountPeerIPC || build.AllowDockerGroup || build.RootlessUserNamespace ||
		len(gateway.SupplementaryGroups) != 1 || gateway.SupplementaryGroups[0] != AccountPeerIPC || len(gateway.AmbientCapabilities) != 0 {
		t.Fatal("role identity permissions do not match actual adapters and separate worker/edge")
	}

	dbPath, err := CoreDatabasePath(spec.CoreDataDir, spec.CoreDBName)
	if err != nil {
		t.Fatalf("CoreDatabasePath failed: %v", err)
	}
	expectedDBPath := filepath.Join("/var/lib/acornfox/core", "acornfox.db")
	if dbPath != expectedDBPath {
		t.Fatalf("expected dbPath %s, got %s", expectedDBPath, dbPath)
	}
}

func TestUnifiedLayoutSecurityRejections(t *testing.T) {
	t.Run("core granted docker group rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		core := spec.RoleIdentities[RoleNameCore]
		core.AllowDockerGroup = true
		spec.RoleIdentities[RoleNameCore] = core

		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core role is granted docker group")
		}
	})

	t.Run("core with unauthorized supplementary group rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		core := spec.RoleIdentities[RoleNameCore]
		core.SupplementaryGroups = []string{"docker"}
		spec.RoleIdentities[RoleNameCore] = core

		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core role has supplementary groups")
		}
	})

	t.Run("core granted root or sudo rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		core := spec.RoleIdentities[RoleNameCore]
		core.AllowRoot = true
		spec.RoleIdentities[RoleNameCore] = core
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core role has allow_root")
		}

		spec = DefaultUnifiedLayoutSpec()
		core = spec.RoleIdentities[RoleNameCore]
		core.AllowSudo = true
		spec.RoleIdentities[RoleNameCore] = core
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core role has allow_sudo")
		}
	})

	t.Run("container runtime missing docker supplementary group rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		c := spec.RoleIdentities[RoleNameContainerRuntime]
		c.SupplementaryGroups = []string{AccountPeerIPC}
		spec.RoleIdentities[RoleNameContainerRuntime] = c

		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when container-runtime lacks docker supplementary group")
		}
	})

	t.Run("source adapter falsely claiming rootless worker rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		build := spec.RoleIdentities[RoleNameSourceBuild]
		build.RootlessUserNamespace = true
		spec.RoleIdentities[RoleNameSourceBuild] = build

		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when source adapter claims BuildKit worker namespace")
		}
	})

	t.Run("application gateway claiming Caddy bind capability rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		gw := spec.RoleIdentities[RoleNameApplicationGateway]
		gw.AmbientCapabilities = []string{"CAP_NET_BIND_SERVICE"}
		spec.RoleIdentities[RoleNameApplicationGateway] = gw

		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when application adapter claims edge bind capability")
		}
	})

	t.Run("application gateway needs only peer IPC group", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		gw := spec.RoleIdentities[RoleNameApplicationGateway]
		gw.SupplementaryGroups = nil
		spec.RoleIdentities[RoleNameApplicationGateway] = gw
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("Gateway without peer IPC group accepted")
		}
		spec = DefaultUnifiedLayoutSpec()
		gw = spec.RoleIdentities[RoleNameApplicationGateway]
		gw.SupplementaryGroups = []string{AccountPeerIPC, "docker"}
		spec.RoleIdentities[RoleNameApplicationGateway] = gw
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("Gateway with Docker group accepted")
		}
	})

	t.Run("dedicated IPC group or binding mode missing rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		build := spec.RoleIdentities[RoleNameSourceBuild]
		build.SupplementaryGroups = nil
		spec.RoleIdentities[RoleNameSourceBuild] = build
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("source adapter without peer IPC group accepted")
		}
		spec = DefaultUnifiedLayoutSpec()
		spec.IPC.BindingMode = 0o600
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("unreadable root-owned peer binding accepted")
		}
	})

	t.Run("extra or missing role identities rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		delete(spec.RoleIdentities, RoleNameApplicationGateway)
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when required role identity is missing")
		}

		spec = DefaultUnifiedLayoutSpec()
		spec.RoleIdentities["extra-unauthorized-role"] = RoleIdentityRequirement{ServiceUser: "extra"}
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when extra role identity is present")
		}
	})

	t.Run("extra or missing role state dirs rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		delete(spec.RoleStateDirs, RoleNameApplicationGateway)
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when required role state dir is missing")
		}

		spec = DefaultUnifiedLayoutSpec()
		spec.RoleStateDirs["extra-role"] = "/var/lib/acornfox/extra"
		spec.RoleStateDirModes["extra-role"] = 0o700
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when extra role state dir is present")
		}
	})

	t.Run("arbitrary root releases dir rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.ReleasesDir = "/tmp/releases"
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when releases_dir is not canonical UnifiedReleasesDir")
		}
	})

	t.Run("arbitrary config dir rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.ConfigDir = "/etc/custom-acornfox"
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when config_dir is not canonical UnifiedConfigDir")
		}
	})

	t.Run("core config file outside config dir rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.CoreConfigFile = "/tmp/core.json"
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core_config_file is outside config_dir")
		}
	})

	t.Run("core config file unreadable mode 0600 rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.CoreConfigFileMode = 0o600
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core_config_file is mode 0600 (unreadable to non-root core)")
		}
	})

	t.Run("core config file wrong owner rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.CoreConfigFileOwner = AccountCore
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when core_config_file is owned by core instead of root")
		}
	})

	t.Run("core data dir mode not 0700 rejected", func(t *testing.T) {
		modes := []uint32{0o750, 0o755, 0o777, 0o600}
		for _, m := range modes {
			spec := DefaultUnifiedLayoutSpec()
			spec.CoreDataDirMode = m
			if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
				t.Fatalf("expected error when core data dir mode is %o", m)
			}
		}
	})

	t.Run("backup dir mode not 0700 rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		spec.BackupDirMode = 0o755
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when backup dir mode is not 0700")
		}
	})

	t.Run("non-canonical role state dir rejected", func(t *testing.T) {
		spec := DefaultUnifiedLayoutSpec()
		// Target a wrong leaf under the correct parent
		spec.RoleStateDirs[RoleNameContainerRuntime] = "/var/lib/acornfox/wrong-leaf"
		if err := ValidateUnifiedLayoutSecurity(spec); err == nil {
			t.Fatal("expected error when role state dir is not canonical UnifiedContainerStateDir")
		}
	})
}

func TestValidateDBBasename(t *testing.T) {
	valid := []string{
		"acornfox.db",
		"test.sqlite",
		"data.db",
		"app-1.db",
	}
	for _, v := range valid {
		if err := ValidateDBBasename(v); err != nil {
			t.Fatalf("expected %q to be valid db basename, got: %v", v, err)
		}
	}

	invalid := []string{
		"",
		" ",
		"..",
		".",
		"/var/lib/acornfox/acornfox.db",
		"foo/bar",
		"acornfox.lock",
		"acornfox.db-wal",
		"acornfox.db-shm",
		"foo\x00bar",
		"foo\\bar",
	}
	for _, inv := range invalid {
		if err := ValidateDBBasename(inv); err == nil {
			t.Fatalf("expected %q to be rejected as invalid db basename", inv)
		}
	}
}

func TestHostIdentityAllocationState(t *testing.T) {
	unallocated, err := NewUnallocatedIdentity(RoleNameCore)
	if err != nil {
		t.Fatalf("NewUnallocatedIdentity failed: %v", err)
	}
	if unallocated.Allocated {
		t.Fatal("expected unallocated identity to have Allocated = false")
	}
	if unallocated.UID != -1 || unallocated.GID != -1 {
		t.Fatalf("expected unallocated UID/GID -1, got %d/%d", unallocated.UID, unallocated.GID)
	}
	if unallocated.Status != "pending_host_allocation" {
		t.Fatalf("expected status pending_host_allocation, got %s", unallocated.Status)
	}

	// Unknown role rejected
	if _, err := NewUnallocatedIdentity("unknown-role"); err == nil {
		t.Fatal("expected error for unknown role allocation")
	}

	resolved, err := NewResolvedIdentity(RoleNameCore, 1001, 1001)
	if err != nil {
		t.Fatalf("unexpected error resolving identity: %v", err)
	}
	if !resolved.Allocated {
		t.Fatal("expected resolved identity to have Allocated = true")
	}
	if resolved.UID != 1001 || resolved.GID != 1001 {
		t.Fatalf("expected UID/GID 1001/1001, got %d/%d", resolved.UID, resolved.GID)
	}
	if resolved.Status != "resolved" {
		t.Fatalf("expected status resolved, got %s", resolved.Status)
	}

	// Root UID 0 or GID 0 strictly rejected
	if _, err := NewResolvedIdentity(RoleNameCore, 0, 1001); err == nil {
		t.Fatal("expected error resolving root UID 0")
	}
	if _, err := NewResolvedIdentity(RoleNameCore, 1001, 0); err == nil {
		t.Fatal("expected error resolving root GID 0")
	}
	if _, err := NewResolvedIdentity(RoleNameCore, 0, 0); err == nil {
		t.Fatal("expected error resolving root UID/GID 0/0")
	}

	// Negative UID/GID rejected
	if _, err := NewResolvedIdentity(RoleNameCore, -1, 1001); err == nil {
		t.Fatal("expected error resolving negative UID")
	}
	if _, err := NewResolvedIdentity(RoleNameCore, 1001, -5); err == nil {
		t.Fatal("expected error resolving negative GID")
	}

	// Unknown role rejected
	if _, err := NewResolvedIdentity("unknown-role", 1001, 1001); err == nil {
		t.Fatal("expected error resolving unknown role")
	}
}

func TestReleasePathDerivations(t *testing.T) {
	releasesRoot := "/opt/acornfox/releases"
	relID := "ur-20260927-v1"

	dir, err := ReleaseDirectory(releasesRoot, relID)
	if err != nil {
		t.Fatalf("ReleaseDirectory failed: %v", err)
	}
	expectedDir := "/opt/acornfox/releases/ur-20260927-v1"
	if dir != expectedDir {
		t.Fatalf("expected %s, got %s", expectedDir, dir)
	}

	binPath, err := ReleaseBinPath(releasesRoot, relID, "acornfox-core")
	if err != nil {
		t.Fatalf("ReleaseBinPath failed: %v", err)
	}
	expectedBin := "/opt/acornfox/releases/ur-20260927-v1/bin/acornfox-core"
	if binPath != expectedBin {
		t.Fatalf("expected %s, got %s", expectedBin, binPath)
	}

	webPath, err := ReleaseWebPath(releasesRoot, relID)
	if err != nil {
		t.Fatalf("ReleaseWebPath failed: %v", err)
	}
	expectedWeb := "/opt/acornfox/releases/ur-20260927-v1/web"
	if webPath != expectedWeb {
		t.Fatalf("expected %s, got %s", expectedWeb, webPath)
	}

	// Traversal in releaseID
	if _, err := ReleaseDirectory(releasesRoot, "../evil"); err == nil {
		t.Fatal("expected error on path traversal in releaseID")
	}

	// Invalid characters in releaseID
	if _, err := ReleaseDirectory(releasesRoot, "rel/with/slashes"); err == nil {
		t.Fatal("expected error on slashes in releaseID")
	}

	// Non-absolute root
	if _, err := ReleaseDirectory("relative/releases", relID); err == nil {
		t.Fatal("expected error on non-absolute releasesRoot")
	}
}
