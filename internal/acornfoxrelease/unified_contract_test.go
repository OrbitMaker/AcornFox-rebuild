package acornfoxrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sampleValidSQLiteCompatibility() SQLiteCompatibilityV1 {
	checksums := []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	}
	migrations := []SQLiteMigrationPinV1{
		{Version: Migration0001AdminAuth, Checksum: checksums[0]},
		{Version: Migration0002ApplicationRepository, Checksum: checksums[1]},
		{Version: Migration0003TaskFencing, Checksum: checksums[2]},
		{Version: Migration0004AuditEvidence, Checksum: checksums[3]},
		{Version: Migration0005PackIntents, Checksum: checksums[4]},
		{Version: Migration0006PackProtocolExecution, Checksum: checksums[5]},
		{Version: Migration0007PackArtifactStaging, Checksum: checksums[6]},
		{Version: Migration0008PackActivation, Checksum: checksums[7]},
		{Version: Migration0009ImageDelivery, Checksum: checksums[8]},
		{Version: Migration0010ImageExecution, Checksum: checksums[9]},
		{Version: Migration0011ImageLifecycle, Checksum: checksums[10]},
		{Version: Migration0012SourceBuild, Checksum: checksums[11]},
		{Version: Migration0013ImagePublicAccess, Checksum: checksums[12]},
	}
	return SQLiteCompatibilityV1{
		MinSchemaVersion:   Migration0001AdminAuth,
		MaxSchemaVersion:   Migration0013ImagePublicAccess,
		RequiredMigrations: migrations,
		ReadWriteMode:      "exclusive_writer",
		RollbackPolicy:     RollbackRequiresDataRestore,
	}
}

func sampleValidManifest() UnifiedReleaseManifestV1 {
	artCoreHash := strings.Repeat("a", 64)
	artCLIHash := strings.Repeat("b", 64)
	artUIHash := strings.Repeat("c", 64)
	artHostUpHash := strings.Repeat("d", 64)
	artDockerHash := strings.Repeat("e", 64)
	artBuildKitHash := strings.Repeat("1", 64)
	artCaddyHash := strings.Repeat("2", 64)
	toolchainHash := strings.Repeat("3", 64)

	artifacts := []UnifiedArtifactV1{
		{ID: "acornfox-core-bin", RelativePath: "bin/acornfox-core", SizeBytes: 15000000, SHA256: artCoreHash, Executable: true},
		{ID: "acornfox-cli-bin", RelativePath: "bin/acornfox", SizeBytes: 12000000, SHA256: artCLIHash, Executable: true},
		{ID: "acornfox-ui-assets", RelativePath: "web/index.html", SizeBytes: 50000, SHA256: artUIHash, Executable: false},
		{ID: "acornfox-host-update-bin", RelativePath: "bin/acornfox-host-update", SizeBytes: 8000000, SHA256: artHostUpHash, Executable: true},
		{ID: "pinned-docker-bin", RelativePath: "embedded/bin/docker", SizeBytes: 40000000, SHA256: artDockerHash, Executable: true},
		{ID: "pinned-buildkitd-bin", RelativePath: "embedded/bin/buildkitd", SizeBytes: 30000000, SHA256: artBuildKitHash, Executable: true},
		{ID: "pinned-caddy-bin", RelativePath: "embedded/bin/caddy", SizeBytes: 25000000, SHA256: artCaddyHash, Executable: true},
	}

	// Synthetic bytes and hashes below are contract fixtures, never real release artifacts.
	addSynthetic := func(id, path string) {
		sum := sha256.Sum256([]byte("synthetic contract fixture: " + id))
		artifacts = append(artifacts, UnifiedArtifactV1{ID: id, RelativePath: path, SizeBytes: 128, SHA256: hex.EncodeToString(sum[:]), Executable: true})
	}
	for _, member := range []struct{ id, path string }{
		{"fixture-container-runner", "bin/acornfox-container"}, {"fixture-source-runner", "bin/acornfox-source-build"}, {"fixture-gateway-runner", "bin/acornfox-gateway"}, {"fixture-policy-executor", "bin/acornfox-build-network"},
		{"fixture-dockerd", "embedded/bin/dockerd"}, {"fixture-containerd", "embedded/bin/containerd"}, {"fixture-containerd-shim", "embedded/bin/containerd-shim-runc-v2"}, {"fixture-runc", "embedded/bin/runc"}, {"fixture-docker-proxy", "embedded/bin/docker-proxy"},
		{"fixture-buildctl", "embedded/bin/buildctl"}, {"fixture-rootlesskit", "embedded/bin/rootlesskit"},
	} {
		addSynthetic(member.id, member.path)
	}

	components := UnifiedComponentsV1{
		Core:                 UnifiedComponentRefV1{ArtifactID: "acornfox-core-bin"},
		CLI:                  UnifiedComponentRefV1{ArtifactID: "acornfox-cli-bin"},
		UI:                   UnifiedComponentRefV1{ArtifactID: "acornfox-ui-assets"},
		HostUpdate:           UnifiedComponentRefV1{ArtifactID: "acornfox-host-update-bin"},
		BuildNetworkExecutor: UnifiedComponentRefV1{ArtifactID: "fixture-policy-executor"},
	}

	roles := []UnifiedRoleV1{
		{Name: RoleContainerRuntime, Description: "Container execution bridge via standalone and engine", RunnerArtifactID: "fixture-container-runner"},
		{Name: RoleSourceBuild, Description: "Rootless source build engine using BuildKit", RunnerArtifactID: "fixture-source-runner"},
		{Name: RoleApplicationGateway, Description: "Edge reverse proxy and ACME gateway using Caddy", RunnerArtifactID: "fixture-gateway-runner"},
	}

	dependencies := []UnifiedDependencyPolicyV1{
		{
			Name:               DependencyDocker,
			RuntimeArtifactIDs: []string{"pinned-docker-bin", "fixture-dockerd", "fixture-containerd", "fixture-containerd-shim", "fixture-runc", "fixture-docker-proxy"},
			SupportedCondition: DependencySupportedConditionV1{
				MinVersion:  "24.0.0",
				ProbeSocket: "/var/run/docker.sock",
				ReusePolicy: "reuse_existing_compatible",
			},
			PinnedProvisioning: DependencyPinnedRecipeV1{
				ArtifactID:         "pinned-docker-bin",
				SourceURL:          "https://download.docker.com/linux/static/stable/x86_64/docker-26.1.4.tgz",
				SourceSHA256:       artDockerHash,
				SizeBytes:          40000000,
				TargetRelativePath: "embedded/bin/docker",
			},
		},
		{
			Name: DependencyGit,
			SupportedCondition: DependencySupportedConditionV1{
				MinVersion:  "2.34.0",
				ReusePolicy: "reuse_existing_compatible",
			},
			GitHostPackages: &GitHostPackagePolicyV1{
				Packages: []GitHostPackagePinV1{
					{Name: "git", Version: "1:2.43.0-1ubuntu7.3", Architecture: "amd64", SourceURL: "https://archive.ubuntu.com/ubuntu/pool/main/g/git/git_2.43.0-1ubuntu7.3_amd64.deb", ArchiveSHA256: strings.Repeat("f", 64), SizeBytes: 2000000},
					{Name: "git-man", Version: "1:2.43.0-1ubuntu7.3", Architecture: "all", SourceURL: "https://archive.ubuntu.com/ubuntu/pool/main/g/git/git-man_2.43.0-1ubuntu7.3_all.deb", ArchiveSHA256: strings.Repeat("e", 64), SizeBytes: 1000000},
				},
				Executables: []GitExecutionPinV1{{Path: "/usr/bin/git", ResolvedPath: "/usr/bin/git", SHA256: strings.Repeat("d", 64)}, {Path: "/usr/lib/git-core/git-remote-https", ResolvedPath: "/usr/lib/git-core/git-remote-http", SHA256: strings.Repeat("c", 64)}},
			},
		},
		{
			Name:               DependencyBuildKit,
			RuntimeArtifactIDs: []string{"pinned-buildkitd-bin", "fixture-buildctl", "fixture-rootlesskit"},
			SupportedCondition: DependencySupportedConditionV1{
				MinVersion:  "0.13.0",
				ProbeSocket: "/run/acornfox-buildkit/buildkitd.sock",
				ReusePolicy: "reuse_existing_compatible",
			},
			BuildKitSources: []DependencySourceArchiveV1{
				{Name: "buildkit", SourceURL: "https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz", SourceSHA256: artBuildKitHash, SizeBytes: 92882168},
				{Name: "rootlesskit", SourceURL: "https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz", SourceSHA256: strings.Repeat("9", 64), SizeBytes: 23335815},
			},
			BuildKitMembers: []DependencyMemberSourceV1{{ArtifactID: "pinned-buildkitd-bin", SourceName: "buildkit"}, {ArtifactID: "fixture-buildctl", SourceName: "buildkit"}, {ArtifactID: "fixture-rootlesskit", SourceName: "rootlesskit"}},
		},
		{
			Name:               DependencyCaddy,
			RuntimeArtifactIDs: []string{"pinned-caddy-bin"},
			SupportedCondition: DependencySupportedConditionV1{
				MinVersion:  "2.7.0",
				ReusePolicy: "reuse_existing_compatible",
			},
			PinnedProvisioning: DependencyPinnedRecipeV1{
				ArtifactID:         "pinned-caddy-bin",
				SourceURL:          "https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz",
				SourceSHA256:       artCaddyHash,
				SizeBytes:          25000000,
				TargetRelativePath: "embedded/bin/caddy",
			},
		},
	}

	return UnifiedReleaseManifestV1{
		SchemaVersion:             UnifiedReleaseManifestSchemaV1,
		Product:                   UnifiedProduct,
		ReleaseID:                 "ur-20260927-v1",
		Version:                   "1.0.0",
		TargetOS:                  UnifiedTargetOS,
		TargetDistribution:        UnifiedTargetDistribution,
		TargetDistributionVersion: UnifiedTargetDistributionVersion,
		TargetArchitecture:        UnifiedTargetArchitecture,
		Provenance: UnifiedProvenanceV1{
			SourceRepository: "https://github.com/open-card/open-card",
			SourceCommit:     strings.Repeat("0", 40),
			BuildTimestamp:   "2026-09-27T12:00:00Z",
			ToolchainSHA256:  toolchainHash,
		},
		Components:          components,
		Roles:               roles,
		Artifacts:           artifacts,
		Dependencies:        dependencies,
		SQLiteCompatibility: sampleValidSQLiteCompatibility(),
	}
}

func TestValidUnifiedReleaseManifest(t *testing.T) {
	manifest := sampleValidManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}

	canonical, err := CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		t.Fatalf("failed to canonicalize manifest: %v", err)
	}

	witness, err := ParseUnifiedManifestV1(canonical)
	if err != nil {
		t.Fatalf("failed to parse valid canonical manifest: %v", err)
	}
	if !witness.Valid() {
		t.Fatal("expected witness to be valid")
	}

	snap, err := witness.Snapshot()
	if err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	if snap.ReleaseID != "ur-20260927-v1" {
		t.Fatalf("unexpected release ID %q", snap.ReleaseID)
	}
	if snap.Version != "1.0.0" {
		t.Fatalf("unexpected version %q", snap.Version)
	}
	if len(snap.Roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(snap.Roles))
	}
	if len(snap.Dependencies) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(snap.Dependencies))
	}

	coreArt, err := witness.ComponentArtifact(ComponentCore)
	if err != nil || coreArt.ID != "acornfox-core-bin" || !coreArt.Executable {
		t.Fatalf("unexpected core artifact: %+v, err: %v", coreArt, err)
	}
}

func TestWitnessSnapshotPreservesGitRuntimeArtifactIDShape(t *testing.T) {
	for _, item := range []struct {
		name string
		ids  []string
	}{
		{name: "empty_array", ids: []string{}},
		{name: "nil_slice", ids: nil},
	} {
		t.Run(item.name, func(t *testing.T) {
			manifest := sampleValidManifest()
			manifest.Dependencies[1].RuntimeArtifactIDs = item.ids // Git has no embedded runtime members.
			canonical, err := CanonicalUnifiedManifestV1(manifest)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := ParseUnifiedManifestV1(canonical)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := witness.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if (snapshot.Dependencies[1].RuntimeArtifactIDs == nil) != (item.ids == nil) {
				t.Fatal("snapshot changed Git runtime_artifact_ids null/empty shape")
			}
			got, err := CanonicalUnifiedManifestV1(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(canonical) {
				t.Fatal("snapshot changed canonical manifest bytes")
			}
			digest := sha256.Sum256(got)
			want, err := witness.ManifestSHA256()
			if err != nil || hex.EncodeToString(digest[:]) != want {
				t.Fatal("snapshot changed trusted manifest digest")
			}
		})
	}
}

func TestUnifiedManifestRejectionInvariants(t *testing.T) {
	t.Run("wrong schema version", func(t *testing.T) {
		m := sampleValidManifest()
		m.SchemaVersion = 2
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for schema version 2")
		}
	})

	t.Run("wrong product", func(t *testing.T) {
		m := sampleValidManifest()
		m.Product = "other-product"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for invalid product")
		}
	})

	t.Run("wrong platform architecture", func(t *testing.T) {
		m := sampleValidManifest()
		m.TargetArchitecture = "arm64"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for arm64 on amd64 profile")
		}
	})

	t.Run("wrong OS distribution", func(t *testing.T) {
		m := sampleValidManifest()
		m.TargetDistribution = "debian"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for non-ubuntu distribution")
		}
	})

	t.Run("missing required official role", func(t *testing.T) {
		m := sampleValidManifest()
		m.Roles = m.Roles[:2]
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when official role is missing")
		}
	})

	t.Run("unexpected extraneous role", func(t *testing.T) {
		m := sampleValidManifest()
		m.Roles = append(m.Roles, UnifiedRoleV1{
			Name:             "unauthorized-extra-role",
			Description:      "Fake role",
			RunnerArtifactID: "acornfox-core-bin",
		})
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for unauthorized role")
		}
	})

	t.Run("role references unknown runner artifact", func(t *testing.T) {
		m := sampleValidManifest()
		m.Roles[0].RunnerArtifactID = "nonexistent-artifact"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for unknown runner artifact")
		}
	})

	t.Run("role runner artifact not marked executable", func(t *testing.T) {
		m := sampleValidManifest()
		m.Artifacts[0].Executable = false // Core component must be executable
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when runner artifact is not executable")
		}
	})

	t.Run("missing required dependency", func(t *testing.T) {
		m := sampleValidManifest()
		m.Dependencies = m.Dependencies[:3]
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when named dependency is missing")
		}
	})

	t.Run("dependency missing pinned recipe artifact", func(t *testing.T) {
		m := sampleValidManifest()
		m.Dependencies[0].PinnedProvisioning.ArtifactID = ""
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when dependency has empty pinned artifact_id")
		}
	})

	t.Run("dependency pinned recipe references unknown artifact", func(t *testing.T) {
		m := sampleValidManifest()
		m.Dependencies[0].PinnedProvisioning.ArtifactID = "unknown-artifact"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when dependency references unknown artifact")
		}
	})

	t.Run("dependency pinned recipe target path mismatch", func(t *testing.T) {
		m := sampleValidManifest()
		m.Dependencies[0].PinnedProvisioning.TargetRelativePath = "embedded/bin/other-docker"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when recipe target path differs from artifact path")
		}
	})

	t.Run("invalid dependency reuse policy", func(t *testing.T) {
		m := sampleValidManifest()
		m.Dependencies[0].SupportedCondition.ReusePolicy = "arbitrary_upgrade"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for non-reuse policy")
		}
	})

	t.Run("artifact path collision", func(t *testing.T) {
		m := sampleValidManifest()
		m.Artifacts[1].RelativePath = m.Artifacts[0].RelativePath // both target bin/acornfox-core
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when multiple artifacts share same relative path")
		}
	})

	t.Run("artifact relative path traversal", func(t *testing.T) {
		badPaths := []string{
			"../etc/passwd",
			"/bin/acornfox",
			"bin/../../etc/shadow",
			".",
			"",
			"bin/foo\x00bar",
		}
		for _, bp := range badPaths {
			m := sampleValidManifest()
			m.Artifacts[0].RelativePath = bp
			if err := m.Validate(); err == nil {
				t.Fatalf("expected validation error for bad path %q", bp)
			}
		}
	})

	t.Run("artifact non-positive size", func(t *testing.T) {
		m := sampleValidManifest()
		m.Artifacts[0].SizeBytes = 0
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for zero size artifact")
		}
		m.Artifacts[0].SizeBytes = -10
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for negative size artifact")
		}
	})

	t.Run("artifact size exceeding limit", func(t *testing.T) {
		m := sampleValidManifest()
		m.Artifacts[0].SizeBytes = maxArtifactSizeBytes + 1
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for oversize artifact")
		}
	})

	t.Run("artifact invalid sha256", func(t *testing.T) {
		m := sampleValidManifest()
		m.Artifacts[0].SHA256 = "not-a-valid-sha256"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for invalid sha256")
		}
	})

	t.Run("sqlite migration count mismatch", func(t *testing.T) {
		m := sampleValidManifest()
		m.SQLiteCompatibility.RequiredMigrations = m.SQLiteCompatibility.RequiredMigrations[:12]
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error when fewer than 13 migrations declared")
		}
	})

	for _, kind := range []string{"unknown migration", "unknown max"} {
		t.Run("sqlite "+kind, func(t *testing.T) {
			m := sampleValidManifest()
			c := &m.SQLiteCompatibility
			switch kind {
			case "unknown migration":
				c.RequiredMigrations[12].Version = "0014_unknown"
			case "unknown max":
				c.MaxSchemaVersion = "0014_unknown"
			}
			if err := m.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", kind)
			}
		})
	}

	t.Run("sqlite invalid rollback policy", func(t *testing.T) {
		m := sampleValidManifest()
		m.SQLiteCompatibility.RollbackPolicy = "arbitrary_rollback"
		if err := m.Validate(); err == nil {
			t.Fatal("expected validation error for invalid rollback policy")
		}
	})

	t.Run("raw bytes with trailing garbage", func(t *testing.T) {
		m := sampleValidManifest()
		raw, err := CanonicalUnifiedManifestV1(m)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		withGarbage := append(raw, []byte("   extra-token")...)
		if _, err := ParseUnifiedManifestV1(withGarbage); err == nil {
			t.Fatal("expected parse error on trailing tokens")
		}
	})

	t.Run("unknown fields rejected", func(t *testing.T) {
		raw := `{"schema_version":1,"product":"acornfox","unknown_injected_field":"evil"}`
		if _, err := ParseUnifiedManifestV1([]byte(raw)); err == nil {
			t.Fatal("expected error on unknown fields")
		}
	})
}

func TestUnifiedManifestTrustVerification(t *testing.T) {
	manifest := sampleValidManifest()
	canonical, err := CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	witness, err := ParseUnifiedManifestV1(canonical)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	expectedSHA, err := witness.ManifestSHA256()
	if err != nil {
		t.Fatalf("sha256: %v", err)
	}

	correctPin := TrustedReleasePinV1{
		ExpectedReleaseID:      "ur-20260927-v1",
		ExpectedManifestSHA256: expectedSHA,
		ExpectedSourceCommit:   strings.Repeat("0", 40),
	}

	if err := VerifyUnifiedManifestTrust(witness, correctPin); err != nil {
		t.Fatalf("expected trust verification to pass, got: %v", err)
	}

	// Mismatched manifest digest
	badPinSHA := correctPin
	badPinSHA.ExpectedManifestSHA256 = strings.Repeat("f", 64)
	if err := VerifyUnifiedManifestTrust(witness, badPinSHA); err == nil {
		t.Fatal("expected error for mismatched manifest sha256")
	}

	// Mismatched release ID
	badPinID := correctPin
	badPinID.ExpectedReleaseID = "ur-different-id"
	if err := VerifyUnifiedManifestTrust(witness, badPinID); err == nil {
		t.Fatal("expected error for mismatched release ID")
	}

	// Mismatched commit
	badPinCommit := correctPin
	badPinCommit.ExpectedSourceCommit = strings.Repeat("1", 40)
	if err := VerifyUnifiedManifestTrust(witness, badPinCommit); err == nil {
		t.Fatal("expected error for mismatched commit")
	}
}

func TestWitnessNestedImmutability(t *testing.T) {
	manifest := sampleValidManifest()
	canonical, err := CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	witness, err := ParseUnifiedManifestV1(canonical)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	origSHA, err := witness.ManifestSHA256()
	if err != nil {
		t.Fatalf("sha256: %v", err)
	}

	pin := TrustedReleasePinV1{
		ExpectedReleaseID:      "ur-20260927-v1",
		ExpectedManifestSHA256: origSHA,
		ExpectedSourceCommit:   strings.Repeat("0", 40),
	}

	// 1. Mutate returned snapshot nested slices
	snap, err := witness.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	snap.SQLiteCompatibility.RequiredMigrations[0].Checksum = strings.Repeat("9", 64)
	snap.Dependencies[0].PinnedProvisioning.SourceURL = "https://evil.example.test/fake.tar.gz"
	snap.Dependencies[0].RuntimeArtifactIDs[0] = "fixture-gateway-runner"
	snap.Dependencies[2].BuildKitSources[0].SourceSHA256 = strings.Repeat("0", 64)
	snap.Dependencies[2].BuildKitMembers[0].SourceName = "rootlesskit"
	snap.Dependencies[1].GitHostPackages.Packages[0].ArchiveSHA256 = strings.Repeat("0", 64)
	snap.Artifacts[0].SHA256 = strings.Repeat("0", 64)

	// Re-query and assert internal state is untampered
	freshSnap, err := witness.Snapshot()
	if err != nil {
		t.Fatalf("fresh snapshot: %v", err)
	}
	if freshSnap.SQLiteCompatibility.RequiredMigrations[0].Checksum == strings.Repeat("9", 64) {
		t.Fatal("external mutation of returned RequiredMigrations leaked into witness internal state")
	}
	if freshSnap.Dependencies[0].RuntimeArtifactIDs[0] == "fixture-gateway-runner" {
		t.Fatal("runtime closure slice was not deep-copied")
	}
	if freshSnap.Dependencies[0].PinnedProvisioning.SourceURL == "https://evil.example.test/fake.tar.gz" {
		t.Fatal("external mutation of returned Dependencies leaked into witness internal state")
	}
	if freshSnap.Dependencies[2].BuildKitSources[0].SourceSHA256 == strings.Repeat("0", 64) || freshSnap.Dependencies[2].BuildKitMembers[0].SourceName != "buildkit" || freshSnap.Dependencies[1].GitHostPackages.Packages[0].ArchiveSHA256 == strings.Repeat("0", 64) {
		t.Fatal("new finite dependency provenance was not deep-copied")
	}
	if freshSnap.Artifacts[0].SHA256 == strings.Repeat("0", 64) {
		t.Fatal("external mutation of returned Artifacts leaked into witness internal state")
	}

	// 2. Assert witness hash and trust verification are completely unaffected
	currSHA, err := witness.ManifestSHA256()
	if err != nil || currSHA != origSHA {
		t.Fatalf("witness manifest SHA drifted after external mutations: got %s, expected %s", currSHA, origSHA)
	}
	if err := VerifyUnifiedManifestTrust(witness, pin); err != nil {
		t.Fatalf("trust verification failed after external mutations: %v", err)
	}
}

func TestUnifiedRoleAndDependencyClosureStaySeparate(t *testing.T) {
	m := sampleValidManifest()
	m.Roles[1].RunnerArtifactID = "pinned-buildkitd-bin"
	if m.Validate() == nil {
		t.Fatal("buildkitd impersonated source adapter")
	}
	m = sampleValidManifest()
	for i := range m.Artifacts {
		if m.Artifacts[i].ID == m.Components.BuildNetworkExecutor.ArtifactID {
			for _, art := range m.Artifacts {
				if art.ID == m.Roles[1].RunnerArtifactID {
					m.Artifacts[i].SHA256 = art.SHA256
					break
				}
			}
			break
		}
	}
	if m.Validate() == nil {
		t.Fatal("copied source adapter impersonated build policy executor")
	}
	m = sampleValidManifest()
	for i := range m.Artifacts {
		if m.Artifacts[i].ID == m.Roles[1].RunnerArtifactID {
			for _, art := range m.Artifacts {
				if art.ID == m.Roles[0].RunnerArtifactID {
					m.Artifacts[i].SHA256 = art.SHA256
					break
				}
			}
			break
		}
	}
	if m.Validate() == nil {
		t.Fatal("one executable impersonated two business adapters")
	}
	m = sampleValidManifest()
	for i := range m.Artifacts {
		if m.Artifacts[i].ID == "fixture-source-runner" {
			for _, a := range m.Artifacts {
				if a.ID == "pinned-buildkitd-bin" {
					m.Artifacts[i].SHA256 = a.SHA256
				}
			}
		}
	}
	if m.Validate() == nil {
		t.Fatal("copied worker bytes impersonated source adapter")
	}
	m = sampleValidManifest()
	m.Dependencies[0].RuntimeArtifactIDs = []string{"pinned-docker-bin"}
	if m.Validate() == nil {
		t.Fatal("Docker CLI-only recipe impersonated Engine closure")
	}
	m = sampleValidManifest()
	m.Dependencies[2].RuntimeArtifactIDs = []string{"pinned-buildkitd-bin", "fixture-buildctl"}
	if m.Validate() == nil {
		t.Fatal("BuildKit recipe omitted rootlesskit")
	}
	m = sampleValidManifest()
	m.Dependencies[2].BuildKitMembers[2].SourceName = "buildkit"
	if m.Validate() == nil {
		t.Fatal("RootlessKit member borrowed BuildKit archive")
	}
	m = sampleValidManifest()
	m.Dependencies[2].BuildKitSources = m.Dependencies[2].BuildKitSources[:1]
	if m.Validate() == nil {
		t.Fatal("BuildKit accepted one archive for two upstreams")
	}
	m = sampleValidManifest()
	m.Dependencies[1].GitHostPackages.Packages = m.Dependencies[1].GitHostPackages.Packages[:1]
	if m.Validate() == nil {
		t.Fatal("Git package closure omitted git-man")
	}
	m = sampleValidManifest()
	m.Dependencies[1].GitHostPackages.Packages[0].SourceURL = "https://archive.ubuntu.com/ubuntu/pool/main/g/git/git_2.43.0-1ubuntu7.2_amd64.deb"
	if m.Validate() == nil {
		t.Fatal("Git package archive URL had a different Ubuntu revision")
	}
	m = sampleValidManifest()
	m.Components.BuildNetworkExecutor.ArtifactID = ""
	if m.Validate() == nil {
		t.Fatal("missing managed policy executor accepted")
	}
}
