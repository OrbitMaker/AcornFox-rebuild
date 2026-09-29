package unifiedinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxrelease"
)

// This byte fixture supplies probe facts only to test glue composition; it is
// deliberately not a real runner, installation or operational-ready witness.
func intakeFixture(t *testing.T) (IntakeInput, string) {
	t.Helper()
	root := t.TempDir()
	digest := func(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
	m := acornfoxrelease.UnifiedReleaseManifestV1{SchemaVersion: 1, Product: "acornfox", ReleaseID: "ur-intake-fixture", Version: "1.0.0", TargetOS: "linux", TargetDistribution: "ubuntu", TargetDistributionVersion: "24.04", TargetArchitecture: "amd64", Provenance: acornfoxrelease.UnifiedProvenanceV1{SourceRepository: "https://github.com/acme/acornfox", SourceCommit: strings.Repeat("a", 40), BuildTimestamp: "2026-09-28T00:00:00Z", ToolchainSHA256: strings.Repeat("b", 64)}}
	in := IntakeInput{InventoryUID: os.Getuid(), InventoryGID: os.Getgid(), Facts: HostFacts{OS: "linux", Distribution: "ubuntu", DistributionVersion: "24.04", Architecture: "amd64"}}
	// All bytes here are synthetic contract fixtures, never production artifacts.
	addPath := func(id, rel string, executable bool) acornfoxrelease.UnifiedComponentRefV1 {
		body := []byte("fixture bytes for " + id)
		mode := os.FileMode(0755)
		if !executable {
			mode = 0644
		}
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		in.Inventory = append(in.Inventory, ArtifactFile{id, rel, file})
		m.Artifacts = append(m.Artifacts, acornfoxrelease.UnifiedArtifactV1{ID: id, RelativePath: rel, SizeBytes: int64(len(body)), SHA256: digest(body), Executable: executable})
		return acornfoxrelease.UnifiedComponentRefV1{ArtifactID: id}
	}
	add := func(id string, executable bool) acornfoxrelease.UnifiedComponentRefV1 {
		rel := "bin/" + id
		if !executable {
			rel = "web/core.html"
		}
		return addPath(id, rel, executable)
	}
	m.Components = acornfoxrelease.UnifiedComponentsV1{Core: add("core", true), CLI: add("cli", true), UI: add("ui", false), HostUpdate: add("host-update", true), BuildNetworkExecutor: addPath("build-network-executor", "bin/acornfox-build-network", true)}
	for _, role := range []struct {
		name, path string
		actions    []string
	}{{"container-runtime", "bin/acornfox-container", []string{"deploy_image", "observe_image"}}, {"source-build", "bin/acornfox-source-build", []string{"prepare_source", "build", "cancel_build"}}, {"application-gateway", "bin/acornfox-gateway", []string{"bind_route", "unbind_route", "observe_certificate"}}} {
		id := addPath(role.name, role.path, true).ArtifactID
		a := m.Artifacts[len(m.Artifacts)-1]
		m.Roles = append(m.Roles, acornfoxrelease.UnifiedRoleV1{Name: role.name, Description: "fixture", RunnerArtifactID: id})
		in.Facts.Roles = append(in.Facts.Roles, RoleFact{role.name, id, a.SHA256, role.actions})
	}
	in.Facts.HostUpdate = RoleFact{acornfoxrelease.ComponentHostUpdate, "host-update", m.Artifacts[3].SHA256, []string{"native_sqlite_preflight", "switch_managed_release", "restore_sqlite"}}
	for _, name := range []string{"docker", "git", "buildkit", "caddy"} {
		if name == "git" {
			policy := acornfoxrelease.GitHostPackagePolicyV1{
				Packages: []acornfoxrelease.GitHostPackagePinV1{
					{Name: "git", Version: "1:2.43.0-1ubuntu7.3", Architecture: "amd64", SourceURL: "https://archive.ubuntu.com/ubuntu/pool/main/g/git/git_2.43.0-1ubuntu7.3_amd64.deb", ArchiveSHA256: digest([]byte("fixture Git package archive")), SizeBytes: 2000000},
					{Name: "git-man", Version: "1:2.43.0-1ubuntu7.3", Architecture: "all", SourceURL: "https://archive.ubuntu.com/ubuntu/pool/main/g/git/git-man_2.43.0-1ubuntu7.3_all.deb", ArchiveSHA256: digest([]byte("fixture Git manual package archive")), SizeBytes: 1000000},
				},
				Executables: []acornfoxrelease.GitExecutionPinV1{{Path: "/usr/bin/git", ResolvedPath: "/usr/bin/git", SHA256: digest([]byte("fixture installed git"))}, {Path: "/usr/lib/git-core/git-remote-https", ResolvedPath: "/usr/lib/git-core/git-remote-http", SHA256: digest([]byte("fixture installed HTTPS helper"))}},
			}
			m.Dependencies = append(m.Dependencies, acornfoxrelease.UnifiedDependencyPolicyV1{Name: name, SupportedCondition: acornfoxrelease.DependencySupportedConditionV1{MinVersion: "2.34.0", ReusePolicy: "reuse_existing_compatible"}, GitHostPackages: &policy})
			loader := func(label, targetPath, targetSHA string, libraries []GitLoaderLibraryFact) *GitLoaderReadbackFact {
				return &GitLoaderReadbackFact{LoaderPath: "/lib64/ld-linux-x86-64.so.2", LoaderResolvedPath: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", LoaderSHA256: digest([]byte("fixture fixed loader")), LoaderOwnerUID: 0, LoaderMode: 0o755, LoaderELFClass: "ELF64", LoaderELFMachine: "x86-64", TargetPath: targetPath, TargetSHA256: targetSHA, OutputSHA256: digest([]byte("fixture loader output " + label)), OutputSizeBytes: 512, ExitCode: 0, Resolved: libraries}
			}
			libc := GitLoaderLibraryFact{SONAME: "libc.so.6", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libc.so.6"}
			zlib := GitLoaderLibraryFact{SONAME: "libz.so.1", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libz.so.1"}
			pcre := GitLoaderLibraryFact{SONAME: "libpcre2-8.so.0", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0"}
			curl := GitLoaderLibraryFact{SONAME: "libcurl-gnutls.so.4", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4"}
			gnutls := GitLoaderLibraryFact{SONAME: "libgnutls.so.30", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libgnutls.so.30"} // transitive loader result, not direct DT_NEEDED
			readback := &GitHostReadbackFact{
				Packages: []GitInstalledPackageFact{{Name: "git", Version: "1:2.43.0-1ubuntu7.3", Architecture: "amd64", Origin: "Ubuntu"}, {Name: "git-man", Version: "1:2.43.0-1ubuntu7.3", Architecture: "all", Origin: "Ubuntu"}},
				Executables: []GitExecutionFact{
					{Path: "/usr/bin/git", ResolvedPath: "/usr/bin/git", LinkOwnerPackage: "git", TargetOwnerPackage: "git", SHA256: digest([]byte("fixture installed git")), NeededLibraries: []string{libc.SONAME, zlib.SONAME, pcre.SONAME}, Loader: loader("git", "/usr/bin/git", digest([]byte("fixture installed git")), []GitLoaderLibraryFact{libc, zlib, pcre})},
					{Path: "/usr/lib/git-core/git-remote-https", ResolvedPath: "/usr/lib/git-core/git-remote-http", LinkTarget: "git-remote-http", LinkOwnerPackage: "git", TargetOwnerPackage: "git", SHA256: digest([]byte("fixture installed HTTPS helper")), NeededLibraries: []string{libc.SONAME, curl.SONAME}, Loader: loader("https", "/usr/lib/git-core/git-remote-http", digest([]byte("fixture installed HTTPS helper")), []GitLoaderLibraryFact{libc, curl, gnutls})},
				},
				GitExecPath: "/usr/lib/git-core", PresentBeforeInstall: true,
			}
			in.Facts.Dependencies = append(in.Facts.Dependencies, DependencyFact{Name: name, Ownership: "preexisting_external", Version: "2.43.0", GitHost: readback})
			continue
		}
		paths := map[string][]string{
			"docker":   {"embedded/bin/docker", "embedded/bin/dockerd", "embedded/bin/containerd", "embedded/bin/containerd-shim-runc-v2", "embedded/bin/runc", "embedded/bin/docker-proxy"},
			"buildkit": {"embedded/bin/buildkitd", "embedded/bin/buildctl", "embedded/bin/rootlesskit"},
			"caddy":    {"embedded/bin/caddy"},
		}[name]
		ids := make([]string, 0, len(paths))
		var first acornfoxrelease.UnifiedArtifactV1
		for i, path := range paths {
			id := "dependency-" + name + "-" + filepath.Base(path)
			addPath(id, path, true)
			ids = append(ids, id)
			if i == 0 {
				first = m.Artifacts[len(m.Artifacts)-1]
			}
		}
		probe := ""
		if name == "docker" {
			probe = "/var/run/docker.sock"
		}
		if name == "buildkit" {
			probe = "/run/acornfox-buildkit/buildkitd.sock"
		}
		archiveSHA := digest([]byte("synthetic archive source for " + name)) // archive differs from any member bytes.
		if name == "buildkit" {
			m.Dependencies = append(m.Dependencies, acornfoxrelease.UnifiedDependencyPolicyV1{Name: name, RuntimeArtifactIDs: ids, SupportedCondition: acornfoxrelease.DependencySupportedConditionV1{MinVersion: "1.0.0", ProbeSocket: probe, ReusePolicy: "reuse_existing_compatible"}, BuildKitSources: []acornfoxrelease.DependencySourceArchiveV1{{Name: "buildkit", SourceURL: "https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz", SourceSHA256: archiveSHA, SizeBytes: 92882168}, {Name: "rootlesskit", SourceURL: "https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz", SourceSHA256: digest([]byte("synthetic rootlesskit archive")), SizeBytes: 23335815}}, BuildKitMembers: []acornfoxrelease.DependencyMemberSourceV1{{ArtifactID: ids[0], SourceName: "buildkit"}, {ArtifactID: ids[1], SourceName: "buildkit"}, {ArtifactID: ids[2], SourceName: "rootlesskit"}}})
			in.Facts.Dependencies = append(in.Facts.Dependencies, DependencyFact{Name: name, Ownership: "external", Version: "1.2.0", ProbeSocket: probe})
			continue
		}
		m.Dependencies = append(m.Dependencies, acornfoxrelease.UnifiedDependencyPolicyV1{Name: name, RuntimeArtifactIDs: ids, SupportedCondition: acornfoxrelease.DependencySupportedConditionV1{MinVersion: "1.0.0", ProbeSocket: probe, ReusePolicy: "reuse_existing_compatible"}, PinnedProvisioning: acornfoxrelease.DependencyPinnedRecipeV1{ArtifactID: ids[0], SourceURL: "https://example.org/" + name, SourceSHA256: archiveSHA, SizeBytes: first.SizeBytes, TargetRelativePath: first.RelativePath}})
		in.Facts.Dependencies = append(in.Facts.Dependencies, DependencyFact{Name: name, Ownership: "external", Version: "1.2.0", ProbeSocket: probe})
	}
	versions := []string{acornfoxrelease.Migration0001AdminAuth, acornfoxrelease.Migration0002ApplicationRepository, acornfoxrelease.Migration0003TaskFencing, acornfoxrelease.Migration0004AuditEvidence, acornfoxrelease.Migration0005PackIntents, acornfoxrelease.Migration0006PackProtocolExecution, acornfoxrelease.Migration0007PackArtifactStaging, acornfoxrelease.Migration0008PackActivation, acornfoxrelease.Migration0009ImageDelivery, acornfoxrelease.Migration0010ImageExecution, acornfoxrelease.Migration0011ImageLifecycle, acornfoxrelease.Migration0012SourceBuild, acornfoxrelease.Migration0013ImagePublicAccess}
	for _, version := range versions {
		m.SQLiteCompatibility.RequiredMigrations = append(m.SQLiteCompatibility.RequiredMigrations, acornfoxrelease.SQLiteMigrationPinV1{Version: version, Checksum: strings.Repeat("c", 64)})
	}
	m.SQLiteCompatibility.MinSchemaVersion = versions[0]
	m.SQLiteCompatibility.MaxSchemaVersion = versions[len(versions)-1]
	m.SQLiteCompatibility.ReadWriteMode = "exclusive_writer"
	m.SQLiteCompatibility.RollbackPolicy = acornfoxrelease.RollbackRequiresDataRestore
	in.Facts.SQLiteTarget = append([]acornfoxrelease.SQLiteMigrationPinV1(nil), m.SQLiteCompatibility.RequiredMigrations...)
	raw, err := acornfoxrelease.CanonicalUnifiedManifestV1(m)
	if err != nil {
		t.Fatal(err)
	}
	in.Witness, err = acornfoxrelease.ParseUnifiedManifestV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	in.TrustedPin = acornfoxrelease.TrustedReleasePinV1{ExpectedReleaseID: m.ReleaseID, ExpectedManifestSHA256: digest(raw), ExpectedSourceCommit: m.Provenance.SourceCommit}
	return in, root
}

func TestIntakeComposesObservedBytesAndRejectsUninstallableFacts(t *testing.T) {
	input, root := intakeFixture(t)
	pre, err := InspectCandidate(context.Background(), input)
	if err != nil || len(pre.Artifacts) != len(input.Inventory) || len(pre.Dependencies) != 4 {
		t.Fatalf("preflight err=%v", err)
	}
	// These cases exercise only new glue boundaries, not existing parser/trust,
	// path/layout or provider matrices. No account/service/DB/pointer API exists.
	for _, test := range []struct {
		name   string
		change func(*IntakeInput)
		want   error
	}{
		{"partial witness", func(v *IntakeInput) { v.Witness = acornfoxrelease.UnifiedManifestWitness{} }, acornfoxrelease.ErrUnifiedManifest},
		{"source role missing", func(v *IntakeInput) { v.Facts.Roles = append([]RoleFact{v.Facts.Roles[0]}, v.Facts.Roles[2:]...) }, ErrIncomplete},
		{"health only gateway", func(v *IntakeInput) {
			v.Facts.Roles = append([]RoleFact(nil), v.Facts.Roles...)
			v.Facts.Roles[2].Actions = []string{"health"}
		}, ErrIncomplete},
		{"legacy host updater", func(v *IntakeInput) { v.Facts.HostUpdate.Actions = []string{"apply_0040"} }, ErrIncomplete},
		{"external incompatible", func(v *IntakeInput) {
			v.Facts.Dependencies = append([]DependencyFact(nil), v.Facts.Dependencies...)
			v.Facts.Dependencies[0].Version = "0.9.0"
		}, ErrIncompatible},
		{"actual native schema newer", func(v *IntakeInput) {
			v.Facts.SQLiteTarget = append(append([]acornfoxrelease.SQLiteMigrationPinV1(nil), v.Facts.SQLiteTarget...), acornfoxrelease.SQLiteMigrationPinV1{Version: "0014_unknown", Checksum: strings.Repeat("d", 64)})
		}, ErrIncompatible},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := input
			test.change(&copy)
			got, err := InspectCandidate(context.Background(), copy)
			if !errors.Is(err, test.want) || len(got.Artifacts) != 0 || got.ReleaseID != "" {
				t.Fatalf("failure returned candidate: %#v err=%v", got, err)
			}
		})
	}
	// A same-length byte change must be caught by the reused actual-stream hash.
	path := filepath.Join(root, "bin/cli")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := InspectCandidate(context.Background(), input); err == nil || len(got.Artifacts) != 0 {
		t.Fatal("altered bytes accepted")
	}
}

func TestManagedRuntimeClosureUsesActualMembersNotArchiveDigest(t *testing.T) {
	in, _ := intakeFixture(t)
	manifest, err := in.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	kit := manifest.Dependencies[2]
	fact := in.Facts.Dependencies[2]
	fact.Ownership = "managed"
	for _, source := range kit.BuildKitSources {
		observed := DependencySourceFact{Name: source.Name, SourceURL: source.SourceURL, ArchiveSHA256: source.SourceSHA256, SizeBytes: source.SizeBytes}
		for _, member := range kit.BuildKitMembers {
			if member.SourceName != source.Name {
				continue
			}
			art, err := in.Witness.Artifact(member.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
			observed.Members = append(observed.Members, DependencyMemberFact{ArtifactID: member.ArtifactID, SHA256: art.SHA256})
		}
		fact.ProvisionedSources = append(fact.ProvisionedSources, observed)
	}
	in.Facts.Dependencies[2] = fact
	if _, err := InspectCandidate(context.Background(), in); err != nil {
		t.Fatalf("two real source archives and their mapped members rejected: %v", err)
	}
	in.Facts.Dependencies[2].ProvisionedSources[1].Members = nil
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatalf("managed BuildKit missing rootlesskit accepted: %v", err)
	}
	in.Facts.Dependencies[2] = fact
	in.Facts.Dependencies[2].ProvisionedSources[1].Members = append([]DependencyMemberFact(nil), fact.ProvisionedSources[0].Members[:1]...)
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatalf("BuildKit member borrowed RootlessKit source: %v", err)
	}
}

func TestGitHostPackageOriginNeedsActualClosureEvidence(t *testing.T) {
	in, _ := intakeFixture(t)
	manifest, err := in.Witness.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	fact := in.Facts.Dependencies[1]
	originalHost := fact.GitHost
	fact.Ownership = "external"
	in.Facts.Dependencies[1] = fact
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatal("Git host package was disguised as generic external", err)
	}
	fact.Ownership = "preexisting_external"
	missingLibrary := *fact.GitHost
	missingLibrary.Executables = append([]GitExecutionFact(nil), fact.GitHost.Executables...)
	truncatedLoader := *missingLibrary.Executables[1].Loader
	truncatedLoader.Resolved = truncatedLoader.Resolved[:1] // the direct libcurl dependency is missing
	missingLibrary.Executables[1].Loader = &truncatedLoader
	fact.GitHost = &missingLibrary
	in.Facts.Dependencies[1] = fact
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatal("loader output missing a direct HTTPS-helper dependency was accepted", err)
	}
	wrongLink := *originalHost
	wrongLink.Executables = append([]GitExecutionFact(nil), originalHost.Executables...)
	wrongLink.Executables[1].LinkTarget = "../outside-helper"
	fact.GitHost = &wrongLink
	in.Facts.Dependencies[1] = fact
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatal("Git HTTPS alias escaped the fixed same-package target", err)
	}
	fact.Ownership = "acornfox_provisioned_host_package"
	readback := *originalHost
	readback.Packages = append([]GitInstalledPackageFact(nil), readback.Packages...)
	readback.PresentBeforeInstall = false
	readback.InstallReceiptSHA256 = strings.Repeat("f", 64)
	for i, pin := range manifest.Dependencies[1].GitHostPackages.Packages {
		readback.Packages[i].DebControlVersion = pin.Version
		readback.Packages[i].SourceURL = pin.SourceURL
		readback.Packages[i].ArchiveSHA256 = pin.ArchiveSHA256
		readback.Packages[i].SizeBytes = pin.SizeBytes
	}
	fact.GitHost = &readback
	in.Facts.Dependencies[1] = fact
	got, err := InspectCandidate(context.Background(), in)
	if err != nil || got.Dependencies[1] != (DependencyDecision{Name: "git", Ownership: "acornfox_provisioned_host_package", Action: "use_provisioned_host_package"}) {
		t.Fatal("exact finite Git package readback rejected", err)
	}
	readback.Packages[0].ArchiveSHA256 = strings.Repeat("0", 64)
	if got, err := InspectCandidate(context.Background(), in); !errors.Is(err, ErrIncompatible) || len(got.Artifacts) != 0 {
		t.Fatal("Git provisioned package borrowed wrong archive", err)
	}
	missing := DependencyFact{Name: "git", Ownership: "absent"}
	in.Facts.Dependencies[1] = missing
	got, err = InspectArtifactCandidate(context.Background(), in)
	if err != nil || got.Dependencies[1] != (DependencyDecision{Name: "git", Ownership: "absent", Action: "provision_required"}) {
		t.Fatal("missing Git did not remain provision_required", err)
	}
}
