// Package unifiedinstall joins the existing release/layout contracts without
// adding installation authority or an install-to-release import cycle.
package unifiedinstall

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/install"
)

var (
	ErrIncomplete   = errors.New("unified candidate is incomplete")
	ErrIncompatible = errors.New("unified candidate is incompatible with observed facts")
)

// ArtifactFile is an already-opened regular artifact from the caller's protected
// stage. The caller must use the existing secure root/path binding before opening
// it and retain/close the descriptor. Intake neither opens paths nor publishes.
type ArtifactFile struct {
	ArtifactID   string
	RelativePath string
	File         *os.File
}

// RoleFact comes from a controlled business-interface probe, not manifest text
// or a health-only check. It describes observed actions; it is not readiness.
type RoleFact struct {
	Name             string
	RunnerArtifactID string
	ArtifactSHA256   string
	Actions          []string
}

type DependencyFact struct {
	Name                           string
	Ownership                      string // external, managed, absent; Git has two explicit host-package origins
	Version                        string // normalized numeric major.minor.patch
	ProbeSocket                    string
	ProvisionedSourceArchiveSHA256 string                 // actual archived source provenance, distinct from installed members
	Members                        []DependencyMemberFact // actual managed installed member identities
	ProvisionedSources             []DependencySourceFact // BuildKit's two actual, separately checked archives
	GitHost                        *GitHostReadbackFact   // only the finite Ubuntu Git host-package branch
}

type DependencySourceFact struct {
	Name, SourceURL, ArchiveSHA256 string
	SizeBytes                      int64
	Members                        []DependencyMemberFact
}
type GitInstalledPackageFact struct {
	Name, Version, Architecture, Origin, SourceURL, ArchiveSHA256 string
	DebControlVersion                                             string // downloaded .deb control Version; provisioned only
	SizeBytes                                                     int64
}
type GitExecutionFact struct {
	Path, ResolvedPath, LinkTarget, LinkOwnerPackage, TargetOwnerPackage, SHA256 string
	NeededLibraries                                                              []string // actual ELF DT_NEEDED from the fixed executable
	Loader                                                                       *GitLoaderReadbackFact
}
type GitLoaderLibraryFact struct{ SONAME, ResolvedPath string }
type GitLoaderReadbackFact struct {
	LoaderPath, LoaderResolvedPath, LoaderSHA256 string
	LoaderOwnerUID, LoaderMode                   uint32
	LoaderELFClass, LoaderELFMachine             string
	TargetPath, TargetSHA256, OutputSHA256       string
	OutputSizeBytes                              int64
	ExitCode                                     int
	Resolved                                     []GitLoaderLibraryFact // file-backed loader --list results, not VDSO
}
type GitHostReadbackFact struct {
	Packages             []GitInstalledPackageFact
	Executables          []GitExecutionFact
	GitExecPath          string
	PresentBeforeInstall bool
	InstallReceiptSHA256 string
}

type HostFacts struct {
	OS, Distribution, DistributionVersion, Architecture string
	// SQLiteTarget is the actual selected Core initializer's migrations, whether
	// preparing a fresh install or an existing database. Never invent older pins.
	SQLiteTarget []acornfoxrelease.SQLiteMigrationPinV1
	Roles        []RoleFact
	HostUpdate   RoleFact // observed Native SQLite updater actions, never the old PG/helper profile
	Dependencies []DependencyFact
}

type IntakeInput struct {
	Witness    acornfoxrelease.UnifiedManifestWitness
	TrustedPin acornfoxrelease.TrustedReleasePinV1
	// Inventory must be the complete observed stage inventory, not a selected subset.
	Inventory                  []ArtifactFile
	InventoryUID, InventoryGID int
	Facts                      HostFacts
}

type DependencyMemberFact struct{ ArtifactID, SHA256 string }
type DependencyDecision struct{ Name, Ownership, Action string }

// Preflight reports an observed inventory only. It does not authorize host
// actions, certify operational readiness, or represent an install/upgrade.
type Preflight struct {
	ReleaseID, Version, SourceCommit, ManifestSHA256 string
	Artifacts                                        []acornfoxrelease.UnifiedArtifactV1
	Dependencies                                     []DependencyDecision
}

// InspectArtifactCandidate verifies the trusted complete manifest, selected
// host/schema compatibility, dependency observations and every staged FD. It
// does not require business roles or the updater to be running before their
// bytes can be safely staged, and it never reports operational readiness.
func InspectArtifactCandidate(ctx context.Context, input IntakeInput) (Preflight, error) {
	return inspectCandidate(ctx, input, false, true)
}

// InspectCandidate is the strict post-install composition check. Observed
// business actions and Native updater actions remain mandatory here.
func InspectCandidate(ctx context.Context, input IntakeInput) (Preflight, error) {
	return inspectCandidate(ctx, input, true, true)
}

// This package-private entry is reachable only from the protected bootstrap
// repair stage. Missing dependency facts are explicitly unresolved, never
// interpreted as absent or compatible.
func inspectRepairArtifactCandidate(ctx context.Context, input IntakeInput) (Preflight, error) {
	if len(input.Facts.Dependencies) != 0 || len(input.Facts.Roles) != 0 || input.Facts.HostUpdate.Name != "" || len(input.Facts.HostUpdate.Actions) != 0 {
		return Preflight{}, ErrIncomplete
	}
	return inspectCandidate(ctx, input, false, false)
}

func inspectCandidate(ctx context.Context, input IntakeInput, requireActions, requireDependencies bool) (Preflight, error) {
	if ctx == nil || ctx.Err() != nil {
		return Preflight{}, errors.New("intake context is unavailable")
	}
	if err := acornfoxrelease.VerifyUnifiedManifestTrust(input.Witness, input.TrustedPin); err != nil {
		return Preflight{}, err
	}
	manifest, err := input.Witness.Snapshot()
	if err != nil {
		return Preflight{}, err
	}
	if err := install.ValidateUnifiedLayoutSecurity(install.DefaultUnifiedLayoutSpec()); err != nil {
		return Preflight{}, err
	}
	facts := input.Facts
	if facts.OS != manifest.TargetOS || facts.Distribution != manifest.TargetDistribution || facts.DistributionVersion != manifest.TargetDistributionVersion || facts.Architecture != manifest.TargetArchitecture {
		return Preflight{}, ErrIncompatible
	}
	// Compare the actual selected initializer against the current strict contract.
	// The selected Core initializer must exactly match these source contract pins;
	// neither missing target migrations nor future pins are silently accepted.
	if !slices.Equal(facts.SQLiteTarget, manifest.SQLiteCompatibility.RequiredMigrations) {
		return Preflight{}, fmt.Errorf("%w: SQLite initializer migration pins differ", ErrIncompatible)
	}
	artifacts := make(map[string]acornfoxrelease.UnifiedArtifactV1, len(manifest.Artifacts))
	for _, a := range manifest.Artifacts {
		artifacts[a.ID] = a
	}
	if requireActions {
		if err := checkRoles(manifest, facts.Roles, artifacts); err != nil {
			return Preflight{}, err
		}
		updater := facts.HostUpdate
		updaterArtifact := artifacts[manifest.Components.HostUpdate.ArtifactID]
		if updater.Name != acornfoxrelease.ComponentHostUpdate || updater.RunnerArtifactID != updaterArtifact.ID || updater.ArtifactSHA256 != updaterArtifact.SHA256 {
			return Preflight{}, fmt.Errorf("%w: missing Native host-update facts", ErrIncomplete)
		}
		for _, action := range []string{"native_sqlite_preflight", "switch_managed_release", "restore_sqlite"} {
			if !slices.Contains(updater.Actions, action) {
				return Preflight{}, fmt.Errorf("%w: missing Native host-update action", ErrIncomplete)
			}
		}
	}
	var decisions []DependencyDecision
	if requireDependencies {
		decisions, err = checkDependencies(manifest.Dependencies, facts.Dependencies, artifacts)
		if err != nil {
			return Preflight{}, err
		}
	}
	if input.InventoryUID < 0 || input.InventoryGID < 0 || len(input.Inventory) != len(artifacts) {
		return Preflight{}, ErrIncomplete
	}
	seen := make(map[string]bool, len(input.Inventory))
	for _, entry := range input.Inventory {
		a, ok := artifacts[entry.ArtifactID]
		if !ok || seen[entry.ArtifactID] || entry.RelativePath != a.RelativePath || entry.File == nil {
			return Preflight{}, ErrIncomplete
		}
		seen[entry.ArtifactID] = true
		if err := artifactio.CleanRelative(entry.RelativePath); err != nil {
			return Preflight{}, err
		}
		before, err := entry.File.Stat()
		if err != nil {
			return Preflight{}, err
		}
		mode := os.FileMode(0644)
		if a.Executable {
			mode = 0755
		}
		if !before.Mode().IsRegular() || before.Mode().Perm() != mode || before.Size() != a.SizeBytes {
			return Preflight{}, fmt.Errorf("%w: artifact size/type/mode differs", ErrIncomplete)
		}
		if err := artifactio.CheckFileOwner(before, input.InventoryUID, input.InventoryGID); err != nil {
			return Preflight{}, err
		}
		reader, err := artifactio.NewExactArchiveReader(contextReader{ctx, io.NewSectionReader(entry.File, 0, a.SizeBytes+1)}, a.SizeBytes, a.SizeBytes)
		if err != nil {
			return Preflight{}, err
		}
		if err := artifactio.VerifyArchiveMember(reader, a.SizeBytes, nil, a.SHA256, nil, a.RelativePath, uint32(mode)); err != nil {
			return Preflight{}, err
		}
		if err := reader.Finish(a.SHA256); err != nil {
			return Preflight{}, err
		}
		after, err := entry.File.Stat()
		if err != nil {
			return Preflight{}, err
		}
		if err := artifactio.CheckFileOwner(after, input.InventoryUID, input.InventoryGID); err != nil {
			return Preflight{}, err
		}
		if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
			return Preflight{}, fmt.Errorf("%w: artifact changed during observation", ErrIncomplete)
		}
	}
	if err := ctx.Err(); err != nil {
		return Preflight{}, err
	}
	digest, err := input.Witness.ManifestSHA256()
	if err != nil {
		return Preflight{}, err
	}
	return Preflight{ReleaseID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.Provenance.SourceCommit, ManifestSHA256: digest, Artifacts: append([]acornfoxrelease.UnifiedArtifactV1(nil), manifest.Artifacts...), Dependencies: decisions}, nil
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func checkRoles(manifest acornfoxrelease.UnifiedReleaseManifestV1, facts []RoleFact, artifacts map[string]acornfoxrelease.UnifiedArtifactV1) error {
	if len(facts) != len(manifest.Roles) {
		return fmt.Errorf("%w: missing official business role facts", ErrIncomplete)
	}
	observed := make(map[string]RoleFact, len(facts))
	for _, fact := range facts {
		if _, exists := observed[fact.Name]; exists {
			return ErrIncomplete
		}
		observed[fact.Name] = fact
	}
	forbidden := map[string]bool{manifest.Components.Core.ArtifactID: true, manifest.Components.CLI.ArtifactID: true, manifest.Components.HostUpdate.ArtifactID: true, manifest.Components.BuildNetworkExecutor.ArtifactID: true}
	for _, role := range manifest.Roles {
		fact, ok := observed[role.Name]
		a := artifacts[role.RunnerArtifactID]
		if !ok || forbidden[role.RunnerArtifactID] || fact.RunnerArtifactID != role.RunnerArtifactID || fact.ArtifactSHA256 != a.SHA256 {
			return fmt.Errorf("%w: official role runner identity differs", ErrIncomplete)
		}
		var required []string
		switch role.Name {
		case acornfoxrelease.RoleContainerRuntime:
			required = []string{"deploy_image", "observe_image"}
		case acornfoxrelease.RoleSourceBuild:
			required = []string{"prepare_source", "build", "cancel_build"}
		case acornfoxrelease.RoleApplicationGateway:
			required = []string{"bind_route", "unbind_route", "observe_certificate"}
		default:
			return ErrIncomplete
		}
		for _, action := range required {
			if !slices.Contains(fact.Actions, action) {
				return fmt.Errorf("%w: missing business action for %s", ErrIncomplete, role.Name)
			}
		}
		// Declared tool recipes are dependencies, not AcornFox role adapters.
		for _, dep := range manifest.Dependencies {
			for _, id := range dep.RuntimeArtifactIDs {
				member := artifacts[id]
				if role.RunnerArtifactID == id || a.SHA256 == member.SHA256 {
					return fmt.Errorf("%w: upstream runtime member impersonates business runner", ErrIncomplete)
				}
			}
		}
	}
	return nil
}

func checkDependencies(policies []acornfoxrelease.UnifiedDependencyPolicyV1, facts []DependencyFact, artifacts map[string]acornfoxrelease.UnifiedArtifactV1) ([]DependencyDecision, error) {
	if len(policies) != len(facts) {
		return nil, fmt.Errorf("%w: missing dependency observations", ErrIncomplete)
	}
	observed := make(map[string]DependencyFact, len(facts))
	for _, fact := range facts {
		if _, exists := observed[fact.Name]; exists {
			return nil, ErrIncomplete
		}
		observed[fact.Name] = fact
	}
	decisions := make([]DependencyDecision, 0, len(policies))
	for _, policy := range policies {
		fact, ok := observed[policy.Name]
		if !ok {
			return nil, ErrIncomplete
		}
		if fact.Ownership == "absent" {
			if fact.Version != "" || fact.ProbeSocket != "" || fact.ProvisionedSourceArchiveSHA256 != "" || len(fact.Members) != 0 || len(fact.ProvisionedSources) != 0 || fact.GitHost != nil {
				return nil, ErrIncompatible
			}
			if policy.Name == acornfoxrelease.DependencyGit {
				decisions = append(decisions, DependencyDecision{policy.Name, "absent", "provision_required"})
				continue
			}
			decisions = append(decisions, DependencyDecision{policy.Name, "managed", "provision_required"})
			continue
		}
		if policy.Name == acornfoxrelease.DependencyGit {
			decision, err := checkGitHostPackage(policy, fact)
			if err != nil {
				return nil, err
			}
			decisions = append(decisions, decision)
			continue
		}
		if fact.Ownership != "external" && fact.Ownership != "managed" {
			return nil, ErrIncompatible
		}
		if !supportedVersion(fact.Version, policy.SupportedCondition.MinVersion) || (policy.SupportedCondition.ProbeSocket != "" && fact.ProbeSocket != policy.SupportedCondition.ProbeSocket) {
			return nil, fmt.Errorf("%w: dependency %s cannot be reused", ErrIncompatible, policy.Name)
		}
		if policy.Name == acornfoxrelease.DependencyBuildKit {
			if err := checkBuildKitSources(policy, fact, artifacts); err != nil {
				return nil, err
			}
			decisions = append(decisions, DependencyDecision{policy.Name, fact.Ownership, "reuse_existing_compatible"})
			continue
		}
		if len(fact.ProvisionedSources) != 0 || fact.GitHost != nil {
			return nil, ErrIncompatible
		}
		if fact.Ownership == "external" && (fact.ProvisionedSourceArchiveSHA256 != "" || len(fact.Members) != 0) {
			return nil, fmt.Errorf("%w: external dependency cannot borrow managed provenance", ErrIncompatible)
		}
		if fact.Ownership == "managed" {
			if fact.ProvisionedSourceArchiveSHA256 != policy.PinnedProvisioning.SourceSHA256 || len(fact.Members) != len(policy.RuntimeArtifactIDs) {
				return nil, fmt.Errorf("%w: managed dependency provenance or closure differs", ErrIncompatible)
			}
			members := make(map[string]string, len(fact.Members))
			for _, member := range fact.Members {
				if members[member.ArtifactID] != "" {
					return nil, ErrIncompatible
				}
				members[member.ArtifactID] = member.SHA256
			}
			for _, id := range policy.RuntimeArtifactIDs {
				if members[id] != artifacts[id].SHA256 {
					return nil, fmt.Errorf("%w: managed dependency member differs", ErrIncompatible)
				}
			}
		}
		decisions = append(decisions, DependencyDecision{policy.Name, fact.Ownership, "reuse_existing_compatible"})
	}
	return decisions, nil
}

func checkBuildKitSources(policy acornfoxrelease.UnifiedDependencyPolicyV1, fact DependencyFact, artifacts map[string]acornfoxrelease.UnifiedArtifactV1) error {
	if fact.GitHost != nil {
		return ErrIncompatible
	}
	if fact.Ownership == "external" {
		if fact.ProvisionedSourceArchiveSHA256 != "" || len(fact.Members) != 0 || len(fact.ProvisionedSources) != 0 {
			return ErrIncompatible
		}
		return nil
	}
	if fact.ProvisionedSourceArchiveSHA256 != "" || len(fact.Members) != 0 || len(fact.ProvisionedSources) != 2 {
		return fmt.Errorf("%w: BuildKit source archives are incomplete", ErrIncompatible)
	}
	wantSources := map[string]acornfoxrelease.DependencySourceArchiveV1{}
	wantMembers := map[string]map[string]string{"buildkit": {}, "rootlesskit": {}}
	for _, source := range policy.BuildKitSources {
		wantSources[source.Name] = source
	}
	for _, member := range policy.BuildKitMembers {
		wantMembers[member.SourceName][member.ArtifactID] = artifacts[member.ArtifactID].SHA256
	}
	seenSources := map[string]bool{}
	for _, source := range fact.ProvisionedSources {
		pin, ok := wantSources[source.Name]
		if !ok || seenSources[source.Name] || source.SourceURL != pin.SourceURL || source.ArchiveSHA256 != pin.SourceSHA256 || source.SizeBytes != pin.SizeBytes || len(source.Members) != len(wantMembers[source.Name]) {
			return fmt.Errorf("%w: BuildKit archive provenance differs", ErrIncompatible)
		}
		seenSources[source.Name] = true
		seenMembers := map[string]bool{}
		for _, member := range source.Members {
			wantSHA, ok := wantMembers[source.Name][member.ArtifactID]
			if !ok || seenMembers[member.ArtifactID] || member.SHA256 != wantSHA {
				return fmt.Errorf("%w: BuildKit member borrowed another source", ErrIncompatible)
			}
			seenMembers[member.ArtifactID] = true
		}
	}
	if !seenSources["buildkit"] || !seenSources["rootlesskit"] {
		return ErrIncompatible
	}
	return nil
}

func observedSHA(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}

func checkGitHostPackage(policy acornfoxrelease.UnifiedDependencyPolicyV1, fact DependencyFact) (DependencyDecision, error) {
	var zero DependencyDecision
	if fact.Ownership != "preexisting_external" && fact.Ownership != "acornfox_provisioned_host_package" ||
		!supportedVersion(fact.Version, policy.SupportedCondition.MinVersion) || fact.ProbeSocket != "" ||
		fact.ProvisionedSourceArchiveSHA256 != "" || len(fact.Members) != 0 || len(fact.ProvisionedSources) != 0 || fact.GitHost == nil {
		return zero, fmt.Errorf("%w: Git host ownership or evidence missing", ErrIncompatible)
	}
	readback := fact.GitHost
	if readback.GitExecPath != "/usr/lib/git-core" || len(readback.Packages) != 2 || len(readback.Executables) != 2 {
		return zero, ErrIncompatible
	}
	provisioned := fact.Ownership == "acornfox_provisioned_host_package"
	if provisioned && (readback.PresentBeforeInstall || !observedSHA(readback.InstallReceiptSHA256)) ||
		!provisioned && (!readback.PresentBeforeInstall || readback.InstallReceiptSHA256 != "") {
		return zero, fmt.Errorf("%w: Git install origin differs", ErrIncompatible)
	}
	pins := map[string]acornfoxrelease.GitHostPackagePinV1{}
	for _, pin := range policy.GitHostPackages.Packages {
		pins[pin.Name] = pin
	}
	seenPackages := map[string]bool{}
	observedPackageVersion := ""
	for _, pkg := range readback.Packages {
		pin, ok := pins[pkg.Name]
		if !ok || seenPackages[pkg.Name] || pkg.Origin != "Ubuntu" || pkg.Architecture != pin.Architecture || pkg.Version == "" {
			return zero, ErrIncompatible
		}
		seenPackages[pkg.Name] = true
		if observedPackageVersion != "" && observedPackageVersion != pkg.Version {
			return zero, fmt.Errorf("%w: Git package pair versions differ", ErrIncompatible)
		}
		observedPackageVersion = pkg.Version
		if pkg.Name == "git" {
			upstream := pkg.Version
			if _, tail, found := strings.Cut(upstream, ":"); found {
				upstream = tail
			}
			upstream, _, _ = strings.Cut(upstream, "-")
			if upstream != fact.Version {
				return zero, fmt.Errorf("%w: Git observed version differs from package", ErrIncompatible)
			}
		}
		if provisioned {
			if pkg.Version != pin.Version || pkg.DebControlVersion != pin.Version || pkg.SourceURL != pin.SourceURL || pkg.ArchiveSHA256 != pin.ArchiveSHA256 || pkg.SizeBytes != pin.SizeBytes {
				return zero, fmt.Errorf("%w: provisioned Git package differs from pin", ErrIncompatible)
			}
		} else if pkg.SourceURL != "" || pkg.ArchiveSHA256 != "" || pkg.SizeBytes != 0 || pkg.DebControlVersion != "" {
			return zero, fmt.Errorf("%w: preexisting Git borrowed provisioning proof", ErrIncompatible)
		}
	}
	if !seenPackages["git"] || !seenPackages["git-man"] {
		return zero, ErrIncompatible
	}
	wantExecutables := map[string]string{}
	wantResolved := map[string]string{}
	for _, pin := range policy.GitHostPackages.Executables {
		wantExecutables[pin.Path] = pin.SHA256
		wantResolved[pin.Path] = pin.ResolvedPath
	}
	seenExecutables := map[string]bool{}
	gitNeeded, httpsNeeded := false, false
	for _, executable := range readback.Executables {
		wantSHA, ok := wantExecutables[executable.Path]
		wantLink := ""
		if executable.Path == "/usr/lib/git-core/git-remote-https" {
			wantLink = "git-remote-http"
		}
		if !ok || seenExecutables[executable.Path] || executable.ResolvedPath != wantResolved[executable.Path] || executable.LinkTarget != wantLink || executable.LinkOwnerPackage != "git" || executable.TargetOwnerPackage != "git" || !observedSHA(executable.SHA256) || provisioned && executable.SHA256 != wantSHA || len(executable.NeededLibraries) == 0 || len(executable.NeededLibraries) > 32 || executable.Loader == nil {
			return zero, fmt.Errorf("%w: Git executable closure unavailable", ErrIncompatible)
		}
		seenExecutables[executable.Path] = true
		probe := executable.Loader
		if probe.LoaderPath != "/lib64/ld-linux-x86-64.so.2" ||
			probe.LoaderResolvedPath != "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" && probe.LoaderResolvedPath != "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ||
			probe.LoaderOwnerUID != 0 || probe.LoaderMode != 0o755 || probe.LoaderELFClass != "ELF64" || probe.LoaderELFMachine != "x86-64" ||
			probe.TargetPath != executable.ResolvedPath || probe.TargetSHA256 != executable.SHA256 ||
			!observedSHA(probe.LoaderSHA256) || !observedSHA(probe.OutputSHA256) || probe.OutputSizeBytes <= 0 || probe.OutputSizeBytes > 64<<10 || probe.ExitCode != 0 || len(probe.Resolved) == 0 || len(probe.Resolved) > 64 {
			return zero, fmt.Errorf("%w: Git fixed loader readback unavailable", ErrIncompatible)
		}
		resolved := map[string]bool{}
		for _, library := range probe.Resolved {
			if library.SONAME == "" || strings.ContainsAny(library.SONAME, "/\\\x00 \t\r\n") || resolved[library.SONAME] || filepath.Clean(library.ResolvedPath) != library.ResolvedPath ||
				!strings.HasPrefix(library.ResolvedPath, "/lib/x86_64-linux-gnu/") && !strings.HasPrefix(library.ResolvedPath, "/usr/lib/x86_64-linux-gnu/") {
				return zero, fmt.Errorf("%w: Git loader library path invalid", ErrIncompatible)
			}
			resolved[library.SONAME] = true
		}
		perExecutable := map[string]bool{}
		for _, name := range executable.NeededLibraries {
			if name == "" || strings.ContainsAny(name, "/\\\x00 \t\r\n") || perExecutable[name] {
				return zero, fmt.Errorf("%w: Git ELF dependency name invalid", ErrIncompatible)
			}
			perExecutable[name] = true
			if !resolved[name] {
				return zero, fmt.Errorf("%w: direct Git ELF dependency absent from loader readback", ErrIncompatible)
			}
			if executable.Path == "/usr/bin/git" && name == "libc.so.6" {
				gitNeeded = true
			}
			if executable.Path == "/usr/lib/git-core/git-remote-https" && strings.HasPrefix(name, "libcurl") {
				httpsNeeded = true
			}
		}
	}
	if !gitNeeded || !httpsNeeded {
		return zero, fmt.Errorf("%w: Git and HTTPS helper dynamic closure incomplete", ErrIncompatible)
	}
	if provisioned {
		return DependencyDecision{policy.Name, fact.Ownership, "use_provisioned_host_package"}, nil
	}
	return DependencyDecision{policy.Name, fact.Ownership, "reuse_existing_compatible"}, nil
}

func supportedVersion(actual, minimum string) bool {
	parse := func(v string) ([3]uint64, bool) {
		var out [3]uint64
		parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
		if len(parts) != 3 {
			return out, false
		}
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 64)
			if err != nil || p == "" {
				return out, false
			}
			out[i] = n
		}
		return out, true
	}
	a, ok := parse(actual)
	if !ok {
		return false
	}
	b, ok := parse(minimum)
	if !ok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}
