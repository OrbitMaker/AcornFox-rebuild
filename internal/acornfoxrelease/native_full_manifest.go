package acornfoxrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/artifactio"
)

var ErrNativeFullManifest = errors.New("Native full manifest inputs are incomplete or untrusted")
var ErrNativeFullCommitUnknown = errors.New("Native full manifest output commit is uncertain")

const nativeFullSchemaOutputLimit = 8 << 10
const nativeFullMaterialLimit int64 = 1 << 30

// An independently pinned finite table of actual archives, selected archive
// members and Git host-package bytes. It is not a target-host observation.
type NativeFullMaterialInputsV1 struct {
	SchemaVersion                     int                         `json:"schema_version"`
	Dependencies                      []UnifiedDependencyPolicyV1 `json:"dependencies"`
	Sources                           []NativeFullSourceFileV1    `json:"sources"`
	Members                           []NativeFullMemberFileV1    `json:"members"`
	GitExecutables                    []NativeFullGitFileV1       `json:"git_executables"`
	GitExtractionEvidenceRelativeFile string                      `json:"git_extraction_evidence_relative_file"`
	GitExtractionEvidenceSHA256       string                      `json:"git_extraction_evidence_sha256"`
}
type NativeFullSourceFileV1 struct {
	Name         string `json:"name"`
	RelativeFile string `json:"relative_file"`
}
type NativeFullMemberFileV1 struct {
	ArtifactID         string `json:"artifact_id"`
	SourceName         string `json:"source_name"`
	ArchivePath        string `json:"archive_path"`
	TargetRelativePath string `json:"target_relative_path"`
	SHA256             string `json:"sha256"`
	SizeBytes          int64  `json:"size_bytes"`
}
type NativeFullGitFileV1 struct {
	Path         string `json:"path"`
	ResolvedPath string `json:"resolved_path"`
	RelativeFile string `json:"relative_file"`
	SizeBytes    int64  `json:"size_bytes"`
}
type NativeFullManifestRequest struct {
	ProductRoot           string
	ProductResponse       []byte
	ProductResponseSHA256 string
	MaterialRoot          string
	MaterialInputs        []byte
	MaterialInputsSHA256  string
	Output                string
}
type NativeFullManifestResult struct {
	Output                string `json:"output"`
	Bundle                string `json:"bundle"`
	ManifestSHA256        string `json:"manifest_sha256"`
	MaterialClosureSHA256 string `json:"material_closure_sha256"`
}
type nativeFullObservedSource struct {
	Name      string `json:"name"`
	SourceURL string `json:"source_url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}
type nativeFullObservedMember struct {
	ArtifactID   string `json:"artifact_id"`
	SourceName   string `json:"source_name"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
}
type nativeFullClosure struct {
	SchemaVersion                            int                        `json:"schema_version"`
	ManifestSHA256                           string                     `json:"manifest_sha256"`
	ProductResponseSHA256                    string                     `json:"product_response_sha256"`
	MaterialInputsSHA256                     string                     `json:"material_inputs_sha256"`
	Sources                                  []nativeFullObservedSource `json:"sources"`
	Members                                  []nativeFullObservedMember `json:"members"`
	GitExecutables                           []nativeFullObservedMember `json:"git_executables"`
	GitDebMemberRelationReverified           bool                       `json:"git_deb_member_relation_reverified"`
	GitDebExternalExtractionEvidenceRequired bool                       `json:"git_deb_external_extraction_evidence_required"`
	GitDebExternalExtractionEvidenceSHA256   string                     `json:"git_deb_external_extraction_evidence_sha256"`
	TargetHostReadbackRequired               bool                       `json:"target_host_readback_required"`
}
type nativeSchemaRunner func(context.Context, *os.File) ([]byte, error)
type nativeFullArchivePin struct {
	SourceURL, SHA256 string
	SizeBytes         int64
}

// BuildNativeFullManifestV1 produces a byte candidate only. The sole stage is
// output/bundle; output/material-closure.json is not an install payload member.
func BuildNativeFullManifestV1(ctx context.Context, req NativeFullManifestRequest) (NativeFullManifestResult, error) {
	return buildNativeFullManifest(ctx, req, runPinnedCoreNativeSchema)
}

func buildNativeFullManifest(ctx context.Context, req NativeFullManifestRequest, runSchema nativeSchemaRunner) (result NativeFullManifestResult, err error) {
	if ctx == nil || runSchema == nil || ctx.Err() != nil || !digestText.MatchString(req.ProductResponseSHA256) || !digestText.MatchString(req.MaterialInputsSHA256) {
		return result, ErrNativeFullManifest
	}
	for _, path := range []string{req.ProductRoot, req.MaterialRoot, req.Output} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return result, ErrNativeFullManifest
		}
	}
	if pathWithin(req.ProductRoot, req.Output) || pathWithin(req.MaterialRoot, req.Output) || pathWithin(req.Output, req.ProductRoot) || pathWithin(req.Output, req.MaterialRoot) {
		return result, ErrNativeFullManifest
	}
	productPin, err := pinPrivateNativeFullInput(req.ProductRoot)
	if err != nil {
		return result, err
	}
	defer productPin.close()
	materialPin, err := pinPrivateNativeFullInput(req.MaterialRoot)
	if err != nil {
		return result, err
	}
	defer materialPin.close()
	var product struct {
		Output  string                 `json:"output"`
		Receipt NativeProductReceiptV1 `json:"receipt"`
	}
	if sha256Text(req.ProductResponse) != req.ProductResponseSHA256 || decodeNativeFullJSON(req.ProductResponse, &product) != nil || product.Output != req.ProductRoot || product.Receipt.Validate() != nil {
		return result, ErrNativeFullManifest
	}
	receipt := NativePartialReceiptV1(product.Receipt)
	if verifyFileTree(req.ProductRoot, receipt.Files, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil {
		return result, ErrNativeFullManifest
	}
	if verifyNativeFullCoreWebMetadata(req.ProductRoot, receipt) != nil {
		return result, ErrNativeFullManifest
	}
	var materials NativeFullMaterialInputsV1
	if sha256Text(req.MaterialInputs) != req.MaterialInputsSHA256 || decodeNativeFullJSON(req.MaterialInputs, &materials) != nil || materials.SchemaVersion != 1 {
		return result, ErrNativeFullManifest
	}
	expectedSources, expectedMembers, gitPins, checkErr := nativeFullExpectedMaterials(materials.Dependencies)
	if checkErr != nil || len(materials.Sources) != len(expectedSources) || len(materials.Members) != len(expectedMembers) || len(materials.GitExecutables) != len(gitPins) {
		return result, ErrNativeFullManifest
	}
	materialRoot, err := os.OpenRoot(req.MaterialRoot)
	if err != nil {
		return result, err
	}
	defer materialRoot.Close()
	observedSources := make([]nativeFullObservedSource, 0, len(materials.Sources))
	seenSources := map[string]bool{}
	seenSourceFiles := map[string]bool{}
	for _, source := range materials.Sources {
		want, ok := expectedSources[source.Name]
		if !ok || seenSources[source.Name] || seenSourceFiles[source.RelativeFile] {
			return result, ErrNativeFullManifest
		}
		size, digest, readErr := inspectNativeFullFile(materialRoot, source.RelativeFile, 0644, nativeFullMaterialLimit)
		if readErr != nil || size != want.SizeBytes || digest != want.SHA256 {
			return result, ErrNativeFullManifest
		}
		observedSources = append(observedSources, nativeFullObservedSource{source.Name, want.SourceURL, digest, size})
		seenSources[source.Name] = true
		seenSourceFiles[source.RelativeFile] = true
	}
	observedMembers := make([]nativeFullObservedMember, 0, len(materials.Members))
	memberArtifacts := make([]UnifiedArtifactV1, 0, len(materials.Members))
	seenMemberIDs := map[string]bool{}
	seenMemberTargets := map[string]bool{}
	for _, member := range materials.Members {
		wantSource, ok := expectedMembers[member.ArtifactID]
		if !ok || seenMemberIDs[member.ArtifactID] || seenMemberTargets[member.TargetRelativePath] || member.SourceName != wantSource || !seenSources[member.SourceName] || !validRelativeFile(member.ArchivePath) || !validRelativeFile(member.TargetRelativePath) || !strings.HasPrefix(member.TargetRelativePath, "embedded/bin/") || !digestText.MatchString(member.SHA256) || member.SizeBytes < 1 || member.SizeBytes > maxGoBinaryOutputBytes {
			return result, ErrNativeFullManifest
		}
		memberArtifacts = append(memberArtifacts, UnifiedArtifactV1{member.ArtifactID, member.TargetRelativePath, member.SizeBytes, member.SHA256, true})
		observedMembers = append(observedMembers, nativeFullObservedMember{member.ArtifactID, member.SourceName, member.TargetRelativePath, member.SHA256, member.SizeBytes})
		seenMemberIDs[member.ArtifactID] = true
		seenMemberTargets[member.TargetRelativePath] = true
	}
	observedGit := make([]nativeFullObservedMember, 0, len(materials.GitExecutables))
	seenGit := map[string]bool{}
	seenGitFiles := map[string]bool{}
	for _, source := range materials.GitExecutables {
		pin, ok := gitPins[source.Path]
		if !ok || seenGit[source.Path] || seenGitFiles[source.RelativeFile] || source.ResolvedPath != pin.ResolvedPath || source.SizeBytes < 1 || source.SizeBytes > maxGoBinaryOutputBytes {
			return result, ErrNativeFullManifest
		}
		size, digest, readErr := inspectNativeFullFile(materialRoot, source.RelativeFile, 0755, maxGoBinaryOutputBytes)
		if readErr != nil || size != source.SizeBytes || digest != pin.SHA256 {
			return result, ErrNativeFullManifest
		}
		observedGit = append(observedGit, nativeFullObservedMember{source.Path, "git-host-package", source.ResolvedPath, digest, size})
		seenGit[source.Path] = true
		seenGitFiles[source.RelativeFile] = true
	}
	if !digestText.MatchString(materials.GitExtractionEvidenceSHA256) {
		return result, ErrNativeFullManifest
	}
	_, gitEvidenceSHA, gitEvidenceErr := inspectNativeFullFile(materialRoot, materials.GitExtractionEvidenceRelativeFile, 0644, 1<<20)
	if gitEvidenceErr != nil || gitEvidenceSHA != materials.GitExtractionEvidenceSHA256 {
		return result, ErrNativeFullManifest
	}
	if len(seenSources) != len(expectedSources) || len(seenMemberIDs) != len(expectedMembers) || len(seenGit) != len(gitPins) {
		return result, ErrNativeFullManifest
	}
	schema, err := readNativeCoreSchema(ctx, filepath.Join(req.ProductRoot, "bin/acornfox-core"), receipt, runSchema)
	if err != nil {
		return result, err
	}
	artifacts := make([]UnifiedArtifactV1, 0, len(receipt.Files)+len(memberArtifacts))
	for _, file := range receipt.Files {
		mode := os.FileMode(file.Mode)
		size, digest, readErr := inspectNativeFullProductFile(req.ProductRoot, file.Path, mode)
		if readErr != nil || digest != file.SHA256 || size < 1 {
			return result, ErrNativeFullManifest
		}
		id := nativeFullProductID(file.Path)
		if id == "" {
			return result, ErrNativeFullManifest
		}
		artifacts = append(artifacts, UnifiedArtifactV1{id, file.Path, size, digest, mode == 0755})
	}
	artifacts = append(artifacts, memberArtifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].RelativePath < artifacts[j].RelativePath })
	manifest := UnifiedReleaseManifestV1{
		SchemaVersion: UnifiedReleaseManifestSchemaV1, Product: UnifiedProduct, ReleaseID: "release-" + receipt.Version, Version: receipt.Version,
		TargetOS: UnifiedTargetOS, TargetDistribution: UnifiedTargetDistribution, TargetDistributionVersion: UnifiedTargetDistributionVersion, TargetArchitecture: UnifiedTargetArchitecture,
		Provenance: UnifiedProvenanceV1{SourceRepository: receipt.SourceRepository, SourceCommit: receipt.SourceCommit, BuildTimestamp: time.Now().UTC().Format(time.RFC3339), ToolchainSHA256: receipt.ToolchainSHA256},
		Components: UnifiedComponentsV1{Core: UnifiedComponentRefV1{"core"}, CLI: UnifiedComponentRefV1{"cli"}, UI: UnifiedComponentRefV1{"core-ui"}, HostUpdate: UnifiedComponentRefV1{"host-update"}, BuildNetworkExecutor: UnifiedComponentRefV1{"build-network"}},
		Roles:      []UnifiedRoleV1{{RoleContainerRuntime, "Container runtime adapter", "container-runner"}, {RoleSourceBuild, "Source build adapter", "source-runner"}, {RoleApplicationGateway, "Application gateway adapter", "gateway-runner"}},
		Artifacts:  artifacts, Dependencies: materials.Dependencies,
		SQLiteCompatibility: SQLiteCompatibilityV1{MinSchemaVersion: Migration0001AdminAuth, MaxSchemaVersion: Migration0013ImagePublicAccess, RequiredMigrations: schema, ReadWriteMode: "exclusive_writer", RollbackPolicy: RollbackRequiresDataRestore},
	}
	rawManifest, err := CanonicalUnifiedManifestV1(manifest)
	if err != nil {
		return result, err
	}
	witness, err := ParseUnifiedManifestV1(rawManifest)
	if err != nil {
		return result, err
	}
	manifestSHA, err := witness.ManifestSHA256()
	if err != nil {
		return result, err
	}
	sort.Slice(observedSources, func(i, j int) bool { return observedSources[i].Name < observedSources[j].Name })
	sort.Slice(observedMembers, func(i, j int) bool { return observedMembers[i].RelativePath < observedMembers[j].RelativePath })
	sort.Slice(observedGit, func(i, j int) bool { return observedGit[i].ArtifactID < observedGit[j].ArtifactID })
	closure := nativeFullClosure{SchemaVersion: 1, ManifestSHA256: manifestSHA, ProductResponseSHA256: req.ProductResponseSHA256, MaterialInputsSHA256: req.MaterialInputsSHA256, Sources: observedSources, Members: observedMembers, GitExecutables: observedGit, GitDebMemberRelationReverified: false, GitDebExternalExtractionEvidenceRequired: true, GitDebExternalExtractionEvidenceSHA256: gitEvidenceSHA, TargetHostReadbackRequired: true}
	rawClosure, err := json.Marshal(closure)
	if err != nil {
		return result, err
	}
	if !productPin.validAt(req.ProductRoot) || !materialPin.validAt(req.MaterialRoot) || verifyFileTree(req.ProductRoot, receipt.Files, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil {
		return result, ErrNativeFullManifest
	}
	return writeNativeFullOutput(ctx, req, receipt, materials, expectedSources, observedSources, observedGit, rawManifest, rawClosure, manifestSHA)
}

func nativeFullProductID(path string) string {
	switch path {
	case "bin/acornfox-core":
		return "core"
	case "bin/acornfox":
		return "cli"
	case "bin/acornfox-host-helper":
		return "host-helper"
	case "bin/acornfox-container":
		return "container-runner"
	case "bin/acornfox-source-build":
		return "source-runner"
	case "bin/acornfox-gateway":
		return "gateway-runner"
	case "bin/acornfox-host-update":
		return "host-update"
	case "bin/acornfox-build-network":
		return "build-network"
	case "web/core.html":
		return "core-ui"
	}
	if strings.HasPrefix(path, "web/") {
		digest := sha256.Sum256([]byte(path))
		return "web-" + hex.EncodeToString(digest[:8])
	}
	return ""
}

func decodeNativeFullJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return ErrNativeFullManifest
	}
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrNativeFullManifest
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(body, canonical) {
		return ErrNativeFullManifest
	}
	return nil
}

func pinPrivateNativeFullInput(path string) (*directoryPin, error) {
	canonical, resolveErr := filepath.EvalSymlinks(path)
	if resolveErr != nil || canonical != path {
		return nil, ErrNativeFullManifest
	}
	pin, err := pinDirectory(path)
	if err != nil {
		return nil, ErrNativeFullManifest
	}
	info, err := pin.file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		pin.close()
		return nil, ErrNativeFullManifest
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		pin.close()
		return nil, ErrNativeFullManifest
	}
	return pin, nil
}

func nativeFullExpectedMaterials(deps []UnifiedDependencyPolicyV1) (map[string]nativeFullArchivePin, map[string]string, map[string]GitExecutionPinV1, error) {
	sources := map[string]nativeFullArchivePin{}
	members := map[string]string{}
	git := map[string]GitExecutionPinV1{}
	if len(deps) != 4 {
		return nil, nil, nil, ErrNativeFullManifest
	}
	seen := map[string]bool{}
	for _, dep := range deps {
		if seen[dep.Name] {
			return nil, nil, nil, ErrNativeFullManifest
		}
		seen[dep.Name] = true
		switch dep.Name {
		case DependencyDocker, DependencyCaddy:
			sources[dep.Name] = nativeFullArchivePin{dep.PinnedProvisioning.SourceURL, dep.PinnedProvisioning.SourceSHA256, dep.PinnedProvisioning.SizeBytes}
			for _, id := range dep.RuntimeArtifactIDs {
				members[id] = dep.Name
			}
		case DependencyBuildKit:
			for _, source := range dep.BuildKitSources {
				sources[source.Name] = nativeFullArchivePin{source.SourceURL, source.SourceSHA256, source.SizeBytes}
			}
			for _, ref := range dep.BuildKitMembers {
				members[ref.ArtifactID] = ref.SourceName
			}
		case DependencyGit:
			if dep.GitHostPackages == nil {
				return nil, nil, nil, ErrNativeFullManifest
			}
			for _, pkg := range dep.GitHostPackages.Packages {
				sources[pkg.Name] = nativeFullArchivePin{pkg.SourceURL, pkg.ArchiveSHA256, pkg.SizeBytes}
			}
			for _, pin := range dep.GitHostPackages.Executables {
				git[pin.Path] = pin
			}
		default:
			return nil, nil, nil, ErrNativeFullManifest
		}
	}
	if !seen[DependencyDocker] || !seen[DependencyCaddy] || !seen[DependencyBuildKit] || !seen[DependencyGit] || len(sources) != 6 || len(members) != 10 || len(git) != 2 {
		return nil, nil, nil, ErrNativeFullManifest
	}
	return sources, members, git, nil
}

// For the four actual gzip archives, selected members are read directly from
// the pinned archive and written into the caller's new partial bundle. Git
// .deb/zstd provenance is separate approved collector evidence and must be
// re-observed on the target host.
func verifyNativeFullArchiveMembership(ctx context.Context, root, target *os.Root, sources []NativeFullSourceFileV1, members []NativeFullMemberFileV1, pins map[string]nativeFullArchivePin) error {
	wanted := map[string]map[string]NativeFullMemberFileV1{}
	for _, member := range members {
		if wanted[member.SourceName] == nil {
			wanted[member.SourceName] = map[string]NativeFullMemberFileV1{}
		}
		if wanted[member.SourceName][member.ArchivePath].ArtifactID != "" {
			return ErrNativeFullManifest
		}
		wanted[member.SourceName][member.ArchivePath] = member
	}
	for _, source := range sources {
		if source.Name == "git" || source.Name == "git-man" {
			continue
		}
		pin, ok := pins[source.Name]
		if !ok || len(wanted[source.Name]) == 0 {
			return ErrNativeFullManifest
		}
		before, err := root.Lstat(source.RelativeFile)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0644 || before.Size() != pin.SizeBytes {
			return ErrNativeFullManifest
		}
		file, err := root.OpenFile(source.RelativeFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() || opened.Mode() != before.Mode() || !opened.ModTime().Equal(before.ModTime()) {
			file.Close()
			return ErrNativeFullManifest
		}
		exact, err := artifactio.NewExactArchiveReader(file, pin.SizeBytes, nativeFullMaterialLimit)
		if err != nil {
			file.Close()
			return err
		}
		gzipReader, err := gzip.NewReader(exact)
		if err != nil {
			file.Close()
			return err
		}
		reader := tar.NewReader(gzipReader)
		found := map[string]bool{}
		seenEntries := map[string]bool{}
		var expanded int64
		for {
			if ctx.Err() != nil {
				gzipReader.Close()
				file.Close()
				return ctx.Err()
			}
			header, nextErr := reader.Next()
			if nextErr == io.EOF {
				break
			}
			if nextErr != nil {
				gzipReader.Close()
				file.Close()
				return ErrNativeFullManifest
			}
			name := strings.TrimPrefix(header.Name, "./")
			name = strings.TrimSuffix(name, "/")
			if (name == "" || name == ".") && header.Typeflag == tar.TypeDir {
				continue
			}
			if !validRelativeFile(name) || strings.Contains(name, "\\") || header.Size < 0 || header.Size > nativeFullMaterialLimit-expanded {
				gzipReader.Close()
				file.Close()
				return ErrNativeFullManifest
			}
			if seenEntries[name] {
				gzipReader.Close()
				file.Close()
				return ErrNativeFullManifest
			}
			seenEntries[name] = true
			expanded += header.Size
			if header.Typeflag == tar.TypeDir {
				continue
			}
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				gzipReader.Close()
				file.Close()
				return ErrNativeFullManifest
			}
			if spec, selected := wanted[source.Name][name]; selected {
				if found[name] || header.Size != spec.SizeBytes || header.Mode != 0755 {
					gzipReader.Close()
					file.Close()
					return ErrNativeFullManifest
				}
				if target != nil {
					if err := writeNativeFullArchiveMember(target, "bundle/payload/"+spec.TargetRelativePath, reader, header.Size, spec.SHA256); err != nil {
						gzipReader.Close()
						file.Close()
						return err
					}
				} else {
					hash := sha256.New()
					if n, copyErr := io.CopyN(hash, reader, header.Size); copyErr != nil || n != header.Size || hex.EncodeToString(hash.Sum(nil)) != spec.SHA256 {
						gzipReader.Close()
						file.Close()
						return ErrNativeFullManifest
					}
				}
				found[name] = true
			}
		}
		if len(found) != len(wanted[source.Name]) {
			gzipReader.Close()
			file.Close()
			return ErrNativeFullManifest
		}
		if n, drainErr := io.Copy(io.Discard, io.LimitReader(gzipReader, nativeFullMaterialLimit-expanded+1)); drainErr != nil || n > nativeFullMaterialLimit-expanded {
			gzipReader.Close()
			file.Close()
			return ErrNativeFullManifest
		}
		closeGzip := gzipReader.Close()
		finishErr := exact.Finish(pin.SHA256)
		closedInfo, closedStatErr := file.Stat()
		closeFile := file.Close()
		after, statErr := root.Lstat(source.RelativeFile)
		if closeGzip != nil || finishErr != nil || closedStatErr != nil || closeFile != nil || statErr != nil || !os.SameFile(before, closedInfo) || !os.SameFile(before, after) || after.Size() != before.Size() || closedInfo.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !closedInfo.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() || closedInfo.Mode() != before.Mode() {
			return ErrNativeFullManifest
		}
	}
	return nil
}

func writeNativeFullArchiveMember(target *os.Root, path string, reader io.Reader, size int64, expectedSHA string) error {
	if !validRelativeFile(path) || size < 1 || size > maxGoBinaryOutputBytes || !digestText.MatchString(expectedSHA) || ensureCandidateDirectories(target, path) != nil {
		return ErrNativeFullManifest
	}
	file, err := target.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	if err := file.Chmod(0755); err != nil {
		file.Close()
		return err
	}
	opened, statErr := file.Stat()
	hash := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(file, hash), reader, size)
	syncErr := file.Sync()
	closeErr := file.Close()
	after, afterErr := target.Lstat(path)
	if statErr != nil || copyErr != nil || syncErr != nil || closeErr != nil || afterErr != nil || n != size || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0755 || !os.SameFile(opened, after) || after.Size() != size || after.Mode().Perm() != 0755 || linkCount(after) != 1 || hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return ErrNativeFullManifest
	}
	return nil
}

func inspectNativeFullFile(root *os.Root, path string, mode os.FileMode, max int64) (int64, string, error) {
	if !validRelativeFile(path) {
		return 0, "", ErrNativeFullManifest
	}
	part := ""
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "" {
			part = component
		} else {
			part += "/" + component
		}
		info, err := root.Lstat(part)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return 0, "", ErrNativeFullManifest
		}
		if part != path && !info.IsDir() {
			return 0, "", ErrNativeFullManifest
		}
	}
	before, err := root.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != mode || linkCount(before) != 1 || before.Size() < 1 || before.Size() > max {
		return 0, "", ErrNativeFullManifest
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, "", err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return 0, "", ErrNativeFullManifest
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.NewSectionReader(file, 0, before.Size()+1))
	closeErr := file.Close()
	after, statErr := root.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || n != before.Size() {
		return 0, "", ErrNativeFullManifest
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func inspectNativeFullProductFile(rootPath, path string, mode os.FileMode) (int64, string, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return 0, "", err
	}
	defer root.Close()
	maximum := maxGoBinaryOutputBytes
	if strings.HasPrefix(path, "web/") {
		maximum = maxWebDistMemberBytes
	}
	return inspectNativeFullFile(root, path, mode, maximum)
}

func verifyNativeFullCoreWebMetadata(rootPath string, receipt NativePartialReceiptV1) error {
	var expected string
	for _, file := range receipt.Files {
		if file.Path == "web/build-metadata.json" {
			expected = file.SHA256
		}
	}
	if expected == "" {
		return ErrNativeFullManifest
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	size, digest, err := inspectNativeFullFile(root, "web/build-metadata.json", 0644, maxWebMetadataBytes)
	if err != nil || digest != expected {
		return ErrNativeFullManifest
	}
	file, err := root.OpenFile("web/build-metadata.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxWebMetadataBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != size || sha256Text(raw) != expected {
		return ErrNativeFullManifest
	}
	plan := GoBuildPlanV1{nativePartial: true, releaseVersion: receipt.Version, sourceCommit: receipt.SourceCommit, sourceRepositoryURL: receipt.SourceRepository}
	return parseWebMetadata(raw, plan)
}

func readNativeCoreSchema(ctx context.Context, path string, receipt NativePartialReceiptV1, runner nativeSchemaRunner) (pins []SQLiteMigrationPinV1, err error) {
	var expected string
	for _, file := range receipt.Files {
		if file.Path == "bin/acornfox-core" {
			expected = file.SHA256
		}
	}
	if expected == "" {
		return nil, ErrNativeFullManifest
	}
	binary, err := openPinnedBinary(path, false)
	if err != nil {
		return nil, ErrNativeFullManifest
	}
	defer func() {
		if closeErr := binary.Close(); closeErr != nil {
			pins = nil
			err = errors.Join(ErrNativeFullManifest, closeErr)
		}
	}()
	if binary.info.Mode().Perm() != 0755 {
		return nil, ErrNativeFullManifest
	}
	before, err := binary.digest()
	if err != nil || before != expected {
		return nil, ErrNativeFullManifest
	}
	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := runner(timeout, binary.file)
	if err != nil || len(raw) == 0 || len(raw) > nativeFullSchemaOutputLimit {
		return nil, ErrNativeFullManifest
	}
	var description struct {
		SchemaVersion      int                    `json:"schema_version"`
		RequiredMigrations []SQLiteMigrationPinV1 `json:"required_migrations"`
	}
	if decodeNativeFullJSON(raw, &description) != nil || description.SchemaVersion != 1 {
		return nil, ErrNativeFullManifest
	}
	after, err := binary.digest()
	if err != nil || before != after {
		return nil, ErrNativeFullManifest
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(binary.info, current) {
		return nil, ErrNativeFullManifest
	}
	compat := SQLiteCompatibilityV1{MinSchemaVersion: Migration0001AdminAuth, MaxSchemaVersion: Migration0013ImagePublicAccess, RequiredMigrations: description.RequiredMigrations, ReadWriteMode: "exclusive_writer", RollbackPolicy: RollbackRequiresDataRestore}
	if compat.Validate() != nil {
		return nil, ErrNativeFullManifest
	}
	return description.RequiredMigrations, nil
}

func runPinnedCoreNativeSchema(ctx context.Context, binary *os.File) ([]byte, error) {
	if binary == nil {
		return nil, ErrNativeFullManifest
	}
	// Linux execve resolves this inherited FD after ExtraFiles maps it to 3.
	// It never reopens the mutable product-root pathname.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "native-schema")
	cmd.ExtraFiles = []*os.File{binary}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var output cappedBuffer
	output.limit = nativeFullSchemaOutputLimit
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || output.exceeded {
		return nil, ErrNativeFullManifest
	}
	return output.Bytes(), nil
}

func writeNativeFullOutput(ctx context.Context, req NativeFullManifestRequest, receipt NativePartialReceiptV1, materials NativeFullMaterialInputsV1, expectedSources map[string]nativeFullArchivePin, observedSources []nativeFullObservedSource, observedGit []nativeFullObservedMember, rawManifest, rawClosure []byte, manifestSHA string) (result NativeFullManifestResult, err error) {
	if ctx.Err() != nil || !filepath.IsAbs(req.Output) || filepath.Clean(req.Output) != req.Output {
		return result, ErrNativeFullManifest
	}
	parent, parentPin, err := pinStageParent(filepath.Dir(req.Output))
	if err != nil {
		return result, err
	}
	defer parentPin.close()
	if parent != filepath.Dir(req.Output) || pathWithin(req.ProductRoot, parent) || pathWithin(req.MaterialRoot, parent) {
		return result, ErrNativeFullManifest
	}
	output := filepath.Join(parent, filepath.Base(req.Output))
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		return result, ErrNativeFullManifest
	}
	partial, err := os.MkdirTemp(parent, ".partial-native-full-")
	if err != nil {
		return result, err
	}
	partialPin, err := pinDirectory(partial)
	if err != nil {
		return result, err
	}
	defer partialPin.close()
	committed := false
	defer func() {
		if !committed && parentPin.validAt(parent) && partialPin.validAt(partial) {
			if cleanupErr := os.RemoveAll(partial); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	target, err := os.OpenRoot(partial)
	if err != nil {
		return result, err
	}
	if err := target.Mkdir("bundle", 0700); err != nil {
		target.Close()
		return result, err
	}
	if err := target.Mkdir("bundle/payload", 0700); err != nil {
		target.Close()
		return result, err
	}
	entries := make([]FileEntryV1, 0, len(receipt.Files)+len(materials.Members))
	for _, file := range receipt.Files {
		if ctx.Err() != nil {
			target.Close()
			return result, ctx.Err()
		}
		path := "bundle/payload/" + file.Path
		maximum := maxGoBinaryOutputBytes
		if strings.HasPrefix(file.Path, "web/") {
			maximum = maxWebDistMemberBytes
		}
		if err := copyCandidateFile(req.ProductRoot, file.Path, target, path, file, file.Mode, maximum); err != nil {
			target.Close()
			return result, err
		}
		if err := syncNativeFullFile(target, path); err != nil {
			target.Close()
			return result, err
		}
		entries = append(entries, file)
	}
	materialRoot, openErr := os.OpenRoot(req.MaterialRoot)
	if openErr != nil {
		target.Close()
		return result, openErr
	}
	archiveErr := verifyNativeFullArchiveMembership(ctx, materialRoot, target, materials.Sources, materials.Members, expectedSources)
	closeMaterialErr := materialRoot.Close()
	if archiveErr != nil || closeMaterialErr != nil {
		target.Close()
		return result, ErrNativeFullManifest
	}
	for _, member := range materials.Members {
		entries = append(entries, FileEntryV1{Path: member.TargetRelativePath, SHA256: member.SHA256, Mode: 0755})
	}
	if err := writeNativeFullSmallFile(target, "bundle/manifest.json", rawManifest); err != nil {
		target.Close()
		return result, err
	}
	if err := writeNativeFullSmallFile(target, "material-closure.json", rawClosure); err != nil {
		target.Close()
		return result, err
	}
	if err := target.Close(); err != nil {
		return result, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if verifyFileTree(filepath.Join(partial, "bundle", "payload"), entries, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil || verifyNativeFullTopLevel(partial, rawManifest, rawClosure) != nil {
		return result, ErrNativeFullManifest
	}
	materialRoot, openErr = os.OpenRoot(req.MaterialRoot)
	if openErr != nil {
		return result, openErr
	}
	defer materialRoot.Close()
	sourceFacts := map[string]nativeFullObservedSource{}
	for _, source := range observedSources {
		sourceFacts[source.Name] = source
	}
	for _, source := range materials.Sources {
		want := sourceFacts[source.Name]
		size, digest, readErr := inspectNativeFullFile(materialRoot, source.RelativeFile, 0644, nativeFullMaterialLimit)
		if readErr != nil || size != want.SizeBytes || digest != want.SHA256 {
			return result, ErrNativeFullManifest
		}
	}
	gitFacts := map[string]nativeFullObservedMember{}
	for _, member := range observedGit {
		gitFacts[member.ArtifactID] = member
	}
	for _, member := range materials.GitExecutables {
		want := gitFacts[member.Path]
		size, digest, readErr := inspectNativeFullFile(materialRoot, member.RelativeFile, 0755, maxGoBinaryOutputBytes)
		if readErr != nil || size != want.SizeBytes || digest != want.SHA256 {
			return result, ErrNativeFullManifest
		}
	}
	_, evidenceSHA, evidenceErr := inspectNativeFullFile(materialRoot, materials.GitExtractionEvidenceRelativeFile, 0644, 1<<20)
	if evidenceErr != nil || evidenceSHA != materials.GitExtractionEvidenceSHA256 {
		return result, ErrNativeFullManifest
	}
	if err := syncNativeFullDirectories(partial); err != nil {
		return result, err
	}
	if !parentPin.validAt(parent) || !partialPin.validAt(partial) || ctx.Err() != nil {
		return result, ErrNativeFullManifest
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		return result, ErrNativeFullManifest
	}
	if err := renameDirectoryNoReplace(parentPin.file, filepath.Base(partial), parentPin.file, filepath.Base(output)); err != nil {
		return result, err
	}
	committed = true
	if err := parentPin.file.Sync(); err != nil {
		return result, errors.Join(ErrNativeFullCommitUnknown, err)
	}
	after, statErr := os.Lstat(output)
	original, originalErr := partialPin.file.Stat()
	if statErr != nil || originalErr != nil || !os.SameFile(after, original) || !parentPin.validAt(parent) || verifyNativeFullTopLevel(output, rawManifest, rawClosure) != nil || verifyFileTree(filepath.Join(output, "bundle", "payload"), entries, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil {
		return result, ErrNativeFullCommitUnknown
	}
	return NativeFullManifestResult{Output: output, Bundle: filepath.Join(output, "bundle"), ManifestSHA256: manifestSHA, MaterialClosureSHA256: sha256Text(rawClosure)}, nil
}

func syncNativeFullFile(root *os.Root, path string) error {
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}
func writeNativeFullSmallFile(root *os.Root, path string, raw []byte) error {
	if len(raw) < 1 || len(raw) > 1<<20 || ensureCandidateDirectories(root, path) != nil {
		return ErrNativeFullManifest
	}
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	n, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	info, statErr := root.Lstat(path)
	if writeErr != nil || syncErr != nil || closeErr != nil || statErr != nil || n != len(raw) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(raw)) {
		return ErrNativeFullManifest
	}
	return nil
}
func syncNativeFullDirectories(root string) error {
	var dirs []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrNativeFullManifest
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if err := artifactio.SyncDirectory(dir); err != nil {
			return err
		}
	}
	return nil
}
func verifyNativeFullTopLevel(root string, manifest, closure []byte) error {
	top, err := os.ReadDir(root)
	if err != nil || len(top) != 2 || top[0].Name() != "bundle" || top[1].Name() != "material-closure.json" {
		return ErrNativeFullManifest
	}
	bundle, err := os.ReadDir(filepath.Join(root, "bundle"))
	if err != nil || len(bundle) != 2 || bundle[0].Name() != "manifest.json" || bundle[1].Name() != "payload" {
		return ErrNativeFullManifest
	}
	for _, item := range []struct {
		path string
		body []byte
	}{{filepath.Join(root, "bundle", "manifest.json"), manifest}, {filepath.Join(root, "material-closure.json"), closure}} {
		info, err := os.Lstat(item.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(item.body)) || linkCount(info) != 1 {
			return ErrNativeFullManifest
		}
		actual, err := os.ReadFile(item.path)
		if err != nil || !bytes.Equal(actual, item.body) {
			return ErrNativeFullManifest
		}
	}
	return nil
}
