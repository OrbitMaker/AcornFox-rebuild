package acornfoxrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNativeFullArchiveMemberMustMatchActualSourceBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	compressed := gzip.NewWriter(&raw)
	archive := tar.NewWriter(compressed)
	body := []byte("real upstream member")
	if err := archive.WriteHeader(&tar.Header{Name: "bin/tool", Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docker.tgz"), raw.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	sources := []NativeFullSourceFileV1{{Name: "docker", RelativeFile: "docker.tgz"}}
	members := []NativeFullMemberFileV1{{ArtifactID: "tool", SourceName: "docker", ArchivePath: "bin/tool", TargetRelativePath: "embedded/bin/tool", SHA256: strings.Repeat("a", 64), SizeBytes: int64(len(body))}}
	pins := map[string]nativeFullArchivePin{"docker": {SourceURL: "https://example.invalid/docker.tgz", SHA256: sha256Text(raw.Bytes()), SizeBytes: int64(raw.Len())}}
	if err := verifyNativeFullArchiveMembership(context.Background(), opened, nil, sources, members, pins); err == nil {
		t.Fatal("member not present with claimed hash was accepted")
	}
	members[0].SHA256 = sha256Text(body)
	if err := verifyNativeFullArchiveMembership(context.Background(), opened, nil, sources, members, pins); err != nil {
		t.Fatalf("actual archive/member relationship rejected: %v", err)
	}
}

func nativeFullProductFixture(t *testing.T) (NativeFullManifestRequest, string, string) {
	t.Helper()
	productRoot := t.TempDir()
	materialRoot := t.TempDir()
	outputParent := t.TempDir()
	for _, dir := range []string{productRoot, materialRoot, outputParent} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"bin", "web"} {
		if err := os.Mkdir(filepath.Join(productRoot, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := make([]FileEntryV1, 0, 10)
	for _, target := range nativeProductFixedTargets {
		path := "bin/" + target.name
		body := []byte("fixture executable " + target.name)
		if err := os.WriteFile(filepath.Join(productRoot, path), body, 0755); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0755})
	}
	for _, path := range []string{"web/core.html", "web/build-metadata.json"} {
		body := []byte("fixture web " + path)
		if path == "web/build-metadata.json" {
			body, _ = json.Marshal(map[string]string{"apiBaseUrl": "/api/v1", "mode": "live", "product": "acornfox-core", "releaseId": "release-1.2.3", "schemaVersion": "acornfox-core-release-build-attestation.v1", "sourceCommit": strings.Repeat("a", 40), "sourceRepository": "https://github.com/acme/acornfox-fixture", "version": "1.2.3"})
		}
		if err := os.WriteFile(filepath.Join(productRoot, path), body, 0644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	tree, _ := json.Marshal(files)
	receipt := NativeProductReceiptV1{SchemaVersion: 1, Profile: "native_product", Architecture: Architecture, Version: "1.2.3", SourceRepository: "https://github.com/acme/acornfox-fixture", SourceCommit: strings.Repeat("a", 40), InputsSHA256: strings.Repeat("b", 64), SourcePolicySHA256: strings.Repeat("c", 64), ToolchainSHA256: strings.Repeat("d", 64), TreeSHA256: sha256Text(tree), Files: files}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	response, _ := json.Marshal(struct {
		Output  string                 `json:"output"`
		Receipt NativeProductReceiptV1 `json:"receipt"`
	}{productRoot, receipt})
	materials, _ := json.Marshal(NativeFullMaterialInputsV1{SchemaVersion: 1})
	output := filepath.Join(outputParent, "full")
	req := NativeFullManifestRequest{ProductRoot: productRoot, ProductResponse: response, ProductResponseSHA256: sha256Text(response), MaterialRoot: materialRoot, MaterialInputs: materials, MaterialInputsSHA256: sha256Text(materials), Output: output}
	return req, productRoot, materialRoot
}

func TestNativeFullManifestRejectsMissingMaterialAndProductDrift(t *testing.T) {
	req, productRoot, _ := nativeFullProductFixture(t)
	called := false
	runner := func(context.Context, *os.File) ([]byte, error) { called = true; return nil, nil }
	if _, err := buildNativeFullManifest(context.Background(), req, runner); err == nil || called {
		t.Fatal("missing dependency bytes reached Core or emitted manifest")
	}
	if _, err := os.Lstat(req.Output); !os.IsNotExist(err) {
		t.Fatal("missing materials created output")
	}
	if err := os.WriteFile(filepath.Join(productRoot, "bin/acornfox-core"), []byte("changed"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := buildNativeFullManifest(context.Background(), req, runner); err == nil || called {
		t.Fatal("product byte drift reached Core or emitted manifest")
	}
	if _, err := os.Lstat(req.Output); !os.IsNotExist(err) {
		t.Fatal("product drift created output")
	}
}

// All bytes in this test are explicitly synthetic. It proves the success
// writer/manifest closure, not upstream publisher provenance or a real Core.
func TestNativeFullManifestWritesCanonicalBundleAndBoundClosure(t *testing.T) {
	req, _, materialRoot := nativeFullProductFixture(t)
	for _, name := range []string{"sources", "members"} {
		if err := os.Mkdir(filepath.Join(materialRoot, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := sampleValidManifest()
	material := NativeFullMaterialInputsV1{SchemaVersion: 1, Dependencies: fixture.Dependencies}
	artifactPaths := map[string]string{}
	for _, a := range fixture.Artifacts {
		artifactPaths[a.ID] = a.RelativePath
	}
	selected := map[string][]NativeFullMemberFileV1{}
	write := func(relative string, body []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(materialRoot, relative), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	for i := range material.Dependencies {
		dep := &material.Dependencies[i]
		if dep.Name == DependencyGit {
			continue
		}
		for _, id := range dep.RuntimeArtifactIDs {
			source := dep.Name
			if dep.Name == DependencyBuildKit {
				for _, mapping := range dep.BuildKitMembers {
					if mapping.ArtifactID == id {
						source = mapping.SourceName
					}
				}
			}
			target := artifactPaths[id]
			if target == "" {
				t.Fatalf("synthetic artifact %s absent", id)
			}
			archivePath := filepath.Base(target)
			if source == "docker" {
				archivePath = "docker/" + archivePath
			}
			if source == "buildkit" {
				archivePath = "bin/" + archivePath
			}
			body := []byte("synthetic archive member: " + id)
			member := NativeFullMemberFileV1{ArtifactID: id, SourceName: source, ArchivePath: archivePath, TargetRelativePath: target, SHA256: sha256Text(body), SizeBytes: int64(len(body))}
			material.Members = append(material.Members, member)
			selected[source] = append(selected[source], member)
		}
	}
	makeArchive := func(name string, items []NativeFullMemberFileV1) (string, []byte) {
		t.Helper()
		var raw bytes.Buffer
		compressed := gzip.NewWriter(&raw)
		archive := tar.NewWriter(compressed)
		for _, member := range items {
			body := []byte("synthetic archive member: " + member.ArtifactID)
			if err := archive.WriteHeader(&tar.Header{Name: member.ArchivePath, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write(body); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		relative := "sources/" + name + ".tar.gz"
		write(relative, raw.Bytes(), 0644)
		return relative, raw.Bytes()
	}
	for _, name := range []string{"docker", "buildkit", "rootlesskit", "caddy"} {
		relative, archive := makeArchive(name, selected[name])
		material.Sources = append(material.Sources, NativeFullSourceFileV1{Name: name, RelativeFile: relative})
		for i := range material.Dependencies {
			dep := &material.Dependencies[i]
			if dep.Name == name && (name == DependencyDocker || name == DependencyCaddy) {
				dep.PinnedProvisioning.SourceSHA256 = sha256Text(archive)
				dep.PinnedProvisioning.SizeBytes = int64(len(archive))
			}
			if dep.Name == DependencyBuildKit {
				for j := range dep.BuildKitSources {
					if dep.BuildKitSources[j].Name == name {
						dep.BuildKitSources[j].SourceSHA256 = sha256Text(archive)
						dep.BuildKitSources[j].SizeBytes = int64(len(archive))
					}
				}
			}
		}
	}
	for i := range material.Dependencies {
		dep := &material.Dependencies[i]
		if dep.Name != DependencyGit {
			continue
		}
		for j := range dep.GitHostPackages.Packages {
			pkg := &dep.GitHostPackages.Packages[j]
			body := []byte("synthetic signed-package fixture: " + pkg.Name)
			relative := "sources/" + pkg.Name + ".deb"
			write(relative, body, 0644)
			pkg.ArchiveSHA256 = sha256Text(body)
			pkg.SizeBytes = int64(len(body))
			material.Sources = append(material.Sources, NativeFullSourceFileV1{Name: pkg.Name, RelativeFile: relative})
		}
		for j := range dep.GitHostPackages.Executables {
			pin := &dep.GitHostPackages.Executables[j]
			body := []byte("synthetic host executable: " + pin.Path)
			relative := "members/git-exec-" + string(rune('a'+j))
			write(relative, body, 0755)
			pin.SHA256 = sha256Text(body)
			material.GitExecutables = append(material.GitExecutables, NativeFullGitFileV1{Path: pin.Path, ResolvedPath: pin.ResolvedPath, RelativeFile: relative, SizeBytes: int64(len(body))})
		}
	}
	evidence := []byte(`{"synthetic_only":true,"claim":"external extraction witness fixture"}`)
	material.GitExtractionEvidenceRelativeFile = "git-extraction-evidence.json"
	material.GitExtractionEvidenceSHA256 = sha256Text(evidence)
	write(material.GitExtractionEvidenceRelativeFile, evidence, 0644)
	materialRaw, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	req.MaterialInputs = materialRaw
	req.MaterialInputsSHA256 = sha256Text(materialRaw)
	schemaRaw, err := json.Marshal(struct {
		SchemaVersion      int                    `json:"schema_version"`
		RequiredMigrations []SQLiteMigrationPinV1 `json:"required_migrations"`
	}{1, fixture.SQLiteCompatibility.RequiredMigrations})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	result, err := buildNativeFullManifest(context.Background(), req, func(_ context.Context, opened *os.File) ([]byte, error) {
		called = true
		if _, err := opened.Stat(); err != nil {
			t.Fatal(err)
		}
		return schemaRaw, nil
	})
	if err != nil || !called {
		t.Fatalf("synthetic full bundle did not commit: %+v %v", result, err)
	}
	if result.Output != req.Output || result.Bundle != filepath.Join(req.Output, "bundle") {
		t.Fatal("bundle escaped exclusive output")
	}
	manifestRaw, err := os.ReadFile(filepath.Join(result.Bundle, "manifest.json"))
	if err != nil || sha256Text(manifestRaw) != result.ManifestSHA256 {
		t.Fatal("canonical manifest missing or changed", err)
	}
	witness, err := ParseUnifiedManifestV1(manifestRaw)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := witness.Snapshot()
	if err != nil || len(snapshot.Artifacts) != 20 || len(snapshot.Roles) != 3 {
		t.Fatalf("wrong full byte inventory: %d %v", len(snapshot.Artifacts), err)
	}
	for _, artifact := range snapshot.Artifacts {
		path := filepath.Join(result.Bundle, "payload", artifact.RelativePath)
		body, err := os.ReadFile(path)
		if err != nil || int64(len(body)) != artifact.SizeBytes || sha256Text(body) != artifact.SHA256 {
			t.Fatalf("payload drift: %s %v", artifact.RelativePath, err)
		}
	}
	closureRaw, err := os.ReadFile(filepath.Join(req.Output, "material-closure.json"))
	if err != nil || sha256Text(closureRaw) != result.MaterialClosureSHA256 {
		t.Fatal("closure missing or changed", err)
	}
	var closure nativeFullClosure
	if err := json.Unmarshal(closureRaw, &closure); err != nil {
		t.Fatal(err)
	}
	if closure.ManifestSHA256 != result.ManifestSHA256 || len(closure.Sources) != 6 || len(closure.Members) != 10 || len(closure.GitExecutables) != 2 || !closure.TargetHostReadbackRequired || closure.GitDebMemberRelationReverified {
		t.Fatal("material closure did not bind actual bytes and host-readback boundary")
	}
	top, err := os.ReadDir(req.Output)
	if err != nil || len(top) != 2 || top[0].Name() != "bundle" || top[1].Name() != "material-closure.json" {
		t.Fatal("extra material entered bundle root", err)
	}
}

func TestNativeFullCoreSchemaRejectsMalformedReadOnlyOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("fixed fixture binary")
	path := filepath.Join(dir, "core")
	if err := os.WriteFile(path, body, 0755); err != nil {
		t.Fatal(err)
	}
	receipt := NativePartialReceiptV1{Files: []FileEntryV1{{Path: "bin/acornfox-core", SHA256: sha256Text(body), Mode: 0755}}}
	for _, bad := range [][]byte{
		[]byte(`{"schema_version":1,"required_migrations":[]}`),
		[]byte(`{"schema_version":1,"required_migrations":[{"version":"0001_admin_auth","checksum":"x"}],"unexpected":true}`),
		[]byte(`{"schema_version":1,"required_migrations":[]}{}`),
	} {
		if _, err := readNativeCoreSchema(context.Background(), path, receipt, func(context.Context, *os.File) ([]byte, error) { return bad, nil }); err == nil {
			t.Fatalf("invalid Core descriptor accepted: %s", bad)
		}
	}
}

func TestNativeFullCoreSchemaRunnerReceivesPinnedFileNotMutablePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("original pinned fixture executable")
	path := filepath.Join(dir, "core")
	if err := os.WriteFile(path, body, 0755); err != nil {
		t.Fatal(err)
	}
	receipt := NativePartialReceiptV1{Files: []FileEntryV1{{Path: "bin/acornfox-core", SHA256: sha256Text(body), Mode: 0755}}}
	descriptor, _ := json.Marshal(struct {
		SchemaVersion      int                    `json:"schema_version"`
		RequiredMigrations []SQLiteMigrationPinV1 `json:"required_migrations"`
	}{1, sampleValidManifest().SQLiteCompatibility.RequiredMigrations})
	called := false
	pins, err := readNativeCoreSchema(context.Background(), path, receipt, func(_ context.Context, opened *os.File) ([]byte, error) {
		called = true
		original := path + "-original"
		if err := os.Rename(path, original); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte("replacement"), 0755); err != nil {
			return nil, err
		}
		got, err := io.ReadAll(io.NewSectionReader(opened, 0, int64(len(body))))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("inherited FD drifted to pathname replacement: %q %v", got, err)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		if err := os.Rename(original, path); err != nil {
			return nil, err
		}
		return descriptor, nil
	})
	if err != nil || !called || len(pins) != 13 {
		t.Fatalf("pinned Core descriptor refused: %d %v", len(pins), err)
	}
}
