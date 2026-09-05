package acornfoxrelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This exercises candidate classification with unit fixture payloads. It is
// not host acceptance of those fixture executables.
func releaseArtifactFixture(t *testing.T) *CandidateArtifactStageV1 {
	t.Helper()
	plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license := candidateTreeFixture(t, releaseLicenseFixture)
	t.Cleanup(func() { _ = goStage.Close(); _ = webStage.Close() })
	tree, err := BuildReleaseCandidateTreeV1(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	if tree.receipt.Synthetic {
		t.Fatal("release tree mislabeled synthetic")
	}
	raw, err := os.ReadFile(filepath.Join(tree.root, "release", "sbom.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "acornfox.invalid") || strings.Contains(string(raw), "Synthetic release-tree") || !strings.Contains(string(raw), `"licenseDeclared":"AGPL-3.0-only"`) {
		t.Fatal("release SBOM retained placeholder identity")
	}
	var sbom struct {
		Extracted []struct {
			ID   string `json:"licenseId"`
			Text string `json:"extractedText"`
		} `json:"hasExtractedLicensingInfos"`
	}
	if json.Unmarshal(raw, &sbom) != nil || len(sbom.Extracted) != 1 || sbom.Extracted[0].ID != "LicenseRef-"+sha256Text([]byte(sbom.Extracted[0].Text)) {
		t.Fatal("upstream license reference lost its exact text")
	}
	stage, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Close() })
	return stage
}

func releaseLicenseFixture(t *testing.T, paths []string) (string, LicenseInputsV1) {
	t.Helper()
	root := buildTaskRoot(t)
	agpl, err := os.ReadFile("../../docs/licenses/AGPL-3.0-only.txt")
	if err != nil {
		t.Fatal(err)
	}
	manifest := ReleaseLicenseManifestV1{SchemaVersion: 1, Product: Product, License: "AGPL-3.0-only", Copyright: "Copyright (C) 2026 AcornFox contributors", Created: "2026-09-06T00:00:00Z", Components: []LicensedComponentV1{{Name: "unit-fixture", Version: "1", License: "AGPL-3.0-only", Source: "https://example.org/fixture", Notice: string(agpl), NoticeSHA256: sha256Text(agpl)}}}
	manifest.Components = append(manifest.Components, LicensedComponentV1{Name: "upstream-fixture", Version: "1", License: "LicenseRef-" + sha256Text(agpl), Source: "https://example.org/upstream", Notice: string(agpl), NoticeSHA256: sha256Text(agpl)})
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files := []FileEntryV1{}
	for _, path := range paths {
		body := []byte("Fixture notice only.\n")
		if strings.HasSuffix(path, "licenses-manifest.json") {
			body = raw
		}
		if strings.HasSuffix(path, "AGPL-3.0-only.txt") {
			body = agpl
		}
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, 0644); err != nil {
			t.Fatal(err)
		}
		files = append(files, FileEntryV1{Path: path, SHA256: sha256Text(body), Mode: 0644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return root, LicenseInputsV1{SchemaVersion: 1, Product: Product, Files: files}
}

func TestReleaseCandidateIsVerifiedWithoutInventingHostOrPublicAcceptance(t *testing.T) {
	stage := releaseArtifactFixture(t)
	if _, err := VerifySyntheticCandidateV1(stage); err == nil {
		t.Fatal("real candidate accepted by synthetic entry point")
	}
	verified, err := VerifyReleaseCandidateV1(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	r, err := verified.Receipt()
	if err != nil || r.Synthetic || r.State != releaseCandidateInternallyVerified || r.ProductionAccepted || r.PublicReleased {
		t.Fatal("incorrect release acceptance classification", err)
	}
	raw, err := os.ReadFile(filepath.Join(stage.root, "build-record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record candidateBuildRecordV1
	if json.Unmarshal(raw, &record) != nil || record.Synthetic || record.ProductionAccepted || record.CandidateAccepted {
		t.Fatal("incorrect build record")
	}
	synthetic := candidateArtifactFixture(t)
	if _, err := VerifyReleaseCandidateV1(synthetic); err == nil {
		t.Fatal("synthetic candidate accepted as real")
	}
}
