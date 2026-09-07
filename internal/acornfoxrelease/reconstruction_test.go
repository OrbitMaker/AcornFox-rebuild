package acornfoxrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestFullSyntheticReconstructionV1(t *testing.T) {
	origin, commit, toolchain := reconstructionOrigin(t)
	clones := make([]string, 0, 2)
	parent := t.TempDir()
	for _, name := range []string{"first", "second"} {
		clones = append(clones, reconstructionClone(t, origin, parent, name, commit))
	}
	first := reconstructSyntheticCandidate(t, clones[0], toolchain)
	defer first.close(t)
	second := reconstructSyntheticCandidate(t, clones[1], toolchain)
	defer second.close(t)
	for _, pair := range []struct {
		name        string
		first, next any
	}{
		{"go", first.goReceipt, second.goReceipt},
		{"web", first.webReceipt, second.webReceipt},
		{"candidate tree", first.treeReceipt, second.treeReceipt},
		{"artifact", first.artifactReceipt, second.artifactReceipt},
		{"verified", first.verifiedReceipt, second.verifiedReceipt},
	} {
		if !reflect.DeepEqual(pair.first, pair.next) {
			t.Fatalf("independent %s receipts differ:\n%#v\n%#v", pair.name, pair.first, pair.next)
		}
	}
	if first.verifiedReceipt.State != syntheticCandidateInternallyVerified || !first.verifiedReceipt.Synthetic || !first.verifiedReceipt.InstallerVerified || first.verifiedReceipt.ProductionAccepted || first.verifiedReceipt.PublicReleased {
		t.Fatalf("unapproved reconstruction receipt=%#v", first.verifiedReceipt)
	}
	for _, entry := range first.artifactReceipt.Files {
		left, err := os.ReadFile(filepath.Join(first.verified.stage.root, entry.Path))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second.verified.stage.root, entry.Path))
		if err != nil || !reflect.DeepEqual(left, right) {
			t.Fatalf("artifact bytes differ for %s: %v", entry.Path, err)
		}
	}
	for _, result := range []reconstructionResult{first, second} {
		var binding install.AcornFoxCandidateBindingV1
		if err := json.Unmarshal(readArtifactFile(t, result.verified.stage, "candidate-binding.json"), &binding); err != nil || binding.NMinusOne != nil {
			t.Fatalf("binding=%#v err=%v", binding, err)
		}
		var manifest install.Manifest
		if err := json.Unmarshal(readArtifactFile(t, result.verified.stage, "release-manifest.json"), &manifest); err != nil || manifest.NMinusOne != nil {
			t.Fatalf("manifest=%#v err=%v", manifest, err)
		}
	}
}

type reconstructionResult struct {
	goReceipt       GoBinaryReceiptV1
	webReceipt      WebBuildReceiptV1
	treeReceipt     CandidateTreeReceiptV1
	artifactReceipt CandidateArtifactReceiptV1
	verifiedReceipt VerifiedCandidateReceiptV1
	verified        *VerifiedCandidateStageV1
}

func (r reconstructionResult) close(t *testing.T) {
	t.Helper()
	if r.verified != nil {
		if err := r.verified.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func reconstructionOrigin(t *testing.T) (string, string, ToolchainInputsV1) {
	t.Helper()
	origin, _, _, _, toolchain := syntheticGoReleaseRepository(t)
	gitRun(t, origin, "checkout", "-q", "-b", "reconstruction")
	for _, required := range install.AcornFoxV1RequiredFiles() {
		source, ok := staticSourcePath(required.Path)
		if !ok {
			continue
		}
		path := filepath.Join(origin, filepath.FromSlash(source))
		if _, err := os.Lstat(path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		writeReleaseFile(t, path, "synthetic static "+source+"\n")
		if required.Mode == 0o755 {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	gitRun(t, origin, "add", ".")
	gitRun(t, origin, "commit", "-qm", "reconstruction-static-inputs")
	commit := gitRun(t, origin, "rev-parse", "HEAD")
	return origin, commit, toolchain
}

func reconstructionClone(t *testing.T, origin, parent, name, commit string) string {
	t.Helper()
	gitRun(t, parent, "clone", "--no-local", origin, name)
	root := filepath.Join(parent, name)
	gitRun(t, root, "remote", "set-url", "origin", "https://github.com/acme/acornfox-fixture")
	gitRun(t, root, "checkout", "-q", "--detach", commit)
	return root
}

func reconstructSyntheticCandidate(t *testing.T, root string, toolchain ToolchainInputsV1) reconstructionResult {
	t.Helper()
	policy := policyForTree(t, root, "github.com/acme/acornfox-fixture")
	runtimeRoot, runtime := candidateRuntimeInputRoot(t)
	licenseRoot, license := candidateLicenseRoot(t, installerFixturePaths(func(path string) bool { return strings.HasPrefix(path, "docs/licenses/") }))
	witness := witnessForInputs(t, policy, toolchain, runtime, license)
	witness.decision.SourceCommit = gitRun(t, root, "rev-parse", "HEAD")
	raw, err := CanonicalDecisionV1(witness.decision)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = ParseDecisionV1(raw, sha256Text(raw))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareGoBuildPlanV1(context.Background(), witness, policy, toolchain, root, buildTaskRoot(t), localNPMCLIPath(t))
	defer plan.Close()
	if err != nil || !plan.Valid() {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	goStage, err := BuildGoBinariesV1(context.Background(), plan, buildTaskRoot(t))
	if err != nil {
		t.Fatalf("build go binaries: %v", err)
	}
	goReceipt, err := goStage.Receipt()
	if err != nil {
		t.Fatalf("go receipt: %v", err)
	}
	npmCache := buildTaskRoot(t)
	if err := os.Mkdir(filepath.Join(npmCache, "_cacache"), 0o700); err != nil {
		t.Fatal(err)
	}
	webStage, err := buildWebAssetsV1(context.Background(), plan, buildTaskRoot(t), npmCache, reconstructionWebNode(t, plan))
	if err != nil {
		t.Fatalf("build web: %v", err)
	}
	webReceipt, err := webStage.Receipt()
	if err != nil {
		t.Fatalf("web receipt: %v", err)
	}
	tree, err := buildCandidateTreeForTest(plan, goStage, webStage, runtimeRoot, runtime, licenseRoot, license, buildTaskRoot(t))
	if err != nil {
		t.Fatalf("build candidate tree: %v", err)
	}
	treeReceipt, err := tree.Receipt()
	if err != nil {
		t.Fatalf("candidate tree receipt: %v", err)
	}
	if err := goStage.Close(); err != nil {
		t.Fatalf("close go stage: %v", err)
	}
	if err := webStage.Close(); err != nil {
		t.Fatalf("close web stage: %v", err)
	}
	artifact, err := SealCandidateArtifactsV1(tree, buildTaskRoot(t))
	if err != nil {
		t.Fatalf("seal candidate artifacts: %v", err)
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("close candidate tree: %v", err)
	}
	artifactReceipt, err := artifact.Receipt()
	if err != nil {
		t.Fatalf("verify candidate: %v", err)
	}
	verified, err := VerifySyntheticCandidateV1(artifact)
	if err != nil {
		t.Fatalf("verified receipt: %v", err)
	}
	verifiedReceipt, err := verified.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	return reconstructionResult{goReceipt: goReceipt, webReceipt: webReceipt, treeReceipt: treeReceipt, artifactReceipt: artifactReceipt, verifiedReceipt: verifiedReceipt, verified: verified}
}

func reconstructionWebNode(t *testing.T, plan GoBuildPlanV1) goCommandRunner {
	t.Helper()
	return func(_ context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if name != plan.nodeExecutable.path {
			t.Fatalf("untrusted node executable %q", name)
		}
		for _, required := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "npm_config_offline=true", "npm_config_ignore_scripts=true"} {
			if !containsString(env, required) {
				t.Fatalf("missing controlled web environment %q", required)
			}
		}
		if len(args) == 1 && args[0] == "--version" {
			return []byte(plan.toolchain.NodeVersion + "\n"), nil
		}
		if len(args) > 0 && args[0] == plan.npmCLI.path {
			switch {
			case len(args) == 2 && args[1] == "--version":
				return []byte(plan.toolchain.NPMVersion + "\n"), nil
			case len(args) == 3 && args[1] == "cache" && args[2] == "verify":
				return []byte("verified\n"), nil
			case len(args) == 6 && args[1] == "ci":
				return []byte("installed\n"), nil
			}
		}
		if len(args) == 2 && args[1] == "--noEmit" {
			return []byte("checked\n"), nil
		}
		if len(args) == 4 && args[1] == "build" && args[2] == "--mode" && args[3] == "acornfox-release" {
			dist := filepath.Join(dir, "dist")
			if err := os.MkdirAll(filepath.Join(dist, "assets"), 0o700); err != nil {
				t.Fatal(err)
			}
			metadata, err := json.Marshal(map[string]string{"apiBaseUrl": "/api/v1", "mode": "live", "product": Product, "releaseId": "release-" + plan.releaseVersion, "schemaVersion": webReleaseSchemaVersion, "sourceCommit": plan.sourceCommit, "sourceRepository": plan.sourceRepositoryURL, "version": plan.releaseVersion})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dist, "build-metadata.json"), metadata, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dist, "index.html"), []byte("<main>AcornFox</main>\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dist, "assets", "app-abcdefgh.js"), []byte("asset\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []byte("built\n"), nil
		}
		return nil, errors.New("unexpected synthetic web command")
	}
}
