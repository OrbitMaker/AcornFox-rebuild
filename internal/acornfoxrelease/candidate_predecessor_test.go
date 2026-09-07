package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func successorArtifactFixture(t *testing.T) (*CandidateArtifactStageV1, []byte) {
	t.Helper()
	bootstrap := releaseArtifactFixture(t)
	predecessor := readArtifactFile(t, bootstrap, "candidate-binding.json")
	tree := releaseTreeFixture(t, "1.2.4-test.1")
	stage, err := SealSuccessorCandidateArtifactsV1(tree, buildTaskRoot(t), predecessor, bootstrap.receipt.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Close() })
	return stage, predecessor
}

func installerCandidateInput(t *testing.T, stage *CandidateArtifactStageV1, predecessor []byte) install.VerifyAcornFoxCandidateArtifactsV1Input {
	t.Helper()
	archive := readArtifactFile(t, stage, candidateArchiveName(stage.receipt.Version))
	return install.VerifyAcornFoxCandidateArtifactsV1Input{
		Binding: readArtifactFile(t, stage, "candidate-binding.json"), BindingSHA256: stage.receipt.BindingSHA256,
		Manifest: readArtifactFile(t, stage, "release-manifest.json"), BundleManifest: readArtifactFile(t, stage, "bundle-manifest.sha256"),
		Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive)), PredecessorBinding: predecessor,
	}
}

func TestSuccessorCandidatePinsBootstrapAndRetainsUnapprovedClassification(t *testing.T) {
	stage, predecessor := successorArtifactFixture(t)
	var old, binding install.AcornFoxCandidateBindingV1
	if json.Unmarshal(predecessor, &old) != nil || old.NMinusOne != nil || old.Version == stage.receipt.Version || old.MigrationVersion != Migration {
		t.Fatal("fixture must start from a distinct bootstrap at the same migration")
	}
	if json.Unmarshal(readArtifactFile(t, stage, "candidate-binding.json"), &binding) != nil || binding.NMinusOne == nil {
		t.Fatal("successor lacks predecessor binding")
	}
	n := binding.NMinusOne
	if n.Version != old.Version || n.MigrationVersion != old.MigrationVersion || n.SourceCommit != old.SourceCommit || n.ReleaseManifestSHA256 != old.ManifestSHA256 || n.ArchiveSHA256 != old.ArchiveSHA256 || n.BundleManifestSHA256 != old.BundleManifestSHA256 || n.BindingSHA256 != sha256Text(predecessor) {
		t.Fatal("successor did not preserve exact predecessor identity")
	}
	for name, raw := range map[string][]byte{"missing": nil, "changed": append(append([]byte(nil), predecessor...), '\n')} {
		t.Run(name, func(t *testing.T) {
			if _, err := install.VerifyAcornFoxCandidateArtifactsV1(installerCandidateInput(t, stage, raw)); err == nil {
				t.Fatal("installer accepted missing or changed predecessor")
			}
		})
	}
	if _, err := install.VerifyAcornFoxCandidateArtifactsV1(installerCandidateInput(t, stage, predecessor)); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyReleaseCandidateV1(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	r, err := verified.Receipt()
	if err != nil || r.Synthetic || r.ProductionAccepted || r.PublicReleased || !r.InstallerVerified || r.Artifact.PredecessorBindingSHA256 != sha256Text(predecessor) || len(r.Artifact.Files) != 6 {
		t.Fatal("incorrect successor receipt", err)
	}
	// Neither caller-owned input bytes nor returned receipts can retarget the stage.
	predecessor[0] = '!'
	r.Artifact.PredecessorBindingSHA256 = strings.Repeat("0", 64)
	if _, err := verified.Receipt(); err != nil {
		t.Fatal("caller-owned values aliased sealed predecessor", err)
	}
}

func TestCandidatePredecessorAcceptsPinnedLegacy0034Only(t *testing.T) {
	raw := []byte(`{"schema_version":1,"product":"acornfox","version":"0.1.0-beta.1","release_id":"release-0.1.0-beta.1","source_repository":"https://github.com/EleJiuDeiChi/acornfox","source_commit":"6ed40027c0ac892e404c31e5daafaf0749eec216","architecture":"amd64","migration_version":"0034","manifest_sha256":"77c8f27ad93012ef606bf9bbf5ad820989a9a2f40928f22584fdbddc4be23d47","archive_sha256":"ef4722471203272dc0961c63a1d32a275b6ec44a82cf600f992c16fb7aaf849d","bundle_manifest_sha256":"429130db1deffb69cf0bd2b9d40b1cf0dfcf620ad6bb7233f2c5e5d23b89dd69"}`)
	n, m, err := candidatePredecessor(raw, sha256Text(raw))
	if err != nil || n == nil || m == nil || n.MigrationVersion != install.AcornFoxLegacyPredecessorMigration || m.MigrationVersion != n.MigrationVersion {
		t.Fatalf("legacy predecessor=%+v/%+v err=%v", n, m, err)
	}
	if _, _, err := candidatePredecessor(raw, strings.Repeat("0", 64)); err == nil {
		t.Fatal("legacy predecessor accepted an unpinned digest")
	}
}

func TestSuccessorSealRejectsUnpinnedOrNoncanonicalPredecessorWithoutOutput(t *testing.T) {
	bootstrap := releaseArtifactFixture(t)
	raw := readArtifactFile(t, bootstrap, "candidate-binding.json")
	tree := releaseTreeFixture(t, "1.2.4-test.1")
	noncanonical := append(append([]byte(nil), raw...), '\n')
	for _, test := range []struct {
		name string
		raw  []byte
		sha  string
	}{
		{"both missing", nil, ""}, {"missing raw", nil, bootstrap.receipt.BindingSHA256},
		{"missing sha", raw, ""}, {"wrong sha", raw, strings.Repeat("0", 64)},
		{"wrong raw", noncanonical, bootstrap.receipt.BindingSHA256}, {"noncanonical", noncanonical, sha256Text(noncanonical)},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := buildTaskRoot(t)
			stage, err := SealSuccessorCandidateArtifactsV1(tree, parent, test.raw, test.sha)
			if err == nil || stage != nil {
				t.Fatal("invalid predecessor accepted")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid predecessor created output", err)
			}
		})
	}
}

func TestSuccessorStageRejectsPredecessorRemovalReplacementAndSemanticTampering(t *testing.T) {
	stage, predecessor := successorArtifactFixture(t)
	privatePath := filepath.Join(stage.root, predecessorBindingFile)
	for _, change := range []struct {
		name string
		fn   func() error
	}{
		{"removed", func() error { return os.Remove(privatePath) }},
		{"changed", func() error { return os.WriteFile(privatePath, []byte("changed"), 0644) }},
		{"symlink", func() error {
			if err := os.Remove(privatePath); err != nil {
				return err
			}
			return os.Symlink(filepath.Join(stage.root, "candidate-binding.json"), privatePath)
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			if err := change.fn(); err != nil {
				t.Fatal(err)
			}
			if _, err := stage.Receipt(); err == nil {
				t.Fatal("changed private predecessor accepted")
			}
			if verified, err := VerifyReleaseCandidateV1(stage); err == nil || verified != nil {
				t.Fatal("changed private predecessor verified")
			}
			_ = os.Remove(privatePath)
			if err := os.WriteFile(privatePath, predecessor, 0644); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Keep every ordinary cross-hash consistent while changing the predecessor
	// identity in both manifest and binding, so only predecessor checks reject it.
	original := map[string][]byte{}
	for _, f := range stage.receipt.Files {
		original[f.Path] = readArtifactFile(t, stage, f.Path)
	}
	originalReceipt := cloneArtifactReceipt(stage.receipt)
	for _, field := range []string{"version", "source", "manifest", "archive", "bundle", "binding"} {
		t.Run(field, func(t *testing.T) {
			var binding install.AcornFoxCandidateBindingV1
			if json.Unmarshal(original["candidate-binding.json"], &binding) != nil {
				t.Fatal("invalid fixture")
			}
			switch field {
			case "version":
				binding.NMinusOne.Version = "9.9.9"
			case "source":
				binding.NMinusOne.SourceCommit = strings.Repeat("0", 40)
			case "manifest":
				binding.NMinusOne.ReleaseManifestSHA256 = strings.Repeat("0", 64)
			case "archive":
				binding.NMinusOne.ArchiveSHA256 = strings.Repeat("0", 64)
			case "bundle":
				binding.NMinusOne.BundleManifestSHA256 = strings.Repeat("0", 64)
			case "binding":
				binding.NMinusOne.BindingSHA256 = strings.Repeat("0", 64)
			}
			var manifest install.Manifest
			if json.Unmarshal(original["release-manifest.json"], &manifest) != nil {
				t.Fatal("invalid fixture")
			}
			n := binding.NMinusOne
			manifest.NMinusOne = &install.NMinusOne{Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit, ReleaseManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256, BundleManifestSHA256: n.BundleManifestSHA256}
			manifestRaw := mustJSON(t, manifest)
			writeArtifactFileAndReceipt(t, stage, "release-manifest.json", manifestRaw)
			if err := os.WriteFile(filepath.Join(stage.root, "payload/release/manifest.json"), manifestRaw, 0644); err != nil {
				t.Fatal(err)
			}
			binding.ManifestSHA256 = stage.receipt.ManifestSHA256
			writeArtifactFileAndReceipt(t, stage, "candidate-binding.json", mustJSON(t, binding))
			var record candidateBuildRecordV1
			if json.Unmarshal(original["build-record.json"], &record) != nil {
				t.Fatal("invalid fixture")
			}
			record.ManifestSHA256 = stage.receipt.ManifestSHA256
			writeArtifactFileAndReceipt(t, stage, "build-record.json", mustJSON(t, record))
			rewriteArchiveDAG(t, stage, archiveForCandidateTest(t, stage, archiveTestOptions{}))
			if stage.receipt.Validate() != nil || !verifyManifest(manifestRaw, stage.treeReceipt, stage.receipt) {
				t.Fatal("ordinary cross-hashes or manifest facts were not consistent")
			}
			if stage.validOwned() {
				t.Fatal("tampered predecessor semantics accepted")
			}
			if _, err := install.VerifyAcornFoxCandidateArtifactsV1(installerCandidateInput(t, stage, predecessor)); err == nil || !strings.Contains(err.Error(), "predecessor") {
				t.Fatalf("wanted installer predecessor rejection, got %v", err)
			}
			for name, raw := range original {
				if err := os.WriteFile(filepath.Join(stage.root, name), raw, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(stage.root, "payload/release/manifest.json"), original["release-manifest.json"], 0644); err != nil {
				t.Fatal(err)
			}
			stage.receipt = cloneArtifactReceipt(originalReceipt)
		})
	}
}
