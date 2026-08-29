package install

// This file contains the small, public contract used by the root-only
// open-card-upgrade command.  It deliberately derives every mutable identity
// from the transaction and a verified release manifest; callers never supply
// an activation, database, evidence, or filesystem path.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// UpgradeCLIIdentity is the complete secret-free identity derived by the
// privileged command before it constructs an engine. Recovery evidence is a
// digest only; it is never a caller-controlled string.
type UpgradeCLIIdentity struct {
	Request                 UpgradeRequest
	RecoveryEvidenceSHA256  string
	UpgradeExecutableSHA256 string
}

// VerifiedUpgradeReleaseV1 couples the release identity with the exact
// manifest-declared command binary digest used to bind the running helper.
type VerifiedUpgradeReleaseV1 struct {
	Release                 ReleaseV1
	UpgradeExecutableSHA256 string
}

// DeriveUpgradeCLIIdentity binds the activation and candidate database to one
// transaction and release manifest.  The domain tags avoid collisions with
// other digest-bearing installer records.
func DeriveUpgradeCLIIdentity(transactionID string, verified VerifiedUpgradeReleaseV1) (UpgradeCLIIdentity, error) {
	release := verified.Release
	if !validID(transactionID) || !release.valid() || !validSHA(verified.UpgradeExecutableSHA256) {
		return UpgradeCLIIdentity{}, errors.New("invalid upgrade cli identity")
	}
	activationDigest := sha256.Sum256([]byte("open-card-upgrade-activation-v1\n" + transactionID + "\n" + release.ManifestSHA256))
	activationID := "act-" + hex.EncodeToString(activationDigest[:])[:24]
	databaseName, err := CandidateDatabaseName(activationID)
	if err != nil {
		return UpgradeCLIIdentity{}, errors.New("invalid upgrade cli candidate")
	}
	recoveryDigest := sha256.Sum256([]byte("open-card-upgrade-recovery-evidence-v1\n" + transactionID + "\n" + activationID + "\n" + release.ManifestSHA256))
	return UpgradeCLIIdentity{
		Request: UpgradeRequest{
			TransactionID:           transactionID,
			CandidateRelease:        release,
			CandidateActivationID:   activationID,
			CandidateDatabaseName:   databaseName,
			RecoveryEvidenceSHA256:  hex.EncodeToString(recoveryDigest[:]),
			RequestedManifestSHA256: release.ManifestSHA256,
		},
		RecoveryEvidenceSHA256:  hex.EncodeToString(recoveryDigest[:]),
		UpgradeExecutableSHA256: verified.UpgradeExecutableSHA256,
	}, nil
}

// LoadVerifiedProductionUpgradeRelease reads only the fixed production
// release location. It rejects links, non-root ownership, writable release
// objects, bad manifest identity, and any payload mismatch before returning a
// ReleaseV1 suitable for an upgrade request.
func LoadVerifiedProductionUpgradeRelease(releaseID, manifestSHA256 string) (VerifiedUpgradeReleaseV1, error) {
	return loadVerifiedUpgradeReleaseAt(DefaultInstallPrefix, releaseID, manifestSHA256, 0, 0)
}

// loadVerifiedUpgradeReleaseAt is intentionally package-private. It gives the
// contract tests a task-owned root while the only exported caller is pinned to
// /opt/open-card and root ownership.
func loadVerifiedUpgradeReleaseAt(prefix, releaseID, manifestSHA256 string, uid, gid int) (VerifiedUpgradeReleaseV1, error) {
	if !validID(releaseID) || !validSHA(manifestSHA256) {
		return VerifiedUpgradeReleaseV1{}, errors.New("invalid upgrade release selector")
	}
	if !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix || prefix == string(filepath.Separator) {
		return VerifiedUpgradeReleaseV1{}, errors.New("invalid upgrade release selector")
	}
	if err := verifyUpgradeReleasePath(prefix, releaseID, uid, gid); err != nil {
		return VerifiedUpgradeReleaseV1{}, err
	}
	relativeManifest := filepath.ToSlash(filepath.Join("releases", releaseID, "manifest.json"))
	root, err := os.OpenRoot(prefix)
	if err != nil {
		return VerifiedUpgradeReleaseV1{}, errors.New("open upgrade release root failed")
	}
	defer root.Close()
	file, err := root.OpenFile(relativeManifest, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return VerifiedUpgradeReleaseV1{}, errors.New("open upgrade manifest failed")
	}
	raw, readErr := io.ReadAll(file)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !secureUpgradeFile(info, 0o644, uid, gid) || sha256Bytes(raw) != manifestSHA256 {
		return VerifiedUpgradeReleaseV1{}, errors.New("verify upgrade manifest failed")
	}
	manifest, err := parseUpgradeCLIManifest(raw)
	if err != nil || ValidateProductionCandidate(manifest) != nil || manifest.ReleaseID != releaseID {
		return VerifiedUpgradeReleaseV1{}, errors.New("verify upgrade manifest failed")
	}
	if err := verifyUpgradeReleasePath(prefix, releaseID, uid, gid); err != nil {
		return VerifiedUpgradeReleaseV1{}, err
	}
	if err := verifyUpgradeReleaseDescriptors(prefix, releaseID, manifest, uid, gid); err != nil {
		return VerifiedUpgradeReleaseV1{}, errors.New("verify upgrade release failed")
	}
	if err := verifyUpgradeReleasePath(prefix, releaseID, uid, gid); err != nil {
		return VerifiedUpgradeReleaseV1{}, err
	}
	release := ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: manifestSHA256}
	if !release.valid() {
		return VerifiedUpgradeReleaseV1{}, errors.New("verify upgrade release failed")
	}
	var executableSHA string
	for _, file := range manifest.Files {
		if file.Path == "bin/open-card-upgrade" && file.Mode == 0o755 {
			executableSHA = file.SHA256
			break
		}
	}
	if !validSHA(executableSHA) {
		return VerifiedUpgradeReleaseV1{}, errors.New("verify upgrade executable manifest failed")
	}
	return VerifiedUpgradeReleaseV1{Release: release, UpgradeExecutableSHA256: executableSHA}, nil
}

// verifyUpgradeReleaseDescriptors binds manifest metadata, modes, ownership,
// and content to no-follow descriptors rooted at the trusted install prefix.
// It intentionally does not reuse the path-based generic verifier in this
// privileged command path.
func verifyUpgradeReleaseDescriptors(prefix, releaseID string, manifest Manifest, uid, gid int) error {
	expected := make(map[string]FileDigest, len(manifest.Files))
	for _, file := range manifest.Files {
		expected[file.Path] = file
	}
	actual := make(map[string]struct{}, len(expected))
	releaseDir := filepath.Join(prefix, "releases", releaseID)
	if err := filepath.WalkDir(releaseDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unsafe release entry")
		}
		rel, err := filepath.Rel(releaseDir, path)
		if err != nil {
			return err
		}
		if rel == "." || entry.IsDir() {
			return nil
		}
		if rel == "manifest.json" {
			return nil
		}
		if _, ok := expected[filepath.ToSlash(rel)]; !ok {
			return errors.New("unexpected release entry")
		}
		actual[filepath.ToSlash(rel)] = struct{}{}
		return nil
	}); err != nil || len(actual) != len(expected) {
		return errors.New("release set mismatch")
	}
	root, err := os.OpenRoot(prefix)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, declared := range manifest.Files {
		path := filepath.ToSlash(filepath.Join("releases", releaseID, declared.Path))
		file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(file)
		info, statErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || !secureUpgradeFile(info, os.FileMode(declared.Mode), uid, gid) || sha256Bytes(raw) != declared.SHA256 {
			return errors.New("release descriptor mismatch")
		}
	}
	return nil
}

func parseUpgradeCLIManifest(raw []byte) (Manifest, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errors.New("decode upgrade manifest failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, errors.New("decode upgrade manifest failed")
	}
	normalized, err := NormalizeManifest(manifest)
	if err != nil || normalized.Validate() != nil {
		return Manifest{}, errors.New("decode upgrade manifest failed")
	}
	return normalized, nil
}

func verifyUpgradeReleasePath(prefix, releaseID string, uid, gid int) error {
	releasesRoot := filepath.Join(prefix, "releases")
	for _, path := range []string{prefix, releasesRoot, filepath.Join(releasesRoot, releaseID)} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !secureUpgradeOwner(info, uid, gid) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("verify upgrade release path failed")
		}
	}
	return filepath.WalkDir(filepath.Join(releasesRoot, releaseID), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("verify upgrade release path failed")
		}
		info, err := os.Lstat(path)
		if err != nil || !secureUpgradeOwner(info, uid, gid) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("verify upgrade release path failed")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("verify upgrade release path failed")
		}
		return nil
	})
}

func secureUpgradeFile(info os.FileInfo, mode os.FileMode, uid, gid int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == mode && secureUpgradeOwner(info, uid, gid)
}

func secureUpgradeOwner(info os.FileInfo, uid, gid int) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == uid && int(stat.Gid) == gid
}
