package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"syscall"
)

const productionBootstrapReleaseRoot = "/opt/open-card"
const productionBootstrapConfigRoot = "/etc/open-card"
const productionInstallationIDName = "installation-id"

// DeriveProductionBootstrapRequest derives every bootstrap identity from the
// fixed production roots. It deliberately accepts no release path, ID, DSN,
// database, or network input.
func DeriveProductionBootstrapRequest(expectedManifestSHA256, confirmation string) (BootstrapRequest, error) {
	releases, err := ProductionDurableWriter(productionBootstrapReleaseRoot)
	if err != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	defer releases.Close()
	config, err := ProductionDurableWriter(productionBootstrapConfigRoot)
	if err != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	defer config.Close()
	return deriveProductionBootstrapRequest(releases, config, expectedManifestSHA256, confirmation)
}

// deriveProductionBootstrapRequestForTask is intentionally unexported: task
// tests must supply their active/config roots and owner explicitly.
func deriveProductionBootstrapRequestForTask(activeRoot, configRoot string, uid, gid int, expectedManifestSHA256, confirmation string) (BootstrapRequest, error) {
	releases, err := TaskDurableWriter(activeRoot, uid, gid)
	if err != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	defer releases.Close()
	config, err := TaskDurableWriter(configRoot, uid, gid)
	if err != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	defer config.Close()
	return deriveProductionBootstrapRequest(releases, config, expectedManifestSHA256, confirmation)
}

func deriveProductionBootstrapRequest(releases, config *DurableWriter, expectedManifestSHA256, confirmation string) (BootstrapRequest, error) {
	if !validSHA(expectedManifestSHA256) || releases == nil || config == nil || releases.VerifyLiveRoot() != nil || config.VerifyLiveRoot() != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	installationInfo, err := config.ops.Lstat(productionInstallationIDName)
	if err != nil || verifyDurableFile(installationInfo, config.uid, config.gid) != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	installation, state := readInstallationIdentity(config)
	if state != installationIdentityPresent {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	installationID := installation.value
	if confirmation != "BOOTSTRAP:"+installationID {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	release, err := selectBootstrapRC3Release(releases, expectedManifestSHA256)
	if err != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	installationSHA := sha256.Sum256([]byte(installationID))
	request := BootstrapRequest{
		TransactionID:         derivedBootstrapID("bootstrap-", installationID, release.ManifestSHA256, release.SourceCommit, release.Architecture),
		InstallationIDSHA256:  hex.EncodeToString(installationSHA[:]),
		CandidateActivationID: derivedBootstrapID("activation-", installationID, release.ManifestSHA256, release.SourceCommit, release.Architecture),
		Release:               release,
	}
	if request.Validate() != nil {
		return BootstrapRequest{}, ErrBootstrapConflict
	}
	return request, nil
}

func selectBootstrapRC2Release(writer *DurableWriter, expectedManifestSHA256 string) (ReleaseV1, error) {
	return selectBootstrapRelease(writer, expectedManifestSHA256, Gate6CandidateVersion)
}

// selectBootstrapRC3Release selects the current fresh-bootstrap candidate.
// RC2 remains separately selectable for recovery and inspection of journals
// that were created before RC3 became current.
func selectBootstrapRC3Release(writer *DurableWriter, expectedManifestSHA256 string) (ReleaseV1, error) {
	return selectBootstrapRelease(writer, expectedManifestSHA256, Gate7CandidateVersion)
}

func selectBootstrapRelease(writer *DurableWriter, expectedManifestSHA256, version string) (ReleaseV1, error) {
	if writer == nil || writer.ops == nil || writer.VerifyLiveRoot() != nil {
		return ReleaseV1{}, errors.New("invalid release root")
	}
	directory, err := writer.ops.OpenFile("releases", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ReleaseV1{}, err
	}
	defer writer.ops.CloseFile(directory)
	info, err := writer.ops.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, writer.uid, writer.gid) != nil {
		return ReleaseV1{}, errors.New("unsafe releases root")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return ReleaseV1{}, err
	}
	var selected ReleaseV1
	found := false
	for _, entry := range entries {
		if !validID(entry.Name()) {
			return ReleaseV1{}, errors.New("unsafe release entry")
		}
		entryInfo, err := writer.ops.Lstat("releases/" + entry.Name())
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.IsDir() || entryInfo.Mode().Perm()&0o022 != 0 || verifyOwner(entryInfo, writer.uid, writer.gid) != nil {
			return ReleaseV1{}, errors.New("unsafe release entry")
		}
		raw, err := secureReleaseFile(writer, entry.Name(), "manifest.json", 0o644)
		if err != nil || sha256Bytes(raw) != expectedManifestSHA256 {
			continue
		}
		manifest, err := parseReleaseManifest(raw)
		if err != nil || manifest.ReleaseID != entry.Name() || manifest.Version != version || manifest.MigrationVersion != CurrentMigrationVersion || manifest.Architecture != RuntimeArchitecture() || ValidateProductionCandidate(manifest) != nil || verifySecureRelease(writer, entry.Name(), manifest) != nil {
			return ReleaseV1{}, errors.New("invalid matching release")
		}
		if found {
			return ReleaseV1{}, errors.New("multiple matching releases")
		}
		selected = ReleaseV1{ID: manifest.ReleaseID, Version: manifest.Version, SourceCommit: manifest.SourceCommit, Architecture: manifest.Architecture, ManifestSHA256: expectedManifestSHA256}
		found = true
	}
	if !found || !selected.valid() {
		return ReleaseV1{}, errors.New("matching release not found")
	}
	return selected, nil
}

func derivedBootstrapID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(prefix + "\x00" + strings.Join(parts, "\x00")))
	return prefix + hex.EncodeToString(sum[:24])
}

func isLowerHex(value string) bool {
	if len(value) != 48 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
