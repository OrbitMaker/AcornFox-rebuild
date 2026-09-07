package install

import (
	"encoding/json"
	"testing"
)

// Deliberately use different old/new executable bytes: default package fixtures
// share placeholder content and cannot prove recovery executable selection.
func changeAcornFoxRecoveryHelperFixture(t *testing.T, fixture *acornFoxFixture) []byte {
	t.Helper()
	helper := []byte("authenticated successor recovery helper\n")
	files, contents := fixtureManifestAndContents(t, *fixture)
	contents["bin/acornfox-upgrade"] = helper
	for i := range files {
		if files[i].Path == "bin/acornfox-upgrade" {
			files[i].SHA256 = sha256Hex(helper)
		}
	}
	var manifest Manifest
	if json.Unmarshal(fixture.manifestRaw, &manifest) != nil {
		t.Fatal("manifest unavailable")
	}
	manifest.Files = files
	fixture.manifestRaw = acornFoxUpgradeJSON(manifest)
	fixture.binding.ManifestSHA256 = sha256Hex(fixture.manifestRaw)
	fixture.archive = acornFoxArchive(t, fixture.manifestRaw, files, contents, nil)
	refreshAcornFoxArchiveBinding(t, fixture)
	return helper
}
