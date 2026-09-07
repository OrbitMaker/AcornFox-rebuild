package acornfoxrelease

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRepositoryLicenseManifestIncludesPinnedPiMIT(t *testing.T) {
	raw, err := os.ReadFile("../../docs/licenses/licenses-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest ReleaseLicenseManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Validate() != nil {
		t.Fatalf("license manifest invalid: %v", err)
	}
	for _, component := range manifest.Components {
		if component.Name != "pi:@earendil-works/pi-coding-agent" || component.Version != "0.85.1" {
			continue
		}
		if component.License != "MIT" || component.Source != "https://github.com/earendil-works/pi/blob/v0.85.1/LICENSE" || component.NoticeSHA256 != "0457f5bcec3b3b211605dfb5d1a49042fd638f3686a410fe099c24a25af13c48" {
			t.Fatalf("Pi license component = %#v", component)
		}
		return
	}
	t.Fatal("Pi license component is missing")
}
