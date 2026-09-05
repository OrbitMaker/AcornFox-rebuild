package install

import "testing"

func TestAcornFoxWebAssetsAcceptViteSourceMaps(t *testing.T) {
	for _, path := range []string{"web/dist/assets/index-DO3CcaYb.js.map", "web/dist/assets/index-IltnUnCw.css.map", "web/dist/assets/index-DO3CcaYb.js", "web/dist/assets/index-IltnUnCw.css"} {
		if !IsAcornFoxV1WebAssetPath(path) {
			t.Errorf("Vite asset rejected: %s", path)
		}
	}
	for _, path := range []string{"web/dist/assets/index.js.map", "web/dist/assets/index-DO3CcaYb.js.map.sh", "web/dist/assets/nested/index-DO3CcaYb.js.map", "web/dist/assets/../index-DO3CcaYb.js.map"} {
		if IsAcornFoxV1WebAssetPath(path) {
			t.Errorf("noncanonical asset accepted: %s", path)
		}
	}
}
