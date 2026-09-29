package sqlite

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// This is a structurally valid byte fixture for the Store transaction. It is
// not a BuildKit result and cannot establish a physical Build-to-Run case.
func sourceRunArchiveFixture(t *testing.T) ([]byte, string, string) {
	t.Helper()
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(sum[:]) }
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Cmd":["/app"]}}`)
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)}, "layers": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifest)
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", index}, {"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"), manifest}, {"blobs/sha256/" + strings.TrimPrefix(digest(config), "sha256:"), config}} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0444, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), manifestDigest, digest(config)
}
