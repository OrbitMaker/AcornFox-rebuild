package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func digestFixture(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func TestInspectOCIStreamsActualDescriptorAndRejectsIndexAlias(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Cmd":["/app"]}}`)
	layer := make([]byte, 128<<10)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestFixture(config), "size": len(config)}, "layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digestFixture(layer), "size": len(layer)}}})
	manifestSHA := digestFixture(manifest)
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestSHA, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}}}})
	archive := new(bytes.Buffer)
	writer := tar.NewWriter(archive)
	layerOffset := -1
	// Blob before index proves identity validation does not assume tar order.
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"blobs/sha256/" + strings.TrimPrefix(digestFixture(config), "sha256:"), config}, {"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"blobs/sha256/" + strings.TrimPrefix(digestFixture(layer), "sha256:"), layer}, {"index.json", index}, {"blobs/sha256/" + strings.TrimPrefix(manifestSHA, "sha256:"), manifest}} {
		if err := writer.WriteHeader(&tar.Header{Name: item.name, Mode: 0444, Size: int64(len(item.raw))}); err != nil {
			t.Fatal(err)
		}
		if item.name == "blobs/sha256/"+strings.TrimPrefix(digestFixture(layer), "sha256:") {
			layerOffset = archive.Len()
		}
		if _, err := writer.Write(item.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := InspectOCI(context.Background(), bytes.NewReader(archive.Bytes()), manifestSHA, int64(archive.Len()))
	if err != nil || identity.ManifestDigest != manifestSHA || identity.ConfigDigest != digestFixture(config) || identity.OS != "linux" || identity.Architecture != "amd64" || identity.ArchiveSize != int64(archive.Len()) {
		t.Fatalf("actual OCI relation not inspected: %#v %v", identity, err)
	}
	if _, err := InspectOCI(context.Background(), bytes.NewReader(archive.Bytes()), digestFixture(index), int64(archive.Len())); err == nil {
		t.Fatal("index digest silently substituted for selected manifest")
	}
	if _, err := InspectOCI(context.Background(), bytes.NewReader(archive.Bytes()), manifestSHA, int64(archive.Len()-1)); err == nil {
		t.Fatal("archive exceeded explicit bound")
	}
	if layerOffset < 0 {
		t.Fatal("layer payload was not written")
	}
	tampered := append([]byte(nil), archive.Bytes()...)
	tampered[layerOffset] ^= 0xff
	if _, err := InspectOCI(context.Background(), bytes.NewReader(tampered), manifestSHA, int64(len(tampered))); err == nil {
		t.Fatal("referenced layer hash tamper accepted")
	}
}
