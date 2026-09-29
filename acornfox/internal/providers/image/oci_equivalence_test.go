package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func ociExportFixture(t *testing.T, created, label string, corruptBlob bool) (domain.ImageDigest, []byte) {
	t.Helper()
	blob := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(blob)
	digest := hex.EncodeToString(sum[:])
	image := domain.ImageDigest{Repository: "acornfox.local/apps", Digest: "sha256:" + digest}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{map[string]any{"digest": image.Digest, "size": len(blob), "annotations": map[string]string{"org.opencontainers.image.created": created, "example.label": label}}}})
	if err != nil {
		t.Fatal(err)
	}
	if corruptBlob {
		blob = []byte("tampered")
	}
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", index}, {"blobs/sha256/" + digest, blob}} {
		if err := w.WriteHeader(&tar.Header{Name: file.name, Mode: 0644, Size: int64(len(file.raw)), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(file.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return image, buffer.Bytes()
}

func TestOCIRepeatedExportRetainsOriginalArchiveAndEvidence(t *testing.T) {
	root := t.TempDir()
	p := newTestProvider(t, root)
	image, first := ociExportFixture(t, "2026-09-05T01:00:00Z", "same", false)
	_, second := ociExportFixture(t, "2026-09-05T02:00:00Z", "same", false)
	if bytes.Equal(first, second) {
		t.Fatal("fixture needs different export bytes")
	}
	a, err := p.StoreOCI(context.Background(), storeRequest(image, "first-build", "first-export", first))
	if err != nil {
		t.Fatal(err)
	}
	p = newTestProvider(t, root)
	b, err := p.StoreOCI(context.Background(), storeRequest(image, "second-build", "second-export", second))
	if err != nil {
		t.Fatal(err)
	}
	if a.StorageRef != b.StorageRef || a.Evidence.Digest != b.Evidence.Digest || a.SizeBytes != b.SizeBytes {
		t.Fatal("repeat export changed retained evidence")
	}
	reader, _, err := p.OpenOCI(context.Background(), image, operation("verify-retained-original"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(raw, first) {
		t.Fatal("repeat export overwrote original archive")
	}
}

func TestOCIRepeatedExportRejectsOtherContentChanges(t *testing.T) {
	for _, scenario := range []struct {
		name, label string
		corrupt     bool
	}{{"other annotation", "changed", false}, {"corrupt blob", "same", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			p := newTestProvider(t, t.TempDir())
			image, first := ociExportFixture(t, "2026-09-05T01:00:00Z", "same", false)
			_, changed := ociExportFixture(t, "2026-09-05T02:00:00Z", scenario.label, scenario.corrupt)
			if _, err := p.StoreOCI(context.Background(), storeRequest(image, "one", "one", first)); err != nil {
				t.Fatal(err)
			}
			_, err := p.StoreOCI(context.Background(), storeRequest(image, "two", "two", changed))
			assertProviderCode(t, err, contracts.ErrConflict)
		})
	}
}

func TestOCIRepeatedExportRejectsAmbiguousArchives(t *testing.T) {
	image, first := ociExportFixture(t, "2026-09-05T01:00:00Z", "same", false)
	for name, mutate := range map[string]func(*testing.T, []byte) []byte{
		"nonzero trailer": func(_ *testing.T, b []byte) []byte { return append(b, 'x') },
		"second archive":  func(_ *testing.T, b []byte) []byte { return append(b, b...) },
		"regular path alias": func(t *testing.T, b []byte) []byte {
			offset := bytes.Index(b, []byte("index.json"))
			if offset < 0 || offset%512 != 0 {
				t.Fatal("missing fixture header")
			}
			header := b[offset : offset+512]
			copy(header[:100], []byte("index.json/\x00"))
			copy(header[148:156], []byte("        "))
			checksum := 0
			for _, value := range header {
				checksum += int(value)
			}
			copy(header[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
			return b
		},
		"duplicate root key": func(t *testing.T, b []byte) []byte {
			return rewriteOCIExport(t, b, func(h *tar.Header, raw []byte) []byte {
				if h.Name == "index.json" {
					return bytes.Replace(raw, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":1,"schemaVersion":2`), 1)
				}
				return raw
			})
		},
		"duplicate nested key": func(t *testing.T, b []byte) []byte {
			return rewriteOCIExport(t, b, func(h *tar.Header, raw []byte) []byte {
				if h.Name == "index.json" {
					return bytes.Replace(raw, []byte(`"example.label":"same"`), []byte(`"example.label":"changed","example.label":"same"`), 1)
				}
				return raw
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, t.TempDir())
			if _, err := p.StoreOCI(context.Background(), storeRequest(image, "one", "one", first)); err != nil {
				t.Fatal(err)
			}
			_, err := p.StoreOCI(context.Background(), storeRequest(image, "two", "two", mutate(t, append([]byte(nil), first...))))
			assertProviderCode(t, err, contracts.ErrConflict)
		})
	}
}

func rewriteOCIExport(t *testing.T, raw []byte, mutate func(*tar.Header, []byte) []byte) []byte {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(raw))
	var result bytes.Buffer
	w := tar.NewWriter(&result)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		body = mutate(h, body)
		h.Size = int64(len(body))
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}
