package image

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrOCIIdentity = errors.New("OCI archive identity is unverified")

const (
	maxOCIEntries       = 10000
	maxOCIIndexBytes    = 1 << 20
	maxOCIManifestBytes = 2 << 20
	maxOCIConfigBytes   = 8 << 20
	maxOCILayers        = 256
)

type OCIIdentity struct {
	ArchiveSize     int64
	RootIndexDigest string
	ManifestDigest  string
	ConfigDigest    string
	OS              string
	Architecture    string
}
type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}
type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	Manifests     []ociDescriptor `json:"manifests"`
}
type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

func ociDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validOCISHA(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func supportedImageManifest(mediaType string) bool {
	return mediaType == "application/vnd.oci.image.manifest.v1+json" || mediaType == "application/vnd.docker.distribution.manifest.v2+json"
}
func selectedBlobName(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

type ociContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r ociContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func readOCIMetadata(tr *tar.Reader, h *tar.Header, max int64) ([]byte, error) {
	if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
		return nil, ErrOCIIdentity
	}
	if h.Size <= 0 || h.Size > max {
		return nil, ErrOCIIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(tr, max+1))
	if err != nil || int64(len(raw)) != h.Size || int64(len(raw)) > max {
		return nil, ErrOCIIdentity
	}
	return raw, nil
}
func scanOCI(ctx context.Context, archive io.ReadSeeker, fn func(*tar.Header, *tar.Reader) error) error {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind archive", ErrOCIIdentity)
	}
	tr := tar.NewReader(ociContextReader{ctx: ctx, reader: archive})
	for entries := 0; ; {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: read archive entry", ErrOCIIdentity)
		}
		entries++
		if entries > maxOCIEntries {
			return ErrOCIIdentity
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

// InspectOCI consumes only bounded metadata in memory, hashes referenced
// layers through a fixed buffer, and never extracts tar paths. The input must
// be a previously integrity-checked, seekable immutable archive; callers
// reject a missing io.ReadSeeker rather than falling back to io.ReadAll.
// artifactDigest is the persisted Build/Image digest, which must name the
// actual first selected manifest. Index/nested-index digests are not rewritten.
func InspectOCI(ctx context.Context, archive io.ReadSeeker, artifactDigest string, maxArchiveBytes int64) (OCIIdentity, error) {
	var zero OCIIdentity
	if ctx == nil || archive == nil || !validOCISHA(artifactDigest) || maxArchiveBytes <= 0 {
		return zero, ErrOCIIdentity
	}
	size, err := archive.Seek(0, io.SeekEnd)
	if err != nil || size <= 0 || size > maxArchiveBytes {
		return zero, ErrOCIIdentity
	}
	id := OCIIdentity{ArchiveSize: size}
	var index ociIndex
	indexFound := false
	layoutFound := false
	err = scanOCI(ctx, archive, func(h *tar.Header, tr *tar.Reader) error {
		switch h.Name {
		case "oci-layout":
			if layoutFound {
				return ErrOCIIdentity
			}
			raw, err := readOCIMetadata(tr, h, 128)
			if err != nil {
				return err
			}
			var layout struct {
				Version string `json:"imageLayoutVersion"`
			}
			if json.Unmarshal(raw, &layout) != nil || layout.Version != "1.0.0" {
				return ErrOCIIdentity
			}
			layoutFound = true
		case "index.json":
			if indexFound {
				return ErrOCIIdentity
			}
			raw, err := readOCIMetadata(tr, h, maxOCIIndexBytes)
			if err != nil {
				return err
			}
			if json.Unmarshal(raw, &index) != nil || index.SchemaVersion != 2 || len(index.Manifests) == 0 {
				return ErrOCIIdentity
			}
			id.RootIndexDigest = ociDigest(raw)
			indexFound = true
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if !layoutFound || !indexFound {
		return zero, ErrOCIIdentity
	}
	selected := index.Manifests[0]
	if !validOCISHA(selected.Digest) || !supportedImageManifest(selected.MediaType) || selected.Size <= 0 || selected.Size > maxOCIManifestBytes || selected.Digest != artifactDigest {
		return zero, ErrOCIIdentity
	}
	if (selected.Platform.OS != "" && selected.Platform.OS != "linux") || (selected.Platform.Architecture != "" && selected.Platform.Architecture != "amd64") {
		return zero, ErrOCIIdentity
	}
	id.ManifestDigest = selected.Digest
	var manifest ociManifest
	manifestFound := false
	err = scanOCI(ctx, archive, func(h *tar.Header, tr *tar.Reader) error {
		if h.Name != selectedBlobName(selected.Digest) {
			return nil
		}
		if manifestFound {
			return ErrOCIIdentity
		}
		raw, err := readOCIMetadata(tr, h, maxOCIManifestBytes)
		if err != nil {
			return err
		}
		if int64(len(raw)) != selected.Size || ociDigest(raw) != selected.Digest || json.Unmarshal(raw, &manifest) != nil {
			return ErrOCIIdentity
		}
		manifestFound = true
		return nil
	})
	if err != nil || !manifestFound {
		return zero, ErrOCIIdentity
	}
	if manifest.SchemaVersion != 2 || (manifest.MediaType != "" && manifest.MediaType != selected.MediaType) || !validOCISHA(manifest.Config.Digest) || manifest.Config.Size <= 0 || manifest.Config.Size > maxOCIConfigBytes || len(manifest.Layers) > maxOCILayers {
		return zero, ErrOCIIdentity
	}
	id.ConfigDigest = manifest.Config.Digest
	wanted := map[string]int64{manifest.Config.Digest: manifest.Config.Size}
	for _, layer := range manifest.Layers {
		if !validOCISHA(layer.Digest) || layer.Size < 0 || layer.Size > size {
			return zero, ErrOCIIdentity
		}
		if previous, exists := wanted[layer.Digest]; exists && previous != layer.Size {
			return zero, ErrOCIIdentity
		}
		wanted[layer.Digest] = layer.Size
	}
	found := make(map[string]bool, len(wanted))
	configSeen := false
	err = scanOCI(ctx, archive, func(h *tar.Header, tr *tar.Reader) error {
		if !strings.HasPrefix(h.Name, "blobs/sha256/") {
			return nil
		}
		digest := "sha256:" + strings.TrimPrefix(h.Name, "blobs/sha256/")
		expected, needed := wanted[digest]
		if !needed {
			return nil
		}
		if found[digest] || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || h.Size != expected {
			return ErrOCIIdentity
		}
		hash := sha256.New()
		if _, err := io.CopyBuffer(hash, ociContextReader{ctx: ctx, reader: io.LimitReader(tr, h.Size)}, make([]byte, 32<<10)); err != nil {
			return ErrOCIIdentity
		}
		if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
			return ErrOCIIdentity
		}
		found[digest] = true
		if digest == manifest.Config.Digest {
			configSeen = true
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if len(found) != len(wanted) || !configSeen {
		return zero, ErrOCIIdentity
	}
	// Reopen the small config blob after discovering its manifest identity; it may
	// precede index/manifest in a valid tar and must not force buffering layers.
	err = scanOCI(ctx, archive, func(h *tar.Header, tr *tar.Reader) error {
		if h.Name != selectedBlobName(manifest.Config.Digest) {
			return nil
		}
		raw, err := readOCIMetadata(tr, h, maxOCIConfigBytes)
		if err != nil || ociDigest(raw) != manifest.Config.Digest {
			return ErrOCIIdentity
		}
		var cfg struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}
		if json.Unmarshal(raw, &cfg) != nil || cfg.OS != "linux" || cfg.Architecture != "amd64" {
			return ErrOCIIdentity
		}
		id.OS, id.Architecture = cfg.OS, cfg.Architecture
		return nil
	})
	if err != nil || id.OS == "" {
		return zero, ErrOCIIdentity
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return zero, ErrOCIIdentity
	}
	return id, nil
}
