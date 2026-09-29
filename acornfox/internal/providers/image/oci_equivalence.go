package image

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
)

// OCI export timestamps belong to the index descriptor, not the image digest.
// A repeated export can therefore have different archive bytes for the same
// immutable image. Retain the original archive/evidence only after comparing
// every member, validating blob hashes, and ignoring that one annotation.
func equivalentOCIArchives(first, second, imageDigest string) bool {
	a, err := ociArchiveMembers(first, imageDigest)
	if err != nil {
		return false
	}
	b, err := ociArchiveMembers(second, imageDigest)
	return err == nil && reflect.DeepEqual(a, b)
}

func ociArchiveMembers(path, imageDigest string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := tar.NewReader(f)
	members := map[string]string{}
	seen := map[string]bool{}
	for count := 0; ; count++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || count >= 4096 {
			return nil, errors.New("invalid OCI archive")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if seen[name] {
			return nil, errors.New("duplicate OCI archive member")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir && (name == "blobs" || name == "blobs/sha256") {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, errors.New("nonregular OCI member")
		}
		if name == "index.json" || name == "oci-layout" {
			if header.Size < 1 || header.Size > 1<<20 {
				return nil, errors.New("invalid OCI metadata size")
			}
			raw, err := io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
			if name == "index.json" {
				raw, err = normalizedOCIIndex(raw, imageDigest)
				if err != nil {
					return nil, err
				}
			} else if !bytes.Equal(bytes.TrimSpace(raw), []byte(`{"imageLayoutVersion":"1.0.0"}`)) {
				return nil, errors.New("unsupported OCI layout")
			}
			sum := sha256.Sum256(raw)
			members[name] = hex.EncodeToString(sum[:])
			continue
		}
		digest, ok := strings.CutPrefix(name, "blobs/sha256/")
		if !ok || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
			return nil, errors.New("invalid OCI blob path")
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, reader); err != nil {
			return nil, err
		}
		if hex.EncodeToString(hash.Sum(nil)) != digest {
			return nil, errors.New("OCI blob digest mismatch")
		}
		members[name] = digest
	}
	padding, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(padding) > 1<<20 || len(bytes.Trim(padding, "\x00")) != 0 {
		return nil, errors.New("unexpected trailing OCI archive data")
	}
	if members["index.json"] == "" || members["oci-layout"] == "" || members["blobs/sha256/"+strings.TrimPrefix(imageDigest, "sha256:")] == "" {
		return nil, errors.New("incomplete OCI archive")
	}
	return members, nil
}

func normalizedOCIIndex(raw []byte, expected string) ([]byte, error) {
	if err := scanOCIJSON(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var index map[string]any
	if decoder.Decode(&index) != nil {
		return nil, errors.New("invalid OCI index")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, errors.New("trailing OCI index data")
	}
	if version, ok := index["schemaVersion"].(json.Number); !ok || version != "2" {
		return nil, errors.New("invalid OCI index version")
	}
	manifests, ok := index["manifests"].([]any)
	if !ok || len(manifests) != 1 {
		return nil, errors.New("expected one OCI image")
	}
	manifest, ok := manifests[0].(map[string]any)
	if !ok || manifest["digest"] != expected {
		return nil, errors.New("OCI index image mismatch")
	}
	if annotations, ok := manifest["annotations"].(map[string]any); ok {
		delete(annotations, "org.opencontainers.image.created")
		if len(annotations) == 0 {
			delete(manifest, "annotations")
		}
	}
	return json.Marshal(index)
}

func scanOCIJSON(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("OCI index nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate OCI index key")
			}
			seen[key] = true
		}
		if err := scanOCIJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
