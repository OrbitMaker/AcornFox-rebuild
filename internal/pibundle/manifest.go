// Package pibundle owns the exact upstream Pi runtime asset inventory used by
// the AcornFox release builder. It contains no downloader or installer.
package pibundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
)

const (
	Version                = "0.85.1"
	SHA256SUMSSHA256       = "0b70b2e422339b7a1277c3addb3705e1239d21ca1c20a17741a7b1c06d7526b0"
	FileCount              = 218
	MaxFileBytes     int64 = 128 << 20
)

var ErrInvalidManifest = errors.New("pibundle: invalid pinned asset manifest")

type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type assetManifest struct {
	SchemaVersion    int     `json:"schema_version"`
	Version          string  `json:"version"`
	ArchiveSHA256    string  `json:"archive_sha256"`
	SHA256SUMSSHA256 string  `json:"sha256sums_sha256"`
	Files            []Entry `json:"files"`
}

var (
	loadOnce sync.Once
	loaded   assetManifest
	loadErr  error
)

// Entries returns a defensive copy of the pinned upstream file inventory.
func Entries() ([]Entry, error) {
	loadOnce.Do(loadManifest)
	if loadErr != nil {
		return nil, loadErr
	}
	return append([]Entry(nil), loaded.Files...), nil
}

// ValidateRuntimeEntries verifies that the supplied mixed runtime inventory
// contains exactly the pinned pi/** paths and modes. When strictDigest is true,
// every digest must also match the official archive-derived manifest.
func ValidateRuntimeEntries(entries []Entry, strictDigest bool) error {
	expected, err := Entries()
	if err != nil {
		return err
	}
	actual := make([]Entry, 0, len(expected))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Path, "pi/") {
			actual = append(actual, entry)
		}
	}
	if len(actual) != len(expected) {
		return ErrInvalidManifest
	}
	for index := range expected {
		if actual[index].Path != expected[index].Path || actual[index].Mode != expected[index].Mode || strictDigest && actual[index].SHA256 != expected[index].SHA256 {
			return ErrInvalidManifest
		}
	}
	return nil
}

func loadManifest() {
	if digest(manifestRaw) != ManifestSHA256 || len(manifestRaw) == 0 || manifestRaw[len(manifestRaw)-1] != '\n' || bytes.Count(manifestRaw, []byte{'\n'}) != 1 {
		loadErr = ErrInvalidManifest
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&loaded) != nil {
		loadErr = ErrInvalidManifest
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		loadErr = ErrInvalidManifest
		return
	}
	canonical, err := json.Marshal(loaded)
	if err != nil || !bytes.Equal(manifestRaw, append(canonical, '\n')) || loaded.SchemaVersion != 1 || loaded.Version != Version || loaded.ArchiveSHA256 != ArchiveSHA256 || loaded.SHA256SUMSSHA256 != SHA256SUMSSHA256 || len(loaded.Files) != FileCount {
		loadErr = ErrInvalidManifest
		return
	}
	var total int64
	previous := ""
	for _, file := range loaded.Files {
		if file.Path <= previous || !validPath(file.Path) || file.Mode != 0o644 && file.Mode != 0o755 || file.Size < 0 || file.Size > MaxFileBytes || !validDigest(file.SHA256) {
			loadErr = ErrInvalidManifest
			return
		}
		total += file.Size
		previous = file.Path
	}
	if total != TotalBytes {
		loadErr = ErrInvalidManifest
	}
}

func validPath(path string) bool {
	if !strings.HasPrefix(path, "pi/") || strings.HasPrefix(path, "pi/extensions/") || strings.HasSuffix(path, "/") || strings.Contains(path, "\\") || strings.Contains(path, "//") || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
