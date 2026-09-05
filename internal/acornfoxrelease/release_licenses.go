package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const agpl3TextSHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"

// ReleaseLicenseManifestV1 is an explicit, reproducible input. License texts
// are supplied from upstream materials, never guessed by the archive builder.
type ReleaseLicenseManifestV1 struct {
	SchemaVersion int                   `json:"schema_version"`
	Product       string                `json:"product"`
	License       string                `json:"license"`
	Copyright     string                `json:"copyright"`
	Created       string                `json:"created"`
	Components    []LicensedComponentV1 `json:"components"`
}

type LicensedComponentV1 struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	License      string `json:"license"`
	Source       string `json:"source"`
	Notice       string `json:"notice"`
	NoticeSHA256 string `json:"notice_sha256"`
}

func (manifest ReleaseLicenseManifestV1) Validate() error {
	if manifest.SchemaVersion != 1 || manifest.Product != Product || manifest.License != "AGPL-3.0-only" || strings.TrimSpace(manifest.Copyright) == "" || len(manifest.Copyright) > 256 || strings.ContainsAny(manifest.Copyright, "\r\n\x00") || len(manifest.Components) == 0 || len(manifest.Components) > 4096 {
		return errors.New("release license manifest is incomplete")
	}
	created, err := time.Parse(time.RFC3339, manifest.Created)
	if err != nil || created.UTC().Format(time.RFC3339) != manifest.Created {
		return errors.New("release license timestamp is invalid")
	}
	previous := ""
	for _, entry := range manifest.Components {
		// A bundled upstream license/notice set can be retained without
		// guessing a single SPDX expression for mixed-license source.
		if strings.Contains(entry.License, "LicenseRef-") && entry.License != "LicenseRef-"+entry.NoticeSHA256 {
			return errors.New("release extracted license identity is invalid")
		}
		key := entry.Name + "@" + entry.Version
		u, err := url.Parse(entry.Source)
		if entry.Name == "" || entry.Version == "" || key <= previous || len(key) > 512 || entry.License == "" || len(entry.License) > 256 || strings.ContainsAny(entry.License, "\r\n\x00") || entry.License == "NOASSERTION" || entry.License == "NONE" || strings.EqualFold(entry.License, "UNLICENSED") || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || entry.Notice == "" || !digestText.MatchString(entry.NoticeSHA256) || sha256Text([]byte(entry.Notice)) != entry.NoticeSHA256 {
			return errors.New("release dependency license is incomplete")
		}
		previous = key
	}
	return nil
}

func readReleaseLicenseManifest(root string, inputs LicenseInputsV1) (ReleaseLicenseManifestV1, error) {
	var manifest ReleaseLicenseManifestV1
	if VerifyLicenseTree(root, inputs) != nil {
		return manifest, ErrInputs
	}
	raw, err := readLicenseInput(root, inputs, "docs/licenses/licenses-manifest.json")
	if err != nil || len(raw) > int(licenseFileBytes) {
		return manifest, ErrInputs
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Validate() != nil {
		return manifest, ErrInputs
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return manifest, ErrInputs
	}
	license, err := readLicenseInput(root, inputs, "docs/licenses/AGPL-3.0-only.txt")
	if err != nil || sha256Text(license) != agpl3TextSHA256 {
		return manifest, ErrInputs
	}
	return manifest, nil
}

func readLicenseInput(root string, inputs LicenseInputsV1, path string) ([]byte, error) {
	var expected *FileEntryV1
	for i := range inputs.Files {
		if inputs.Files[i].Path == path {
			expected = &inputs.Files[i]
			break
		}
	}
	if expected == nil {
		return nil, ErrInputs
	}
	anchor, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrInputs
	}
	defer anchor.Close()
	file, err := anchor.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInputs
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != expected.Mode || linkCount(info) != 1 || info.Size() > licenseFileBytes {
		return nil, ErrInputs
	}
	raw, err := io.ReadAll(io.LimitReader(file, licenseFileBytes+1))
	if err != nil || int64(len(raw)) > licenseFileBytes || sha256Text(raw) != expected.SHA256 {
		return nil, ErrInputs
	}
	return raw, nil
}
