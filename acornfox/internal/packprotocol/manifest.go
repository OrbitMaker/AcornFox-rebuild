// Package packprotocol contains declarative trust contracts only; it performs
// no downloading, archive expansion, process execution or permission granting.
package packprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/acornfox/acornfox/internal/versionpolicy"
)

const MaxManifestBytes = 128 << 10

type Dependency struct {
	PackID     string `json:"pack_id"`
	MinVersion string `json:"min_version"`
}
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Entry struct {
	Role string `json:"role"`
	Path string `json:"path"`
}
type Manifest struct {
	Schema          string       `json:"schema"`
	PackID          string       `json:"pack_id"`
	Version         string       `json:"version"`
	OS              string       `json:"os"`
	Arch            string       `json:"arch"`
	MinCoreVersion  string       `json:"min_core_version"`
	ProtocolVersion string       `json:"protocol_version"`
	Capabilities    []string     `json:"capabilities"`
	Dependencies    []Dependency `json:"dependencies"`
	Permissions     []string     `json:"permissions"`
	Entries         []Entry      `json:"entries"`
	Files           []File       `json:"files"`
}

func ValidPackID(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return s != "core" && s != "system" && !strings.HasPrefix(s, "acornfox-core") && !strings.HasPrefix(s, "system-")
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Check keys before typed decoding: encoding/json otherwise accepts case aliases
// and silently overwrites duplicate keys. Depth/count limits bound token work.
func strictJSON(b []byte, out any, limit int) error {
	return StrictJSON(b, out, limit)
}

// StrictJSON provides the reviewed strict decoder with depth, key and tail validation.
func StrictJSON(b []byte, out any, limit int) error {
	if len(b) == 0 || len(b) > limit {
		return errors.New("json_size_rejected")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	var walk func(json.Token, int) error
	walk = func(t json.Token, depth int) error {
		tokens++
		if depth > 12 || tokens > 20000 {
			return errors.New("json_structure_bound")
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				k, ok := key.(string)
				if !ok {
					return errors.New("json_key_rejected")
				}
				if k != strings.ToLower(k) {
					return errors.New("json_key_case_rejected")
				}
				if seen[k] {
					return errors.New("json_duplicate_key")
				}
				seen[k] = true
				v, e := d.Token()
				if e != nil {
					return e
				}
				if e = walk(v, depth+1); e != nil {
					return e
				}
			}
			_, e := d.Token()
			return e
		case '[':
			for d.More() {
				v, e := d.Token()
				if e != nil {
					return e
				}
				if e = walk(v, depth+1); e != nil {
					return e
				}
			}
			_, e := d.Token()
			return e
		default:
			return errors.New("json_delimiter_rejected")
		}
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t != json.Delim('{') {
		return errors.New("json_root_rejected")
	}
	if err := walk(t, 0); err != nil {
		return err
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return errors.New("json_tail_rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return errors.New("json_fields_rejected")
	}
	if decoder.Decode(&tail) != io.EOF {
		return errors.New("json_tail_rejected")
	}
	return nil
}
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := strictJSON(raw, &m, MaxManifestBytes); err != nil {
		return m, err
	}
	if m.Schema != "acornfox-pack-manifest-v1" || !ValidPackID(m.PackID) || m.OS != "linux" {
		return m, errors.New("manifest_identity_rejected")
	}
	if _, _, err := versionpolicy.CanonicalizePlatform(m.OS, m.Arch); err != nil {
		return m, err
	}
	if _, err := versionpolicy.ParseSemver(m.Version); err != nil {
		return m, err
	}
	if _, err := versionpolicy.ParseSemver(m.MinCoreVersion); err != nil {
		return m, err
	}
	if m.ProtocolVersion != "1.0" {
		return m, errors.New("manifest_protocol_rejected")
	}
	if len(m.Capabilities) == 0 || len(m.Capabilities) > 32 || len(m.Dependencies) > 16 || len(m.Permissions) > 16 || len(m.Entries) == 0 || len(m.Entries) > 8 || len(m.Files) == 0 || len(m.Files) > 256 {
		return m, errors.New("manifest_count_rejected")
	}
	seen := map[string]bool{}
	for _, c := range m.Capabilities {
		if c == "" || len(c) > 64 || strings.TrimSpace(c) != c || seen[c] {
			return m, errors.New("manifest_capability_rejected")
		}
		for _, r := range c {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
				return m, errors.New("manifest_capability_rejected")
			}
		}
		seen[c] = true
	}
	seen = map[string]bool{}
	for _, d := range m.Dependencies {
		if !ValidPackID(d.PackID) || d.PackID == m.PackID || seen[d.PackID] {
			return m, errors.New("manifest_dependency_rejected")
		}
		if _, err := versionpolicy.ParseSemver(d.MinVersion); err != nil {
			return m, err
		}
		seen[d.PackID] = true
	}
	allowedPermissions := map[string]bool{"network.outbound": true, "state.private": true, "helper.managed-service": true}
	seen = map[string]bool{}
	for _, p := range m.Permissions {
		if !allowedPermissions[p] || seen[p] {
			return m, errors.New("manifest_permission_rejected")
		}
		seen[p] = true
	}
	inventory := map[string]File{}
	var total int64
	for _, f := range m.Files {
		if f.Path == "" || len(f.Path) > 256 || path.Clean(f.Path) != f.Path || strings.ContainsAny(f.Path, "\\\x00") || strings.HasPrefix(f.Path, "/") || (f.Path == ".." || f.Path == ".") || strings.HasPrefix(f.Path, "../") || !validDigest(f.SHA256) || f.Size <= 0 || f.Size > 1<<30 || (f.Mode != 0644 && f.Mode != 0755) {
			return m, errors.New("manifest_file_rejected")
		}
		if _, ok := inventory[f.Path]; ok {
			return m, errors.New("manifest_duplicate_file")
		}
		for _, r := range f.Path {
			if r < 32 || r == 127 {
				return m, errors.New("manifest_path_control_rejected")
			}
		}
		inventory[f.Path] = f
		total += f.Size
		if total > 2<<30 {
			return m, errors.New("manifest_inventory_bound")
		}
	}
	entries := map[string]bool{}
	roles := map[string]bool{}
	for _, e := range m.Entries {
		f, ok := inventory[e.Path]
		if !ok || f.Mode != 0755 || roles[e.Role] || (e.Role != "adapter" && e.Role != "helper") {
			return m, errors.New("manifest_entry_rejected")
		}
		roles[e.Role] = true
		entries[e.Path] = true
	}
	for _, f := range inventory {
		if f.Mode == 0755 && !entries[f.Path] {
			return m, errors.New("manifest_undeclared_executable")
		}
	}
	if !roles["adapter"] {
		return m, errors.New("manifest_adapter_required")
	}
	return m, nil
}
