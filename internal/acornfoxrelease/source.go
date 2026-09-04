package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const maxManifestBytes = 1 << 20

var ErrInputs = errors.New("acornfox release inputs are invalid")

type FileEntryV1 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type SourcePolicyV1 struct {
	SchemaVersion int           `json:"schema_version"`
	Product       string        `json:"product"`
	ModulePath    string        `json:"module_path"`
	Files         []FileEntryV1 `json:"files"`
}

func (p SourcePolicyV1) Validate() error {
	if p.SchemaVersion != 1 || p.Product != Product || !validModulePath(p.ModulePath) {
		return ErrInputs
	}
	return validateEntries(p.Files)
}
func CanonicalSourcePolicyV1(p SourcePolicyV1) ([]byte, error) {
	if p.Validate() != nil {
		return nil, ErrInputs
	}
	return json.Marshal(p)
}
func ParseSourcePolicyV1(w Witness, raw []byte) (SourcePolicyV1, error) {
	var p SourcePolicyV1
	if !w.Valid() || parseCanonical(raw, &p) != nil || p.Validate() != nil || sha256Text(raw) != w.decision.SourcePolicySHA256 {
		return p, ErrInputs
	}
	return p, nil
}

// VerifySourceTree is local-only. A top-level .git directory is ignored as
// repository metadata; every other hidden or extra entry is rejected.
func VerifySourceTree(root string, policy SourcePolicyV1) error {
	return verifyFileTree(root, policy.Files, true)
}

func validModulePath(v string) bool {
	return strings.HasPrefix(v, "github.com/") && !strings.ContainsAny(v, "\\\x00 ") && len(strings.Split(v, "/")) >= 3
}
func validateEntries(entries []FileEntryV1) error {
	if len(entries) == 0 || len(entries) > 4096 {
		return ErrInputs
	}
	for i, e := range entries {
		if !validRelativeFile(e.Path) || !digestText.MatchString(e.SHA256) || (e.Mode != 0o644 && e.Mode != 0o755) || (i > 0 && entries[i-1].Path >= e.Path) {
			return ErrInputs
		}
	}
	return nil
}
func validRelativeFile(p string) bool {
	return p != "" && filepath.ToSlash(filepath.Clean(p)) == p && !strings.ContainsAny(p, "\\\x00") && !strings.HasPrefix(p, ".") && !strings.Contains(p, "//") && !strings.Contains(p, "..")
}
func parseCanonical(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return ErrInputs
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInputs
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInputs
	}
	canonical, e := json.Marshal(target)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrInputs
	}
	return nil
}

func verifyFileTree(root string, entries []FileEntryV1, ignoreGit bool) error {
	if validateEntries(entries) != nil {
		return ErrInputs
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInputs
	}
	want := map[string]FileEntryV1{}
	for _, e := range entries {
		want[e.Path] = e
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrInputs
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return ErrInputs
		}
		rel = filepath.ToSlash(rel)
		if ignoreGit && rel == ".git" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrInputs
		}
		if d.IsDir() {
			return nil
		}
		entry, ok := want[rel]
		if !ok {
			return ErrInputs
		}
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != os.FileMode(entry.Mode) || linkCount(fi) != 1 {
			return ErrInputs
		}
		raw, err := os.ReadFile(path)
		if err != nil || sha256Text(raw) != entry.SHA256 {
			return ErrInputs
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return ErrInputs
	}
	for _, e := range entries {
		if !seen[e.Path] {
			return ErrInputs
		}
	}
	return nil
}
func linkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}
func sortedEntries(entries []FileEntryV1) []FileEntryV1 {
	out := append([]FileEntryV1(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
