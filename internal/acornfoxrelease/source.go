package acornfoxrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

const (
	maxManifestBytes = 1 << 20
	// Source limits keep local policy manifests modest. Runtime limits mirror
	// the sealed installer intake bounds without importing installer authority.
	sourceFileBytes  int64 = 16 << 20
	sourceTreeBytes  int64 = 128 << 20
	licenseFileBytes int64 = 16 << 20
	licenseTreeBytes int64 = 64 << 20
	runtimeFileBytes int64 = 128 << 20
	runtimeTreeBytes int64 = 1 << 30
)

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
	if !w.Valid() || parseCanonical(raw, &p) != nil || p.Validate() != nil || p.ModulePath != modulePathForRepository(w.decision.SourceRepository) || sha256Text(raw) != w.decision.SourcePolicySHA256 {
		return p, ErrInputs
	}
	return p, nil
}

// VerifySourceTree is local-only. A top-level .git directory is ignored as
// repository metadata; every other hidden or extra entry is rejected.
func VerifySourceTree(root string, policy SourcePolicyV1) error {
	if policy.Validate() != nil {
		return ErrInputs
	}
	return verifyFileTree(root, policy.Files, true, treeLimits{sourceFileBytes, sourceTreeBytes})
}

func validModulePath(v string) bool {
	parts := strings.Split(v, "/")
	return len(parts) == 3 && parts[0] == "github.com" && githubPart.MatchString(parts[1]) && githubPart.MatchString(parts[2])
}
func modulePathForRepository(repository string) string {
	return strings.TrimPrefix(repository, "https://")
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
	if p == "" || strings.Contains(p, "\\") || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || part == ".git" || hasASCIIControl(part) {
			return false
		}
	}
	return true
}
func hasASCIIControl(v string) bool {
	for _, b := range []byte(v) {
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
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

type treeLimits struct{ file, total int64 }

func verifyFileTree(root string, entries []FileEntryV1, ignoreGit bool, limits treeLimits) error {
	if validateEntries(entries) != nil {
		return ErrInputs
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInputs
	}
	rootFD, err := os.OpenRoot(root)
	if err != nil {
		return ErrInputs
	}
	defer rootFD.Close()
	openedRoot, err := rootFD.Stat(".")
	if err != nil || !openedRoot.IsDir() || !os.SameFile(info, openedRoot) {
		return ErrInputs
	}
	want := map[string]FileEntryV1{}
	for _, e := range entries {
		want[e.Path] = e
	}
	seen := map[string]bool{}
	var total int64
	var walk func(string) error
	walk = func(dir string) error {
		f, e := rootFD.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return ErrInputs
		}
		children, re := f.ReadDir(-1)
		ce := f.Close()
		if re != nil || ce != nil {
			return ErrInputs
		}
		for _, child := range children {
			rel := child.Name()
			if dir != "." {
				rel = dir + "/" + rel
			}
			before, e := rootFD.Lstat(rel)
			if e != nil {
				return ErrInputs
			}
			if ignoreGit && dir == "." && child.Name() == ".git" && (before.IsDir() || before.Mode().IsRegular()) {
				continue
			}
			if before.Mode()&os.ModeSymlink != 0 {
				return ErrInputs
			}
			if before.IsDir() {
				if walk(rel) != nil {
					return ErrInputs
				}
				continue
			}
			entry, ok := want[rel]
			if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != os.FileMode(entry.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > limits.file {
				return ErrInputs
			}
			file, e := rootFD.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if e != nil {
				return ErrInputs
			}
			opened, se := file.Stat()
			h := sha256.New()
			n, re := io.Copy(h, io.LimitReader(file, limits.file+1))
			ce = file.Close()
			after, ae := rootFD.Lstat(rel)
			if se != nil || re != nil || ce != nil || ae != nil || n != before.Size() || n > limits.file || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
				return ErrInputs
			}
			total += n
			if total > limits.total {
				return ErrInputs
			}
			seen[rel] = true
		}
		return nil
	}
	if walk(".") != nil {
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
