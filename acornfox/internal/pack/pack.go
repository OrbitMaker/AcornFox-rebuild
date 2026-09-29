package pack

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fixedModTime is the ModTime stamped on every tar entry so that the same tree
// always produces byte-identical output regardless of the files' real mtimes.
var fixedModTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// maxBytesOverride lets tests shrink the effective upload cap without producing
// a 200 MB fixture. Zero means "use MaxBytes".
var maxBytesOverride int64

// alwaysExclude are paths (relative, slash form) that are excluded no matter
// what .dockerignore says. Matching is prefix-aware for directories.
var alwaysExclude = []string{".git", ".acornfox"}

// Dir walks root honoring .dockerignore (Docker semantics) and always excluding
// ".git/" and ".acornfox", then writes a deterministic tar.gz to a temp file.
// See the package api.go doc comment for the full contract.
func Dir(root string) (Result, error) {
	root = filepath.Clean(root)

	// Dockerfile at the project root is mandatory; check before packing.
	if fi, err := os.Lstat(filepath.Join(root, "Dockerfile")); err != nil || fi.IsDir() {
		return Result{}, ErrDockerfileMissing
	}

	patterns, err := loadDockerignore(root)
	if err != nil {
		return Result{}, err
	}

	// Collect the set of included regular files / symlinks / dirs, sorted by
	// their slash path for deterministic ordering.
	entries, err := collect(root, patterns)
	if err != nil {
		return Result{}, err
	}

	limit := int64(MaxBytes)
	if maxBytesOverride > 0 {
		limit = maxBytesOverride
	}

	tmp, err := os.CreateTemp("", "acornfox-pack-*.tar.gz")
	if err != nil {
		return Result{}, err
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		_ = tmp.Close()
		if !done {
			_ = os.Remove(tmpName)
		}
	}()

	// Hash the compressed bytes while writing, and count bytes to enforce the
	// cap as early as possible.
	hasher := sha256.New()
	counter := &countWriter{w: io.MultiWriter(tmp, hasher)}

	gz, err := gzip.NewWriterLevel(counter, gzip.BestCompression)
	if err != nil {
		return Result{}, err
	}
	// Zero the gzip header ModTime and leave Name empty for determinism.
	gz.ModTime = time.Time{}
	gz.Name = ""

	tw := tar.NewWriter(gz)

	fileCount := 0
	for _, e := range entries {
		if err := writeEntry(tw, root, e); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return Result{}, err
		}
		if e.mode.IsRegular() {
			fileCount++
		}
		if counter.n > limit {
			_ = tw.Close()
			_ = gz.Close()
			return Result{}, ErrTooLarge
		}
	}

	if err := tw.Close(); err != nil {
		return Result{}, err
	}
	if err := gz.Close(); err != nil {
		return Result{}, err
	}
	if counter.n > limit {
		return Result{}, ErrTooLarge
	}
	if err := tmp.Sync(); err != nil {
		return Result{}, err
	}

	done = true
	return Result{
		Path:   tmpName,
		Bytes:  counter.n,
		Files:  fileCount,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// countWriter counts the bytes written through it.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// entry is one filesystem object selected for inclusion.
type entry struct {
	rel  string // slash-separated path relative to root
	mode os.FileMode
}

// collect walks root depth-first, applies the ignore patterns and the always-
// exclude list, and returns the included entries sorted by rel. Directories are
// included so empty dirs survive; symlinks are stored, never followed.
func collect(root string, patterns []pattern) ([]entry, error) {
	var out []entry

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		if isAlwaysExcluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		mode := info.Mode()
		isDir := d.IsDir()

		excluded := matchExcluded(rel, isDir, patterns)
		if excluded {
			if isDir {
				// A directory may still be un-excluded by a later "!" that
				// targets something inside it, so we cannot skip it outright
				// unless nothing re-includes below. We approximate Docker's
				// behavior: keep descending so exceptions inside can win, but
				// do not emit the dir itself.
				return nil
			}
			return nil
		}

		out = append(out, entry{rel: rel, mode: mode})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// isAlwaysExcluded reports whether rel is or is inside an always-excluded path.
func isAlwaysExcluded(rel string) bool {
	for _, x := range alwaysExclude {
		if rel == x || strings.HasPrefix(rel, x+"/") {
			return true
		}
	}
	return false
}

// writeEntry writes one tar entry with deterministic header fields.
func writeEntry(tw *tar.Writer, root string, e entry) error {
	full := filepath.Join(root, filepath.FromSlash(e.rel))
	fi, err := os.Lstat(full)
	if err != nil {
		return err
	}

	var link string
	if fi.Mode()&os.ModeSymlink != 0 {
		link, err = os.Readlink(full)
		if err != nil {
			return err
		}
	}

	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	hdr.Name = e.rel
	if fi.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	// Determinism: fixed mtime, zero owner ids and empty owner names.
	hdr.ModTime = fixedModTime
	hdr.AccessTime = time.Time{}
	hdr.ChangeTime = time.Time{}
	hdr.Uid = 0
	hdr.Gid = 0
	hdr.Uname = ""
	hdr.Gname = ""
	// Keep only permission and type bits; drop setuid/setgid/sticky noise but
	// preserve the executable bit and the standard rwx perms.
	hdr.Mode = int64(fi.Mode().Perm())
	hdr.Format = tar.FormatPAX

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if fi.Mode().IsRegular() {
		f, err := os.Open(full)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
	}
	return nil
}

// ---- .dockerignore matching (Docker fileutils/patternmatcher semantics) ----

// pattern is one compiled .dockerignore line.
type pattern struct {
	cleaned  string   // normalized pattern (slash form, no leading "/", no trailing "/")
	segments []string // cleaned split on "/"
	exclude  bool     // true for "!" exception lines
	dirOnly  bool     // pattern had a trailing "/"
}

// loadDockerignore reads root/.dockerignore and compiles its lines. A missing
// file yields no patterns (nil, nil).
func loadDockerignore(root string) ([]pattern, error) {
	f, err := os.Open(filepath.Join(root, ".dockerignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var patterns []pattern
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		p := compilePattern(sc.Text())
		if p == nil {
			continue
		}
		patterns = append(patterns, *p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
}

// compilePattern normalizes one .dockerignore line, or returns nil for blank
// lines and comments.
func compilePattern(line string) *pattern {
	// Trim trailing CR (CRLF files) and surrounding whitespace like Docker's
	// scanner does after stripping the newline.
	line = strings.TrimRight(line, "\r")
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "#") {
		return nil
	}

	p := pattern{}
	if strings.HasPrefix(trimmed, "!") {
		p.exclude = true
		trimmed = strings.TrimSpace(trimmed[1:])
		if trimmed == "" {
			return nil
		}
	}

	// Convert any Windows separators, strip a leading "/", note and strip a
	// trailing "/".
	norm := convertPathSeparators(trimmed)
	norm = strings.TrimPrefix(norm, "/")
	if strings.HasSuffix(norm, "/") {
		p.dirOnly = true
		norm = strings.TrimSuffix(norm, "/")
	}
	// path.Clean collapses "." and ".." and duplicate slashes the way Docker's
	// filepath.Clean does on the pattern.
	norm = cleanPattern(norm)
	if norm == "" || norm == "." {
		return nil
	}

	p.cleaned = norm
	p.segments = strings.Split(norm, "/")
	return &p
}

// cleanPattern applies path.Clean while keeping a leading "**" meaningful.
func cleanPattern(p string) string {
	c := path.Clean(p)
	if c == "." {
		return ""
	}
	return c
}

// convertPathSeparators turns backslashes into forward slashes so Windows-style
// patterns match the slash paths we walk. Exposed via a helper so tests can
// verify it directly.
func convertPathSeparators(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// matchExcluded reports whether rel (slash form) is excluded given the ordered
// pattern list. Order matters: the last matching pattern wins, and "!" lines
// re-include. A directory match also excludes everything beneath it.
//
// A trailing-slash ("foo/") pattern only matches directories, but files nested
// under a matched directory are still excluded through ancestor matching, so
// the dirOnly flag only affects whether the pattern matches rel exactly.
func matchExcluded(rel string, isDir bool, patterns []pattern) bool {
	excluded := false
	for _, p := range patterns {
		if matchOne(rel, isDir, p) {
			excluded = !p.exclude
		}
	}
	return excluded
}

// matchOne reports whether pattern p matches rel. A pattern matches rel if it
// matches rel exactly (segment-wise, honoring "**") or matches any ancestor of
// rel (so excluding "node_modules" also excludes "node_modules/x").
func matchOne(rel string, isDir bool, p pattern) bool {
	parts := strings.Split(rel, "/")
	// Exact match. A dirOnly pattern only matches rel exactly when rel is a
	// directory; nested files are covered by the ancestor loop below.
	if !p.dirOnly || isDir {
		if matchSegments(p.segments, parts) {
			return true
		}
	}
	// Ancestor match: if the pattern matches a parent path of rel, rel is
	// inside an excluded directory (the ancestor is always a directory, so the
	// dirOnly restriction is satisfied).
	for i := 1; i < len(parts); i++ {
		if matchSegments(p.segments, parts[:i]) {
			return true
		}
	}
	return false
}

// matchSegments matches a pattern's segments against a path's segments with
// filepath.Match semantics per segment plus "**" spanning zero or more
// segments.
func matchSegments(pat, name []string) bool {
	// No pattern segments matches only an empty name.
	if len(pat) == 0 {
		return len(name) == 0
	}

	if pat[0] == "**" {
		// "**" matches zero or more path segments. Try consuming 0..len(name).
		// Collapse consecutive "**" first by skipping.
		rest := pat[1:]
		for len(rest) > 0 && rest[0] == "**" {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			// Trailing "**" matches everything remaining.
			return true
		}
		for i := 0; i <= len(name); i++ {
			if matchSegments(rest, name[i:]) {
				return true
			}
		}
		return false
	}

	if len(name) == 0 {
		return false
	}
	ok, err := matchSegment(pat[0], name[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], name[1:])
}

// matchSegment matches one pattern segment against one path segment using
// filepath.Match semantics. A segment "**" would have been handled by the
// caller; here a literal "*" does not cross "/", which is guaranteed because we
// match segment by segment.
func matchSegment(pat, name string) (bool, error) {
	return matchGlob(pat, name)
}

// matchGlob is filepath.Match but always using slash semantics and never
// treating the path separator specially inside a single segment (there is no
// separator inside a segment). We reuse path.Match which uses "/" as separator;
// since segments contain no "/", it behaves as a pure glob.
func matchGlob(pat, name string) (bool, error) {
	return path.Match(pat, name)
}

// String renders a pattern for debugging/tests.
func (p pattern) String() string {
	prefix := ""
	if p.exclude {
		prefix = "!"
	}
	suffix := ""
	if p.dirOnly {
		suffix = "/"
	}
	return fmt.Sprintf("%s%s%s", prefix, p.cleaned, suffix)
}
