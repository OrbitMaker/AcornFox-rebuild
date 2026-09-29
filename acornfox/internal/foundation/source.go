package foundation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"
)

// GitScheme identifies the two Git locator forms supported by the MVP.
type GitScheme string

const (
	GitHTTPS GitScheme = "https"
	GitSSH   GitScheme = "ssh"
)

// GitSource is a canonical, non-secret Git source reference. Ref is kept
// separate from the locator so callers cannot accidentally use a moving
// branch as the content identity.
type GitSource struct {
	Locator string    `json:"locator"`
	Ref     string    `json:"ref"`
	Scheme  GitScheme `json:"scheme"`
}

var (
	ErrInvalidGitLocator = errors.New("invalid git locator")
	ErrInvalidGitRef     = errors.New("invalid git ref")
	ErrInvalidTree       = errors.New("invalid upload tree")
)

// NormalizeGitSource validates and canonicalizes an HTTPS or SSH Git
// locator together with a ref. It intentionally rejects userinfo, query
// strings, fragments and local/file schemes because source locators are
// persisted as product facts and must not carry credentials or ambiguity.
func NormalizeGitSource(locator, ref string) (GitSource, error) {
	canonicalLocator, scheme, err := NormalizeGitLocator(locator)
	if err != nil {
		return GitSource{}, err
	}
	canonicalRef, err := NormalizeGitRef(ref)
	if err != nil {
		return GitSource{}, err
	}
	return GitSource{Locator: canonicalLocator, Ref: canonicalRef, Scheme: scheme}, nil
}

// NormalizeGitAddressAndRef is an explicit alias useful at API boundaries.
func NormalizeGitAddressAndRef(locator, ref string) (GitSource, error) {
	return NormalizeGitSource(locator, ref)
}

// NormalizeGitLocator returns a stable HTTPS URL or SSH locator. Both
// standard SSH forms (ssh://user@host/path and user@host:path) are accepted,
// while canonical output uses the scp-like form for the latter and preserves
// the URL form for the former.
func NormalizeGitLocator(locator string) (string, GitScheme, error) {
	raw := strings.TrimSpace(locator)
	if raw == "" || containsControl(raw) || strings.ContainsAny(raw, "\r\n\t ") {
		return "", "", fmt.Errorf("%w: empty or whitespace", ErrInvalidGitLocator)
	}

	if strings.HasPrefix(strings.ToLower(raw), "ssh://") {
		u, err := url.Parse(raw)
		hasPassword := false
		if u.User != nil {
			_, hasPassword = u.User.Password()
		}
		if err != nil || strings.ToLower(u.Scheme) != "ssh" || u.Host == "" || u.User == nil || u.User.Username() == "" || hasPassword {
			return "", "", fmt.Errorf("%w: malformed ssh URL", ErrInvalidGitLocator)
		}
		if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(u.Host, ":@") {
			// A port is not forbidden by the Git protocol, but accepting it
			// would make the canonical scp/URL forms unexpectedly diverge.
			if strings.Contains(u.Host, "@") {
				return "", "", fmt.Errorf("%w: malformed ssh host", ErrInvalidGitLocator)
			}
		}
		username := strings.ToLower(u.User.Username())
		host := strings.ToLower(strings.TrimSuffix(u.Host, "."))
		if username == "" || host == "" || strings.Contains(host, "@") {
			return "", "", fmt.Errorf("%w: missing ssh identity", ErrInvalidGitLocator)
		}
		cleanPath, err := canonicalRepoPath(u.EscapedPath())
		if err != nil {
			return "", "", err
		}
		return "ssh://" + username + "@" + host + cleanPath, GitSSH, nil
	}

	// SCP-like SSH references have no URI scheme and must contain exactly one
	// user/host separator before the repository path.
	if looksLikeSCPGitLocator(raw) {
		at := strings.LastIndexByte(raw[:strings.IndexByte(raw, ':')], '@')
		colon := strings.IndexByte(raw, ':')
		user := strings.ToLower(raw[:at])
		host := strings.ToLower(strings.TrimSuffix(raw[at+1:colon], "."))
		if user == "" || host == "" || strings.ContainsAny(host, "@/\\") {
			return "", "", fmt.Errorf("%w: malformed scp host", ErrInvalidGitLocator)
		}
		cleanPath, err := canonicalRepoPath(raw[colon+1:])
		if err != nil {
			return "", "", err
		}
		return user + "@" + host + ":" + strings.TrimPrefix(cleanPath, "/"), GitSSH, nil
	}

	u, err := url.Parse(raw)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("%w: HTTPS locator required", ErrInvalidGitLocator)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Host, "."))
	if strings.ContainsAny(host, "@/\\") || strings.Contains(host, ":") {
		// HTTPS sources intentionally use the default HTTPS port only. A
		// non-default port is an explicit endpoint and is rejected here to
		// avoid normalizing two security domains to the same source identity.
		return "", "", fmt.Errorf("%w: invalid HTTPS host", ErrInvalidGitLocator)
	}
	cleanPath, err := canonicalRepoPath(u.EscapedPath())
	if err != nil {
		return "", "", err
	}
	return "https://" + host + cleanPath, GitHTTPS, nil
}

// NormalizeGitRef trims harmless surrounding whitespace and rejects values
// that cannot be safely represented as a Git ref. It does not resolve the ref;
// only a provider that talks to Git can turn it into an immutable commit.
func NormalizeGitRef(ref string) (string, error) {
	value := strings.TrimSpace(ref)
	if value == "" || strings.HasPrefix(value, "-") || containsControl(value) || strings.ContainsAny(value, " \\~^:?*[") {
		return "", fmt.Errorf("%w: invalid characters", ErrInvalidGitRef)
	}
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") {
		return "", fmt.Errorf("%w: invalid path form", ErrInvalidGitRef)
	}
	return value, nil
}

func canonicalRepoPath(rawPath string) (string, error) {
	if rawPath == "" {
		return "", fmt.Errorf("%w: repository path required", ErrInvalidGitLocator)
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil || containsControl(decoded) || strings.Contains(decoded, "\\") {
		return "", fmt.Errorf("%w: invalid repository path", ErrInvalidGitLocator)
	}
	for _, part := range strings.Split(decoded, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: repository traversal", ErrInvalidGitLocator)
		}
	}
	clean := path.Clean("/" + decoded)
	if clean == "/" || clean == "/." {
		return "", fmt.Errorf("%w: invalid repository path", ErrInvalidGitLocator)
	}
	// A trailing slash is never part of a Git repository identity. Preserve a
	// .git suffix but do not add one; callers may use mirrors without it.
	return strings.TrimSuffix(clean, "/"), nil
}

func looksLikeSCPGitLocator(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || colon == len(value)-1 {
		return false
	}
	// A colon before an @ is not an scp locator, and a slash before the colon
	// indicates a URI/path rather than the accepted scp form.
	return strings.Contains(value[:colon], "@") && !strings.Contains(value[:colon], "/")
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// TreeEntry is a deterministic representation of one upload-tree item. Data
// is copied by callers before passing it here if the source can mutate while
// hashing; the function itself never writes to the source.
type TreeEntry struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

// DigestTree computes a content-addressed SHA-256 over sorted, normalized
// entries. Paths, modes and lengths are framed before data, preventing
// ambiguous concatenation and making identical trees independent of map or
// filesystem traversal order.
func DigestTree(entries []TreeEntry) (string, error) {
	canonical := make([]TreeEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name, err := normalizeTreePath(entry.Path)
		if err != nil {
			return "", err
		}
		if _, ok := seen[name]; ok {
			return "", fmt.Errorf("%w: duplicate path %q", ErrInvalidTree, name)
		}
		seen[name] = struct{}{}
		if entry.Mode&fs.ModeSymlink != 0 || !entry.Mode.IsRegular() {
			return "", fmt.Errorf("%w: unsupported file mode for %q", ErrInvalidTree, name)
		}
		if isIgnoredSystemPath(name) {
			continue
		}
		canonical = append(canonical, TreeEntry{Path: name, Data: entry.Data, Mode: entry.Mode.Perm()})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Path < canonical[j].Path })
	h := sha256.New()
	for _, entry := range canonical {
		writeFrame(h, entry.Path)
		writeFrame(h, fmt.Sprintf("%04o", canonicalFileMode(entry.Mode)))
		writeFrame(h, string(entry.Data))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func canonicalFileMode(mode fs.FileMode) fs.FileMode {
	if mode.Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

// DigestUploadTree is a compatibility spelling for source providers.
func DigestUploadTree(entries []TreeEntry) (string, error) { return DigestTree(entries) }

// HashDirectory walks a directory without following symlinks and returns the
// same digest format as DigestTree. Common operating-system metadata is
// omitted; application dotfiles such as .env are retained as source data.
func HashDirectory(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("%w: directory required", ErrInvalidTree)
	}
	entries := make([]TreeEntry, 0)
	err := fs.WalkDir(os.DirFS(root), ".", func(name string, dirent fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if isIgnoredSystemPath(name) {
			if dirent.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if dirent.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %q", ErrInvalidTree, name)
		}
		if dirent.IsDir() {
			return nil
		}
		info, err := dirent.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: special file %q", ErrInvalidTree, name)
		}
		data, err := fs.ReadFile(os.DirFS(root), name)
		if err != nil {
			return err
		}
		entries = append(entries, TreeEntry{Path: name, Data: data, Mode: info.Mode()})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidTree, err)
	}
	return DigestTree(entries)
}

// TreeDigest is a concise alias used by evidence code.
func TreeDigest(root string) (string, error) { return HashDirectory(root) }

func normalizeTreePath(raw string) (string, error) {
	value := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	if value == "" || containsControl(value) || strings.HasPrefix(value, "/") || isWindowsAbsolute(value) {
		return "", fmt.Errorf("%w: unsafe path %q", ErrInvalidTree, raw)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: traversal path %q", ErrInvalidTree, raw)
		}
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: traversal path %q", ErrInvalidTree, raw)
	}
	return clean, nil
}

func isWindowsAbsolute(value string) bool {
	return len(value) >= 3 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':' && value[2] == '/'
}

func isIgnoredSystemPath(name string) bool {
	for _, part := range strings.Split(strings.ReplaceAll(name, "\\", "/"), "/") {
		switch strings.ToLower(part) {
		case ".ds_store", "thumbs.db", "desktop.ini", "__macosx":
			return true
		}
	}
	return false
}

func writeFrame(dst interface{ Write([]byte) (int, error) }, value string) {
	// Length-prefixing makes path and content boundaries explicit. The hash
	// code cannot fail for hash.Hash, so the write result is intentionally
	// ignored.
	_, _ = dst.Write([]byte(fmt.Sprintf("%d:", len(value))))
	_, _ = dst.Write([]byte(value))
}
