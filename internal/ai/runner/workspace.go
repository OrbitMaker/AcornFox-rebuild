package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// securePath rejects absolute action paths, traversal components, symlinks,
// hard links, and special files. It is used for both reads and writes. A
// missing final component is allowed only when allowMissing is true; every
// existing parent is still checked.
func securePath(workspace Workspace, requested string, allowMissing bool, allowDirectory bool) (string, error) {
	workspace = workspace.normalized()
	if err := validateWorkspaceRoot(workspace); err != nil {
		return "", err
	}
	return securePathUnchecked(workspace, requested, allowMissing, allowDirectory)
}

func securePathUnchecked(workspace Workspace, requested string, allowMissing bool, allowDirectory bool) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", fmt.Errorf("%w: path is empty", ErrWorkspaceBoundary)
	}
	if strings.ContainsAny(requested, "\x00\\") || filepath.IsAbs(requested) {
		return "", fmt.Errorf("%w: path must be a relative unix-style path", ErrWorkspaceBoundary)
	}
	rawComponents := strings.Split(filepath.FromSlash(requested), string(filepath.Separator))
	for _, component := range rawComponents {
		if component == ".." || (component == "." && requested != ".") {
			return "", fmt.Errorf("%w: path contains traversal component", ErrWorkspaceBoundary)
		}
	}
	cleaned := filepath.Clean(filepath.FromSlash(requested))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path escapes workspace", ErrWorkspaceBoundary)
	}
	if cleaned == "." {
		if !allowDirectory {
			return "", fmt.Errorf("%w: path is a directory", ErrWorkspaceBoundary)
		}
		return filepath.Clean(workspace.Root), nil
	}
	for _, component := range strings.Split(cleaned, string(filepath.Separator)) {
		if component == ".." || component == "." || component == "" {
			return "", fmt.Errorf("%w: path contains traversal component", ErrWorkspaceBoundary)
		}
	}
	root := filepath.Clean(workspace.Root)
	candidate := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: path escapes workspace", ErrWorkspaceBoundary)
	}
	if sensitivePath(cleaned) {
		return "", fmt.Errorf("%w: %s", ErrSensitivePath, cleaned)
	}
	if err := validateExistingComponents(root, cleaned, allowMissing, allowDirectory); err != nil {
		return "", err
	}
	return candidate, nil
}

func validateExistingComponents(root, relative string, allowMissing, allowDirectory bool) error {
	current := root
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) && allowMissing {
				// Every existing parent has already been checked. Remaining
				// components are checked by the caller before creation.
				return nil
			}
			return fmt.Errorf("%w: path component %s: %v", ErrWorkspaceBoundary, component, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink component %s", ErrSymlinkEscape, component)
		}
		if info.IsDir() {
			if index == len(components)-1 && !allowDirectory {
				return fmt.Errorf("%w: path is a directory", ErrWorkspaceBoundary)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: special file %s", ErrWorkspaceBoundary, component)
		}
		if fileLinkCount(info) > 1 {
			return fmt.Errorf("%w: hard link component %s", ErrSymlinkEscape, component)
		}
		if index != len(components)-1 {
			return fmt.Errorf("%w: non-directory component %s", ErrWorkspaceBoundary, component)
		}
	}
	return nil
}

func secureScopedPath(workspace Workspace, requested string, scope toolsScope, allowMissing bool, allowDirectory bool) (string, error) {
	// This adapter keeps path policy in one place while avoiding an import cycle
	// for the tiny scope enum used by the built-in executor.
	if scope == scopeDraft {
		base := workspace.DraftRoot
		if base == "" {
			return "", fmt.Errorf("%w: a draft root must be authorized for R2 edits", ErrWorkspaceBoundary)
		}
		if filepath.IsAbs(base) {
			basePath := filepath.Clean(base)
			rootPath := filepath.Clean(workspace.Root)
			rel, err := filepath.Rel(rootPath, basePath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("%w: draft root is outside workspace", ErrWorkspaceBoundary)
			}
			base = filepath.ToSlash(rel)
		}
		if strings.TrimSpace(requested) == "" {
			requested = "."
		}
		requested = filepath.ToSlash(filepath.Join(filepath.FromSlash(base), filepath.FromSlash(requested)))
	}
	return securePath(workspace, requested, allowMissing, allowDirectory)
}

type toolsScope string

const (
	scopeWorkspace toolsScope = "workspace"
	scopeDraft     toolsScope = "draft"
)

func isCorePath(workspace Workspace, absolutePath string) bool {
	workspace = workspace.normalized()
	relative, err := filepath.Rel(filepath.Clean(workspace.Root), filepath.Clean(absolutePath))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	first := strings.Split(filepath.ToSlash(relative), "/")[0]
	for _, prefix := range workspace.CorePrefixes {
		prefix = strings.Trim(strings.TrimSpace(prefix), "/")
		if first == prefix {
			return true
		}
	}
	return false
}

func sensitivePath(relative string) bool {
	cleaned := strings.ToLower(filepath.ToSlash(relative))
	base := filepath.Base(cleaned)
	if base == ".env" || strings.HasPrefix(base, ".env.") || base == "credentials" || base == "credentials.json" || base == "secrets" || base == "secret.json" || base == "id_rsa" || base == "id_ed25519" {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".token"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	for _, component := range strings.Split(cleaned, "/") {
		if component == "secrets" || component == "credentials" {
			return true
		}
	}
	return false
}
