package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	testPreOpenPayloadRootHook func(string) error
	testPrePinParentHook       func(string) error
)

var hostComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,100}$`)

func validHostMember(p string) bool {
	if len(p) > 240 || path.Clean(p) != p || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !hostComponent.MatchString(part) || strings.HasSuffix(part, ".") {
			return false
		}
		lower := strings.ToLower(part)
		stem := strings.Split(lower, ".")[0]
		if lower == "userdata" || lower == "user-data" || lower == "uploads" || lower == "workspaces" || lower == "secrets" || lower == "oci" || lower == "distro" || lower == "vm" {
			return false
		}
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || regexp.MustCompile(`^(com|lpt)[1-9]$`).MatchString(stem) {
			return false
		}
		if strings.Contains(lower, "rootfs") || strings.Contains(lower, "guest.raw") || strings.Contains(lower, "base.raw") || strings.Contains(lower, "seed") || strings.Contains(lower, "ssh") || lower == "efi" || strings.HasSuffix(lower, ".vhdx") || strings.HasSuffix(lower, ".qcow2") || strings.HasSuffix(lower, ".img") || strings.HasSuffix(lower, ".iso") || strings.HasSuffix(lower, ".key") {
			return false
		}
	}
	return strings.HasPrefix(p, "launcher/") || strings.HasPrefix(p, "controller/") || strings.HasPrefix(p, "backend/candidate/")
}

// within returns true if candidate is within root directory or equals root.
func within(root, candidate string) bool {
	r, err1 := filepath.Abs(root)
	c, err2 := filepath.Abs(candidate)
	if err1 != nil || err2 != nil {
		return true // fail safe: assume within
	}
	r = filepath.Clean(r)
	c = filepath.Clean(c)
	if r == c {
		return true
	}
	rel, err := filepath.Rel(r, c)
	if err != nil {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func checkRegularPrivateFile(filePath string, outsideDirs []string) (*os.File, error) {
	if filePath == "" {
		return nil, errors.New("key file path is empty")
	}
	cleanPath := filepath.Clean(filePath)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve key file path: %w", err)
	}

	for _, outDir := range outsideDirs {
		if outDir != "" && within(outDir, absPath) {
			return nil, fmt.Errorf("key file %q must be outside directory %q", filePath, outDir)
		}
	}

	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key file %q must not be a symlink", filePath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %q must be a regular file", filePath)
	}
	if info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("key file %q must have permissions 0600 (got %04o)", filePath, info.Mode().Perm())
	}
	if info.Size() > 64<<10 {
		return nil, fmt.Errorf("key file %q exceeds maximum allowed size (64KB)", filePath)
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Getuid() {
			return nil, fmt.Errorf("key file %q must be owned by current user (uid %d, got %d)", filePath, os.Getuid(), stat.Uid)
		}
		if stat.Nlink > 1 {
			return nil, fmt.Errorf("key file %q must not have multiple hardlinks", filePath)
		}
	}

	file, err := os.OpenFile(absPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open key file: %w", err)
	}

	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, errors.New("key file changed during open")
	}

	return file, nil
}

type tempArtifactHolder struct {
	parentRoot *os.Root
	path       string // absolute path for VerifyHostBundle
	tempName   string
	finalName  string
	file       *os.File
	armed      bool
}

func pinOutputParent(destination string) (*os.Root, string, string, error) {
	cleanDest := filepath.Clean(destination)
	absDest, err := filepath.Abs(cleanDest)
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot resolve destination path: %w", err)
	}
	destDir := filepath.Dir(absDest)
	finalName := filepath.Base(absDest)

	if finalName == "." || finalName == "/" || finalName == ".." {
		return nil, "", "", errors.New("invalid output file name")
	}

	// Canonicalize parent directory to resolve standard system symlinks (e.g. /var -> /private/var on macOS)
	canonicalDir, err := filepath.EvalSymlinks(destDir)
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot resolve destination parent directory: %w", err)
	}
	canonicalDir = filepath.Clean(canonicalDir)

	if hook := testPrePinParentHook; hook != nil {
		if err := hook(canonicalDir); err != nil {
			return nil, "", "", err
		}
	}

	trimmed := strings.TrimPrefix(canonicalDir, "/")
	var parts []string
	if trimmed != "" {
		parts = strings.Split(trimmed, "/")
	}

	currentRoot, err := os.OpenRoot("/")
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot open root filesystem: %w", err)
	}

	for _, part := range parts {
		lstatInfo, err := currentRoot.Lstat(part)
		if err != nil {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("cannot lstat component %s in output directory chain: %w", part, err)
		}
		if lstatInfo.Mode()&os.ModeSymlink != 0 {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("symlink not allowed in output path chain: %s", part)
		}
		if !lstatInfo.IsDir() {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("path component %s is not a directory", part)
		}

		// Security check on each ancestor directory
		st, ok := lstatInfo.Sys().(*syscall.Stat_t)
		if !ok {
			currentRoot.Close()
			return nil, "", "", errors.New("cannot inspect filesystem stats")
		}
		isCurrentOwner := int(st.Uid) == os.Getuid()
		isRootSticky := st.Uid == 0 && (lstatInfo.Mode()&os.ModeSticky != 0)
		isRootReadOnly := st.Uid == 0 && (lstatInfo.Mode().Perm()&0022 == 0)
		if !isCurrentOwner && !isRootSticky && !isRootReadOnly {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("insecure directory %q in output path: owned by uid %d without root sticky/read-only", part, st.Uid)
		}
		if isCurrentOwner && (lstatInfo.Mode().Perm()&0022 != 0) {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("insecure directory %q in output path: writable by group or others (%04o)", part, lstatInfo.Mode().Perm())
		}

		nextRoot, err := currentRoot.OpenRoot(part)
		if err != nil {
			currentRoot.Close()
			return nil, "", "", fmt.Errorf("cannot open root for %s: %w", part, err)
		}
		subStat, err := nextRoot.Stat(".")
		if err != nil || !os.SameFile(lstatInfo, subStat) {
			currentRoot.Close()
			nextRoot.Close()
			return nil, "", "", fmt.Errorf("directory %s was replaced during chain verification", part)
		}
		currentRoot.Close()
		currentRoot = nextRoot
	}

	return currentRoot, canonicalDir, finalName, nil
}

func newTempArtifact(destination string) (*tempArtifactHolder, error) {
	parentRoot, canonicalDir, finalName, err := pinOutputParent(destination)
	if err != nil {
		return nil, err
	}

	// Verify destination does not exist via pinned parentRoot
	if _, err := parentRoot.Lstat(finalName); !errors.Is(err, os.ErrNotExist) {
		parentRoot.Close()
		return nil, fmt.Errorf("destination already exists (no-clobber): %s", destination)
	}

	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		parentRoot.Close()
		return nil, err
	}
	tempName := fmt.Sprintf(".%s.tmp.%s", finalName, hex.EncodeToString(randBytes[:]))

	f, err := parentRoot.OpenFile(tempName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		parentRoot.Close()
		return nil, fmt.Errorf("failed to create temporary artifact file via pinned parent: %w", err)
	}

	return &tempArtifactHolder{
		parentRoot: parentRoot,
		path:       filepath.Join(canonicalDir, tempName),
		tempName:   tempName,
		finalName:  finalName,
		file:       f,
		armed:      true,
	}, nil
}

func (h *tempArtifactHolder) Close() error {
	if h.file != nil {
		err := h.file.Close()
		h.file = nil
		return err
	}
	return nil
}

func (h *tempArtifactHolder) Cleanup() {
	if !h.armed {
		if h.parentRoot != nil {
			_ = h.parentRoot.Close()
			h.parentRoot = nil
		}
		return
	}
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
	if h.parentRoot != nil {
		_ = h.parentRoot.Remove(h.tempName)
		_ = h.parentRoot.Close()
		h.parentRoot = nil
	}
	h.armed = false
}

func (h *tempArtifactHolder) Finalize(destination string, perm os.FileMode) error {
	if !h.armed {
		return errors.New("temporary artifact already finalized or cleaned up")
	}
	defer func() {
		if h.parentRoot != nil {
			h.parentRoot.Close()
			h.parentRoot = nil
		}
	}()

	if h.file != nil {
		if err := h.file.Sync(); err != nil {
			return err
		}
		if err := h.file.Close(); err != nil {
			return err
		}
		h.file = nil
	}

	// Double-check destination does not exist via pinned parentRoot before linking
	if _, err := h.parentRoot.Lstat(h.finalName); !errors.Is(err, os.ErrNotExist) {
		_ = h.parentRoot.Remove(h.tempName)
		h.armed = false
		return fmt.Errorf("destination already exists before finalization (no-clobber): %s", destination)
	}

	// Set permissions relative to pinned parentRoot
	if err := h.parentRoot.Chmod(h.tempName, perm); err != nil {
		_ = h.parentRoot.Remove(h.tempName)
		h.armed = false
		return fmt.Errorf("failed to set artifact permissions: %w", err)
	}

	// Descriptor-relative Link for atomic no-clobber creation
	if err := h.parentRoot.Link(h.tempName, h.finalName); err != nil {
		_ = h.parentRoot.Remove(h.tempName)
		h.armed = false
		return fmt.Errorf("atomic no-clobber link failed: %w", err)
	}

	// Verify hard link count is 2 on the linked inode before removing temp
	linkStat, err := h.parentRoot.Lstat(h.finalName)
	if err != nil {
		_ = h.parentRoot.Remove(h.tempName)
		h.armed = false
		return fmt.Errorf("cannot stat created artifact via parent root: %w", err)
	}
	st, ok := linkStat.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 2 {
		_ = h.parentRoot.Remove(h.tempName)
		h.armed = false
		return errors.New("unexpected link count on created artifact")
	}

	// Remove owned temporary link
	if err := h.parentRoot.Remove(h.tempName); err != nil {
		h.armed = false
		return fmt.Errorf("failed to remove temporary link: %w", err)
	}

	// Verify final link count is 1
	finalStat, err := h.parentRoot.Lstat(h.finalName)
	if err != nil {
		h.armed = false
		return fmt.Errorf("cannot verify final artifact link: %w", err)
	}
	stFinal, ok := finalStat.Sys().(*syscall.Stat_t)
	if !ok || stFinal.Nlink != 1 {
		h.armed = false
		return errors.New("final artifact link count is not 1")
	}

	h.armed = false
	return nil
}

func atomicWriteFileNoClobber(destination string, data []byte, perm os.FileMode) error {
	holder, err := newTempArtifact(destination)
	if err != nil {
		return err
	}
	defer holder.Cleanup()

	if _, err := holder.file.Write(data); err != nil {
		return fmt.Errorf("write temporary file failed: %w", err)
	}

	return holder.Finalize(destination, perm)
}
