package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AtomicWriteFile writes a file in the destination directory and renames it
// into place. It does not follow a destination symlink.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if path == "" || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return errors.New("invalid atomic file path")
	}
	parent := filepath.Dir(path)
	if err := ensureNoSymlinkComponents(parent); err != nil {
		return fmt.Errorf("atomic file parent: %w", err)
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", parent, err)
	}
	tmp, err := os.CreateTemp(parent, ".open-card-atomic-*")
	if err != nil {
		return fmt.Errorf("create atomic temporary file: %w", err)
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("atomic destination must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect atomic destination: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("activate atomic file: %w", err)
	}
	return nil
}

func ensureNoSymlinkComponents(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			// macOS exposes /var (and sometimes /tmp) as a stable system
			// symlink to /private/*; accepting only these fixed OS aliases keeps
			// temp-file tests portable without allowing an arbitrary escape.
			if resolveErr == nil && ((current == "/var" && resolved == "/private/var") || (current == "/tmp" && resolved == "/private/tmp")) {
				continue
			}
			return fmt.Errorf("symlink path component %q is not allowed", current)
		}
	}
	return nil
}
