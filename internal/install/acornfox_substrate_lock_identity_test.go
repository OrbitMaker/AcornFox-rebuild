package install

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSubstrateLockRejectsNonemptyAndSharedFiles(t *testing.T) {
	for _, kind := range []string{"nonempty", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, acornFoxSubstrateLock)
			var body []byte
			if kind == "nonempty" {
				body = []byte("foreign contents")
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "hardlink" {
				if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			if _, err := publisher.Inspect(strings.Repeat("a", 64)); err == nil {
				t.Fatal("unsafe lock accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("rejected lock removed")
			}
		})
	}
}

func TestSubstrateLockRechecksPathAfterAcquisition(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, acornFoxSubstrateLock)
	publisher, err := NewTaskAcornFoxSubstratePublisher(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	base := publisher.fs.flock
	publisher.fs.flock = func(file acornFoxSubstrateFile, operation int) error {
		if err := base(file, operation); err != nil {
			return err
		}
		if operation == syscall.LOCK_EX {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.WriteFile(path, nil, 0600)
		}
		return nil
	}
	if _, err := publisher.Inspect(strings.Repeat("a", 64)); err == nil {
		t.Fatal("post-acquisition replacement accepted")
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatal("replacement lock was changed")
	}
}
