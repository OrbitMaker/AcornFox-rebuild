//go:build linux && amd64

package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// This is an actual kernel no-replace assertion, including an already-existing
// empty target directory (which ordinary rename is allowed to replace).
func TestAcornFoxRuntimeLinuxNoReplace(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(map[bool]string{false: "publish", true: "foreign-empty-target"}[occupied], func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Mkdir(filepath.Join(parent, "pending"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(parent, "pending", "key"), []byte("task fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if occupied {
				if err := os.Mkdir(filepath.Join(parent, "runtime"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := os.Open(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			err = acornFoxRuntimeRenameNoReplace(fd, "pending", "runtime")
			if occupied {
				if !errors.Is(err, os.ErrExist) {
					t.Fatalf("target was not preserved: %v", err)
				}
				children, e := os.ReadDir(filepath.Join(parent, "runtime"))
				if e != nil || len(children) != 0 {
					t.Fatal("foreign target changed")
				}
				if _, e := os.Stat(filepath.Join(parent, "pending", "key")); e != nil {
					t.Fatal("source disappeared")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, e := os.Stat(filepath.Join(parent, "runtime", "key")); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
