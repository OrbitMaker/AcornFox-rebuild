//go:build linux && (amd64 || arm64)

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
	cases := []struct {
		name       string
		setup      func(t *testing.T, parent string)
		expectFail bool
	}{
		{
			name:       "publish",
			setup:      nil,
			expectFail: false,
		},
		{
			name: "foreign-empty-target",
			setup: func(t *testing.T, parent string) {
				if err := os.Mkdir(filepath.Join(parent, "runtime"), 0755); err != nil {
					t.Fatal(err)
				}
			},
			expectFail: true,
		},
		{
			name: "foreign-file-target",
			setup: func(t *testing.T, parent string) {
				if err := os.WriteFile(filepath.Join(parent, "runtime"), []byte("existing target file"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			expectFail: true,
		},
		{
			name: "foreign-symlink-target",
			setup: func(t *testing.T, parent string) {
				if err := os.Symlink("/dev/null", filepath.Join(parent, "runtime")); err != nil {
					t.Fatal(err)
				}
			},
			expectFail: true,
		},
		{
			name:       "missing-source",
			setup:      nil,
			expectFail: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			if tc.name != "missing-source" {
				if err := os.Mkdir(filepath.Join(parent, "pending"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(parent, "pending", "key"), []byte("task fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(t, parent)
			}

			fd, err := os.Open(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()

			err = acornFoxRuntimeRenameNoReplace(fd, "pending", "runtime")
			if tc.expectFail {
				if err == nil {
					t.Fatalf("expected error for case %s, got nil", tc.name)
				}
				if tc.name == "foreign-empty-target" {
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
				} else if tc.name == "foreign-file-target" {
					if !errors.Is(err, os.ErrExist) {
						t.Fatalf("target was not preserved: %v", err)
					}
					data, e := os.ReadFile(filepath.Join(parent, "runtime"))
					if e != nil || string(data) != "existing target file" {
						t.Fatal("foreign file target changed")
					}
					if _, e := os.Stat(filepath.Join(parent, "pending", "key")); e != nil {
						t.Fatal("source disappeared")
					}
				} else if tc.name == "foreign-symlink-target" {
					if !errors.Is(err, os.ErrExist) {
						t.Fatalf("target was not preserved: %v", err)
					}
					target, e := os.Readlink(filepath.Join(parent, "runtime"))
					if e != nil || target != "/dev/null" {
						t.Fatal("foreign symlink target changed")
					}
					if _, e := os.Stat(filepath.Join(parent, "pending", "key")); e != nil {
						t.Fatal("source disappeared")
					}
				} else if tc.name == "missing-source" {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("expected ErrNotExist for missing source: %v", err)
					}
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
