package install

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestAcornFoxLiveDirectoriesPrivateUmask(t *testing.T) {
	const child = "ACORNFOX_TEST_LIVE_PRIVATE_UMASK"
	if os.Getenv(child) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAcornFoxLiveDirectoriesPrivateUmask$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("private umask subprocess: %v\n%s", err, out)
		}
		return
	}
	// Umask is process-global; isolate it from parallel package tests.
	syscall.Umask(0077)
	path := t.TempDir()
	store, err := NewTaskAcornFoxRepoStore(path, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, mode := range map[string]os.FileMode{"public": 0755, "group": 0750, "private": 0700} {
		t.Run(name, func(t *testing.T) {
			effects := 0
			if err := acornFoxLiveEnsureDir(root, store, name, mode, func() { effects++ }); err != nil {
				t.Fatal(err)
			}
			info, err := root.Lstat(name)
			if err != nil || info.Mode().Perm() != mode || effects != 1 || verifyOwner(info, os.Getuid(), os.Getgid()) != nil {
				t.Fatalf("new directory mode/owner/effects: info=%v err=%v effects=%d", info, err, effects)
			}
			if err := acornFoxLiveEnsureDir(root, store, name, mode, func() { effects++ }); err != nil || effects != 1 {
				t.Fatalf("exact replay: %v effects=%d", err, effects)
			}
		})
	}
	for _, race := range []bool{false, true} {
		name := "existing"
		if race {
			name = "mkdir-race"
		} else if err := root.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
		previous := acornFoxLiveFaultStep
		if race {
			acornFoxLiveFaultStep = func(step string) error {
				if step == "mkdir" {
					return root.Mkdir(name, 0700)
				}
				return nil
			}
		}
		effects := 0
		err := acornFoxLiveEnsureDir(root, store, name, 0755, func() { effects++ })
		acornFoxLiveFaultStep = previous
		info, statErr := root.Lstat(name)
		if !errors.Is(err, ErrAcornFoxLiveConflict) || statErr != nil || info.Mode().Perm() != 0700 || effects != 0 {
			t.Fatalf("existing directory adopted: race=%t err=%v stat=%v effects=%d", race, err, statErr, effects)
		}
	}
	t.Run("interrupted-prefix-stays-strict", func(t *testing.T) {
		previous := acornFoxLiveFaultStep
		acornFoxLiveFaultStep = func(step string) error {
			if step == "mkdir-post" {
				return errors.New("interrupted after mkdir")
			}
			return nil
		}
		effects := 0
		err := acornFoxLiveEnsureDir(root, store, "interrupted", 0755, func() { effects++ })
		acornFoxLiveFaultStep = previous
		if err == nil || effects != 1 {
			t.Fatalf("interruption err=%v effects=%d", err, effects)
		}
		before, err := root.Lstat("interrupted")
		if err != nil || before.Mode().Perm() != 0700 {
			t.Fatalf("interrupted prefix: %v %v", before, err)
		}
		err = acornFoxLiveEnsureDir(root, store, "interrupted", 0755, func() { effects++ })
		after, statErr := root.Lstat("interrupted")
		if !errors.Is(err, ErrAcornFoxLiveConflict) || statErr != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0700 || effects != 1 {
			t.Fatalf("interrupted prefix adopted: err=%v stat=%v effects=%d", err, statErr, effects)
		}
	})
	t.Run("prepared-substrate", TestAcornFoxLiveMaterializePreparedSubstrateExactly)
}
