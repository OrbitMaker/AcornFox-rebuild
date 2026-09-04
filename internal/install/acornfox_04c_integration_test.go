package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The repository engine accepts only its task-root journal store, already
// verified substrate, and binding. It has no application mutation capability.
var _ func(context.Context, *TaskAcornFoxRepoStore, *PublishedAcornFoxSubstrateV1, string) error = prepareAcornFoxRepository

func TestAcornFox04CRepositoryPreparationLeavesExternalDataUntouched(t *testing.T) {
	for _, tc := range []struct{ name, fault string }{
		{"success", ""},
		{"activation-recovery", "journal-active"},
		{"current-recovery", "journal-current"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, store, published, receipt := acornFoxRepoBootstrapFixture(t)
			sentinel := filepath.Join(t.TempDir(), "application-data")
			if err := os.WriteFile(sentinel, []byte("retained application data"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := acornFox04CSentinel(t, sentinel)
			if tc.fault == "" {
				if err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
					t.Fatal(err)
				}
			} else {
				old := acornFoxRepoBootstrapFaultStep
				acornFoxRepoBootstrapFaultStep = func(step string) error {
					if step == tc.fault {
						return errors.New("fault")
					}
					return nil
				}
				err := prepareAcornFoxRepository(context.Background(), store, published, receipt.CandidateReceipt.BindingSHA256)
				acornFoxRepoBootstrapFaultStep = old
				if !errors.Is(err, ErrAcornFoxRepoBootstrapConflict) {
					t.Fatalf("fault=%v", err)
				}
				if err = store.Close(); err != nil {
					t.Fatal(err)
				}
				fresh, err := NewTaskAcornFoxRepoStore(root, os.Getuid(), os.Getgid())
				if err != nil {
					t.Fatal(err)
				}
				defer fresh.Close()
				if err = prepareAcornFoxRepository(context.Background(), fresh, published, receipt.CandidateReceipt.BindingSHA256); err != nil {
					t.Fatalf("recovery=%v", err)
				}
			}
			after := acornFox04CSentinel(t, sentinel)
			if before != after {
				t.Fatalf("external application sentinel changed: before=%#v after=%#v", before, after)
			}
			if _, err := os.Lstat(filepath.Join(root, acornFoxLiveDir, "opt", "acornfox", "current")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type acornFox04CSentinelSnapshot struct {
	Inode  uint64
	SHA256 string
}

func acornFox04CSentinel(t *testing.T, path string) acornFox04CSentinelSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("sentinel inode unavailable")
	}
	sum := sha256.Sum256(raw)
	return acornFox04CSentinelSnapshot{Inode: uint64(stat.Ino), SHA256: hex.EncodeToString(sum[:])}
}
