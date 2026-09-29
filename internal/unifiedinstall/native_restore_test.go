package unifiedinstall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
	"github.com/open-card/open-card/internal/persistence/sqlite"
)

func TestNativeRestorePhaseIsDurableAndNoReplace(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	id := "backup-" + strings.Repeat("a", 32)
	attempt := strings.Repeat("b", 32)
	plan := NativeRestorePlan{BackupID: id, InstallationID: "fixture-installation", ReleaseID: "fixture-release", ManifestSHA256: strings.Repeat("c", 64), AttemptID: attempt, Request: sqlite.NativeOfflineRestoreRequest{BackupSHA256: strings.Repeat("d", 64), LaunchHighWater: 5}}
	write := func(phase string, p *sqlite.NativeOfflineRestorePrepared) error {
		return persistNativeRestorePhaseAt(context.Background(), plan, phase, p, nil, root, os.Getuid(), os.Getgid())
	}
	if err := write("intent", nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, nativeRestoreJournalDirectory, id+"-"+attempt+"-intent.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("intent not durable/private", err)
	}
	if err := write("intent", nil); err == nil {
		t.Fatal("duplicate restore intent replaced a journal file")
	}
	prepared := &sqlite.NativeOfflineRestorePrepared{QuarantineDirectory: filepath.Join(install.UnifiedBackupDir, "quarantine-"+attempt), CurrentGeneration: 3, SeedGeneration: 5, SourceDBInode: 42, BackupSHA256: plan.Request.BackupSHA256}
	if err := write("quarantined", prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, nativeRestoreJournalDirectory, id+"-"+attempt+"-quarantined.json")); err != nil {
		t.Fatal(err)
	}
}
