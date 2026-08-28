//go:build darwin || linux

package source

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/foundation"
)

func TestPinnedFetchKillsRemoteHelperProcessGroupOnObjectLimit(t *testing.T) {
	root, workspace := t.TempDir(), t.TempDir()
	provider, err := New(Config{UploadRoot: root, WorkspaceRoot: workspace, Limits: foundation.ArchiveLimits{MaxFiles: 8, MaxUnpackedBytes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	gitDir := t.TempDir()
	pidPath := filepath.Join(t.TempDir(), "helper.pid")
	script := filepath.Join(t.TempDir(), "git-wrapper")
	contents := "#!/bin/sh\ndir=\"\"\nif [ \"$1\" = \"-C\" ]; then dir=\"$2\"; fi\nsleep 60 &\nprintf '%s' \"$!\" > " + strconv.Quote(pidPath) + "\nprintf 'xx' > \"$dir/oversized\"\nwait\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	provider.gitBinary = script
	err = provider.gitPinnedFetch(context.Background(), gitDir, gitAuthority{host: "git.public.org", port: 443, addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, "fetch")
	if !errors.Is(err, errGitTooLarge) {
		t.Fatalf("bounded fetch error=%v", err)
	}
	payload, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(payload))
	if err != nil || pid <= 0 {
		t.Fatalf("helper pid=%q err=%v", payload, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Git helper pid %d survived bounded fetch termination: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	entries, err := os.ReadDir(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "oversized" {
		t.Fatalf("unexpected retained fetch files: %#v", entries)
	}
	before, err := os.Stat(filepath.Join(gitDir, "oversized"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	after, err := os.Stat(filepath.Join(gitDir, "oversized"))
	if err != nil || after.Size() != before.Size() {
		t.Fatalf("terminated helper continued writing: before=%v after=%v err=%v", before.Size(), after, err)
	}
}
