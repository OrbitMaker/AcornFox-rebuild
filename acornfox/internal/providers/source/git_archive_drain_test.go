//go:build darwin || linux

package source

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/foundation"
)

func paddedGitArchiveFixture(t *testing.T, tail []byte) (*Provider, string, string) {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	body := []byte("FROM scratch\n")
	if err := writer.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive.Write(tail)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "archive.fixture"), archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "git-archive-fixture")
	// The real child writes more bytes than a normal pipe holds. Its arguments
	// retain the production git argv shape; shell input contains no fixture path.
	script := []byte("#!/bin/sh\nprintf '%s' \"$$\" > \"$2/archive.pid\"\nexec /bin/cat \"$2/archive.fixture\"\n")
	if err := os.WriteFile(wrapper, script, 0700); err != nil {
		t.Fatal(err)
	}
	return &Provider{gitBinary: wrapper, limits: foundation.DefaultArchiveLimits}, dir, t.TempDir()
}

func TestExtractGitArchiveDrainsZeroPaddingBeforeWaiting(t *testing.T) {
	// Tar's logical EOF is followed by valid zero record padding. The long
	// padding makes the pipe deadlock deterministic without a platform-specific
	// pipe resizing dependency; this is not evidence about remote Git latency.
	p, dir, stage := paddedGitArchiveFixture(t, make([]byte, 512<<10))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if err := p.extractGitArchive(ctx, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stage); err != nil {
		t.Fatalf("valid padded archive failed after %s: %v", time.Since(started), err)
	}
	t.Logf("valid zero-padding producer exited in %s", time.Since(started))
	assertArchiveProcessStopped(t, dir, "archive.pid")
	body, err := os.ReadFile(filepath.Join(stage, "Dockerfile"))
	if err != nil || string(body) != "FROM scratch\n" {
		t.Fatalf("extracted source=%q err=%v", body, err)
	}
}

func assertArchiveProcessStopped(t *testing.T, dir, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil || pid <= 1 {
		t.Fatal("invalid fixture PID")
	}
	deadline := time.Now().Add(time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("archive fixture process survived: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExtractGitArchiveRejectsNonPaddingAndBoundedOverflow(t *testing.T) {
	var second bytes.Buffer
	writer := tar.NewWriter(&second)
	if err := writer.WriteHeader(&tar.Header{Name: "second-archive.txt", Mode: 0644, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		tail []byte
		want error
	}{
		{"no padding", nil, nil},
		{"padding limit", make([]byte, 1<<20), nil},
		{"padding overflow", make([]byte, (1<<20)+1), errGitTooLarge},
		{"nonzero trailing data", []byte("unexpected"), errUploadRejected},
		{"nonzero after long padding", append(make([]byte, 512<<10), 1), errUploadRejected},
		{"second archive", second.Bytes(), errUploadRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, dir, stage := paddedGitArchiveFixture(t, tc.tail)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := p.extractGitArchive(ctx, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stage)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			assertArchiveProcessStopped(t, dir, "archive.pid")
			if _, err := os.Stat(filepath.Join(stage, "second-archive.txt")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a second archive was extracted")
			}
		})
	}
}

func TestExtractGitArchiveStopsAnUnboundedZeroProducer(t *testing.T) {
	p, dir, stage := paddedGitArchiveFixture(t, nil)
	script := []byte("#!/bin/sh\nprintf '%s' \"$$\" > \"$2/archive.pid\"\n/bin/cat \"$2/archive.fixture\"\nexec /bin/cat /dev/zero\n")
	if err := os.WriteFile(p.gitBinary, script, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.extractGitArchive(ctx, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stage); !errors.Is(err, errGitTooLarge) {
		t.Fatalf("unbounded producer not rejected by byte limit: %v", err)
	}
	assertArchiveProcessStopped(t, dir, "archive.pid")
}

func TestExtractGitArchiveCancellationKillsInheritedPipeWriters(t *testing.T) {
	p, dir, stage := paddedGitArchiveFixture(t, nil)
	script := []byte("#!/bin/sh\nprintf '%s' \"$$\" > \"$2/archive.pid\"\n/bin/sleep 60 &\nprintf '%s' \"$!\" > \"$2/descendant.pid\"\n/bin/cat \"$2/archive.fixture\"\nwait\n")
	if err := os.WriteFile(p.gitBinary, script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if raw, e := os.ReadFile(filepath.Join(dir, "archive.pid")); e == nil {
			if pid, e := strconv.Atoi(string(raw)); e == nil && pid > 1 {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.extractGitArchive(ctx, dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stage) }()
	readyBy := time.Now().Add(3 * time.Second)
	for {
		body, fileErr := os.ReadFile(filepath.Join(stage, "Dockerfile"))
		_, childErr := os.Stat(filepath.Join(dir, "descendant.pid"))
		if fileErr == nil && string(body) == "FROM scratch\n" && childErr == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("producer exited before cancellation fixture was ready: %v", err)
		default:
		}
		if time.Now().After(readyBy) {
			cancel()
			<-done
			t.Fatal("archive cancellation fixture did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost parent cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled archive kept an inherited stdout writer")
	}

	assertArchiveProcessStopped(t, dir, "archive.pid")
	assertArchiveProcessStopped(t, dir, "descendant.pid")
}
