//go:build linux

package healthcheck

import (
	"context"
	"io"
	"os"
	"syscall"
)

// NewLinuxListenerSource returns the production listener fact adapter. The
// three proc paths are fixed here, not accepted from callers, and each read is
// a no-follow, bounded regular-file read.
func NewLinuxListenerSource() ListenerSource { return linuxListenerSource{} }

type linuxListenerSource struct{}

func (linuxListenerSource) Capture(ctx context.Context) (ListenerFacts, error) {
	if ctx == nil || ctx.Err() != nil {
		return ListenerFacts{}, errLocalProbeFailed
	}
	tcp, err := readFixedProcListenerFact(ctx, "/proc/net/tcp")
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	tcp6, err := readFixedProcListenerFact(ctx, "/proc/net/tcp6")
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	unix, err := readFixedProcListenerFact(ctx, "/proc/net/unix")
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	if ctx.Err() != nil {
		return ListenerFacts{}, errLocalProbeFailed
	}
	return parseLinuxListenerFacts(tcp, tcp6, unix)
}

func readFixedProcListenerFact(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || path != "/proc/net/tcp" && path != "/proc/net/tcp6" && path != "/proc/net/unix" {
		return nil, errLocalProbeFailed
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errListenerFacts
	}
	file := os.NewFile(uintptr(fd), "")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errListenerFacts
	}
	data, err := io.ReadAll(io.LimitReader(file, maxListenerFactBytes+1))
	if err != nil || len(data) > maxListenerFactBytes || ctx.Err() != nil {
		return nil, errListenerFacts
	}
	return data, nil
}
