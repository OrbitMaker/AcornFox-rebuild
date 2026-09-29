//go:build linux

package hostmetrics

import (
	"io"
	"os"
	"syscall"
)

type linuxReader struct{}

func defaultReader() Reader { return linuxReader{} }

func (linuxReader) ReadFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func (linuxReader) Statfs(path string) (Filesystem, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return Filesystem{}, err
	}
	return Filesystem{Blocks: stat.Blocks, AvailableBlocks: stat.Bavail, BlockSize: uint64(stat.Bsize)}, nil
}
