//go:build darwin || linux

package dockerfile

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

func readRootDockerfileNoFollow(path string) ([]byte, bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, errors.New("unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode()&fs.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maxRootDockerfileBytes {
		return nil, false, errors.New("unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxRootDockerfileBytes+1))
	if err != nil || int64(len(raw)) != before.Size() || int64(len(raw)) > maxRootDockerfileBytes {
		return nil, false, errors.New("unsafe")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, false, errors.New("unsafe")
	}
	return raw, false, nil
}
