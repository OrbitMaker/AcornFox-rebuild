package acornfoxrelease

import (
	"errors"
	"os"
	"sync"
	"syscall"
)

// Holding the descriptor prevents inode reuse from turning a replacement
// directory into an apparent identity match. A pin never owns deletion.
type directoryPin struct {
	path string
	file *os.File
	once sync.Once
}

func pinDirectory(path string) (*directoryPin, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	pin := &directoryPin{path: path, file: file}
	if !pin.valid() {
		pin.close()
		return nil, errors.New("directory identity is unavailable")
	}
	return pin, nil
}

func (pin *directoryPin) valid() bool {
	if pin == nil || pin.file == nil {
		return false
	}
	info, err := pin.file.Stat()
	return err == nil && info.IsDir() && samePinnedDirectory(pin.path, info)
}

func (pin *directoryPin) validAt(path string) bool {
	return pin != nil && pin.path == path && pin.valid()
}

func (pin *directoryPin) close() {
	if pin != nil {
		pin.once.Do(func() {
			if pin.file != nil {
				_ = pin.file.Close()
			}
		})
	}
}
