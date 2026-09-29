//go:build darwin

package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func readInteractivePassword(reader io.Reader) (string, error) {
	file, ok := reader.(*os.File)
	if !ok {
		return readLines(reader, 1)
	} // injected tests never need a TTY.
	var old syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCGETA), uintptr(unsafe.Pointer(&old))); errno != 0 {
		return "", errors.New("interactive password input requires a terminal")
	}
	next := old
	next.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCSETA), uintptr(unsafe.Pointer(&next))); errno != 0 {
		return "", errors.New("interactive password input is unavailable")
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCSETA), uintptr(unsafe.Pointer(&old)))
	value, err := readInteractiveLine(bufio.NewReader(file))
	_, _ = file.Write([]byte("\n"))
	return value, err
}
