//go:build linux

package buildnetwork

import (
	"errors"
	"net"
	"syscall"
)

func peerIdentity(connection net.Conn) (uint32, int32, error) {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a Unix connection")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credentials *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		credentials, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, 0, err
	}
	if inner != nil {
		return 0, 0, inner
	}
	return credentials.Uid, credentials.Pid, nil
}
