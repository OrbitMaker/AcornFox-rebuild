//go:build linux

package peer

import (
	"errors"
	"net"
	"syscall"
)

func peerIdentity(connection net.Conn) (Identity, error) {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return Identity{}, errors.New("not a Unix connection")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return Identity{}, err
	}
	var credentials *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		credentials, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return Identity{}, err
	}
	if inner != nil {
		return Identity{}, inner
	}
	return Identity{
		UID: credentials.Uid,
		PID: credentials.Pid,
		GID: credentials.Gid,
	}, nil
}
