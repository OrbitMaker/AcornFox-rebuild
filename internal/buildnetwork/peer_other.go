//go:build !linux

package buildnetwork

import (
	"errors"
	"net"
)

func peerIdentity(net.Conn) (uint32, int32, error) {
	return 0, 0, errors.New("installed build attestation requires Linux")
}
