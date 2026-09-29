//go:build !linux

package buildnetwork

import (
	"net"

	"github.com/acornfox/acornfox/internal/peer"
)

func peerIdentity(conn net.Conn) (uint32, int32, error) {
	_, err := peer.Of(conn)
	return 0, 0, err
}
