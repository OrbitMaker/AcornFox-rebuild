//go:build !linux

package buildnetwork

import (
	"net"

	"github.com/open-card/open-card/internal/localpeer"
)

func peerIdentity(conn net.Conn) (uint32, int32, error) {
	_, err := localpeer.PeerIdentity(conn)
	return 0, 0, err
}
