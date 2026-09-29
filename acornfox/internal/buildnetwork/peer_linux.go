//go:build linux

package buildnetwork

import (
	"net"

	"github.com/acornfox/acornfox/internal/peer"
)

func peerIdentity(connection net.Conn) (uint32, int32, error) {
	id, err := peer.Of(connection)
	if err != nil {
		return 0, 0, err
	}
	return id.UID, id.PID, nil
}
