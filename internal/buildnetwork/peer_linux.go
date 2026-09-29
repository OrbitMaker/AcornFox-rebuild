//go:build linux

package buildnetwork

import (
	"net"

	"github.com/open-card/open-card/internal/localpeer"
)

func peerIdentity(connection net.Conn) (uint32, int32, error) {
	id, err := localpeer.PeerIdentity(connection)
	if err != nil {
		return 0, 0, err
	}
	return id.UID, id.PID, nil
}
