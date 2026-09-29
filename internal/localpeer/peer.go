package localpeer

import (
	"errors"
	"net"
)

var ErrUnsupportedPlatform = errors.New("local peer attestation unsupported on this platform")

// Identity represents the kernel-attested credentials of a Unix domain socket peer.
type Identity struct {
	UID uint32
	PID int32
	GID uint32
}

// PeerIdentity extracts kernel-attested peer credentials from a local Unix connection.
func PeerIdentity(conn net.Conn) (Identity, error) {
	return peerIdentity(conn)
}
