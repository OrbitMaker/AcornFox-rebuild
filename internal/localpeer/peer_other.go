//go:build !linux

package localpeer

import "net"

func peerIdentity(net.Conn) (Identity, error) {
	return Identity{}, ErrUnsupportedPlatform
}
