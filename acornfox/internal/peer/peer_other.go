//go:build !linux

package peer

import "net"

func peerIdentity(net.Conn) (Identity, error) { return Identity{}, ErrUnsupportedPlatform }
