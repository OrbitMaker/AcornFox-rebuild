// Package desktopbridge implements the deliberately small host-to-guest
// forwarding contract for the managed macOS guest.
package desktopbridge

import "fmt"

const (
	GuestSSHPort    uint32 = 22022
	GuestHTTPPort   uint32 = 18080
	GuestHealthPort uint32 = 28481
)

type Target struct {
	Host string
	Port uint16
}

// TargetForPort is intentionally the only destination selector. Callers never
// provide an address, command, or arbitrary guest port.
func TargetForPort(port uint32) (Target, error) {
	switch port {
	case GuestSSHPort:
		return Target{Host: "127.0.0.1", Port: 22}, nil
	case GuestHTTPPort:
		return Target{Host: "127.0.0.1", Port: 8080}, nil
	case GuestHealthPort:
		return Target{Host: "127.0.0.1", Port: 18481}, nil
	default:
		return Target{}, fmt.Errorf("acornfox guest bridge: unsupported virtio port %d", port)
	}
}
