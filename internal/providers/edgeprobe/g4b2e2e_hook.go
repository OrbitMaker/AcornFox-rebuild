//go:build g4b2e2e

package edgeprobe

// This test-only hook retains the production probe's fixed logical target and
// TLS validation. It only swaps the transport dial destination for a
// task-local TLS listener.

import (
	"context"
	"net"
	"time"
)

func NewG4B2E2EProbe(config Config, dial func(context.Context, string, string) (net.Conn, error), now func() time.Time) (Prober, error) {
	return newProbe(config, dial, now)
}
