package imageexecution

import (
	"github.com/acornfox/acornfox/internal/localpeer"
)

// RuntimePeerBinding is aliased from localpeer to prevent duplicate types across packages.
type RuntimePeerBinding = localpeer.RuntimePeerBinding

// ParseRuntimePeerBinding delegates to localpeer.ParseRuntimePeerBinding.
func ParseRuntimePeerBinding(raw []byte) (*RuntimePeerBinding, error) {
	return localpeer.ParseRuntimePeerBinding(raw)
}

// LoadProtectedRuntimePeerBinding delegates to localpeer.LoadProtectedRuntimePeerBinding.
func LoadProtectedRuntimePeerBinding(path string) (*RuntimePeerBinding, error) {
	return localpeer.LoadProtectedRuntimePeerBinding(path)
}
