//go:build !linux

package healthcheck

import "errors"

// NewProductionListenerSource fails closed on platforms where the fixed Linux
// proc listener contract cannot be observed.
func NewProductionListenerSource() (ListenerSource, error) {
	return nil, errors.New("production listener source is unsupported")
}
