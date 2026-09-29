//go:build !linux

package buildnetwork

import (
	"context"
	"errors"
)

type Manager struct{}

func ReadInstalledPolicy() ([]byte, string, error) {
	return nil, "", errors.New("installed build network requires Linux")
}
func NewProductionManager() (*Manager, error) {
	return nil, errors.New("installed build network requires Linux")
}
func NewNativeProductionManager() (*Manager, error) {
	return nil, errors.New("installed build network requires Linux")
}
func (*Manager) Close() error { return nil }
func (*Manager) Serve(context.Context) error {
	return errors.New("installed build network requires Linux")
}
func (*Manager) Cleanup(context.Context) error {
	return errors.New("installed build network requires Linux")
}
