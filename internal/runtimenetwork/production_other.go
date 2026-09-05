//go:build !linux

package runtimenetwork

func productionBackend(bool) (backend, error) { return nil, ErrUnavailable }
