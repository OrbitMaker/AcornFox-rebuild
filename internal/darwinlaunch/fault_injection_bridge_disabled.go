//go:build !acornfox_internal_testing || !darwin || !cgo

package darwinlaunch

const InternalTestingEnabled = false

func injectSpawnFailure(code int) {}
func clearSpawnFailure()          {}
