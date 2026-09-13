//go:build acornfox_internal_testing && darwin && cgo

package darwinlaunch

/*
#cgo CFLAGS: -Wall -Werror -Wno-unused-variable -DACORNFOX_INTERNAL_TESTING=1
#include "security_darwin.h"
*/
import "C"

const InternalTestingEnabled = true

func injectSpawnFailure(code int) {
	C.inject_spawn_failure(C.int(code))
}

func clearSpawnFailure() {
	C.clear_spawn_failure()
}
