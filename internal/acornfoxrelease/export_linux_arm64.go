//go:build linux && arm64

package acornfoxrelease

import "syscall"

const sysRenameat2 = syscall.SYS_RENAMEAT2
