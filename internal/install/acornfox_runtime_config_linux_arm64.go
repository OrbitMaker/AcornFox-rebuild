//go:build linux && arm64

package install

import "syscall"

const acornFoxSysRenameat2 = syscall.SYS_RENAMEAT2
