//go:build unix

package main

import (
	"io/fs"
	"syscall"
)

func singleLinkedProjectFile(info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
