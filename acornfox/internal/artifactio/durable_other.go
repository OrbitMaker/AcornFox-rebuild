//go:build !linux

package artifactio

import (
	"fmt"
	"os"
	"syscall"
)

func CheckFileOwner(info os.FileInfo, uid, gid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return fmt.Errorf("durable owner mismatch")
	}
	return nil
}
