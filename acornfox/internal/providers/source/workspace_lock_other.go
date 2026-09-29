//go:build !darwin && !linux

package source

import "errors"

func acquireWorkspaceRootLock(string) (func(), error) {
	return nil, errors.New("source workspace root lock is unsupported")
}
