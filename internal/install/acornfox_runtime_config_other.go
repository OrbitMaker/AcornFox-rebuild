//go:build !linux || !amd64

package install

import "os"

func acornFoxRuntimeRenameNoReplace(*os.File, string, string) error {
	return ErrAcornFoxRuntimeConfigConflict
}
