//go:build !linux || (!amd64 && !arm64)

package acornfoxrelease

import "os"

func renameDirectoryNoReplace(*os.File, string, *os.File, string) error { return ErrCandidateExport }
