// Package pack turns a project directory into the tar.gz upload that
// acornfox server builds from (docs/n2-contract.md section 3, deploy).
package pack

import "errors"

// MaxBytes is the largest compressed upload the server accepts.
const MaxBytes = 200 << 20

var (
	ErrTooLarge          = errors.New("pack: upload exceeds 200 MB")
	ErrDockerfileMissing = errors.New("pack: no Dockerfile at the project root")
)

// Result describes a packed directory. Path is a temporary file the caller
// must remove.
type Result struct {
	Path   string // tar.gz file
	Bytes  int64  // compressed size
	Files  int    // regular files included
	SHA256 string // hex digest of the tar.gz bytes
}

/*
Implemented in pack.go:

	Dir(root string) (Result, error)
	    // Walks root honoring .dockerignore (Docker semantics: patterns, "!" exceptions,
	    // "**", leading "/" ignored) and always excluding ".git/" and ".acornfox".
	    // Symlinks are stored as symlinks, never followed. Paths use "/" on every OS.
	    // Entries are sorted and headers use fixed mtime/uid/gid/uname so the same tree
	    // always yields the same SHA256 (idempotent redeploys).
	    // Returns ErrDockerfileMissing if root/Dockerfile is absent (before packing) and
	    // ErrTooLarge as soon as the output passes MaxBytes (temp file removed).
*/
