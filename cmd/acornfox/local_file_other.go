//go:build !unix

package main

import "io/fs"

// Platforms without verified link-count support fail closed for local upload.
func singleLinkedProjectFile(info fs.FileInfo) bool { return false }
