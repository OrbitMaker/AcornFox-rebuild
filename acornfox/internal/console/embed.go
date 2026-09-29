// Package console embeds the AcornFox web console (a dependency-free,
// framework-free static site). The server serves FS at "/" with index.html as
// the default document. Files are embedded at build time and never read from
// disk, so the console cannot be tampered with at runtime.
package console

import (
	"embed"
	"io/fs"
)

//go:embed static
var staticFS embed.FS

// FS is the console's static file tree rooted at the "static" directory, so
// index.html is served at "/", app.js at "/app.js", and so on.
var FS fs.FS

func init() {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// The embed directive guarantees "static" exists; a failure here is a
		// build/programming error, not a runtime condition.
		panic("console: embed sub FS: " + err.Error())
	}
	FS = sub
}
