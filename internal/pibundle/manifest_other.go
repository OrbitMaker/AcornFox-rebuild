//go:build !(linux && arm64)

package pibundle

import _ "embed"

const (
	ArchiveSHA256            = "494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a"
	ManifestSHA256           = "e8d788ebaab78af97ca959b91a1abfe9fc820de4a4c6aadcd870bb500679934d"
	ManifestSourcePath       = "internal/pibundle/assets-v0.85.1-linux-x64.json"
	TotalBytes         int64 = 113642165
)

//go:embed assets-v0.85.1-linux-x64.json
var manifestRaw []byte
