//go:build linux && arm64

package pibundle

import _ "embed"

const (
	ArchiveSHA256            = "042d20ae885ee4f3b102815f3280b962c377b2e9fb44de4037908cc530eae4d4"
	ManifestSHA256           = "7217207f1aeb5d298de152897e3aa6eafd7c55be1a534f3da71d0d9649131ec6"
	ManifestSourcePath       = "internal/pibundle/assets-v0.85.1-linux-arm64.json"
	TotalBytes         int64 = 113605101
)

//go:embed assets-v0.85.1-linux-arm64.json
var manifestRaw []byte
