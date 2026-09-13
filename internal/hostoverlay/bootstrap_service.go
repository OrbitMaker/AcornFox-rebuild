package hostoverlay

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

const (
	// BootstrapServiceName is the canonical systemd unit name for the host bootstrap service.
	BootstrapServiceName = "acornfox-host-bootstrap.service"

	// BootstrapUnitPath is the canonical absolute systemd unit file path.
	BootstrapUnitPath = "/etc/systemd/system/acornfox-host-bootstrap.service"

	// BootstrapUnitRelativePath is the unit file path relative to host root.
	BootstrapUnitRelativePath = "etc/systemd/system/acornfox-host-bootstrap.service"

	// BootstrapEnableLinkPath is the canonical absolute enable symlink path.
	BootstrapEnableLinkPath = "/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service"

	// BootstrapEnableLinkRelativePath is the enable symlink path relative to host root.
	BootstrapEnableLinkRelativePath = "etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service"

	// BootstrapEnableLinkTarget is the canonical relative symlink target.
	BootstrapEnableLinkTarget = "../acornfox-host-bootstrap.service"

	// BootstrapUnitFileMode is the canonical file permission mode for the unit file (0644).
	BootstrapUnitFileMode os.FileMode = 0o644
)

// BootstrapUnitText is the immutable canonical systemd service unit declaration.
const BootstrapUnitText = `[Unit]
After=network-online.target docker.service postgresql.service acornfox-upgrade-safe.target
Wants=network-online.target
Requires=acornfox-upgrade-safe.target

[Service]
Type=oneshot
RuntimeDirectory=acornfox-host
RuntimeDirectoryMode=0700
ExecStart=/usr/local/libexec/acornfox-host-bootstrap start
RemainAfterExit=yes
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
`

// BootstrapUnitBytes returns a defensive copy of the canonical unit file bytes.
func BootstrapUnitBytes() []byte {
	return []byte(BootstrapUnitText)
}

// BootstrapUnitSHA256 returns the hex-encoded SHA-256 digest of the canonical unit file bytes.
func BootstrapUnitSHA256() string {
	digest := sha256.Sum256(BootstrapUnitBytes())
	return hex.EncodeToString(digest[:])
}
