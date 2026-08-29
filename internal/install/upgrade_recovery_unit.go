package install

import (
	"crypto/sha256"
	"encoding/hex"
)

// ProductionUpgradeRecoveryUnitPath is the only systemd recovery unit the
// privileged upgrade command will trust. The installer publishes these exact
// bytes; callers may not supply a unit name or fragment path.
const ProductionUpgradeRecoveryUnitPath = "/etc/systemd/system/open-card-upgrade-recover.service"

const productionUpgradeRecoveryUnitText = `[Unit]
Description=Recover interrupted Open Card upgrade
Wants=network-online.target
After=local-fs.target network-online.target
ConditionPathExists=/var/lib/open-card/upgrade-in-progress

[Service]
Type=oneshot
ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover --pending
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system

[Install]
WantedBy=multi-user.target
`

// ProductionUpgradeRecoveryUnitBytes returns a defensive copy of the
// canonical fragment, including its final newline.
func ProductionUpgradeRecoveryUnitBytes() []byte {
	return []byte(productionUpgradeRecoveryUnitText)
}

// ProductionUpgradeRecoveryUnitSHA256 identifies the exact unit fragment
// without exposing a path chosen by a caller.
func ProductionUpgradeRecoveryUnitSHA256() string {
	digest := sha256.Sum256(ProductionUpgradeRecoveryUnitBytes())
	return hex.EncodeToString(digest[:])
}
