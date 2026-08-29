package install

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	ProductionUpgradeRecoveryUnitPath     = "/etc/systemd/system/open-card-upgrade-recover.service"
	ProductionUpgradeSafeBootTargetPath   = "/etc/systemd/system/open-card-upgrade-safe.target"
	ProductionUpgradeFinalizeUnitPath     = "/etc/systemd/system/open-card-upgrade-finalize.service"
	ProductionUpgradeEdgeMarkerDropInPath = "/etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf"
)

const productionUpgradeRecoveryUnitText = `[Unit]
Description=Prepare interrupted Open Card upgrade recovery
Wants=network-online.target
After=local-fs.target network-online.target
Before=open-card-upgrade-safe.target
ConditionPathExists=/var/lib/open-card/upgrade-in-progress

[Service]
Type=oneshot
ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-prepare --pending
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system
`

const productionUpgradeSafeBootTargetText = `[Unit]
Description=Open Card upgrade-safe boot barrier
Requires=open-card-upgrade-recover.service
Wants=open-card-upgrade-finalize.service
After=open-card-upgrade-recover.service
Before=open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service open-card-upgrade-finalize.service

[Install]
WantedBy=multi-user.target
RequiredBy=open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service
`

const productionUpgradeFinalizeUnitText = `[Unit]
Description=Finalize interrupted Open Card upgrade recovery
After=open-card-upgrade-safe.target
ConditionPathExists=/var/lib/open-card/upgrade-in-progress

[Service]
Type=oneshot
ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-finalize --pending
TimeoutStartSec=15min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system
`

const productionUpgradeEdgeMarkerDropInText = `[Unit]
ConditionPathExists=!/var/lib/open-card/upgrade-in-progress
`

// ProductionUpgradeRecoveryUnitBytes returns a defensive copy of the
// canonical fragment, including its final newline.
func ProductionUpgradeRecoveryUnitBytes() []byte {
	return []byte(productionUpgradeRecoveryUnitText)
}

func ProductionUpgradeSafeBootTargetBytes() []byte {
	return []byte(productionUpgradeSafeBootTargetText)
}
func ProductionUpgradeFinalizeUnitBytes() []byte { return []byte(productionUpgradeFinalizeUnitText) }
func ProductionUpgradeEdgeMarkerDropInBytes() []byte {
	return []byte(productionUpgradeEdgeMarkerDropInText)
}

// ProductionUpgradeRecoveryUnitSHA256 identifies the exact unit fragment
// without exposing a path chosen by a caller.
func ProductionUpgradeRecoveryUnitSHA256() string {
	digest := sha256.Sum256(ProductionUpgradeRecoveryUnitBytes())
	return hex.EncodeToString(digest[:])
}

func ProductionUpgradeSafeBootTargetSHA256() string {
	digest := sha256.Sum256(ProductionUpgradeSafeBootTargetBytes())
	return hex.EncodeToString(digest[:])
}
func ProductionUpgradeFinalizeUnitSHA256() string {
	digest := sha256.Sum256(ProductionUpgradeFinalizeUnitBytes())
	return hex.EncodeToString(digest[:])
}
func ProductionUpgradeEdgeMarkerDropInSHA256() string {
	digest := sha256.Sum256(ProductionUpgradeEdgeMarkerDropInBytes())
	return hex.EncodeToString(digest[:])
}
