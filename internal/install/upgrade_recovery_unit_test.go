package install

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestProductionUpgradeRecoveryUnitIsExactAndDigested(t *testing.T) {
	want := "[Unit]\nDescription=Recover interrupted Open Card upgrade\nWants=network-online.target\nAfter=local-fs.target network-online.target\nConditionPathExists=/var/lib/open-card/upgrade-in-progress\n\n[Service]\nType=oneshot\nExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover --pending\nTimeoutStartSec=15min\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system\n\n[Install]\nWantedBy=multi-user.target\n"
	first := ProductionUpgradeRecoveryUnitBytes()
	second := ProductionUpgradeRecoveryUnitBytes()
	if string(first) != want || string(second) != want {
		t.Fatalf("recovery unit drifted: %q", first)
	}
	first[0] = '!'
	if string(ProductionUpgradeRecoveryUnitBytes()) != want {
		t.Fatal("recovery unit bytes are not defensive")
	}
	digest := sha256.Sum256([]byte(want))
	if got := ProductionUpgradeRecoveryUnitSHA256(); got != hex.EncodeToString(digest[:]) {
		t.Fatalf("recovery unit digest=%s", got)
	}
}
